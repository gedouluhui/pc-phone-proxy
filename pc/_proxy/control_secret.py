# -*- coding: utf-8 -*-
"""DPAPI-backed secret for this user's loopback Clash control API.

The ciphertext is safe to place in a per-user diagnostic bundle; the plaintext
never leaves the process except in the local Authorization header.  A damaged
or foreign-user store is a hard error: silently replacing it would let an
attacker desynchronise the running sing-box and its controller.
"""
import base64
import csv
import io
import os
import secrets
import subprocess
import sys

if sys.platform != "win32":
    raise RuntimeError("control_secret requires Windows DPAPI")

import ctypes
import functools
from ctypes import wintypes

_ENTROPY = b"PhoneProxy loopback control API\x00v1"
NOWIN = 0x08000000


class ControlSecretError(RuntimeError):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


_crypt = ctypes.WinDLL("crypt32", use_last_error=True)
_crypt.CryptProtectData.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR,
                                    ctypes.POINTER(_Blob), ctypes.c_void_p,
                                    ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(_Blob)]
_crypt.CryptProtectData.restype = wintypes.BOOL
_crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p,
                                      ctypes.POINTER(_Blob), ctypes.c_void_p,
                                      ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(_Blob)]
_crypt.CryptUnprotectData.restype = wintypes.BOOL
_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel.LocalFree.argtypes = [ctypes.c_void_p]
_kernel.LocalFree.restype = ctypes.c_void_p


def default_path():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise ControlSecretError("LOCALAPPDATA is unavailable")
    return os.path.join(base, "PhoneProxy", "control-secret.bin")


def _current_sid():
    try:
        raw = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=10,
                             creationflags=NOWIN, check=True).stdout
        sid = next(csv.reader(io.StringIO(raw)))[1].strip()
        if not sid.startswith("S-1-"):
            raise ValueError("unexpected SID")
        return sid
    except Exception as exc:
        raise ControlSecretError("cannot determine current user SID") from exc


def _harden_acl(path):
    sid = _current_sid()
    result = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                             "*" + sid + ":(F)"], capture_output=True, text=True,
                            creationflags=NOWIN, timeout=20)
    if result.returncode != 0:
        try:
            os.remove(path)
        except OSError:
            pass
        raise ControlSecretError("cannot restrict control-secret ACL: " +
                                 (result.stderr or result.stdout).strip()[-300:])


def _protect(data, entropy=_ENTROPY):
    source = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    extra = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
    incoming = _Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    entropy_blob = _Blob(len(entropy), ctypes.cast(extra, ctypes.POINTER(ctypes.c_ubyte)))
    output = _Blob()
    ok = _crypt.CryptProtectData(ctypes.byref(incoming), "PhoneProxy control API",
                                 ctypes.byref(entropy_blob), None, None, 1,
                                 ctypes.byref(output))
    if not ok:
        raise ControlSecretError("CryptProtectData failed: %d" % ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        _kernel.LocalFree(output.pbData)


def _unprotect(data, entropy=_ENTROPY):
    if not data:
        raise ControlSecretError("control-secret store is empty")
    source = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    extra = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
    incoming = _Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    entropy_blob = _Blob(len(entropy), ctypes.cast(extra, ctypes.POINTER(ctypes.c_ubyte)))
    output = _Blob()
    ok = _crypt.CryptUnprotectData(ctypes.byref(incoming), None, ctypes.byref(entropy_blob),
                                   None, None, 1, ctypes.byref(output))
    if not ok:
        raise ControlSecretError("CryptUnprotectData failed: %d" % ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        _kernel.LocalFree(output.pbData)


def _valid_secret(value):
    return len(value) >= 32 and all(c.isalnum() or c in "-_=" for c in value)


@functools.lru_cache(maxsize=1)
def _get_default():
    return _load_or_create(default_path())


def get_or_create(path=None):
    """Return the existing user-bound secret, or create it exclusively.

    The default store is cached for this process; hundreds of concurrent delay
    probes must not each spawn ``whoami`` and decrypt DPAPI.  Explicit paths are
    never cached (used by tests and isolated installations).
    """
    return _get_default() if path is None else _load_or_create(os.path.abspath(path))


def _load_or_create(path):
    """Never overwrite an existing file.  Two simultaneous starters may race;
    the loser reads the winner's complete ciphertext and uses the same secret.
    """
    path = os.path.abspath(path)
    if os.path.exists(path):
        raw = _read(path)
        return _decode(raw)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    encrypted = _protect(token.encode("ascii"))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _decode(_read(path))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    _harden_acl(path)
    return token


def _read(path):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(16384)
    except OSError as exc:
        raise ControlSecretError("cannot read control-secret store") from exc
    if len(raw) > 8192 or len(raw) < 32:
        raise ControlSecretError("control-secret store has an invalid size")
    return raw


def _decode(raw):
    try:
        value = _unprotect(raw).decode("ascii")
    except Exception as exc:
        if isinstance(exc, ControlSecretError):
            raise
        raise ControlSecretError("control-secret plaintext is invalid") from exc
    if not _valid_secret(value):
        raise ControlSecretError("control-secret plaintext has an invalid format")
    return value
