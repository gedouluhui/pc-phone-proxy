# -*- coding: utf-8 -*-
"""Atomic configuration replacement with real verification and rollback.

A valid JSON document and a live process are not proof of a working tunnel.
Callers supply a verifier that exercises the actual service.  The old process
is not stopped until the candidate passes its static check; the candidate is
not promoted until the verifier explicitly reports success.
"""
import contextlib
import json
import os
import shutil
import tempfile
from pathlib import Path


class TransactionError(RuntimeError):
    pass


@contextlib.contextmanager
def write_lock(final_path):
    """Cross-process advisory lock; the OS releases it if a writer crashes."""
    path = final_path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    stream = open(path, "a+b")
    locked = False
    try:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise TransactionError("another configuration writer is active") from exc
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise TransactionError("another configuration writer is active") from exc
        locked = True
        yield
    finally:
        if locked:
            try:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        stream.close()


def _encode(content):
    if isinstance(content, bytes):
        return content
    if isinstance(content, (dict, list)):
        return (json.dumps(content, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    if isinstance(content, str):
        return content.encode("utf-8")
    raise TypeError("configuration content must be bytes, text, dict or list")


def _atomic_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".",
                                     suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.remove(temporary)
        except OSError:
            pass


def stage(final_path, content):
    staged = final_path + ".new"
    _atomic_write(staged, _encode(content))
    return staged


def promote(staged_path, final_path):
    os.replace(staged_path, final_path)


def restore(previous_path, final_path):
    _atomic_write(final_path, Path(previous_path).read_bytes())


def _check_ok(result):
    if isinstance(result, tuple):
        return bool(result) and result[0] == 0
    if isinstance(result, bool):
        return result
    if isinstance(result, int):
        return result == 0
    return False


def _verify_ok(result):
    if isinstance(result, tuple):
        result = result[0] if result else None
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        return result.strip().lower() in ("ok", "healthy", "good", "success", "pass", "passed")
    return False


def _launch_ok(result):
    if isinstance(result, tuple):
        return bool(result) and result[0] is not None
    return result is not None


def _remove(path, log):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log("configuration cleanup warning (%s): %r" % (path, exc))


class ConfigTransaction:
    def __init__(self, final_path, check, launch, verify, stop_current, log=print):
        self.final_path = os.path.abspath(final_path)
        self.check = check
        self.launch = launch
        self.verify = verify
        self.stop_current = stop_current
        self.log = log
        self._active = None

    def _check(self, path):
        try:
            return _check_ok(self.check(path))
        except BaseException as exc:
            self.log("configuration check failed (%s): %r" % (path, exc))
            return False

    def _launch(self, path):
        try:
            self._active = self.launch(path)
            return _launch_ok(self._active)
        except BaseException as exc:
            self._active = None
            self.log("configuration launch failed (%s): %r" % (path, exc))
            return False

    def _stop_owned(self):
        """Last-resort cleanup uses the Popen object we created, never a PID guess."""
        process = self._active[0] if isinstance(self._active, tuple) else self._active
        self._active = None
        if process is None:
            return
        try:
            poll = getattr(process, "poll", None)
            if callable(poll) and poll() is not None:
                return
            terminate = getattr(process, "terminate", None) or getattr(process, "kill", None)
            if not callable(terminate):
                return
            terminate()
            process.wait(timeout=6)
        except Exception as exc:
            self.log("owned candidate cleanup warning: %r" % (exc,))

    def _rollback(self, previous_path, have_previous):
        try:
            self.stop_current()
        except BaseException as exc:
            self.log("stopping rejected candidate failed: %r" % (exc,))
        self._stop_owned()
        if not have_previous:
            return False
        try:
            restore(previous_path, self.final_path)
        except OSError as exc:
            self.log("restoring previous configuration failed: %r" % (exc,))
            return False
        if not self._check(self.final_path):
            self.log("previous configuration no longer passes check; manual recovery required")
            return False
        if not self._launch(self.final_path):
            self.log("previous configuration could not be relaunched; manual recovery required")
            return False
        self.log("previous configuration restored and relaunched")
        _remove(previous_path, self.log)
        return True

    def apply(self, content):
        staged = self.final_path + ".new"
        previous = self.final_path + ".prev"
        rejected = self.final_path + ".broken"
        have_previous = os.path.isfile(self.final_path)
        promoted = False
        try:
            with write_lock(self.final_path):
                stage(self.final_path, content)
                if not self._check(staged):
                    self.log("candidate configuration rejected; current service untouched")
                    return False
                if have_previous:
                    try:
                        shutil.copyfile(self.final_path, previous)
                    except OSError as exc:
                        self.log("cannot snapshot previous configuration: %r" % (exc,))
                        return False
                try:
                    self.stop_current()
                except BaseException as exc:
                    self.log("stopping current service failed: %r" % (exc,))
                    self._rollback(previous, have_previous)
                    return False
                if not self._launch(staged):
                    self._preserve_rejected(staged, rejected)
                    self._rollback(previous, have_previous)
                    return False
                try:
                    healthy = _verify_ok(self.verify(staged))
                except BaseException as exc:
                    self.log("candidate verification failed: %r" % (exc,))
                    healthy = False
                if not healthy:
                    self._preserve_rejected(staged, rejected)
                    self._rollback(previous, have_previous)
                    return False
                try:
                    promote(staged, self.final_path)
                    promoted = True
                except OSError as exc:
                    self.log("promoting verified configuration failed: %r" % (exc,))
                    self._rollback(previous, have_previous)
                    return False
                # Past this point the new service is committed.  Cleanup must
                # never trigger a rollback to a configuration no longer in use.
                _remove(previous, self.log)
                self.log("verified configuration committed")
                return True
        finally:
            if not promoted:
                _remove(staged, self.log)

    def _preserve_rejected(self, staged, rejected):
        try:
            shutil.copyfile(staged, rejected)
        except OSError as exc:
            self.log("could not preserve rejected configuration: %r" % (exc,))
