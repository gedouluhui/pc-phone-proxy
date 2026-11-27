# -*- coding: utf-8 -*-
"""Bounded public HTTP(S) downloads with DNS pinning and manual redirects.

The hostname is used for Host and TLS SNI; the socket is connected only to an
address returned by the one validation-time DNS lookup.  Every redirect repeats
validation and pinning.  Environment proxies are never consulted.
"""
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse


class Rejected(ValueError):
    pass


class FetchError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _ip(value):
    text = str(value).split("%", 1)[0]
    address = ipaddress.ip_address(text)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def _allowed(address, allow_private):
    return allow_private or bool(address.is_global)


def validate_url(url, allow_private=False):
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise Rejected("invalid source URL") from exc
    if parsed.scheme not in ("http", "https") or not hostname:
        raise Rejected("source URL must be HTTP or HTTPS with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise Rejected("source URL credentials are not allowed")
    if parsed.fragment:
        raise Rejected("source URL fragments are not allowed")
    if any(ord(char) < 32 for char in url):
        raise Rejected("source URL contains control characters")
    try:
        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise Rejected("source hostname is not valid IDNA") from exc
    if not host:
        raise Rejected("source hostname is empty")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 0 < port < 65536:
        raise Rejected("source port is out of range")
    try:
        literal = _ip(host)
    except ValueError:
        literal = None
    if literal is not None and not _allowed(literal, allow_private):
        raise Rejected("private or non-public source address is not allowed")
    return parsed, host, port


def _resolve(host, port, allow_private):
    try:
        literal = _ip(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _allowed(literal, allow_private):
            raise Rejected("private or non-public source address is not allowed")
        return [str(literal)]
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError("source hostname resolution failed") from exc
    addresses = []
    for answer in answers:
        try:
            address = _ip(answer[4][0])
        except (ValueError, IndexError, TypeError):
            raise Rejected("source resolver returned an invalid address")
        if not _allowed(address, allow_private):
            raise Rejected("source DNS returned a private or non-public address")
        text = str(address)
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        raise Rejected("source DNS returned no addresses")
    return addresses


def validate_redirect(old_url, new_url, allow_private=False):
    old = urllib.parse.urlsplit(old_url)
    joined = urllib.parse.urljoin(old_url, new_url)
    new = urllib.parse.urlsplit(joined)
    if old.scheme == "https" and new.scheme == "http":
        raise Rejected("HTTPS source cannot downgrade to HTTP")
    return validate_url(joined, allow_private=allow_private)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, connect_ip, connect_port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._connect_ip = connect_ip
        self._connect_port = connect_port
        # Python stores this callback on the instance, so a class override is
        # silently ignored.  Replace the instance callback explicitly.
        self._create_connection = self._connect_pinned

    def _connect_pinned(self, address, timeout, source_address=None):
        return socket.create_connection((self._connect_ip, self._connect_port),
                                        timeout, source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, connect_ip, connect_port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = connect_ip
        self._connect_port = connect_port
        self._create_connection = self._connect_pinned

    def _connect_pinned(self, address, timeout, source_address=None):
        return socket.create_connection((self._connect_ip, self._connect_port),
                                        timeout, source_address)


def _authority(host, port):
    value = "[%s]" % host if ":" in host else host
    return "%s:%d" % (value, port)


def _target_authority(address, port):
    value = "[%s]" % address if ":" in address else address
    return "%s:%d" % (value, port)


def _proxy_endpoint(proxy):
    if not proxy:
        return None
    parsed, host, port = validate_url(proxy, allow_private=True)
    if parsed.scheme != "http":
        raise Rejected("bootstrap proxy must be HTTP")
    addresses = _resolve(host, port, allow_private=True)
    if not all(_ip(address).is_loopback for address in addresses):
        raise Rejected("bootstrap proxy must be loopback-only")
    return addresses[0], port


def _read_body(response, budget, keep):
    declared = response.getheader("Content-Length")
    if declared is not None:
        try:
            if int(declared) > budget:
                raise FetchError("source response exceeds byte limit")
        except ValueError:
            raise FetchError("source response has an invalid Content-Length")
    chunks = [] if keep else None
    used = 0
    while used < budget:
        chunk = response.read(min(65536, budget - used + 1))
        if not chunk:
            break
        used += len(chunk)
        if used > budget:
            raise FetchError("source response exceeds byte limit")
        if keep:
            chunks.append(chunk)
    return (b"".join(chunks) if keep else b""), used


def _request_once(url, allow_private, proxy, timeout, budget):
    parsed, host, port = validate_url(url, allow_private=allow_private)
    address = _resolve(host, port, allow_private)[0]
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {"User-Agent": "curl/8.5.0", "Accept": "*/*",
               "Accept-Encoding": "identity", "Connection": "close",
               "Host": _authority(host, port)}
    connection = None
    try:
        if parsed.scheme == "https":
            connect_ip, connect_port = proxy or (address, port)
            connection = _PinnedHTTPSConnection(host, port, connect_ip, connect_port, timeout)
            if proxy:
                # CONNECT to the validated address, then TLS still uses the
                # original hostname for certificate checks and SNI.
                connection.set_tunnel(address, port, headers={"Host": _authority(host, port)})
            target = path
        else:
            connect_ip, connect_port = proxy or (address, port)
            connection = _PinnedHTTPConnection(host, port, connect_ip, connect_port, timeout)
            target = ("http://" + _target_authority(address, port) + path) if proxy else path
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        status = response.status
        location = response.getheader("Location")
        redirect = status in (301, 302, 303, 307, 308)
        body, used = _read_body(response, budget, keep=not redirect)
        if redirect:
            if not location:
                raise FetchError("source redirect has no Location", status)
            return status, urllib.parse.urljoin(url, location), b"", used
        if status != 200:
            raise FetchError("source returned HTTP %d" % status, status)
        return status, None, body, used
    except Rejected:
        raise
    except FetchError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise FetchError("source request failed") from exc
    finally:
        if connection is not None:
            connection.close()


def fetch(url, max_bytes=16 * 1024 * 1024, timeout=30, allow_private=False,
          proxy=None, max_redirects=3):
    if not isinstance(max_bytes, int) or not 0 < max_bytes <= 64 * 1024 * 1024:
        raise Rejected("max_bytes must be between 1 and 64 MiB")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise Rejected("timeout must be positive")
    if not isinstance(max_redirects, int) or not 0 <= max_redirects <= 8:
        raise Rejected("max_redirects must be between 0 and 8")
    proxy_endpoint = _proxy_endpoint(proxy)
    deadline = time.monotonic() + timeout
    current = url
    remaining = max_bytes
    for hop in range(max_redirects + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError("source download timed out")
        status, location, body, used = _request_once(
            current, allow_private, proxy_endpoint, left, remaining)
        remaining -= used
        if location is None:
            return body
        if hop >= max_redirects:
            raise FetchError("too many source redirects", status)
        joined = urllib.parse.urljoin(current, location)
        validate_redirect(current, joined, allow_private=allow_private)
        current = joined
    raise FetchError("source redirect limit exceeded")


def safe_url(url):
    """Reporting origin only: paths and queries may contain subscription tokens."""
    try:
        parsed, host, port = validate_url(url, allow_private=True)
        return "%s://%s" % (parsed.scheme, _authority(host, port))
    except (Rejected, TypeError, ValueError):
        return "***"


def digest(data):
    return hashlib.sha256(data).hexdigest()
