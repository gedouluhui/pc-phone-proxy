# -*- coding: utf-8 -*-
"""Authenticated, proxy-free requests to this installation's loopback API."""
import json
import urllib.error
import urllib.parse
import urllib.request

from control_secret import ControlSecretError, get_or_create


class ControlApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Rejected(ControlApiError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Rejected("Clash control API must not redirect")


def validate_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise Rejected("invalid Clash control URL") from exc
    if parsed.scheme != "http" or host not in ("127.0.0.1", "::1", "localhost"):
        raise Rejected("Clash control URL must be plain HTTP on loopback")
    if parsed.username is not None or parsed.password is not None or not port:
        raise Rejected("Clash control URL must not include credentials")
    return parsed


def headers():
    try:
        secret = get_or_create()
    except ControlSecretError as exc:
        raise ControlApiError("local control secret unavailable") from exc
    return {"Authorization": "Bearer " + secret}


def request(method, url, *, timeout=3.0, body=None, json_body=None):
    validate_url(url)
    try:
        auth = headers()
    except ControlApiError:
        raise
    except Exception as exc:
        raise ControlApiError("local control secret unavailable") from exc
    data = body
    hdrs = dict(auth)
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(8 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        raise ControlApiError("Clash control API returned HTTP %d" % exc.code, exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ControlApiError("Clash control API request failed") from exc


def json_request(method, url, **kwargs):
    raw = request(method, url, **kwargs)
    try:
        return json.loads(raw.decode("utf-8", "replace") or "{}")
    except (ValueError, UnicodeError) as exc:
        raise ControlApiError("Clash control API returned invalid JSON") from exc
