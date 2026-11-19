"""Pure, allowlisted diagnostic views. Never use these to build runtime configs.

Unknown fields and nested objects are not display data. URI/credential-bearing
text is suppressed as a whole, never partially redacted into a shareable URI.
HTML escaping is a separate responsibility of the report renderer.
"""
import math
import re
from urllib.parse import urlsplit

REDACTED = "[details omitted]"
_CREDENTIAL_TEXT = re.compile(
    r"://|@|\?|%[0-9a-f]{2}|(?:^|[^a-z0-9])(?:password|passwd|pass|token|secret|uuid|"
    r"authorization|userinfo|username|user|api[_-]?key|credentials|bearer|basic)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


def text(value):
    if not isinstance(value, str):
        return REDACTED
    # Check the entire field before truncating, including encoded URLs/credentials.
    if _CREDENTIAL_TEXT.search(value) or any(ord(c) < 32 for c in value):
        return REDACTED
    return value[:240]


def number(value):
    if type(value) not in (int, float) or abs(value) > 1e15 or not math.isfinite(value):
        return None
    return value


def boolean(value):
    return value if type(value) is bool else None


def project(value, schema):
    if not isinstance(value, dict):
        return {}
    return {key: convert(value[key]) for key, convert in schema.items() if key in value}


def records(value, convert):
    return [convert(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def strings(value):
    return [text(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


def row(value):
    schema = {key: text for key in ("id", "tag", "label", "kind", "proto", "host", "server", "loc", "err")}
    schema.update({key: number for key in ("port", "score", "ttfb_ms", "speed_kbps", "dl_kbps",
                                           "ul_kbps", "cg_ttfb_ms", "weight")})
    schema.update({key: boolean for key in ("ok_both", "chatgpt_ok", "github_ok")})
    result = {"id": "", "label": "—", "proto": "—"}
    result.update(project(value, schema))
    if result.get("score") is None:
        result.pop("score", None)
    return result


def previous(value):
    return project(value, {"at": text, "sys_enabled": boolean, "sys_server": text, "geph_running": boolean})


def verification(value):
    schema = {"ok": boolean, "plain_http": boolean, "endpoint": text, "err": text,
              "ttfb_ms": number, "speed_kbps": number, "upload_kbps": number}
    result = project(value, schema)
    if isinstance(value, dict) and "fast" in value:
        result["fast"] = project(value["fast"], schema)
    return result


GATE_NAMES = ("chatgpt", "chatgpt_api", "claude", "kaggle", "google", "github", "huggingface")
BROWSER_NAMES = ("cloudflare_trace", "chatgpt", "chatgpt_login", "claude", "gemini", "google",
                 "youtube", "github", "huggingface", "x", "wikipedia", "kaggle")


def markers(value):
    allowed = {"unsupported_country", "challenge", "blocked"}
    return [v for v in value if isinstance(v, str) and v in allowed] if isinstance(value, list) else []


def site(value):
    return project(value, {"code": text, "size": number, "secs": number, "verdict": text, "markers": markers})


def gate(value):
    result = project(value, {"endpoint": text, "role": text, "general": boolean, "fast": boolean})
    result["sites"] = project(value.get("sites"), {key: site for key in GATE_NAMES})
    return result


def local_pac_url(value):
    if not isinstance(value, str):
        return REDACTED
    try:
        url = urlsplit(value)
        if (url.scheme == "http" and url.hostname in ("127.0.0.1", "::1") and
                url.port and 1 <= url.port <= 65535 and not url.username and not url.password and
                not url.query and not url.fragment and url.path == "/proxy.pac" and
                not any(ord(c) <= 32 for c in value)):
            return value
    except ValueError:
        pass
    return REDACTED


def applied(value):
    if isinstance(value, str) and value.startswith("PAC "):
        url = local_pac_url(value[4:])
        return "PAC " + url
    return text(value)


def pac(value):
    return project(value, {"ok": boolean, "url": local_pac_url, "port": number, "general": text,
                           "fast": text, "hk": text, "steam": text, "err": text})


def state(value):
    return project(value, {
        "at": text, "chosen": row, "rows": lambda v: records(v, row), "applied": applied,
        "previous": previous, "baseline": previous, "endpoint": text, "verify": verification,
        "mode": text, "pac": pac, "general": text, "fast": text, "cli": text,
        "gates": lambda v: records(v, gate), "pinned": boolean,
        "groups": lambda v: project(v, {"general": strings, "fast": strings}),
        "dead_summary": lambda v: {},
    })


def history(value):
    return records(value, lambda v: project(v, {"at": text, "secs": number,
                                               "rows": lambda rows: records(rows, row)}))


def browser(value):
    # Raw page text, redirects, headers and unknown site records are intentionally excluded.
    return project(value, {"at": text, "browser": text, "rows": lambda rows: project(rows, {
        key: lambda v: project(v, {"status": number, "secs": number, "title": text, "err": text})
        for key in BROWSER_NAMES
    })})
