"""Real diagnostic/render functions, synthetic data and memory-only application I/O."""
import ast
import copy
import html
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import sys
import time
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_fixtures import SOURCE, functions, tree

# Absolute but virtual: none of these paths are ever opened on the filesystem.
ROOT = str(Path(__file__).resolve().parent / "synthetic-not-on-disk")
ACTIVE = os.path.join(ROOT, "active-fixture.json")
TRIALS = os.path.join(ROOT, "trials-fixture.json")
REPORT = os.path.join(ROOT, "report-fixture.html")
MARKERS = ("CANARY_USER_41", "CANARY_PASSWORD_42", "CANARY_QUERY_43", "CANARY_NESTED_44")
URI = "trojan://%s:%s@node.example:443?token=%s" % MARKERS[:3]
XSS = '<img src=x onerror="alert(1)">'


class MemoryFiles:
    def __init__(self, values):
        self.data = {str(k): json.dumps(v) for k, v in values.items()}
        self.access = []

    def open(self, path, mode="r", **kwargs):
        path = str(path)
        assert os.path.isabs(path) and os.path.commonpath([ROOT, path]) == ROOT, path
        self.access.append((path, mode))
        if "r" in mode:
            if path not in self.data:
                raise FileNotFoundError(path)
            return io.StringIO(self.data[path])
        assert mode == "w", mode
        owner = self

        class Output(io.StringIO):
            def close(self):
                owner.data[path] = self.getvalue()
                super().close()
        return Output()

    def isfile(self, path):
        assert os.path.commonpath([ROOT, str(path)]) == ROOT, path
        return str(path) in self.data


def diagnostics_module():
    path = SOURCE / "diagnostics.py"
    if not path.is_file():
        return None  # Old-code red tests exercise existing functions without a proposed API.
    ns = {"__name__": "diagnostics_fixture"}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), ns)
    return types.SimpleNamespace(**ns)


def record(**kw):
    return dict({"tag": "node-1", "id": "node-1", "kind": "node", "label": "Synthetic node",
                 "proto": "trojan", "server": "node.example", "host": "node.example", "port": 443,
                 "loc": "US", "dl_kbps": 800, "ul_kbps": 120, "cg_ttfb_ms": 100,
                 "ttfb_ms": 100, "speed_kbps": 800, "score": 950, "chatgpt_ok": True,
                 "github_ok": True, "ok_both": True, "uri": URI,
                 "user": MARKERS[0], "password": MARKERS[1], "token": MARKERS[2],
                 "outbound": {"password": MARKERS[3]}, "unknown": {"secret": MARKERS[3]}}, **kw)


def state():
    return {"at": "2026-11-18T00:00:00Z", "chosen": record(), "rows": [record()],
            "mode": "pac", "endpoint": "127.0.0.1:2101", "general": "127.0.0.1:2101",
            "fast": "127.0.0.1:2103", "previous": {"sys_enabled": True, "sys_server": URI, "token": MARKERS[2]},
            "baseline": {"sys_enabled": True, "sys_server": URI, "outbound": {"password": MARKERS[3]}},
            "verify": {"ok": False, "err": "connect " + URI, "speed_kbps": 800, "ttfb_ms": 100,
                       "fast": {"err": "password=" + MARKERS[1]}},
            "gates": [{"endpoint": "127.0.0.1:2101", "general": True, "fast": True,
                       "sites": {"chatgpt": {"code": "200", "size": 60000, "secs": 0.3,
                                            "verdict": "ok", "location": URI,
                                            "markers": ["password=" + MARKERS[1]]}}}]}


def emit_bestroute(row, old):
    """Execute only main's actual diagnostic section, never selection/control/startup.

    Structural anchors are the existing rows_out assignment and PINNED write. The latter
    is excluded; the complete ACTIVE dump in between remains real production code.
    """
    parsed, path = tree("bestroute")
    main = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    start = next(i for i, n in enumerate(main.body) if isinstance(n, ast.Assign) and
                 any(isinstance(t, ast.Name) and t.id == "rows_out" for t in n.targets))
    end = next(i for i, n in enumerate(main.body) if isinstance(n, ast.With) and
               isinstance(n.items[0].context_expr, ast.Call) and
               isinstance(n.items[0].context_expr.args[0], ast.Name) and
               n.items[0].context_expr.args[0].id == "PINNED")
    files = MemoryFiles({ACTIVE: old})
    namespace = {"rows": [row], "gen": [row], "P": types.SimpleNamespace(ACTIVE=ACTIVE),
                 # Only old rows use this dependency; chosen/unknown/nested data still expose the defect.
                 "N": types.SimpleNamespace(redact_uri=lambda _: "[redacted]"),
                 "json": json, "time": time, "open": files.open,
                 "score": functions("bestroute", ["score"]).score,
                 "D": diagnostics_module(), "GENERAL_HTTP": 2101,
                 "pac_info": {"url": "http://127.0.0.1:8891/proxy.pac", "ok": True},
                 "general_ep": "127.0.0.1:2101", "fast_ep": "127.0.0.1:2103", "CLI_MIXED": 2090,
                 "ver": old["verify"], "gates": old["gates"], "gtags": ["g0"], "ftags": ["f0"]}
    before = copy.deepcopy((row, old))
    exec(compile(ast.Module(body=main.body[start:end], type_ignores=[]), path, "exec"), namespace)
    assert (row, old) == before, "Diagnostic projection must not mutate runtime records"
    return json.loads(files.data[ACTIVE])


def render(act=None, history=None, browser=None):
    values = {}
    if act is not None:
        values[ACTIVE] = act
    if history is not None:
        values[TRIALS] = history
    if browser is not None:
        values[os.path.join(ROOT, "edge_check.json")] = browser
    files = MemoryFiles(values)
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(isfile=files.isfile, join=os.path.join))
    module = functions("proxyctl", ["render_report"], json=json, io=types.SimpleNamespace(open=files.open),
                       open=files.open, os=fake_os, HERE=ROOT, ACTIVE=ACTIVE, TRIALS=TRIALS, REPORT=REPORT,
                       current_proxy=lambda: {}, D=diagnostics_module(), escape=html.escape)
    before = copy.deepcopy(values)
    assert module.render_report() == REPORT
    assert values == before
    return files.data[REPORT], files.access


class HtmlAudit(HTMLParser):
    def __init__(self, markup):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


class DiagnosticPrivacy(unittest.TestCase):
    def assertPrivate(self, value):
        blob = value if isinstance(value, str) else json.dumps(value)
        for marker in MARKERS:
            self.assertNotIn(marker, blob)

    def test_chosen_and_rows_are_whitelisted_without_mutation(self):
        result = emit_bestroute(record(), state())
        for where in ("chosen", "rows"):
            with self.subTest(where=where):
                value = result[where]
                self.assertPrivate(value)
                rows = value if isinstance(value, list) else [value]
                for row in rows:
                    self.assertFalse({"uri", "user", "password", "token", "outbound", "unknown"} & row.keys())
        self.assertEqual(result["chosen"]["id"], "pinned-general")
        self.assertEqual(result["rows"][0]["speed_kbps"], 800)
        self.assertEqual(result["chosen"]["port"], 443)  # Preserve existing record contract, not process behavior.
        self.assertEqual(result["groups"], {"general": ["g0"], "fast": ["f0"]})

    def test_previous_baseline_verify_and_gates_are_projected(self):
        result = emit_bestroute(record(chatgpt_ok=False, chatgpt_verdict="connect " + URI), state())
        for key in ("rows", "previous", "baseline", "verify", "gates"):
            with self.subTest(key=key):
                self.assertPrivate(result[key])
        self.assertEqual(result["previous"]["sys_enabled"], True)
        self.assertEqual(result["gates"][0]["sites"]["chatgpt"]["code"], "200")

    def test_html_cannot_expose_credentials_in_any_text_surface(self):
        for field, value in (("label", URI), ("err", "password=" + MARKERS[1]),
                             ("proto", "token=" + MARKERS[2]), ("label", {"password": MARKERS[3]})):
            act = state()
            act["rows"] = [record(ok_both=False, **{field: value})]
            with self.subTest(field=field, value=value):
                markup, _ = render(act, browser={"browser": "Edge", "rows": {
                    "chatgpt": {"status": 200, "secs": 1, "title": URI, "text": MARKERS[3]}}})
                self.assertPrivate(markup)

    def test_html_xss_is_visible_text_not_markup(self):
        act = state()
        act["rows"] = [record(label=XSS, err=XSS, proto=XSS, ok_both=False)]
        markup, _ = render(act, history=[{"at": XSS, "secs": 1, "rows": []}],
                           browser={"browser": XSS, "at": XSS, "rows": {
                               "chatgpt": {"title": XSS, "status": 200, "secs": 1}}})
        audit = HtmlAudit(markup)
        self.assertNotIn(XSS, markup)
        self.assertIn(html.escape(XSS, quote=True), markup)
        self.assertGreaterEqual("".join(audit.text).count(XSS), 6)
        self.assertFalse({"script", "img", "iframe", "object", "embed", "a", "link"} & {t for t, _ in audit.tags})
        self.assertFalse(any(k.lower().startswith("on") or k in {"href", "src", "srcdoc"}
                             for _, attrs in audit.tags for k in attrs))

    def test_offline_document_metadata_and_csp(self):
        markup, access = render(state())
        audit = HtmlAudit(markup)
        self.assertIn(("html", {"lang": "zh-CN"}), audit.tags)
        self.assertTrue(any(t == "meta" and a.get("name") == "viewport" for t, a in audit.tags))
        csp = next((a.get("content", "") for t, a in audit.tags if t == "meta" and
                    a.get("http-equiv", "").lower() == "content-security-policy"), "")
        for directive in ("default-src 'none'", "script-src 'none'", "connect-src 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, csp)
        self.assertTrue(all(os.path.commonpath([ROOT, p]) == ROOT for p, _ in access))

    def test_credential_text_is_discarded_whole_even_when_quoted_or_encoded(self):
        values = [URI, 'failed: {"password": "' + MARKERS[1] + '"}',
                  "failed: {'token': '" + MARKERS[2] + "'}", "userinfo=" + MARKERS[0],
                  "user=" + MARKERS[0], "Authorization: Bearer " + MARKERS[1],
                  "password " + MARKERS[1], "api-key=" + MARKERS[2],
                  "https%3A%2F%2F" + MARKERS[0], "//" + MARKERS[0] + ":" + MARKERS[1] + "@node.example"]
        for value in values:
            with self.subTest(value=value):
                act = state()
                act["rows"] = [record(label=value, err=value, ok_both=False)]
                markup, _ = render(act, browser={"rows": {"chatgpt": {"title": value}}})
                self.assertPrivate(markup)
                projected = diagnostics_module().text(value)
                self.assertNotIn("node.example", projected)  # No half-URI retention.
                self.assertEqual(projected, diagnostics_module().REDACTED)

    def test_malformed_display_values_do_not_crash_or_turn_into_secrets(self):
        for bad in (None, [], {"password": MARKERS[1]}, "token=" + MARKERS[2],
                    float("inf"), float("nan"), 10 ** 1000):
            with self.subTest(kind=type(bad).__name__):
                act = state()
                act["chosen"] = record(speed_kbps=bad, ttfb_ms=bad)
                act["rows"] = [record(score=bad, speed_kbps=bad, ttfb_ms=bad)]
                markup, _ = render(act, browser={"rows": {"chatgpt": {"title": XSS, "secs": bad}}})
                self.assertPrivate(markup)
        for bad in (None, [], "token=" + MARKERS[2]):
            act = {"chosen": bad, "rows": bad, "gates": bad, "verify": bad}
            markup, _ = render(act, history=[{}], browser={"rows": bad})
            self.assertPrivate(markup)

    def test_safe_local_pac_metadata_and_unknown_fields(self):
        module = diagnostics_module()
        original = state()
        original.update({"unknown": {"password": MARKERS[1]},
                         "pac": {"ok": True, "url": "http://127.0.0.1:8891/proxy.pac", "unknown": URI},
                         "applied": "PAC http://127.0.0.1:8891/proxy.pac"})
        safe = module.state(original)
        self.assertPrivate(safe)
        self.assertNotIn("unknown", safe)
        self.assertEqual(safe["pac"]["url"], "http://127.0.0.1:8891/proxy.pac")
        self.assertEqual(safe["applied"], original["applied"])
        self.assertEqual(module.state(safe), safe)
        for url in (URI, "http://127.0.0.1:8891/proxy.pac?token=" + MARKERS[2],
                    "http://evil.example:8891/proxy.pac", "http://127.0.0.1:0/proxy.pac"):
            self.assertEqual(module.local_pac_url(url), module.REDACTED)

    def test_history_fallback_and_empty_report_positive_controls(self):
        markup, _ = render(history=[{"at": "synthetic-time", "secs": 2,
                                     "rows": [record(label="Synthetic history", err="timeout", ok_both=False)]}])
        self.assertIn("Synthetic history", markup)
        self.assertIn("timeout", markup)
        empty, _ = render()
        self.assertIn("本次未跑站点闸门", empty)
        normal, _ = render(state())
        for text in ("Synthetic node", "800 kB/s", "127.0.0.1:2101", "2026-11-18"):
            self.assertIn(text, normal)


if __name__ == "__main__":
    unittest.main(verbosity=2)
