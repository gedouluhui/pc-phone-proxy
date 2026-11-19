"""Synthetic PAC execution tests. Requires Node; never probes an endpoint."""
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_fixtures import functions, load_pac

G, F, H, S, D = ["127.0.0.1:" + str(p) for p in (2101, 2103, 2086, 2096, 2199)]
NODE = shutil.which("node")
VM = r'''
const vm = require('node:vm');
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
function shExpMatch(s, p) {
  // PAC shell wildcards, including character classes used by this production PAC.
  let r = '^';
  for (let i = 0; i < p.length; ++i) {
    let c = p[i];
    if (c === '*') r += '.*';
    else if (c === '?') r += '.';
    else if (c === '[' && p.indexOf(']', i) > i) {
      let end = p.indexOf(']', i); r += p.slice(i, end + 1); i = end;
    } else r += /[\\^$.*+?()[\]{}|]/.test(c) ? '\\' + c : c;
  }
  return new RegExp(r + '$').test(s);
}
const context = vm.createContext({
  dnsDomainIs: (h, d) => h.endsWith(d),
  isPlainHostName: h => !h.includes('.'), shExpMatch
});
vm.runInContext(input.pac, context, {timeout: 1000});
const routes = input.hosts.map(h => {
  context.testHost = h;
  return vm.runInContext('FindProxyForURL("https://" + testHost + "/", testHost)', context, {timeout: 1000});
});
process.stdout.write(JSON.stringify({routes, injected: context.INJECTED || false}));
'''


def execute(pac, hosts):
    if not NODE:
        raise AssertionError("Node is required; security execution tests must not silently skip")
    r = subprocess.run([NODE, "-e", VM], input=json.dumps({"pac": pac, "hosts": hosts}),
                       capture_output=True, text=True, encoding="utf-8", timeout=15)
    if r.returncode:
        raise AssertionError("Generated PAC failed in Node VM: " + r.stderr)
    return json.loads(r.stdout)


def chain(*eps, direct=False):
    return "; ".join(["PROXY " + ep for ep in dict.fromkeys(eps) if ep] + (["DIRECT"] if direct else []))


class PacSecurity(unittest.TestCase):
    def setUp(self):
        self.p = load_pac()

    def render(self, **kw):
        return self.p["render_pac"](**dict({"general": G, "fast": F, "stamp": "synthetic"}, **kw))

    def test_protected_matrix_keeps_selected_exit_without_direct(self):
        # Removing protection from any earlier Steam/HK/dynamic branch must fail here.
        protected = self.p["GENERAL"]
        self.assertTrue({"chatgpt.com", "openai.com", "claude.ai"}.issubset(protected))
        for steam, hk, dyn in itertools.product((None, S), (None, H), (False, True)):
            with self.subTest(steam=steam, hk=hk, dyn=dyn):
                pac = self.render(steam=steam, hk=hk,
                                  dyn={"ai": {"proxy": D, "domains": protected}} if dyn else {})
                hosts = protected + ["API." + h.upper() + "." for h in protected]
                result = execute(pac, hosts)
                self.assertFalse(result["injected"])
                for host, actual in zip(hosts, result["routes"]):
                    base = host.lower().removeprefix("api.").rstrip(".")
                    first = S if steam and base in self.p["STEAM"] else H if hk and base in self.p["HK"] else D if dyn else None
                    expected = chain(first, F, G) if first else chain(G, F)
                    self.assertEqual(actual, expected, host)
                    self.assertNotIn("DIRECT", actual.split("; "))

    def test_product_policy_positive_controls(self):
        hosts = ["unlisted.example", "steampowered.com", "reddit.com", "kimi.com", "kaggle.com",
                 "paypal.com", "localhost", "printer.local", "service.corp", "192.168.0.1",
                 "100.64.0.2", "172.31.0.2", "169.254.1.2", "[fd00::1]", "[::1]",
                 "aistudio.google.com", "gemini.google.com", "google.com", "dynamic.example"]
        routes = execute(self.render(steam=S, hk=H, dyn={"GOOGLE": {"proxy": H, "domains": ["google.com"]},
                            "normal": {"proxy": D, "domains": ["dynamic.example"]}}), hosts)["routes"]
        google = chain(F, G, S, direct=True)
        self.assertEqual(routes, [chain(F, G, direct=True), chain(S, F, G, direct=True),
                                chain(H, F, G, direct=True)] + ["DIRECT"] * 12 +
                                [google, google, chain(H, F, G, direct=True), chain(D, F, G, direct=True)])

    def test_protection_wins_explicit_list_intersections(self):
        for name in ("DOMESTIC", "SENSITIVE", "DIRECT", "FAST", "GOOGLE_APP"):
            with self.subTest(name=name):
                self.p[name] = self.p[name] + ["chatgpt.com"]
                route = execute(self.render(steam=S), ["chatgpt.com"])["routes"][0]
                # Preserve Google support-region priority when that list overlaps.
                expected = chain(F, G, S) if name == "GOOGLE_APP" else chain(S, F, G)
                self.assertEqual(route, expected)
                self.p = load_pac()
        self.p["GENERAL"] += ["protected.local", "protected.cn"]
        self.assertEqual(execute(self.render(), ["protected.local", "protected.cn"])["routes"], [chain(G, F)] * 2)

    def test_domain_normalization_and_label_boundaries(self):
        pac = self.render(dyn={"Case": {"proxy": D, "domains": ["EXAMPLE.COM.", "xn--bcher-kva.example"]}})
        hosts = ["example.com", "Sub.Example.COM.", "example.com.evil", "evil-example.com",
                 "xn--bcher-kva.example"]
        self.assertEqual(execute(pac, hosts)["routes"], [chain(D, F, G, direct=True)] * 2 +
                         [chain(F, G, direct=True)] * 2 + [chain(D, F, G, direct=True)])

    def test_invalid_domains_are_rejected(self):
        for domain in ['evil"; INJECTED=true; //', "evil\\name.com", "bad\x00.com", "bad\n.com",
                       "bücher.example", "*.example.com", ".example.com", "a..com", "-a.com", "a_.com",
                       "example.com..", "a" * 64 + ".com", " example.com", "https://example.com", 12, None]:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                self.render(dyn={"bad": {"proxy": D, "domains": [domain]}})
        with self.assertRaises(ValueError):
            self.p["_js_list"]("GOOD", "example.com")

    def test_identifiers_are_ascii_and_collision_free(self):
        for name in ("a-b", "A B", "中文", "é", "9bad", 'x; INJECTED=true; //'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.p["_js_list"](name, ["example.com"])
            with self.subTest(dynamic=name), self.assertRaises(ValueError):
                self.render(dyn={name: {"proxy": D, "domains": ["example.com"]}})
        pac = self.render(dyn={"route": {"proxy": D, "domains": ["one.example"]},
                               "ROUTE": {"proxy": H, "domains": ["two.example"]}})
        self.assertEqual(execute(pac, ["one.example", "two.example"])["routes"],
                         [chain(D, F, G, direct=True), chain(H, F, G, direct=True)])

    def test_endpoints_are_strict_and_all_roles_are_validated(self):
        bad = ["127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:1.5",
               "127.0.0.1:80x", "127.0.0.1:８０", "127.0.0.1:80\n", "127.0.0.1: 80",
               "localhost:80", "192.0.2.1:80", "::1:80", "[::2]:80",
               '127.0.0.1:80"; INJECTED=true; //', "127.0.0.1:80; DIRECT", 123, False]
        for ep, role in itertools.product(bad, ("general", "fast", "hk", "steam", "dyn")):
            with self.subTest(ep=ep, role=role), self.assertRaises(ValueError):
                self.render(**({"dyn": {"x": {"proxy": ep, "domains": ["example.com"]}}} if role == "dyn" else {role: ep}))
        self.assertEqual(execute(self.render(general="[::1]:65535", fast="127.0.0.1:1"), ["claude.ai"])["routes"],
                         [chain("[::1]:65535", "127.0.0.1:1")])

    def test_invalid_dynamic_shapes_and_reserved_identifiers(self):
        for name in ("class", "switch", "let", "const", "null", "delete", "enum", "implements"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.p["_js_list"](name, ["example.com"])
        for dyn in ([1], {"valid": 42}, {"valid": {"proxy": D, "domains": ""}},
                    {"valid": {"proxy": D, "domains": 0}}):
            with self.subTest(dyn=dyn), self.assertRaises(ValueError):
                self.render(dyn=dyn)

    def test_vm_helpers_have_independent_positive_and_negative_controls(self):
        pac = '''function FindProxyForURL(url, host) {
          return JSON.stringify([dnsDomainIs(host, ".example.com"), isPlainHostName(host),
                                 shExpMatch(host, "192.168.*"), shExpMatch(host, "file?.example.com")]);
        }'''
        results = [json.loads(v) for v in execute(pac, ["api.example.com", "evil-example.com",
                    "localhost", "192.168.1.2", "192X168X1X2", "file1.example.com"])["routes"]]
        self.assertEqual(results, [[True, False, False, False], [False, False, False, False],
                                  [False, True, False, False], [False, False, True, False],
                                  [False, True, False, False], [True, False, False, True]])

    def test_empty_exits_reject_and_duplicate_exits_collapse(self):
        with self.assertRaises(ValueError):
            self.render(general=None, fast=None, hk=None, steam=None)
        with self.assertRaises(ValueError):
            self.p["_chain"]([], direct=False)
        self.assertEqual(execute(self.render(general=G, fast=G, steam=G, hk=G),
                                 ["chatgpt.com", "claude.ai", "unlisted.example"])["routes"],
                         [chain(G), chain(G), chain(G, direct=True)])

    def test_stamp_is_data_not_executable_comment(self):
        stamp = 'test\nINJECTED=true;\n// "\\\x00\r\u2028\u2029'
        result = execute(self.render(stamp=stamp), ["claude.ai"])
        self.assertFalse(result["injected"])
        self.assertEqual(result["routes"], [chain(G, F)])

    def test_existing_pac_regressions_without_runtime_imports(self):
        # Load the existing tests' actual function bodies, not process/port tests.
        import ast
        import types
        here = Path(__file__).resolve().parent
        ns = {"pacroute": types.SimpleNamespace(**self.p)}
        endpoint = functions("pacroute", ["pac_endpoints"]).pac_endpoints
        ns["pacroute"].pac_endpoints = endpoint
        for filename, selected in (("test_pacroute.py", {"check", "test_pac_private_and_default", "test_sensitive_domains"}),
                                   ("test_route_selfheal.py", {"check", "test_pac_endpoints_roundtrip"})):
            path = here / filename
            parsed = ast.parse(path.read_text(encoding="utf-8"))
            body = [n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name in selected]
            exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), ns)
            for name in sorted(selected - {"check"}):
                ns[name]()


if __name__ == "__main__":
    unittest.main(verbosity=2)
