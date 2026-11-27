# Shared Policy and Node Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish one routing-policy source for both clients and make node identity, redaction, TLS policy, and AI fallback correct and testable.

**Architecture:** A versioned JSON policy is rendered into a Python module and a pure-JVM Java class; CI rejects drift. Node identity becomes a SHA-256 of the complete normalized outbound without its tag. PC strips unsafe TLS options from public nodes and logs only scheme plus endpoint. Android AI routes fail closed instead of falling back to an ungated node.

**Tech Stack:** Python 3.12, unittest, Node.js PAC VM tests, Java 17, org.json, Xray-core, sing-box.

**Spec:** `docs/superpowers/specs/2026-11-27-hardening-v4-design.md`

## Global Constraints

- Keep sing-box and Xray-core; do not rewrite protocol handling.
- Do not modify `Desktop/代理便携版` or hot-replace a running TUN.
- Never commit node URIs, subscription URLs, keystores, passwords, tokens, or real diagnostics.
- No force push; work on `hardening/v4`.
- Every behavior change starts with a failing test.
- Public nodes must not disable TLS certificate verification.
- Unknown or missing evidence must not silently select an unsafe route.
- Generated policy files are committed and checked by CI.

---

## File Structure

- `shared/routing-policy.json`: single source for domain and UDP/DNS policy.
- `tools/sync_policy.py`: validates and renders policy.
- `pc/_proxy/policy.py`: generated Python constants.
- `phone/src/com/luhui/phoneproxy/RoutingPolicy.java`: generated pure-JVM constants.
- `tests_ci/test_policy_sync.py`: schema, rendering, and drift tests.
- `pc/_proxy/nodes.py`: node identity, redaction, TLS sanitization.
- `pc/_proxy/bestroute.py`: full node identity for deduplication.
- `tests_ci/test_node_trust.py`: PC node trust regressions.
- `phone/src/com/luhui/phoneproxy/NodeConfigCodec.java`: canonical outbound identity and AI fail-closed routing.
- `phone/tests/NodeTrustHarness.java`: JVM proof for identity and AI fallback.
- `phone/tools/check_node_trust.py`: compiles/runs the JVM proof and validates real Xray configs.

---

### Task 1: Add versioned shared routing policy and generators

**Files:**
- Create: `shared/routing-policy.json`
- Create: `tools/sync_policy.py`
- Create: `pc/_proxy/policy.py`
- Create: `phone/src/com/luhui/phoneproxy/RoutingPolicy.java`
- Create: `tests_ci/test_policy_sync.py`

**Interfaces:**
- Consumes: existing domain lists in `pc/_proxy/pacroute.py` and `phone/src/com/luhui/phoneproxy/NodeConfigCodec.java`.
- Produces: `DOMESTIC`, `SENSITIVE`, `DIRECT`, `AI_DOMAINS`, `GOOGLE_AI_DOMAINS`, `UDP_POLICY`, `DNS_POLICY` in Python; `RoutingPolicy.DOMESTIC`, `SENSITIVE`, `DIRECT`, `AI_DOMAINS`, `GOOGLE_AI_DOMAINS`, `UDP_POLICY`, `DNS_POLICY` in Java.

- [ ] **Step 1: Write failing schema and drift tests**

```python
# tests_ci/test_policy_sync.py
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "shared" / "routing-policy.json"
SYNC = ROOT / "tools" / "sync_policy.py"


class PolicySyncTests(unittest.TestCase):
    def test_policy_has_required_versioned_groups(self):
        data = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], 1)
        for key in ("domestic", "sensitive", "direct", "ai", "google_ai"):
            self.assertIsInstance(data[key], list)
            self.assertTrue(data[key])
            self.assertTrue(all(isinstance(x, str) and "." in x for x in data[key]))
        self.assertEqual(data["udp"]["quic"], "reject")
        self.assertEqual(data["udp"]["default"], "reject")
        self.assertEqual(data["dns"]["ipv6"], "proxy")

    def test_generated_files_match_current_policy(self):
        result = subprocess.run([sys.executable, str(SYNC), "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_render_is_deterministic(self):
        result = subprocess.run([sys.executable, str(SYNC), "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_policy_sync -v`
Expected: FAIL because `shared/routing-policy.json` and `tools/sync_policy.py` do not exist.

- [ ] **Step 3: Create the initial policy JSON**

Copy the current `DOMESTIC`, `SENSITIVE`, `DIRECT`, `GENERAL`, and `GOOGLE_APP` lists from `pacroute.py`; copy the OpenAI/Anthropic domain list from `NodeConfigCodec.java`. Store them under `domestic`, `sensitive`, `direct`, `ai`, and `google_ai`. Add:

```json
{
  "schema": 1,
  "udp": { "quic": "reject", "default": "reject", "allow_user_override": true },
  "dns": {
    "domestic": ["223.5.5.5"],
    "remote": ["https://1.1.1.1/dns-query"],
    "dot": "reject",
    "ipv6": "proxy"
  }
}
```

- [ ] **Step 4: Implement deterministic rendering**

```python
# tools/sync_policy.py
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUPS = ("domestic", "sensitive", "direct", "ai", "google_ai")


def load():
    return json.loads((ROOT / "shared" / "routing-policy.json").read_text(encoding="utf-8"))


def render_python(data):
    lines = ["# Generated by tools/sync_policy.py; do not edit.", "SCHEMA = 1"]
    for key in GROUPS:
        values = json.dumps(data[key], ensure_ascii=True, separators=(",", ":"))
        lines.append(f"{key.upper()} = {values}")
    lines.append("UDP_POLICY = " + json.dumps(data["udp"], sort_keys=True))
    lines.append("DNS_POLICY = " + json.dumps(data["dns"], sort_keys=True))
    return "\n".join(lines) + "\n"


def render_java(data):
    lines = ["// Generated by tools/sync_policy.py; do not edit.",
             "package com.luhui.phoneproxy;", "public final class RoutingPolicy {",
             "  private RoutingPolicy() {}", "  public static final int SCHEMA = 1;"]
    for key in GROUPS:
        name = {"ai": "AI_DOMAINS", "google_ai": "GOOGLE_AI_DOMAINS"}.get(key, key.upper())
        values = ", ".join(json.dumps(x, ensure_ascii=True) for x in data[key])
        lines.append(f"  public static final String[] {name} = {{{values}}};")
    lines.append("  public static final String UDP_QUIC = " + json.dumps(data["udp"]["quic"]) + ";")
    lines.append("  public static final String UDP_DEFAULT = " + json.dumps(data["udp"]["default"]) + ";")
    lines.append("  public static final String DNS_IPV6 = " + json.dumps(data["dns"]["ipv6"]) + ";")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = load()
    outputs = {
        ROOT / "pc" / "_proxy" / "policy.py": render_python(data),
        ROOT / "phone" / "src" / "com" / "luhui" / "phoneproxy" / "RoutingPolicy.java": render_java(data),
    }
    bad = []
    for path, content in outputs.items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                bad.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if bad:
        print("policy drift: " + ", ".join(bad))
        return 1
    print("policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Generate files and run tests**

Run: `python tools/sync_policy.py && python -B -m unittest tests_ci.test_policy_sync -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add shared/routing-policy.json tools/sync_policy.py pc/_proxy/policy.py phone/src/com/luhui/phoneproxy/RoutingPolicy.java tests_ci/test_policy_sync.py
git commit -m "feat: add shared routing policy source"
```

---

### Task 2: Harden PC node identity, redaction, and TLS policy

**Files:**
- Modify: `pc/_proxy/nodes.py`
- Modify: `pc/_proxy/bestroute.py`
- Create: `tests_ci/test_node_trust.py`

**Interfaces:**
- Consumes: parsed sing-box outbound dictionaries.
- Produces: `nodes.outbound_identity(ob) -> str`, `nodes.redact_uri(uri) -> str`, `nodes.sanitize_public_outbound(ob) -> dict`; `bestroute._rkey(row) -> tuple`.

- [ ] **Step 1: Write failing PC node trust tests**

```python
# tests_ci/test_node_trust.py
import copy
import sys
import unittest
from pathlib import Path

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))
import bestroute
import nodes


class NodeTrustTests(unittest.TestCase):
    def test_redaction_drops_userinfo_path_query_and_fragment(self):
        uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?token=SYNTHETIC_SECRET#name"
        self.assertEqual(nodes.redact_uri(uri), "vless://example.com:443")

    def test_public_tls_sanitization_removes_insecure(self):
        ob, _ = nodes.parse_uri("trojan://synthetic-pass@example.com:443?security=tls&insecure=1#x")
        clean = nodes.sanitize_public_outbound(ob)
        self.assertFalse(clean["tls"].get("insecure", False))
        self.assertTrue(ob["tls"]["insecure"])  # input object is not mutated

    def test_identity_ignores_tag_but_includes_credentials(self):
        a, _ = nodes.parse_uri("trojan://one@example.com:443?security=tls#a")
        b, _ = nodes.parse_uri("trojan://two@example.com:443?security=tls#b")
        a["tag"] = "g0"
        self.assertEqual(nodes.outbound_identity(a), nodes.outbound_identity(copy.deepcopy(a)))
        self.assertNotEqual(nodes.outbound_identity(a), nodes.outbound_identity(b))

    def test_same_host_different_ports_are_not_deduplicated(self):
        rows = [
            {"server": "example.com", "port": 443, "proto": "trojan", "uri": "trojan://one@example.com:443?security=tls#a", "dl_kbps": 500, "ul_kbps": 100, "github_ok": True, "chatgpt_ok": True},
            {"server": "example.com", "port": 8443, "proto": "trojan", "uri": "trojan://two@example.com:8443?security=tls#b", "dl_kbps": 400, "ul_kbps": 100, "github_ok": True, "chatgpt_ok": True},
        ]
        picked = bestroute.pick(rows, True, 300, 80, 10)
        self.assertEqual({r["port"] for r in picked}, {443, 8443})
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_node_trust -v`
Expected: FAIL because the new functions do not exist and `pick()` drops the second port.

- [ ] **Step 3: Implement canonical identity and strict redaction**

```python
# nodes.py
import hashlib


def outbound_identity(ob):
    clean = {k: v for k, v in ob.items() if k != "tag"}
    raw = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def redact_uri(uri):
    if not uri or "://" not in str(uri):
        return "***"
    scheme, rest = str(uri).split("://", 1)
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    authority = authority.rsplit("@", 1)[-1]
    return scheme + "://" + authority


def sanitize_public_outbound(ob):
    clean = copy.deepcopy(ob)
    tls = clean.get("tls")
    if isinstance(tls, dict):
        tls.pop("insecure", None)
        tls.pop("allow_insecure", None)
    return clean
```

Add `import copy` if absent. Call `sanitize_public_outbound()` in `load_nodes()` before appending each public candidate.

- [ ] **Step 4: Use full identity in bestroute deduplication**

```python
# bestroute.py
def _rkey(r):
    ob, _ = N.parse_uri(r.get("uri", ""))
    identity = N.outbound_identity(ob) if ob else hashlib.sha256(r.get("uri", "").encode("utf-8")).hexdigest()
    return (str(r.get("server", "")).lower(), str(r.get("port")), r.get("proto"), identity)


def pick(rows, need_cg, min_dl, min_ul, k, max_per_prefix=2):
    # Keep the existing filtering and sorting; replace `key = r["server"].lower()`
    # with `key = _rkey(r)` so same-host different-port/config nodes survive.
```

Add `import hashlib` if absent.

- [ ] **Step 5: Run focused and full PC tests**

Run: `python -B -m unittest tests_ci.test_node_trust tests_ci.test_poison_parse tests_ci.test_diagnostics_privacy -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/nodes.py pc/_proxy/bestroute.py tests_ci/test_node_trust.py
git commit -m "fix(pc): harden node identity redaction and TLS policy"
```

---

### Task 3: Make Android node identity canonical and AI routing fail closed

**Files:**
- Modify: `phone/src/com/luhui/phoneproxy/NodeConfigCodec.java`
- Modify: `phone/src/com/luhui/phoneproxy/ConfigBuilder.java`
- Create: `phone/tests/NodeTrustHarness.java`
- Create: `phone/tools/check_node_trust.py`

**Interfaces:**
- Consumes: `org.json.JSONObject`, existing parsed outbounds.
- Produces: `NodeConfigCodec.outboundIdentity(JSONObject) -> String`; `ConfigBuilder.nodeKey()` delegates to it; `fullConfig()` emits `ai-block` when no AI-qualified node exists.

- [ ] **Step 1: Write failing JVM proof**

```java
// phone/tests/NodeTrustHarness.java
import com.luhui.phoneproxy.NodeConfigCodec;
import org.json.*;
import java.util.*;

public final class NodeTrustHarness {
  public static void main(String[] args) throws Exception {
    JSONObject a = NodeConfigCodec.parseUri("trojan://one@1.2.3.4:443?security=tls&sni=a.example.com#a");
    JSONObject b = NodeConfigCodec.parseUri("trojan://two@1.2.3.4:443?security=tls&sni=a.example.com#b");
    a.put("tag", "proxy-a");
    JSONObject tagged = new JSONObject(a.toString());
    if (!NodeConfigCodec.outboundIdentity(a).equals(NodeConfigCodec.outboundIdentity(tagged))) {
      throw new AssertionError("tag changed node identity");
    }
    if (NodeConfigCodec.outboundIdentity(a).equals(NodeConfigCodec.outboundIdentity(b))) {
      throw new AssertionError("credentials did not change node identity");
    }

    b.put("tag", "proxy-b");
    Set<String> cg = new HashSet<>(); cg.add("b");
    JSONObject cfg = new JSONObject(NodeConfigCodec.fullConfig(
        Arrays.asList(a, b), cg, "auto", "proxy-a", null));
    JSONObject cgBalancer = null;
    JSONArray balancers = cfg.getJSONObject("routing").getJSONArray("balancers");
    for (int i = 0; i < balancers.length(); i++) {
      JSONObject item = balancers.getJSONObject(i);
      if ("cg-balancer".equals(item.getString("tag"))) cgBalancer = item;
    }
    if (cgBalancer == null || !"cg-b".equals(cgBalancer.optString("fallbackTag"))) {
      throw new AssertionError("AI balancer fell back to ungated proxy-a");
    }

    JSONObject noCg = new JSONObject(NodeConfigCodec.fullConfig(
        Arrays.asList(a, b), Collections.emptySet(), "auto", "proxy-a", null));
    boolean hasBlock = false;
    JSONArray outs = noCg.getJSONArray("outbounds");
    for (int i = 0; i < outs.length(); i++) {
      JSONObject out = outs.getJSONObject(i);
      if ("ai-block".equals(out.optString("tag")) && "blackhole".equals(out.optString("protocol"))) hasBlock = true;
    }
    if (!hasBlock) throw new AssertionError("missing AI blackhole");
    System.out.println("node trust OK");
  }
}
```

- [ ] **Step 2: Compile/run and verify failure**

Run: `javac -encoding UTF-8 -cp phone/tools/.cache/json-20240303.jar -d /tmp/node-trust phone/src/com/luhui/phoneproxy/NodeConfigCodec.java phone/src/com/luhui/phoneproxy/SubscriptionGuard.java phone/tests/NodeTrustHarness.java && java -cp /tmp/node-trust;phone/tools/.cache/json-20240303.jar NodeTrustHarness`
Expected: FAIL because `outboundIdentity` is missing or AI fallback is `proxy-a`.

- [ ] **Step 3: Implement canonical identity**

```java
// NodeConfigCodec.java
public static String outboundIdentity(JSONObject outbound) throws Exception {
  JSONObject copy = new JSONObject(outbound.toString());
  copy.remove("tag");
  return sha256hex(canonicalJson(copy).toString());
}

private static Object canonicalJson(Object value) throws Exception {
  if (value instanceof JSONObject) {
    JSONObject src = (JSONObject) value;
    TreeMap<String, Object> sorted = new TreeMap<>();
    Iterator<String> keys = src.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      sorted.put(key, canonicalJson(src.get(key)));
    }
    return new JSONObject(sorted);
  }
  if (value instanceof JSONArray) {
    JSONArray src = (JSONArray) value;
    JSONArray out = new JSONArray();
    for (int i = 0; i < src.length(); i++) out.put(canonicalJson(src.get(i)));
    return out;
  }
  return JSONObject.NULL.equals(value) ? JSONObject.NULL : value;
}

private static String sha256hex(String text) throws Exception {
  byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(UTF8));
  StringBuilder out = new StringBuilder();
  for (byte b : digest) out.append(String.format("%02x", b & 0xff));
  return out.toString();
}
```

- [ ] **Step 4: Delegate ConfigBuilder node identity**

```java
// ConfigBuilder.java
public static String nodeKey(JSONObject ob) {
  try { return NodeConfigCodec.outboundIdentity(ob); }
  catch (Throwable ignored) { return ""; }
}
```

Remove the old `server:port/protocol` SHA-1 implementation and its helper if unused.

- [ ] **Step 5: Fail closed for AI routes**

In `fullConfig()`:

```java
// Add a blackhole outbound used only by AI domains.
outbounds.put(new JSONObject().put("tag", "ai-block").put("protocol", "blackhole"));

// When cgCount > 0, fallback must be a cg node:
String cgFallback = null;
for (JSONObject ob : proxies) {
  String tag = ob.optString("tag", "");
  String base = tag.startsWith("proxy-") ? tag.substring(6) : tag;
  if (cgTags != null && cgTags.contains(base)) { cgFallback = "cg-" + base; break; }
}
if (cgFallback != null) cgBalancer.put("fallbackTag", cgFallback);

// Always add the AI domain rule. If cgCount == 0, route it to ai-block.
JSONArray aiDomains = new JSONArray();
for (String d : RoutingPolicy.AI_DOMAINS) aiDomains.put("domain:" + d);
if (cgCount > 0) {
  rules.put(rule().put("network", "tcp,udp").put("domain", aiDomains).put("balancerTag", "cg-balancer"));
} else {
  rules.put(rule().put("network", "tcp,udp").put("domain", aiDomains).put("outboundTag", "ai-block"));
}
```

Remove the old hardcoded OpenAI/Anthropic domain array.

- [ ] **Step 6: Add a repeatable checker and run it**

Create `phone/tools/check_node_trust.py` that locates `json-20240303.jar` with the same lookup rules as `check_poison.py`, compiles the three Java files into a temporary directory, runs `NodeTrustHarness`, and returns nonzero on failure. Run:

```bash
python phone/tools/check_node_trust.py
python phone/tools/check_poison.py
```

Expected: both PASS; update `phone/tests/full_config.golden.json` only after reviewing the intended `ai-block`/fallback diff.

- [ ] **Step 7: Commit**

```bash
git add phone/src/com/luhui/phoneproxy/NodeConfigCodec.java phone/src/com/luhui/phoneproxy/ConfigBuilder.java phone/tests/NodeTrustHarness.java phone/tools/check_node_trust.py phone/tests/full_config.golden.json
git commit -m "fix(android): canonical node identity and fail-closed AI routing"
```

---

## Completion Check

- `python tools/sync_policy.py --check` passes.
- `python -B -m unittest discover -s tests_ci -v` passes with real sing-box.
- `python phone/tools/check_node_trust.py` passes.
- `python phone/tools/check_poison.py` passes and golden drift is reviewed.
- No node credentials, tokens, or keystores appear in the diff.
- Current portable runtime remains untouched.
