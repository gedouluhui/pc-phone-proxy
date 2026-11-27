# Windows Trusted Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Windows automatic switching fail closed, process termination ownership-checked, local control authenticated, configuration changes transactional, and source downloads bounded and SSRF-resistant.

**Architecture:** Add focused modules for process identity, DPAPI-backed control secrets, authenticated Clash API calls, staged configuration transactions, and pinned-IP source fetching. Existing scripts remain entry points but delegate dangerous operations to these modules.

**Tech Stack:** Python 3.12, Windows CIM/PowerShell, DPAPI via ctypes, sing-box Clash API, urllib/http.client, unittest.

**Spec:** `docs/superpowers/specs/2026-11-27-hardening-v4-design.md`

## Global Constraints

- Do not modify the running `Desktop/代理便携版`.
- Unknown ownership means do not terminate.
- Unknown measurement means do not switch a healthy tunnel.
- No node URI, subscription token, password, or secret in logs.
- Every behavior change starts with a failing test.
- Public nodes cannot disable TLS verification.
- No force push and no secret-bearing files in git.

## Implementation Status (2026-11-27)

- Task 1 (fail-closed switching), Task 2 (stable process identity), Task 3 (authenticated local control API), and Task 4 (transactional configuration changes) are implemented.
- The control secret is 32 random bytes encoded as URL-safe base64, protected with user-scoped DPAPI plus application entropy, and stored with a current-user-only ACL. Existing corrupt/foreign ciphertext fails closed and is never overwritten automatically.
- All four Clash API configuration generators include the secret. Synchronous and asynchronous clients disable ambient proxies, send Bearer authorization, reject non-loopback URLs and redirects, and treat missing secrets or HTTP errors as hard failures.
- Configuration replacement uses an OS-released cross-process lock, atomic `.new` staging, static validation before shutdown, real service verification before promotion, and automatic restoration/relaunch on launch or verification failure. Pinned exits, the TUN supervisor, and elevated TUN startup all use this transaction; rejected candidates are retained as `.broken` for diagnosis.
- Verification includes a real sing-box process proving missing and incorrect credentials return HTTP 401. Real TUN traffic, network-switch behaviour, and non-current-user DPAPI/ACL denial still require machine-level acceptance testing.

---

## File Structure

- `pc/_proxy/process_identity.py`: process inspection, recording, matching, termination.
- `pc/_proxy/control_secret.py`: DPAPI protect/unprotect and user-only ACL.
- `pc/_proxy/control_api.py`: Bearer-authenticated local HTTP helpers.
- `pc/_proxy/config_transaction.py`: staged check/launch/verify/promote/rollback primitives.
- `pc/_proxy/source_fetch.py`: bounded manual redirects and pinned-IP HTTP(S) GET.
- `tests_ci/test_process_identity.py`: synthetic identity and PID-reuse tests.
- `tests_ci/test_control_secret.py`: DPAPI round-trip and ACL tests with platform guards.
- `tests_ci/test_control_api.py`: authorization and no-proxy tests.
- `tests_ci/test_config_transaction.py`: commit/rollback state-machine tests.
- `tests_ci/test_source_fetch.py`: private-address, redirect, size, and pinning tests.

---

### Task 1: Make automatic switching fail closed

**Files:**
- Modify: `pc/_proxy/tun_supervisor.py`
- Modify: `pc/_proxy/rescan.py`
- Modify: `pc/_proxy/nodes.py`
- Modify: `tests_ci/test_tun_safety.py`

**Interfaces:**
- Produces: `pool_switch_ok(verdicts, min_live=2, allow_unknown=False) -> bool`; `switch_min_live(prev_live) -> int`.

- [ ] **Step 1: Write failing gate tests**

```python
# tests_ci/test_tun_safety.py
def test_no_verdicts_is_rejected(self):
    self.assertFalse(self.S.pool_switch_ok({}))

def test_unknown_requires_explicit_emergency_mode(self):
    self.assertFalse(self.S.pool_switch_ok({}, allow_unknown=False))
    self.assertTrue(self.S.pool_switch_ok({}, allow_unknown=True))

def test_current_healthy_count_is_not_capped(self):
    self.assertEqual(self.S.switch_min_live(10), 10)
    self.assertEqual(self.S.switch_min_live(3), 3)
```

Replace the old `test_no_verdicts_keeps_old_behaviour` and the capped expectation in `test_min_live_follows_current_tunnel`.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_tun_safety.PoolSwitch tests_ci.test_tun_safety.NoRegression -v`
Expected: FAIL on empty verdicts and `switch_min_live(10)`.

- [ ] **Step 3: Implement fail-closed gates**

```python
def pool_switch_ok(verdicts, min_live=SWITCH_MIN_LIVE, allow_unknown=False):
    if not verdicts:
        return bool(allow_unknown)
    live = sum(1 for value in verdicts.values() if value in ("ok", "bad"))
    return live >= min_live


def switch_min_live(prev_live):
    try:
        previous = int(prev_live or 0)
    except (TypeError, ValueError):
        previous = 0
    return max(SWITCH_MIN_LIVE, previous)
```

In `maintain()`, change the gate exception log to “拒绝切换” and keep the normal call fail-closed. In `rescan.main()`, abort when `direct_path_contaminated()` returns anything other than `(False, reason)`. In `nodes.tcp_prefilter()`, raise when TUN is active and the direct SOCKS helper cannot start.

- [ ] **Step 4: Roll back unknown post-switch results**

Change `restart()` so `verdict in ("broken", "unknown")` restores the previous configuration. Replace `test_unknown_keeps_new_tunnel` with `test_unknown_rolls_back`, asserting the old config is relaunched and retained on disk.

- [ ] **Step 5: Run focused and full tests**

Run: `python -B -m unittest tests_ci.test_tun_safety -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/tun_supervisor.py pc/_proxy/rescan.py pc/_proxy/nodes.py tests_ci/test_tun_safety.py
git commit -m "fix(pc): fail closed on unknown tunnel switch evidence"
```

---

### Task 2: Add process identity and migrate dangerous termination paths

**Files:**
- Create: `pc/_proxy/process_identity.py`
- Create: `tests_ci/test_process_identity.py`
- Modify: `pc/_proxy/proxyctl.py`
- Modify: `pc/_proxy/stop_proxy.py`
- Modify: `pc/_proxy/pacroute.py`
- Modify: `pc/_proxy/deep_test.py`
- Modify: `pc/_proxy/tun_mode.py`
- Modify: `pc/_proxy/tun_supervisor.py`

**Interfaces:**
- Produces: `inspect(pid) -> dict | None`; `record(pid, config_path, record_path) -> dict`; `matches(record, expected_config=None) -> bool`; `terminate_if_owned(pid, record_path=None, expected_config=None, log=print) -> bool`.

- [ ] **Step 1: Write failing identity tests**

```python
# tests_ci/test_process_identity.py
import copy
import unittest
from unittest import mock
import process_identity as identity

BASE = {
    "pid": 123, "created_at": "2026-11-27T10:00:00Z",
    "exe_path": r"C:\PhoneProxy\sing-box.exe",
    "exe_sha256": "a" * 64, "command_line": "sing-box run -c config.json",
    "owner_sid": "S-1-5-21-test", "config_sha256": "b" * 64,
}

class ProcessIdentityTests(unittest.TestCase):
    def test_pid_reuse_is_rejected(self):
        changed = dict(BASE, created_at="2026-11-27T10:01:00Z")
        with mock.patch.object(identity, "inspect", return_value=changed):
            self.assertFalse(identity.matches(BASE))

    def test_config_change_is_rejected(self):
        changed = dict(BASE, config_sha256="c" * 64)
        with mock.patch.object(identity, "inspect", return_value=changed):
            self.assertFalse(identity.matches(BASE, expected_config="config.json"))

    def test_unknown_identity_is_not_terminated(self):
        with mock.patch.object(identity, "inspect", return_value=None), \
             mock.patch.object(identity.subprocess, "run") as run:
            self.assertFalse(identity.terminate_if_owned(123, record_path="missing.json"))
            run.assert_not_called()
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_process_identity -v`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement identity module**

`inspect()` uses one PowerShell CIM query per PID and returns PID, UTC creation time, executable path, command line, owner SID, executable SHA-256, and optional config SHA-256. `record()` writes JSON atomically. `matches()` re-inspects and requires every recorded field to match; any missing field is unknown. `terminate_if_owned()` calls `taskkill /PID <pid> /T /F` only after a positive match.

- [ ] **Step 4: Migrate kill paths**

- `proxyctl.kill_port()` skips a listener when identity cannot be proven.
- `proxyctl.stop_pinned()` accepts both legacy PID-only and new identity records, but legacy records without creation time are not terminated.
- `stop_proxy.kill_foreign_copies()` no longer kills by generic filename across arbitrary directories; it only handles records created by this installation.
- `stop_proxy.kill_our_stack()`, `stop_pinned()`, `kill_tree()`, and `pacroute.stop_server()` use `terminate_if_owned()`.
- `deep_test.kill_stale()` uses identity records.
- `tun_mode.foreign_tun_pids()` is advisory only; `stop_stack()` terminates only recorded identities.
- `tun_supervisor.stop_current()` uses the TUN identity record.

- [ ] **Step 5: Run focused and full tests**

Run: `python -B -m unittest tests_ci.test_process_identity tests_ci.test_route_selfheal tests_ci.test_tun_safety -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/process_identity.py tests_ci/test_process_identity.py pc/_proxy/proxyctl.py pc/_proxy/stop_proxy.py pc/_proxy/pacroute.py pc/_proxy/deep_test.py pc/_proxy/tun_mode.py pc/_proxy/tun_supervisor.py
git commit -m "fix(pc): require process identity before termination"
```

---

### Task 3: Authenticate local Clash API

**Files:**
- Create: `pc/_proxy/control_secret.py`
- Create: `pc/_proxy/control_api.py`
- Create: `tests_ci/test_control_secret.py`
- Create: `tests_ci/test_control_api.py`
- Modify: `pc/_proxy/nodes.py`
- Modify: `pc/_proxy/bestroute.py`
- Modify: `pc/_proxy/deep_test.py`
- Modify: `pc/_proxy/tun_mode.py`
- Modify: `pc/_proxy/start_proxy.py`
- Modify: `pc/_proxy/watchdog.py`
- Modify: `pc/_proxy/tun_supervisor.py`

**Interfaces:**
- Produces: `control_secret.get_or_create(path=None) -> str`; `control_api.headers() -> dict`; `control_api.request(method, url, **kwargs) -> bytes`.

- [ ] **Step 1: Write failing auth tests**

```python
# tests_ci/test_control_api.py
import unittest
from unittest import mock
import control_api

class ControlApiTests(unittest.TestCase):
    @mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret")
    def test_bearer_header_is_sent(self, secret):
        with mock.patch.object(control_api.urllib.request, "build_opener") as opener:
            control_api.request("GET", "http://127.0.0.1:19090/version")
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-secret")
```

Add a DPAPI round-trip test that is skipped only on non-Windows and an ACL test using a temporary file.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_control_secret tests_ci.test_control_api -v`
Expected: FAIL because modules do not exist.

- [ ] **Step 3: Implement secret storage and authenticated client**

Use `CryptProtectData`/`CryptUnprotectData`; store ciphertext under `%LOCALAPPDATA%\PhoneProxy\control-secret.bin`; restrict ACL to the current user. `control_api.request()` always disables environment proxies and adds the Bearer header.

- [ ] **Step 4: Wire configs and clients**

Add `"secret": control_secret.get_or_create()` to every sing-box Clash API config. Replace direct local API calls in `start_proxy`, `watchdog`, `tun_supervisor`, and async code in `nodes`/`deep_test` with authenticated headers. Missing secret or HTTP 401/403 is a hard failure.

- [ ] **Step 5: Run full tests**

Run: `python -B -m unittest discover -s tests_ci -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/control_secret.py pc/_proxy/control_api.py tests_ci/test_control_secret.py tests_ci/test_control_api.py pc/_proxy/nodes.py pc/_proxy/bestroute.py pc/_proxy/deep_test.py pc/_proxy/tun_mode.py pc/_proxy/start_proxy.py pc/_proxy/watchdog.py pc/_proxy/tun_supervisor.py
git commit -m "feat(pc): authenticate local Clash control API"
```

---

### Task 4: Add transactional configuration primitives and adopt them

**Files:**
- Create: `pc/_proxy/config_transaction.py`
- Create: `tests_ci/test_config_transaction.py`
- Modify: `pc/_proxy/bestroute.py`
- Modify: `pc/_proxy/tun_supervisor.py`
- Modify: `pc/_proxy/tun_mode.py`

**Interfaces:**
- Produces: `stage(final_path, content) -> str`; `promote(staged_path, final_path) -> None`; `restore(previous_path, final_path) -> None`; `ConfigTransaction(final_path, check, launch, verify, stop_current, log).apply(content) -> bool`.

- [ ] **Step 1: Write failing transaction tests**

```python
# tests_ci/test_config_transaction.py
import unittest
from config_transaction import ConfigTransaction

class TransactionTests(unittest.TestCase):
    def test_failed_verification_restores_previous(self):
        calls = []
        tx = ConfigTransaction(
            "config.json", check=lambda p: (0, ""),
            launch=lambda p: calls.append("launch:" + open(p).read()) or object(),
            verify=lambda p: "broken", stop_current=lambda: calls.append("stop"),
            log=lambda *a: None)
        self.assertFalse(tx.apply('{"new": true}'))
        self.assertEqual(calls, ["stop", "launch:{\"new\": true}", "launch:{\"old\": true}"])
        self.assertIn("old", open("config.json").read())
```

The test uses a temporary directory and an existing `{"old": true}` config.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_config_transaction -v`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement transaction primitive**

`apply()` stages `.new`, checks it, copies the previous config, stops current, launches candidate, verifies, then promotes. Any failure before promotion restores and relaunches the previous config. Cleanup failure after promotion is a warning, not a rollback.

- [ ] **Step 4: Adopt in bestroute and TUN paths**

Replace ad hoc write/check/stop/start sequences in `bestroute.start/main`, `tun_supervisor.restart`, and `tun_mode.start_admin` with the transaction primitive. Keep role-specific health probes as the verifier.

- [ ] **Step 5: Run full tests**

Run: `python -B -m unittest discover -s tests_ci -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/config_transaction.py tests_ci/test_config_transaction.py pc/_proxy/bestroute.py pc/_proxy/tun_supervisor.py pc/_proxy/tun_mode.py
git commit -m "refactor(pc): make configuration switches transactional"
```

---

### Task 5: Bound and pin source downloads

**Files:**
- Create: `pc/_proxy/source_fetch.py`
- Create: `tests_ci/test_source_fetch.py`
- Modify: `pc/_proxy/harvest.py`

**Interfaces:**
- Produces: `validate_url(url) -> tuple`; `fetch(url, max_bytes=16*1024*1024, timeout=30, allow_private=False) -> bytes`.

- [ ] **Step 1: Write failing source-fetch tests**

```python
# tests_ci/test_source_fetch.py
import unittest
import source_fetch

class SourceFetchTests(unittest.TestCase):
    def test_private_literal_is_rejected(self):
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.validate_url("http://127.0.0.1/nodes")

    def test_https_downgrade_redirect_is_rejected(self):
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.validate_redirect("https://example.com/a", "http://example.com/b")

    def test_private_resolution_is_rejected(self):
        with unittest.mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 0))]):
            with self.assertRaises(source_fetch.Rejected):
                source_fetch.fetch("https://example.com/nodes", allow_private=False)
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -B -m unittest tests_ci.test_source_fetch -v`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement pinned fetch**

Use `http.client` with a connection subclass whose `_create_connection()` connects to the already validated IP while retaining the original Host header and TLS SNI. Follow at most three redirects manually, reject HTTPS→HTTP, enforce a cumulative byte limit, and hash the returned bytes.

- [ ] **Step 4: Wire harvest**

Replace `requests.get()` in `harvest.fetch()` with `source_fetch.fetch()`. Keep the existing source list and retry policy; failures must not fall back to an unpinned path.

- [ ] **Step 5: Run full tests**

Run: `python -B -m unittest discover -s tests_ci -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pc/_proxy/source_fetch.py tests_ci/test_source_fetch.py pc/_proxy/harvest.py
git commit -m "fix(pc): bound and pin public source downloads"
```

---

## Completion Check

- All new tests were observed failing before implementation.
- `python -B -m unittest discover -s tests_ci -v` passes with real sing-box.
- Unknown ownership never terminates a process.
- Unknown measurement never switches a healthy tunnel.
- Local Clash API rejects missing/incorrect credentials.
- Failed configuration verification restores the previous config.
- Source fetch rejects private addresses, downgrade redirects, and oversized bodies.
- No real node credentials or secrets are present in the diff.
