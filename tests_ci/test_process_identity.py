"""Process termination must require a stable, rechecked identity."""
import contextlib
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import process_identity as identity


BASE = {
    "pid": 123,
    "created_at": "2026-11-27T10:00:00Z",
    "exe_path": r"C:\PhoneProxy\sing-box.exe",
    "exe_sha256": "a" * 64,
    "command_line": "sing-box run -c config.json",
    "owner_sid": "S-1-5-21-test",
    "config_path": "config.json",
    "config_sha256": "b" * 64,
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

    def test_owner_change_is_rejected(self):
        changed = dict(BASE, owner_sid="S-1-5-21-other")
        with mock.patch.object(identity, "inspect", return_value=changed):
            self.assertFalse(identity.matches(BASE))

    def test_atomic_rename_keeps_identity_when_final_hash_matches(self):
        launched = dict(BASE, config_path="config.new")
        renamed = dict(launched, config_sha256="")
        with mock.patch.object(identity, "inspect", return_value=renamed), \
             mock.patch.object(identity, "_sha256", return_value="b" * 64):
            self.assertTrue(identity.matches(launched, expected_config="config.json"))

    def test_unknown_identity_is_not_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            record_path = os.path.join(directory, "missing.json")
            with mock.patch.object(identity, "inspect", return_value=None), \
                 mock.patch.object(identity.subprocess, "run") as run:
                self.assertFalse(identity.terminate_if_owned(123, record_path=record_path))
                run.assert_not_called()

    def test_matching_identity_is_terminated_once(self):
        with tempfile.TemporaryDirectory() as directory:
            record_path = os.path.join(directory, "process.json")
            Path(record_path).write_text(json.dumps(BASE), encoding="utf-8")
            with mock.patch.object(identity, "inspect", return_value=copy.deepcopy(BASE)), \
                 mock.patch.object(identity.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertTrue(identity.terminate_if_owned(123, record_path=record_path))
                self.assertEqual(run.call_args.args[0][:3], ["taskkill", "/PID", "123"])

    def test_record_is_written_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            record_path = os.path.join(directory, "process.json")
            with mock.patch.object(identity, "inspect", return_value=copy.deepcopy(BASE)):
                identity.record(123, "config.json", record_path)
            self.assertEqual(json.loads(Path(record_path).read_text(encoding="utf-8"))["pid"], 123)
            self.assertFalse(Path(record_path + ".tmp").exists())

    def test_proxyctl_does_not_kill_legacy_pid_only_record(self):
        import proxyctl
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "pinned_pids.json")
            Path(path).write_text(json.dumps([123]), encoding="utf-8")
            with mock.patch.object(proxyctl, "PIN_PIDS", path), \
                 mock.patch.object(proxyctl, "pid_image", return_value="sing-box.exe"), \
                 mock.patch.object(proxyctl, "pid_cmdline", return_value="singbox_pinned.json"), \
                 mock.patch.object(proxyctl.subprocess, "run") as run:
                proxyctl.stop_pinned()
                run.assert_not_called()

    def test_proxyctl_kills_only_matching_identity_record(self):
        import proxyctl
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "pinned_pids.json")
            config_path = os.path.join(proxyctl.HERE, "singbox_pinned.json")
            record = dict(BASE, config_path=config_path,
                          command_line="sing-box run -c " + config_path)
            Path(path).write_text(json.dumps([record]), encoding="utf-8")
            with mock.patch.object(proxyctl, "PIN_PIDS", path), \
                 mock.patch.object(identity, "inspect", return_value=copy.deepcopy(record)), \
                 mock.patch.object(identity, "_sha256", return_value="b" * 64), \
                 mock.patch.object(identity.subprocess, "run") as run:
                run.returncode.returncode = 0
                proxyctl.stop_pinned()
                self.assertEqual(run.call_args.args[0][:3], ["taskkill", "/PID", "123"])

    def test_pacroute_stop_server_ignores_legacy_pid(self):
        import pacroute
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "pac_server.pid")
            Path(path).write_text("123", encoding="utf-8")
            with mock.patch.object(pacroute, "PID_PATH", path), \
                 mock.patch.object(pacroute.I, "inspect", return_value=None), \
                 mock.patch.object(pacroute.subprocess, "run") as run:
                pacroute.stop_server()
                run.assert_not_called()

    def test_stop_proxy_kill_tree_requires_identity(self):
        import stop_proxy
        with mock.patch.object(stop_proxy.P, "pid_image", return_value="python.exe"), \
             mock.patch.object(stop_proxy.subprocess, "run") as run:
            self.assertFalse(stop_proxy.kill_tree(123))
            run.assert_not_called()

    def test_stop_proxy_process_scan_excludes_current_and_parent(self):
        import stop_proxy
        rows = [
            {"ProcessId": os.getpid(), "Name": "python.exe", "CommandLine": "_proxy\\tun_mode.py"},
            {"ProcessId": os.getppid(), "Name": "python.exe", "CommandLine": "_proxy\\tun_mode.py"},
            {"ProcessId": 999, "Name": "python.exe", "CommandLine": "_proxy\\watchdog.py"},
            {"ProcessId": 1000, "Name": "powershell.exe", "CommandLine": "_proxy\\tun_mode.py"},
        ]
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(rows).encode("utf-8"), stderr=b"")
        with mock.patch.object(stop_proxy.subprocess, "run", return_value=result):
            found = stop_proxy.our_processes()
        self.assertEqual([pid for pid, _, _ in found], [999])

    def test_stop_proxy_can_skip_foreign_tun_during_split_cleanup(self):
        import stop_proxy
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(stop_proxy, "TUN_ACTIVE",
                                                  os.path.join(directory, "missing")))
            stop_tun = stack.enter_context(mock.patch.object(stop_proxy, "stop_tun"))
            stack.enter_context(mock.patch.object(stop_proxy, "kill_foreign_copies", return_value=[]))
            stack.enter_context(mock.patch.object(stop_proxy, "stop_watchdog", return_value=False))
            stack.enter_context(mock.patch.object(stop_proxy.pacroute, "clear_pac"))
            stack.enter_context(mock.patch.object(stop_proxy.P, "stop_gateway"))
            stack.enter_context(mock.patch.object(stop_proxy, "kill_our_stack", return_value=[]))
            stack.enter_context(mock.patch.object(stop_proxy, "stop_pinned", return_value=[]))
            stack.enter_context(mock.patch.object(stop_proxy, "free_ports", return_value=[]))
            stack.enter_context(mock.patch.object(stop_proxy.sysstate, "restore_all"))
            stack.enter_context(mock.patch.object(stop_proxy, "drop_stale_ours", return_value=[]))
            stack.enter_context(mock.patch.object(stop_proxy, "curl_direct", return_value="200"))
            stack.enter_context(mock.patch.object(stop_proxy.P, "listen_ok", return_value=False))
            stack.enter_context(mock.patch.object(stop_proxy, "our_processes", return_value=[
                (61108, "sing-box.exe", "sing-box run -c old\\singbox_tun.json")]))
            stack.enter_context(mock.patch.object(stop_proxy.sysstate, "current", return_value={
                "pac": "", "proxy_enable": 0, "proxy_server": "", "env": {}}))
            rc = stop_proxy.main(skip_tun=True)
        self.assertEqual(rc, 0)
        stop_tun.assert_not_called()

    def test_tun_stop_stack_ignores_unrecorded_process(self):
        import tun_mode
        with mock.patch.object(tun_mode, "tun_pids", return_value=[123]), \
             mock.patch.object(tun_mode, "foreign_tun_pids", return_value=[]), \
             mock.patch.object(tun_mode.P, "port_pids", return_value=[]), \
             mock.patch.object(tun_mode.P, "pid_alive", return_value=True), \
             mock.patch.object(tun_mode.subprocess, "run") as run:
            tun_mode.stop_stack()
            run.assert_not_called()

    def test_start_proxy_does_not_spawn_over_unknown_live_watchdog(self):
        import start_proxy
        with tempfile.TemporaryDirectory() as directory:
            pid_path = os.path.join(directory, "watchdog.pid")
            Path(pid_path).write_text("123", encoding="utf-8")
            with mock.patch.object(start_proxy, "WATCH_PID", pid_path), \
                 mock.patch.object(start_proxy.P, "pid_alive", return_value=True), \
                 mock.patch.object(start_proxy.P, "pid_image", return_value="python.exe"), \
                 mock.patch.object(start_proxy.I, "load_record", return_value={}), \
                 mock.patch.object(start_proxy.subprocess, "Popen") as popen:
                start_proxy.ensure_watchdog()
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
