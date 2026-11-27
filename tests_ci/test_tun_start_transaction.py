"""Elevated TUN startup must use the same commit/rollback contract as the supervisor."""
import itertools
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import tun_mode


class TunStartTransactionTests(unittest.TestCase):
    def sandbox(self, directory, candidate_starts=True, adapter=True):
        paths = {name: os.path.join(directory, filename) for name, filename in {
            "CFG": "singbox_tun.json", "PID": "tun.pid", "IDENTITY": "tun.identity.json",
            "ACTIVE": "TUN_ACTIVE", "LOG": "tun.log", "SB_LOG": "tun_singbox.log",
            "SUP_PID": "tun_supervisor.pid", "SUP_LOG": "tun_supervisor.log",
        }.items()}
        Path(paths["CFG"]).write_text('{"old":true}', encoding="utf-8")
        saved = {name: getattr(tun_mode, name) for name in paths}
        for name, path in paths.items():
            setattr(tun_mode, name, path)
        calls = []
        processes = []

        class Process:
            def __init__(self, pid, starts):
                self.pid = pid
                self.starts = starts
            @property
            def returncode(self):
                return None if self.starts else 7
            def poll(self):
                return self.returncode
            def terminate(self):
                self.starts = False
            def wait(self, timeout=None):
                self.starts = False
                return 0

        def popen(command, **kwargs):
            calls.append(("launch", command[-1]))
            process = Process(2000 + len(processes), candidate_starts if not processes else True)
            processes.append(process)
            return process

        fake_stop = types.ModuleType("stop_proxy")
        fake_stop.main = lambda: calls.append(("stop_split",))
        real_isfile = os.path.isfile
        wintun = os.path.join(tun_mode.HERE, "bin", "wintun.dll")
        patches = [
            mock.patch.object(tun_mode, "build_config", return_value={"new": True}),
            mock.patch.object(tun_mode, "check_config", return_value=(0, "")),
            mock.patch.object(tun_mode, "read_pid", return_value=111),
            mock.patch.object(tun_mode, "alive", return_value=True),
            mock.patch.object(tun_mode, "stop_stack", side_effect=lambda: calls.append(("stop_tun",))),
            mock.patch.object(tun_mode, "adapter_present", return_value=adapter),
            mock.patch.object(tun_mode, "start_supervisor", side_effect=lambda: calls.append(("supervisor",))),
            mock.patch.object(tun_mode, "register_guard_task", side_effect=lambda: calls.append(("guard",))),
            mock.patch.object(tun_mode.subprocess, "Popen", side_effect=popen),
            mock.patch.object(tun_mode.I, "record", side_effect=lambda *a, **k: calls.append(("identity", a[1]))),
            mock.patch.object(tun_mode.time, "sleep", return_value=None),
            mock.patch.object(tun_mode.time, "time", side_effect=itertools.count(step=2.0)),
            mock.patch.object(tun_mode.pacroute, "status", return_value={"pac_url": None}),
            mock.patch.object(tun_mode.os.path, "isfile",
                              side_effect=lambda path: True if path == wintun else real_isfile(path)),
            mock.patch.dict(sys.modules, {"stop_proxy": fake_stop}),
        ]
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(patches)])
        self.addCleanup(lambda: [setattr(tun_mode, name, path) for name, path in saved.items()])
        return paths, calls, processes

    def test_precheck_failure_keeps_existing_tunnel_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, calls, _ = self.sandbox(directory)
            with mock.patch.object(tun_mode, "check_config", return_value=(1, "bad config")):
                rc, message = tun_mode.start_admin()
            self.assertEqual(rc, 1)
            self.assertIn("当前网络未改动", message)
            self.assertEqual(calls, [])
            self.assertIn("old", Path(paths["CFG"]).read_text(encoding="utf-8"))

    def test_success_launches_staged_config_then_promotes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, calls, _ = self.sandbox(directory)
            rc, message = tun_mode.start_admin()
            self.assertEqual(rc, 0, message)
            launches = [call[1] for call in calls if call[0] == "launch"]
            self.assertEqual(len(launches), 1)
            self.assertTrue(launches[0].endswith(".new"), launches)
            self.assertEqual(json.loads(Path(paths["CFG"]).read_text(encoding="utf-8")), {"new": True})
            self.assertFalse(os.path.exists(paths["CFG"] + ".new"))
            self.assertTrue(os.path.isfile(paths["ACTIVE"]))
            self.assertIn(("supervisor",), calls)
            self.assertIn(("guard",), calls)

    def test_adapter_failure_recycles_owned_candidate_without_stopping_split_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, calls, _ = self.sandbox(directory, adapter=False)
            rc, message = tun_mode.start_admin()
            self.assertEqual(rc, 1)
            self.assertEqual(len([call for call in calls if call[0] == "stop_split"]), 1)
            launches = [call[1] for call in calls if call[0] == "launch"]
            self.assertEqual(len(launches), 2)
            self.assertIn("old", Path(paths["CFG"]).read_text(encoding="utf-8"))

    def test_candidate_launch_failure_restores_and_relaunches_old_tun(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, calls, _ = self.sandbox(directory, candidate_starts=False)
            rc, message = tun_mode.start_admin()
            self.assertEqual(rc, 1)
            launches = [call[1] for call in calls if call[0] == "launch"]
            self.assertEqual(len(launches), 2)
            self.assertTrue(launches[0].endswith(".new"))
            self.assertEqual(launches[1], paths["CFG"])
            self.assertEqual(len([call for call in calls if call[0] == "stop_split"]), 1)
            self.assertIn("old", Path(paths["CFG"]).read_text(encoding="utf-8"))
            self.assertTrue(os.path.isfile(paths["CFG"] + ".broken"))
            self.assertIn(("supervisor",), calls)


if __name__ == "__main__":
    unittest.main()
