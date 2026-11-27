"""Pinned exit replacement must verify the real gates before committing config."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import bestroute


class Process:
    pid = 4321
    def poll(self):
        return None
    def terminate(self):
        pass
    def wait(self, timeout=None):
        return 0


class BestrouteTransactionTests(unittest.TestCase):
    def sandbox(self, directory, general=True):
        final = os.path.join(directory, "singbox_pinned.json")
        Path(final).write_text('{"old":true}', encoding="utf-8")
        calls = []
        process = Process()
        patches = [
            mock.patch.object(bestroute, "CFG", final),
            mock.patch.object(bestroute, "PIN_PIDS", os.path.join(directory, "pids.json")),
            mock.patch.object(bestroute, "check_config", return_value=(0, ""), create=True),
            mock.patch.object(bestroute, "start", side_effect=lambda path: calls.append(("launch", path)) or process),
            mock.patch.object(bestroute, "stop_pinned", side_effect=lambda: calls.append(("stop",))),
            mock.patch.object(bestroute.P, "wait_port_free", return_value=True),
            mock.patch.object(bestroute.I, "record_many"),
            mock.patch.object(bestroute.P, "gate_one", side_effect=lambda ep: {
                "role": "", "general": general, "fast": general, "sites": {}}),
            mock.patch.object(bestroute.time, "sleep", return_value=None),
            mock.patch.object(bestroute, "log", lambda *args: None),
        ]
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(patches)])
        return final, calls, process

    def test_general_gate_failure_restores_previous_config(self):
        with tempfile.TemporaryDirectory() as directory:
            final, calls, _ = self.sandbox(directory, general=False)
            self.assertIsNone(bestroute.apply_config({"new": True}))
            launches = [call[1] for call in calls if call[0] == "launch"]
            self.assertEqual(len(launches), 2)
            self.assertTrue(launches[0].endswith(".new"))
            self.assertEqual(launches[1], final)
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))
            self.assertTrue(os.path.isfile(final + ".broken"))

    def test_success_commits_only_after_real_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            final, calls, process = self.sandbox(directory, general=True)
            result = bestroute.apply_config({"new": True})
            self.assertIsNotNone(result)
            self.assertEqual(result[0], process)
            self.assertEqual([gate["role"] for gate in result[1]], ["general", "fast", "cli"])
            self.assertEqual(json.loads(Path(final).read_text(encoding="utf-8")), {"new": True})
            self.assertEqual(len([call for call in calls if call[0] == "launch"]), 1)

    def test_static_check_failure_never_stops_current(self):
        with tempfile.TemporaryDirectory() as directory:
            final, calls, _ = self.sandbox(directory)
            with mock.patch.object(bestroute, "check_config", return_value=(1, "invalid")):
                self.assertIsNone(bestroute.apply_config({"new": True}))
            self.assertEqual(calls, [])
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
