"""Configuration replacement is one checked, verified, rollback-capable transaction."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import config_transaction as transaction


class TransactionTests(unittest.TestCase):
    def make(self, directory, verdict="ok", launch_result=True, check_result=(0, "")):
        final = os.path.join(directory, "singbox.json")
        Path(final).write_text('{"old": true}', encoding="utf-8")
        calls = []

        def check(path):
            calls.append(("check", Path(path).read_text(encoding="utf-8")))
            return check_result

        def launch(path):
            calls.append(("launch", Path(path).read_text(encoding="utf-8")))
            return object() if launch_result else None

        def verify(path):
            calls.append(("verify", Path(path).read_text(encoding="utf-8")))
            if isinstance(verdict, BaseException):
                raise verdict
            return verdict

        def stop():
            calls.append(("stop",))

        tx = transaction.ConfigTransaction(final, check, launch, verify, stop,
                                           lambda *args: None)
        return tx, final, calls

    def test_failed_verification_restores_previous_and_relaunches(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory, verdict="broken")
            self.assertFalse(tx.apply('{"new": true}'))
            self.assertEqual([call[0] for call in calls],
                             ["check", "stop", "launch", "verify", "stop", "check", "launch"])
            self.assertIn('{"old": true}', Path(final).read_text(encoding="utf-8"))
            self.assertIn('{"new": true}', Path(final + ".broken").read_text(encoding="utf-8"))
            self.assertFalse(os.path.exists(final + ".new"))

    def test_success_promotes_candidate_and_cleans_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory, verdict="ok")
            self.assertTrue(tx.apply({"new": True}))
            self.assertEqual(json.loads(Path(final).read_text(encoding="utf-8")), {"new": True})
            self.assertEqual([call[0] for call in calls], ["check", "stop", "launch", "verify"])
            self.assertFalse(os.path.exists(final + ".new"))
            self.assertFalse(os.path.exists(final + ".prev"))

    def test_check_failure_never_stops_or_launches(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory, check_result=(1, "invalid"))
            self.assertFalse(tx.apply('{"new": true}'))
            self.assertEqual([call[0] for call in calls], ["check"])
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))
            self.assertFalse(os.path.exists(final + ".new"))

    def test_launch_failure_restores_previous(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory, launch_result=False)
            self.assertFalse(tx.apply('{"new": true}'))
            self.assertEqual(calls[-1], ("launch", '{"old": true}'))
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))

    def test_verification_exception_is_failure_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory, verdict=RuntimeError("probe failed"))
            self.assertFalse(tx.apply('{"new": true}'))
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))
            self.assertEqual(calls[-1], ("launch", '{"old": true}'))

    def test_owned_candidate_is_terminated_even_if_stop_callback_fails(self):
        class Process:
            def __init__(self):
                self.running = True
                self.terminated = False
            def poll(self):
                return None if self.running else 0
            def terminate(self):
                self.running = False
                self.terminated = True
            def wait(self, timeout=None):
                self.running = False

        with tempfile.TemporaryDirectory() as directory:
            final = os.path.join(directory, "config.json")
            Path(final).write_text('{"old":true}', encoding="utf-8")
            candidate = Process()
            stops = []
            def stop():
                stops.append(1)
                if len(stops) > 1:
                    raise RuntimeError("stop failed")
            tx = transaction.ConfigTransaction(
                final, lambda path: (0, ""), lambda path: candidate,
                lambda path: "broken", stop, lambda *args: None)
            self.assertFalse(tx.apply('{"new":true}'))
            self.assertTrue(candidate.terminated)
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))

    def test_first_install_failure_leaves_no_final_config(self):
        with tempfile.TemporaryDirectory() as directory:
            final = os.path.join(directory, "singbox.json")
            calls = []
            tx = transaction.ConfigTransaction(
                final, lambda path: (0, ""), lambda path: calls.append("launch"),
                lambda path: "unknown", lambda: calls.append("stop"), lambda *args: None)
            self.assertFalse(tx.apply('{"new": true}'))
            self.assertFalse(os.path.exists(final))
            self.assertEqual(calls, ["stop", "launch", "stop"])
            self.assertTrue(os.path.isfile(final + ".broken"))

    def test_concurrent_writer_is_rejected_without_touching_config(self):
        with tempfile.TemporaryDirectory() as directory:
            tx, final, calls = self.make(directory)
            with transaction.write_lock(final):
                with self.assertRaises(transaction.TransactionError):
                    tx.apply('{"new": true}')
            self.assertEqual(calls, [])
            self.assertIn("old", Path(final).read_text(encoding="utf-8"))

    def test_lock_is_released_after_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            final = os.path.join(directory, "singbox.json")
            with self.assertRaises(RuntimeError):
                with transaction.write_lock(final):
                    raise RuntimeError("boom")
            with transaction.write_lock(final):
                pass

    def test_stage_accepts_bytes_and_never_leaves_partial_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            final = os.path.join(directory, "config.json")
            staged = transaction.stage(final, b'{"raw":true}')
            self.assertEqual(staged, final + ".new")
            self.assertEqual(Path(staged).read_bytes(), b'{"raw":true}')
            self.assertFalse(os.path.exists(staged + ".tmp"))


if __name__ == "__main__":
    unittest.main()
