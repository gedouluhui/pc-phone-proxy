"""Tray state must reflect measured service state and fail closed on unknown input."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pc" / "app"))
import tray_state


class TrayStateTests(unittest.TestCase):
    def test_unknown_status_is_not_reported_as_running(self):
        model = tray_state.Model()
        model.update({})
        self.assertEqual(model.state, "idle")
        model.update({"state": "running"})
        self.assertEqual(model.state, "running")
        self.assertIn("运行", model.label())

    def test_measured_health_and_mode_are_shown_without_credentials(self):
        model = tray_state.Model()
        model.update({"state": "running", "mode": "tun", "healthy": 7,
                      "detail": "synthetic", "uri": "vless://secret@example.com"})
        self.assertEqual(model.healthy, 7)
        self.assertEqual(model.mode, "tun")
        self.assertNotIn("secret", model.label())

    def test_disconnect_is_explicit(self):
        model = tray_state.Model()
        model.update({"state": "running", "mode": "split"})
        model.disconnect()
        self.assertEqual(model.state, "idle")
        self.assertEqual(model.mode, "split")


if __name__ == "__main__":
    unittest.main()
