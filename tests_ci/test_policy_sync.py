"""The shared routing policy must stay valid and synchronously generated."""
import json
import subprocess
import sys
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
            self.assertTrue(all(isinstance(x, str) and x and not any(c.isspace() for c in x)
                                and ("." in x or x == "cn") for x in data[key]))
        self.assertEqual(data["udp"]["quic"], "reject")
        self.assertEqual(data["udp"]["default"], "reject")
        self.assertEqual(data["dns"]["ipv6"], "proxy")

    def test_generated_files_match_current_policy(self):
        result = subprocess.run([sys.executable, str(SYNC), "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_render_is_deterministic(self):
        first = subprocess.run([sys.executable, str(SYNC), "--check"],
                               cwd=ROOT, capture_output=True, text=True)
        second = subprocess.run([sys.executable, str(SYNC), "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(first.stdout, second.stdout)


if __name__ == "__main__":
    unittest.main()
