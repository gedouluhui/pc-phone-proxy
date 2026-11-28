"""The local control secret must be encrypted, user-bound and fail closed."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import control_secret


@unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
class ControlSecretTests(unittest.TestCase):
    def test_secret_round_trips_and_is_not_stored_in_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nested", "control-secret.bin")
            first = control_secret.get_or_create(path)
            second = control_secret.get_or_create(path)
            raw = Path(path).read_bytes()
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), 32)
            self.assertNotIn(first.encode("ascii"), raw)
            self.assertNotIn(b"synthetic", raw)

    def test_corrupt_or_empty_store_fails_closed_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "control-secret.bin")
            for damaged in (b"not DPAPI ciphertext", b""):
                Path(path).write_bytes(damaged)
                with self.assertRaises(control_secret.ControlSecretError):
                    control_secret.get_or_create(path)
                self.assertEqual(Path(path).read_bytes(), damaged)

    def test_entropy_is_bound_to_this_application(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "control-secret.bin")
            secret = control_secret.get_or_create(path)
            raw = Path(path).read_bytes()
            with self.assertRaises(control_secret.ControlSecretError):
                control_secret._unprotect(raw, b"another-application")
            self.assertEqual(control_secret._unprotect(raw, control_secret._ENTROPY), secret.encode("ascii"))

    def test_acl_removes_inheritance_and_grants_only_current_user(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "control-secret.bin")
            control_secret.get_or_create(path)
            script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
                      "$a=Get-Acl -LiteralPath $env:TEST_ACL_PATH;"
                      "$a.Access | ForEach-Object { [pscustomobject]@{"
                      "Sid=$_.IdentityReference.Translate("
                      "[System.Security.Principal.SecurityIdentifier]).Value;"
                      "Inherited=$_.IsInherited} } | ConvertTo-Json -Compress")
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, env=dict(os.environ, TEST_ACL_PATH=path),
                creationflags=0x08000000, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            entries = json.loads(result.stdout or "[]")
            if isinstance(entries, dict):
                entries = [entries]
            self.assertTrue(entries)
            sid = control_secret._current_sid()
            for entry in entries:
                self.assertEqual(entry["Sid"], sid)
                self.assertFalse(entry["Inherited"])

    def test_current_sid_does_not_depend_on_whoami_path(self):
        from unittest import mock
        with mock.patch.object(control_secret.subprocess, "run",
                               side_effect=AssertionError("external whoami must not run")):
            self.assertTrue(control_secret._current_sid().startswith("S-1-"))

    def test_default_store_is_inside_current_user_local_appdata(self):
        expected = os.path.join(os.environ["LOCALAPPDATA"], "PhoneProxy",
                                "control-secret.bin")
        self.assertEqual(control_secret.default_path().lower(), expected.lower())


if __name__ == "__main__":
    unittest.main()
