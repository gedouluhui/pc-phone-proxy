"""Android product packaging and per-app proxy must be wired through secure storage."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHONE = ROOT / "phone"
sys.path.insert(0, str(PHONE / "src" / "com" / "luhui" / "phoneproxy"))


class AndroidProductTests(unittest.TestCase):
    def test_target_sdk_is_36(self):
        manifest = (PHONE / "AndroidManifest.xml").read_text(encoding="utf-8")
        self.assertIn('android:targetSdkVersion="36"', manifest)
        self.assertIn('android:usesCleartextTraffic="false"', manifest)

    def test_per_app_selection_is_read_from_secure_store(self):
        service = (PHONE / "src" / "com" / "luhui" / "phoneproxy" /
                   "ProxyVpnService.java").read_text(encoding="utf-8")
        self.assertIn('SecureStore.get(this, "allowed_apps")', service)
        self.assertIn("addAllowedApplication", service)

    def test_apk_is_checked_for_16kb_alignment(self):
        builder = (PHONE / "build_apk.py").read_text(encoding="utf-8")
        self.assertIn('"-P", "16"', builder)
        self.assertIn('"-c", "-P", "16", "4"', builder)

    def test_ci_builds_with_api_36(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("platforms;android-36", workflow)
        self.assertIn("build-tools;36.0.0", workflow)


if __name__ == "__main__":
    unittest.main()
