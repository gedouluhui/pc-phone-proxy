"""CI actions and downloaded binaries must be pinned and verified before use."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_ci_supply_chain as check


WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


class CiSupplyChainTests(unittest.TestCase):
    def test_repository_workflow_passes(self):
        self.assertEqual(check.check_text(WORKFLOW), [])

    def test_tagged_action_is_rejected(self):
        changed = WORKFLOW.replace("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                                    "actions/checkout@v4.2.2")
        self.assertTrue(any("checkout" in error for error in check.check_text(changed)))

    def test_missing_binary_hash_is_rejected(self):
        changed = WORKFLOW.replace(check.SINGBOX_SHA256, "0" * 64)
        self.assertTrue(any("sing-box" in error for error in check.check_text(changed)))

    def test_release_workflows_are_pinned_and_verify_aar(self):
        self.assertEqual(check.check_repository(), [])

    def test_write_permissions_are_rejected(self):
        changed = WORKFLOW.replace("contents: read", "contents: write")
        self.assertTrue(any("permissions" in error for error in check.check_text(changed)))

    def test_unverified_aar_extraction_is_rejected(self):
        changed = WORKFLOW.replace("sha256sum -c -", "true")
        self.assertTrue(any("AAR" in error for error in check.check_text(changed)))


if __name__ == "__main__":
    unittest.main()
