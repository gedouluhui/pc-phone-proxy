"""Regression tests for untrusted PC node data."""
import copy
import sys
import unittest
from pathlib import Path

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import bestroute
import nodes


class NodeTrustTests(unittest.TestCase):
    def test_redaction_drops_userinfo_path_query_and_fragment(self):
        uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?token=SYNTHETIC_SECRET#name"
        self.assertEqual(nodes.redact_uri(uri), "vless://example.com:443")

    def test_public_tls_sanitization_removes_insecure_without_mutating_input(self):
        ob, _ = nodes.parse_uri("trojan://synthetic-pass@example.com:443?security=tls&insecure=1#x")
        clean = nodes.sanitize_public_outbound(ob)
        self.assertFalse(clean["tls"].get("insecure", False))
        self.assertTrue(ob["tls"]["insecure"])

    def test_identity_ignores_tag_but_includes_credentials(self):
        a, _ = nodes.parse_uri("trojan://one@example.com:443?security=tls#a")
        b, _ = nodes.parse_uri("trojan://two@example.com:443?security=tls#b")
        a["tag"] = "g0"
        self.assertEqual(nodes.outbound_identity(a), nodes.outbound_identity(copy.deepcopy(a)))
        self.assertNotEqual(nodes.outbound_identity(a), nodes.outbound_identity(b))

    def test_same_host_different_ports_are_not_deduplicated(self):
        rows = [
            {"server": "example.com", "port": 443, "proto": "trojan",
             "uri": "trojan://one@example.com:443?security=tls#a",
             "dl_kbps": 500, "ul_kbps": 100, "github_ok": True, "chatgpt_ok": True},
            {"server": "example.com", "port": 8443, "proto": "trojan",
             "uri": "trojan://two@example.com:8443?security=tls#b",
             "dl_kbps": 400, "ul_kbps": 100, "github_ok": True, "chatgpt_ok": True},
        ]
        picked = bestroute.pick(rows, True, 300, 80, 10)
        self.assertEqual({row["port"] for row in picked}, {443, 8443})


if __name__ == "__main__":
    unittest.main()
