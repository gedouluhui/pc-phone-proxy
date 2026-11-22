"""Poisoning regressions for the PC share-link parser.

Subscription content is untrusted: a malformed or hostile link must never
raise out of parse_uri, and whatever it does accept must look like a
plausible sing-box outbound with a server that load_nodes will filter.
"""
import random
import sys
import unittest
from pathlib import Path

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import nodes  # noqa: E402  (stdlib-only module, no work on import)


VALID = [
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws#ok",
    "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
    "?encryption=none&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&sid=0123&type=grpc&serviceName=gs#ok",
    "vmess://eyJ2IjoiMiIsInBzIjoib2siLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6"
    "IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=",
    "trojan://secret@example.com:443?security=tls&type=tcp#ok",
    "ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388#ok",
    "http://user:pass@example.com:8080#ok",
]

MUTATIONS = [
    "", "   ", "not a uri", "://", "vless://", "vmess://", "ss://", "trojan://",
    "file:///etc/passwd", "ftp://example.com/x", "https://example.com/",
    "vless://@example.com:443", "vless://id@:443", "vless://id@example.com:0",
    "vless://id@example.com:65536", "vless://id@example.com:99999999999999999999",
    "vless://%zz@example.com:443", "vless://id%00@example.com:443",
    "vless://x@[::1]:443", "vless://x@127.0.0.1:443", "vless://x@169.254.169.254:80",
    "vless://x@localhost:443", "vless://x@example.com:443?type=quic",
    "vmess://" + "A" * 200, "vmess://%%%", "vmess://e30=",
    "vmess://eyJhZGQiOiIiLCJwb3J0IjoiIn0=",
    "trojan://@example.com:443", "ss://@example.com:8388",
    "ss://YWVzLTI1Ni1nY206@example.com:8388", "socks5://example.com:notaport",
    "vless://id@example.com:443#" + "r" * 5000,
    "vless://id@example.com:443?security=tls&security=reality",
    "vless://id@example.com:443?type=ws&path=" + "%" * 500,
    "vmess://eyJwb3J0IjoiNDQzIn0=",
    "vless://x@example.com:443?type=h2&security=tls",
    "trojan://p@example.com:443?security=none",
    "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#legacy-ok-on-pc",
]

ALPHABET = "abcXYZ019:/@?#%&=+-_.~[]\\\x00\r\n \"'{}"


def mutations(seed=20261123, count=240):
    rng = random.Random(seed)
    base = VALID[:]
    out = list(MUTATIONS)
    for _ in range(count):
        uri = rng.choice(base)
        kind = rng.randrange(4)
        if kind == 0:
            pos = rng.randrange(len(uri) + 1)
            uri = uri[:pos] + rng.choice(ALPHABET) + uri[pos:]
        elif kind == 1:
            pos = rng.randrange(len(uri))
            uri = uri[:pos] + uri[pos + 1:]
        elif kind == 2:
            pos = rng.randrange(len(uri))
            uri = uri[:pos] + rng.choice(ALPHABET) + uri[pos + 1:]
        else:
            uri = uri[:rng.randrange(len(uri) + 1)]
        out.append(uri)
    return out


class PoisonParseTests(unittest.TestCase):
    def test_never_raises_and_returns_pairs(self):
        for uri in mutations():
            with self.subTest(uri=uri[:80]):
                result = nodes.parse_uri(uri)
                self.assertIsInstance(result, tuple)
                self.assertEqual(len(result), 2)
                ob, meta = result
                if ob is None:
                    self.assertIsNone(meta)
                    continue
                self.assertIsInstance(ob, dict)
                self.assertIn(ob.get("type"), {"vless", "vmess", "trojan", "shadowsocks", "socks", "http"})
                self.assertIsInstance(ob.get("server"), str)
                self.assertTrue(ob["server"])
                port = ob.get("server_port")
                self.assertIsInstance(port, int)
                self.assertTrue(1 <= port <= 65535)
                if ob["type"] == "shadowsocks":
                    # Unsupported ciphers are dropped by load_nodes; parse must
                    # still never emit an outbound with an empty method.
                    self.assertIsInstance(ob["method"], str)
                    self.assertTrue(ob["method"])
                self.assertIsInstance(meta, dict)
                self.assertIn("proto", meta)
                self.assertIn("net", meta)

    def test_unsupported_or_truncated_links_reject(self):
        for uri in ("", "not a uri", "file:///etc/passwd", "ftp://example.com/x",
                    "https://example.com/", "vless://", "vmess://", "vmess://%%%",
                    "ss://", "trojan://", "socks5://example.com:notaport"):
            with self.subTest(uri=uri):
                self.assertEqual(nodes.parse_uri(uri), (None, None))

    def test_forbidden_servers_are_identifiable(self):
        for uri in ("vless://x@127.0.0.1:443", "vless://x@[::1]:443",
                    "vless://x@169.254.169.254:80", "vless://x@localhost:443",
                    "vless://x@10.1.2.3:443", "vless://x@192.168.1.1:443"):
            with self.subTest(uri=uri):
                ob, _ = nodes.parse_uri(uri)
                self.assertIsNotNone(ob)
                self.assertTrue(nodes.is_forbidden_server(ob["server"]))

    def test_valid_links_still_parse(self):
        for uri in VALID:
            with self.subTest(uri=uri[:60]):
                ob, meta = nodes.parse_uri(uri)
                self.assertIsNotNone(ob, uri)
                self.assertFalse(nodes.is_forbidden_server(ob["server"]))
                self.assertTrue(meta["proto"])


if __name__ == "__main__":
    unittest.main()