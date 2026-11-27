"""Repository source manifests must be signed, schema-valid and embedded verbatim."""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import sign_sources
import verify_sources


OPENSSL = shutil.which("openssl")


class PureManifestVerifierTests(unittest.TestCase):
    def test_committed_signature_verifies_without_external_tools(self):
        data = (ROOT / "phone" / "sources.json").read_bytes()
        signature = (ROOT / "phone" / "sources.sig").read_bytes()
        public = (ROOT / "phone" / "source_signing_public.pem").read_bytes()
        self.assertTrue(verify_sources.verify_bytes(data, signature, public))
        self.assertFalse(verify_sources.verify_bytes(data + b" ", signature, public))
        self.assertFalse(verify_sources.verify_bytes(data, signature[:-1], public))
        self.assertFalse(verify_sources.verify_bytes(data, signature, b"not a public key"))


@unittest.skipUnless(OPENSSL, "OpenSSL is required for RSA signing proofs")
class SourceManifestTests(unittest.TestCase):
    def keypair(self, directory, prefix="key"):
        private = os.path.join(directory, prefix + "-private.pem")
        public = os.path.join(directory, prefix + "-public.pem")
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", private], check=True,
                       capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", private, "-pubout", "-out", public],
                       check=True, capture_output=True)
        return private, public

    def manifest(self, version=2):
        return json.dumps({"schema": 1, "version": version,
                           "sources": [
                               {"name": "one", "url": "https://raw.githubusercontent.com/a/b/main/one.txt"},
                               {"name": "two", "url": "https://raw.githubusercontent.com/a/b/main/two.txt"},
                               {"name": "three", "url": "https://raw.githubusercontent.com/a/b/main/three.txt"},
                           ]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def test_valid_tampered_missing_and_wrong_key_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.keypair(directory)
            _, wrong_public = self.keypair(directory, "wrong")
            data = self.manifest()
            signature = sign_sources.sign_bytes(data, private, OPENSSL)
            self.assertTrue(verify_sources.verify_bytes(data, signature, Path(public).read_bytes()))
            tampered = data.replace(b'"version":2', b'"version":3')
            self.assertFalse(verify_sources.verify_bytes(tampered, signature, Path(public).read_bytes()))
            self.assertFalse(verify_sources.verify_bytes(data, b"", Path(public).read_bytes()))
            self.assertFalse(verify_sources.verify_bytes(data, signature, Path(wrong_public).read_bytes()))

    def test_repository_manifest_and_signature_are_valid(self):
        data = (ROOT / "phone" / "sources.json").read_bytes()
        signature = (ROOT / "phone" / "sources.sig").read_bytes()
        public = (ROOT / "phone" / "source_signing_public.pem").read_bytes()
        self.assertTrue(verify_sources.verify_bytes(data, signature, public))
        manifest = json.loads(data)
        self.assertEqual(manifest["schema"], 1)
        self.assertGreaterEqual(manifest["version"], 1)
        self.assertGreaterEqual(len(manifest["sources"]), 3)

    def test_java_embeds_the_same_public_key(self):
        pem = (ROOT / "phone" / "source_signing_public.pem").read_text(encoding="ascii")
        body = "".join(line for line in pem.splitlines() if not line.startswith("---"))
        source = (ROOT / "phone" / "src" / "com" / "luhui" / "phoneproxy" /
                  "SourceManifest.java").read_text(encoding="utf-8")
        declaration = re.search(r'PUBLIC_KEY_DER_B64\s*=\s*(.*?);', source, re.S)
        self.assertIsNotNone(declaration)
        parts = re.findall(r'"([A-Za-z0-9+/=]+)"', declaration.group(1))
        self.assertTrue(parts)
        self.assertEqual(base64.b64decode("".join(parts)), base64.b64decode(body))

    def test_json_sources_match_compiled_builtin_fallback(self):
        manifest = json.loads((ROOT / "phone" / "sources.json").read_text(encoding="utf-8"))
        source = (ROOT / "phone" / "src" / "com" / "luhui" / "phoneproxy" /
                  "ConfigBuilder.java").read_text(encoding="utf-8")
        block = re.search(r"PUBLIC_SOURCES\s*=\s*\{(.*?)\n\s*\};", source, re.S)
        self.assertIsNotNone(block)
        pairs = re.findall(r'\{"([^"]+)",\s*"([^"]+)"\}', block.group(1))
        self.assertEqual([(item["name"], item["url"]) for item in manifest["sources"]], pairs)

    def test_builder_packages_manifest_and_signature_assets(self):
        source = (ROOT / "phone" / "build_apk.py").read_text(encoding="utf-8")
        self.assertIn('"sources.json"', source)
        self.assertIn('"sources.sig"', source)


if __name__ == "__main__":
    unittest.main()
