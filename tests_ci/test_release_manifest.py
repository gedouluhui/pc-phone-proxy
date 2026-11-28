"""Release manifests require a valid signature, exact artifact hashes and monotonic versions."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import release_manifest
import sign_sources

OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "OpenSSL is required for signing proofs")
class ReleaseManifestTests(unittest.TestCase):
    def keypair(self, directory):
        private = os.path.join(directory, "private.pem")
        public = os.path.join(directory, "public.pem")
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", private], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", private, "-pubout", "-out", public],
                       check=True, capture_output=True)
        return private, public

    def payload(self, directory):
        artifact = Path(directory) / "PhoneProxy-Setup.exe"
        artifact.write_bytes(b"synthetic installer")
        record = {"name": artifact.name, "size": artifact.stat().st_size,
                  "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  "url": "https://github.com/example/repo/releases/download/v1/PhoneProxy-Setup.exe"}
        data = release_manifest.build(1, "a" * 40, [record])
        return data, record, artifact

    def test_valid_manifest_and_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.keypair(directory)
            data, record, artifact = self.payload(directory)
            signature = sign_sources.sign_bytes(data, private, OPENSSL)
            parsed = release_manifest.verify_bytes(data, signature, Path(public).read_bytes())
            self.assertEqual(parsed["version"], 1)
            release_manifest.verify_artifact(parsed["artifacts"][0], artifact)

    def test_tamper_rollback_and_hash_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.keypair(directory)
            data, record, artifact = self.payload(directory)
            signature = sign_sources.sign_bytes(data, private, OPENSSL)
            public_bytes = Path(public).read_bytes()
            with self.assertRaises(ValueError):
                release_manifest.verify_bytes(data + b" ", signature, public_bytes)
            with self.assertRaises(ValueError):
                release_manifest.verify_bytes(data, signature, public_bytes, previous_version=1)
            parsed = release_manifest.verify_bytes(data, signature, public_bytes)
            artifact.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                release_manifest.verify_artifact(parsed["artifacts"][0], artifact)

    def test_path_traversal_artifact_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public = self.keypair(directory)
            data, record, artifact = self.payload(directory)
            record["name"] = "../escape.exe"
            data = json.dumps({"schema": 1, "version": 1, "commit": "a" * 40,
                               "artifacts": [record]}).encode("utf-8")
            signature = sign_sources.sign_bytes(data, private, OPENSSL)
            with self.assertRaises(ValueError):
                release_manifest.verify_bytes(data, signature, Path(public).read_bytes())


if __name__ == "__main__":
    unittest.main()
