"""Windows updater stages only verified artifacts and never overwrites the install."""
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
sys.path.insert(0, str(ROOT / "pc" / "app"))
import release_manifest
import sign_sources
import updater

OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL and os.name == "nt", "Windows/OpenSSL updater proof")
class UpdaterTests(unittest.TestCase):
    def keypair(self, directory):
        private = os.path.join(directory, "private.pem")
        public = os.path.join(directory, "public.pem")
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", private], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", private, "-pubout", "-out", public],
                       check=True, capture_output=True)
        return private, public

    def fixture(self, directory):
        private, public = self.keypair(directory)
        artifact = Path(directory) / "PhoneProxy-Setup.exe"
        artifact.write_bytes(b"verified installer")
        record = {"name": artifact.name, "size": artifact.stat().st_size,
                  "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  "url": "https://github.com/example/repo/releases/download/v2/PhoneProxy-Setup.exe"}
        data = release_manifest.build(2, "b" * 40, [record])
        signature = sign_sources.sign_bytes(data, private, OPENSSL)
        manifest = Path(directory) / "release-manifest.json"
        sig = Path(directory) / "release-manifest.sig"
        manifest.write_bytes(data)
        sig.write_bytes(signature)
        return manifest, sig, public, artifact

    def test_valid_artifact_is_staged_without_touching_current_install(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, sig, public, artifact = self.fixture(directory)
            current = Path(directory) / "current"
            current.mkdir()
            marker = current / "installed.exe"
            marker.write_bytes(b"old install")
            stage = updater.stage(manifest, sig, public, directory, previous_version=1)
            self.assertEqual((Path(stage) / artifact.name).read_bytes(), artifact.read_bytes())
            self.assertEqual(marker.read_bytes(), b"old install")

    def test_bad_signature_or_rollback_does_not_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, sig, public, artifact = self.fixture(directory)
            sig.write_bytes(b"bad")
            with self.assertRaises(ValueError):
                updater.stage(manifest, sig, public, directory, previous_version=1)
            signature = sign_sources.sign_bytes(manifest.read_bytes(),
                                                str(Path(directory) / "private.pem"), OPENSSL)
            sig.write_bytes(signature)
            with self.assertRaises(ValueError):
                updater.stage(manifest, sig, public, directory, previous_version=2)


if __name__ == "__main__":
    unittest.main()
