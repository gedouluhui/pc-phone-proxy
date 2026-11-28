"""Release metadata must bind artifacts to exact hashes and source materials."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import generate_provenance
import generate_sbom


class ReleaseMetadataTests(unittest.TestCase):
    def test_cyclonedx_sbom_contains_pinned_components_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "engine.aar"
            artifact.write_bytes(b"synthetic engine")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            output = Path(directory) / "sbom.json"
            generate_sbom.generate([{
                "type": "library", "name": "libv2ray", "version": "26.11.9",
                "bom-ref": "pkg:generic/libv2ray@26.11.9",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "licenses": [{"license": {"id": "MPL-2.0"}}],
            }], output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            self.assertEqual(data["specVersion"], "1.6")
            self.assertEqual(data["components"][0]["hashes"][0]["content"], digest)

    def test_provenance_binds_source_and_artifact_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.txt"
            artifact = Path(directory) / "app.apk"
            source.write_bytes(b"source")
            artifact.write_bytes(b"apk")
            output = Path(directory) / "provenance.json"
            generate_provenance.generate(
                "https://github.com/gedouluhui/pc-phone-proxy", "a" * 40,
                "https://github.com/actions/runner", [source], [artifact], output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(data["subject"][0]["digest"]["sha256"],
                             hashlib.sha256(b"apk").hexdigest())
            materials = data["predicate"]["buildDefinition"]["resolvedDependencies"]
            self.assertEqual(materials[0]["digest"]["sha1"], hashlib.sha1(b"source").hexdigest())

    def test_missing_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                generate_provenance.generate(
                    "https://github.com/example/repo", "b" * 40,
                    "test-builder", [], [Path(directory) / "missing.apk"],
                    Path(directory) / "provenance.json")


if __name__ == "__main__":
    unittest.main()
