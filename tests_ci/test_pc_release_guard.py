"""Windows installer release guard checks PE structure and optional Authenticode."""
import importlib.util
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "pc" / "check_release.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("pc_release_guard", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PcReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pc-release-guard-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installer = self.root / "PhoneProxy-Setup-4.0.0.exe"

    def pe(self, machine=0x8664):
        pe_offset = 0x80
        data = bytearray(pe_offset + 0x100)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, pe_offset)
        data[pe_offset:pe_offset + 4] = b"PE\0\0"
        struct.pack_into("<H", data, pe_offset + 4, machine)
        struct.pack_into("<H", data, pe_offset + 24, 0x20B)
        self.installer.write_bytes(data)
        return self.installer

    def test_x64_and_x86_pe_are_accepted_for_local_unsigned_build(self):
        guard = load_guard()
        for machine, magic in ((0x8664, 0x20B), (0x14C, 0x10B)):
            with self.subTest(machine=hex(machine)):
                self.pe(machine=machine)
                if magic == 0x10B:
                    data = bytearray(self.installer.read_bytes())
                    struct.pack_into("<H", data, 0x80 + 24, magic)
                    self.installer.write_bytes(data)
                self.assertTrue(guard.check_installer(self.installer, require_signature=False))

    def test_non_pe_and_non_x86_compatible_are_rejected(self):
        guard = load_guard()
        self.installer.write_bytes(b"not an installer")
        with self.assertRaises(ValueError):
            guard.check_installer(self.installer, require_signature=False)
        self.pe(machine=0xAA64)
        with self.assertRaises(ValueError):
            guard.check_installer(self.installer, require_signature=False)

    def test_missing_explicit_installer_is_rejected(self):
        guard = load_guard()
        with self.assertRaises(FileNotFoundError):
            guard.check_installer(self.installer, require_signature=False)

    def test_signature_requirement_fails_closed_without_windows_signer(self):
        self.pe()
        guard = load_guard()
        with mock.patch.object(guard, "authenticode", return_value=(False, "")):
            with self.assertRaises(ValueError):
                guard.check_installer(self.installer, require_signature=True)

    def test_release_environment_requires_signature(self):
        guard = load_guard()
        with mock.patch.dict(os.environ, {"PROXY_RELEASE": "1"}):
            self.assertTrue(guard.signature_required())


if __name__ == "__main__":
    unittest.main()
