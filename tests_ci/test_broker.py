"""Elevated broker must authenticate its install, data directory and command surface."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pc" / "app"))
sys.path.insert(0, str(ROOT / "pc" / "_proxy"))
import broker
import install_manifest


class BrokerTests(unittest.TestCase):
    def fixture(self, directory):
        install = Path(directory) / "Program Files" / "PhoneProxy"
        install.mkdir(parents=True)
        files = {}
        for relative in ("app/broker.py", "app/install_manifest.py", "app/updater.py",
                         "app/release_tools/release_manifest.py",
                         "app/release_tools/sign_sources.py",
                         "app/release_tools/verify_sources.py", "_proxy/tun_mode.py",
                         "_proxy/tun_supervisor.py", "_proxy/bin/sing-box.exe",
                         "_proxy/bin/wintun.dll", "runtime/python/python.exe",
                         "runtime/tray.exe"):
            path = install / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("synthetic-" + relative).encode("utf-8"))
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest = install / "install-manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "files": files}), encoding="utf-8")
        return install, manifest

    def test_install_manifest_covers_code_and_binaries(self):
        import make_install_manifest
        with tempfile.TemporaryDirectory() as directory:
            install, manifest = self.fixture(directory)
            make_install_manifest.build(install, manifest)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIn("runtime/tray.exe", data["files"])
            self.assertIn("runtime/python/python.exe", data["files"])
            self.assertIn("app/broker.py", data["files"])
            self.assertNotIn("install-manifest.json", data["files"])

    def test_valid_install_and_hash_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            install, manifest = self.fixture(directory)
            with mock.patch.object(install_manifest, "_acl_safe", return_value=True):
                self.assertTrue(install_manifest.verify_install(install, require_program_files=False))
                (install / "app" / "broker.py").write_bytes(b"tampered")
                self.assertFalse(install_manifest.verify_install(install, require_program_files=False))

    def test_manifest_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            install, manifest = self.fixture(directory)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["files"]["../escape.py"] = "0" * 64
            manifest.write_text(json.dumps(data), encoding="utf-8")
            self.assertFalse(install_manifest.verify_install(install, require_program_files=False))

    def test_data_directory_must_be_current_user_local_appdata(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = os.path.join(directory, "PhoneProxy", "data")
            self.assertTrue(install_manifest.verify_data_dir(expected, directory))
            self.assertFalse(install_manifest.verify_data_dir(os.path.join(directory, "other"), directory))
            self.assertFalse(install_manifest.verify_data_dir(expected + "\\..\\escape", directory))

    def test_portable_and_installed_modes_never_create_elevated_scheduled_task(self):
        import tun_mode
        with mock.patch.object(tun_mode.subprocess, "run") as run:
            tun_mode.register_guard_task()
        run.assert_not_called()

    def test_unregister_does_not_delete_unverified_legacy_action(self):
        import tun_mode
        completed = mock.Mock(returncode=0, stdout=b"<Task><Actions><Exec>"
                              b"<Command>C:\\user\\tun_supervisor.py</Command>"
                              b"<Arguments>--once</Arguments></Exec></Actions></Task>")
        with mock.patch.object(tun_mode.subprocess, "run", return_value=completed) as run:
            tun_mode.unregister_guard_task()
        self.assertEqual(run.call_count, 1)
        self.assertIn("/Query", run.call_args.args[0])

    def test_installer_packages_update_verification_key(self):
        installer = (ROOT / "pc" / "installer" / "PhoneProxy.iss").read_text(encoding="utf-8")
        self.assertIn("release-public.pem", installer)
        for name in ("release_manifest.py", "sign_sources.py", "verify_sources.py"):
            self.assertIn("..\\..\\tools\\" + name, installer)
            self.assertIn("app/release_tools/" + name, install_manifest.REQUIRED)
        self.assertIn('Excludes: "*.pyc,__pycache__"', installer)
        self.assertIn("PHONEPROXY_DATA_DIR", (ROOT / "pc" / "app" / "tray.py").read_text(encoding="utf-8"))

    def test_non_elevated_broker_refuses_before_spawning(self):
        with mock.patch.object(broker.ctypes.windll.shell32, "IsUserAnAdmin", return_value=0), \
             mock.patch.object(broker.subprocess, "run") as run:
            rc = broker.main(["tun-start", "--data-dir", "C:\\temp"])
            self.assertNotEqual(rc, 0)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
