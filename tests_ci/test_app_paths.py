"""Installed mode separates mutable state from read-only program files."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))
import app_paths


class AppPathsTests(unittest.TestCase):
    def test_portable_defaults_to_module_directory(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(app_paths)
            self.assertEqual(app_paths.DATA_DIR, app_paths.HERE)
            self.assertEqual(app_paths.data("tun.pid"), os.path.join(app_paths.HERE, "tun.pid"))

    def test_installed_data_directory_is_absolute_and_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PHONEPROXY_DATA_DIR": directory}):
                importlib.reload(app_paths)
                self.assertEqual(app_paths.DATA_DIR, os.path.abspath(directory))
                self.assertEqual(app_paths.data("logs", "tun.log"),
                                 os.path.join(directory, "logs", "tun.log"))
        importlib.reload(app_paths)


if __name__ == "__main__":
    unittest.main()
