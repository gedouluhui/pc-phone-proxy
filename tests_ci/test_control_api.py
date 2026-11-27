"""Every local Clash request carries authorization and bypasses ambient proxies."""
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import control_api


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ControlApiTests(unittest.TestCase):
    @mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret")
    def test_bearer_header_is_sent(self, secret):
        response = _Response(b'{"version":"test"}')
        with mock.patch.object(control_api.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            body = control_api.request("GET", "http://127.0.0.1:19090/version", timeout=1.5)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-secret")
            self.assertEqual(opener.call_args.args[0].__class__.__name__, "ProxyHandler")
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 1.5)
            self.assertEqual(body, b'{"version":"test"}')

    @mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret")
    def test_remote_url_is_rejected_before_opening(self, secret):
        for url in ("http://example.com:19090/version", "file:///C:/secrets",
                    "https://127.0.0.1:19090/version"):
            with self.subTest(url=url), \
                 mock.patch.object(control_api.urllib.request, "build_opener") as opener:
                with self.assertRaises(control_api.Rejected):
                    control_api.request("GET", url)
                opener.assert_not_called()

    @mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret")
    def test_http_error_is_hard_failure(self, secret):
        error = control_api.urllib.error.HTTPError(
            "http://127.0.0.1:19090/version", 401, "Unauthorized", {}, None)
        with mock.patch.object(control_api.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(control_api.ControlApiError) as raised:
                control_api.request("GET", "http://127.0.0.1:19090/version")
            self.assertEqual(raised.exception.status, 401)

    @mock.patch.object(control_api, "get_or_create", side_effect=RuntimeError("missing secret"))
    def test_missing_secret_is_not_replaced_by_an_empty_token(self, secret):
        with mock.patch.object(control_api.urllib.request, "build_opener") as opener:
            with self.assertRaises(control_api.ControlApiError):
                control_api.request("GET", "http://127.0.0.1:19090/version")
            opener.assert_not_called()

    def test_json_request_has_bearer_and_content_type(self):
        with mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret"), \
             mock.patch.object(control_api.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = _Response(b"{}")
            control_api.request("PUT", "http://127.0.0.1:19090/proxies/auto",
                                json_body={"name": "g1"})
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-secret")
            self.assertEqual(request.get_header("Content-type"), "application/json")
            self.assertEqual(request.data, b'{"name":"g1"}')


@unittest.skipUnless(sys.platform == "win32" and os.environ.get("SINGBOX_BIN"),
                     "requires Windows sing-box (set SINGBOX_BIN)")
class RealControlApiTests(unittest.TestCase):
    def test_singbox_rejects_missing_and_wrong_secret(self):
        binary = os.environ["SINGBOX_BIN"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = "http://127.0.0.1:%d/version" % port
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(control_api, "get_or_create", return_value="synthetic-secret"):
            config = os.path.join(directory, "singbox.json")
            Path(config).write_text(json.dumps({
                "log": {"level": "error"},
                "experimental": {"clash_api": {
                    "external_controller": "127.0.0.1:%d" % port,
                    "secret": "synthetic-secret"}},
                "outbounds": [{"type": "direct", "tag": "direct"}],
            }), encoding="utf-8")
            process = subprocess.Popen([binary, "run", "-c", config],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=0x08000000)
            try:
                deadline = time.time() + 15
                while True:
                    try:
                        version = control_api.json_request("GET", url, timeout=1)
                        break
                    except control_api.ControlApiError:
                        if process.poll() is not None or time.time() >= deadline:
                            self.fail("sing-box control API did not start")
                        time.sleep(0.2)
                self.assertIn("version", version)
                for headers in ({}, {"Authorization": "Bearer wrong-secret"}):
                    request = control_api.urllib.request.Request(url, headers=headers)
                    opener = control_api.urllib.request.build_opener(
                        control_api.urllib.request.ProxyHandler({}))
                    with self.assertRaises(control_api.urllib.error.HTTPError) as raised:
                        opener.open(request, timeout=3)
                    self.assertEqual(raised.exception.code, 401)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=8)


if __name__ == "__main__":
    unittest.main()
