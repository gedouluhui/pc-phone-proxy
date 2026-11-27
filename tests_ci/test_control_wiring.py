"""All generated Clash controllers and clients must use the same authenticated secret."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import bestroute
import deep_test
import nodes
import start_proxy
import tun_mode
import tun_supervisor
import watchdog


SECRET = "synthetic-controller-secret"


class ControlWiringTests(unittest.TestCase):
    def assert_authenticated(self, cfg):
        api = cfg["experimental"]["clash_api"]
        self.assertEqual(api["secret"], SECRET)
        self.assertTrue(api["external_controller"].startswith("127.0.0.1:"))

    def test_nodes_config_has_secret(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(nodes, "CFG", os.path.join(directory, "singbox.json")), \
             mock.patch.object(nodes.control_secret, "get_or_create", return_value=SECRET):
            nodes.write_config([])
            self.assert_authenticated(json.loads(Path(nodes.CFG).read_text(encoding="utf-8")))

    def test_pinned_config_has_secret(self):
        with mock.patch.object(bestroute, "lok", return_value=False), \
             mock.patch.object(bestroute.control_secret, "get_or_create", return_value=SECRET):
            cfg = bestroute.build_config([], [])[0]
            self.assert_authenticated(cfg)

    def test_deep_config_has_secret(self):
        with mock.patch.object(deep_test.control_secret, "get_or_create", return_value=SECRET):
            self.assert_authenticated(deep_test.build_cfg(
                [{"outbound": {"type": "direct", "tag": "n1"}}], 2160, 2161, 9089))

    def test_tun_config_has_secret(self):
        pinned = {"outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "selector", "tag": "grp-general", "outbounds": ["direct"]},
            {"type": "selector", "tag": "grp-any", "outbounds": ["direct"]},
        ]}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(tun_mode, "PINNED", os.path.join(directory, "pinned.json")), \
             mock.patch.object(tun_mode.control_secret, "get_or_create", return_value=SECRET):
            Path(tun_mode.PINNED).write_text(json.dumps(pinned), encoding="utf-8")
            self.assert_authenticated(tun_mode.build_config())

    def test_start_and_watchdog_use_authenticated_client(self):
        with mock.patch.object(start_proxy.control_api, "json_request", return_value={"now": "g1"}) as call:
            self.assertEqual(start_proxy.http_json("http://127.0.0.1:19090/proxies/g"), {"now": "g1"})
            call.assert_called_once()
        with mock.patch.object(watchdog.control_api, "json_request", return_value={"now": "g1"}) as call:
            self.assertEqual(watchdog.http_json("http://127.0.0.1:19090/proxies/g"), {"now": "g1"})
            call.assert_called_once()

    def test_tun_delay_uses_authenticated_client(self):
        with mock.patch.object(tun_supervisor.control_api, "json_request", return_value={"delay": 42}) as call:
            self.assertEqual(tun_supervisor.api_delay("g1", "https://example.com", 5000), 42)
            self.assertEqual(call.call_args.args[0], "GET")

    def test_async_clients_send_bearer_and_disable_ambient_proxy(self):
        class Response:
            status = 200
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            async def json(self, **kwargs):
                return {"delay": 12}

        class Session:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.calls = []
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            def get(self, url, **kwargs):
                self.calls.append(("GET", url, kwargs))
                return Response()
            def put(self, url, **kwargs):
                self.calls.append(("PUT", url, kwargs))
                return Response()

        sessions = []
        def factory(**kwargs):
            session = Session(**kwargs)
            sessions.append(session)
            return session

        fake_aiohttp = mock.Mock(ClientSession=factory)
        with mock.patch.dict(sys.modules, {"aiohttp": fake_aiohttp}), \
             mock.patch.object(nodes.control_api, "headers", return_value={"Authorization": "Bearer " + SECRET}):
            self.assertEqual(asyncio.run(nodes.delay_all(["g1"], conc=1)), {"g1": 12})
            self.assertEqual(asyncio.run(nodes.set_selector("g1")), 200)
        self.assertEqual(len(sessions), 2)
        for session in sessions:
            self.assertFalse(session.kwargs["trust_env"])
            self.assertEqual(session.kwargs["headers"]["Authorization"], "Bearer " + SECRET)


if __name__ == "__main__":
    unittest.main()
