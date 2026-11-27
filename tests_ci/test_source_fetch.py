"""Public source downloads are size-bounded, redirect-limited and DNS-pinned."""
import contextlib
import http.server
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

PROXY = Path(__file__).resolve().parents[1] / "pc" / "_proxy"
sys.path.insert(0, str(PROXY))

import source_fetch


@contextlib.contextmanager
def local_server():
    hosts = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hosts.append(self.headers.get("Host"))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            if self.path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.end_headers()
                return
            if self.path == "/redirect-big":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"x" * 100)
                return
            if self.path == "/fail":
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"unavailable")
                return
            body = b"x" * 100 if self.path == "/big" else b"trusted-list\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], hosts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class SourceFetchTests(unittest.TestCase):
    def test_private_literal_is_rejected(self):
        for url in ("http://127.0.0.1/nodes", "http://10.0.0.1/nodes",
                    "http://[::1]/nodes", "http://169.254.169.254/latest"):
            with self.subTest(url=url), self.assertRaises(source_fetch.Rejected):
                source_fetch.validate_url(url)

    def test_credentials_and_non_http_schemes_are_rejected(self):
        for url in ("https://user:pass@example.com/nodes", "file:///etc/passwd",
                    "ftp://example.com/nodes", "https://example.com:0/nodes"):
            with self.subTest(url=url), self.assertRaises(source_fetch.Rejected):
                source_fetch.validate_url(url)

    def test_private_resolution_is_rejected(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with mock.patch.object(source_fetch.socket, "getaddrinfo", return_value=answer):
            with self.assertRaises(source_fetch.Rejected):
                source_fetch.fetch("https://example.com/nodes")

    def test_mixed_public_and_private_answers_fail_closed(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with mock.patch.object(source_fetch.socket, "getaddrinfo", return_value=answers):
            with self.assertRaises(source_fetch.Rejected):
                source_fetch.fetch("https://example.com/nodes")

    def test_ipv4_mapped_ipv6_private_address_is_rejected(self):
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.validate_url("http://[::ffff:127.0.0.1]/nodes")

    def test_https_downgrade_redirect_is_rejected(self):
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.validate_redirect("https://example.com/a", "http://example.com/b")
        self.assertEqual(source_fetch.validate_redirect(
            "https://example.com/a", "/b")[1], "example.com")

    def test_fetch_resolves_once_and_pins_connection_while_preserving_host(self):
        with local_server() as (port, hosts):
            real = socket.getaddrinfo
            calls = []

            def resolve(host, port, *args, **kwargs):
                if host == "public.test":
                    calls.append(host)
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
                return real(host, port, *args, **kwargs)

            with mock.patch.object(source_fetch.socket, "getaddrinfo", side_effect=resolve):
                body = source_fetch.fetch("http://public.test:%d/ok" % port,
                                          allow_private=True, timeout=5)
            self.assertEqual(body, b"trusted-list\n")
            self.assertEqual(calls, ["public.test"])
            self.assertEqual(hosts, ["public.test:%d" % port])

    def test_redirect_is_followed_with_limit(self):
        with local_server() as (port, _):
            base = "http://127.0.0.1:%d" % port
            self.assertEqual(source_fetch.fetch(base + "/redirect", allow_private=True),
                             b"trusted-list\n")
            with self.assertRaises(source_fetch.FetchError):
                source_fetch.fetch(base + "/loop", allow_private=True)

    def test_oversized_body_is_rejected(self):
        with local_server() as (port, _):
            with self.assertRaises(source_fetch.FetchError):
                source_fetch.fetch("http://127.0.0.1:%d/big" % port,
                                   max_bytes=20, allow_private=True)

    def test_http_error_is_not_returned_as_a_valid_list(self):
        with local_server() as (port, _):
            with self.assertRaises(source_fetch.FetchError) as raised:
                source_fetch.fetch("http://127.0.0.1:%d/fail" % port, allow_private=True)
            self.assertEqual(raised.exception.status, 503)

    def test_redirect_bodies_share_the_cumulative_byte_budget(self):
        with local_server() as (port, _):
            with self.assertRaises(source_fetch.FetchError):
                source_fetch.fetch("http://127.0.0.1:%d/redirect-big" % port,
                                   max_bytes=50, allow_private=True)

    def test_https_socket_is_pinned_but_sni_uses_original_hostname(self):
        context = mock.Mock()
        sock = mock.Mock()
        wrapped = mock.Mock()
        context.wrap_socket.return_value = wrapped
        with mock.patch.object(source_fetch.ssl, "create_default_context", return_value=context), \
             mock.patch.object(source_fetch.socket, "create_connection", return_value=sock) as connect:
            connection = source_fetch._PinnedHTTPSConnection(
                "public.test", 443, "93.184.216.34", 443, 5)
            connection.connect()
        connect.assert_called_once_with(("93.184.216.34", 443), 5, None)
        context.wrap_socket.assert_called_once_with(sock, server_hostname="public.test")
        self.assertIs(connection.sock, wrapped)

    def test_https_proxy_connects_to_validated_ip_not_hostname(self):
        response = mock.Mock(status=200)
        response.getheader.side_effect = lambda name: None if name == "Location" else "2"
        response.read.side_effect = [b"ok", b""]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch.object(source_fetch.socket, "getaddrinfo", return_value=answer), \
             mock.patch.object(source_fetch, "_PinnedHTTPSConnection", return_value=connection) as cls:
            body = source_fetch._request_once(
                "https://public.test/nodes", False, ("127.0.0.1", 8080), 5, 100)
        self.assertEqual(body[2], b"ok")
        connection.set_tunnel.assert_called_once_with(
            "93.184.216.34", 443, headers={"Host": "public.test:443"})
        self.assertEqual(connection.request.call_args.args[1], "/nodes")
        self.assertEqual(connection.request.call_args.kwargs["headers"]["Host"], "public.test:443")
        self.assertEqual(cls.call_args.args[2:4], ("127.0.0.1", 8080))

    def test_non_loopback_bootstrap_proxy_is_rejected(self):
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.fetch("https://example.com/nodes", proxy="http://192.0.2.1:8080")

    def test_digest_is_sha256_of_returned_bytes(self):
        import hashlib
        self.assertEqual(source_fetch.digest(b"abc"), hashlib.sha256(b"abc").hexdigest())


if __name__ == "__main__":
    unittest.main()
