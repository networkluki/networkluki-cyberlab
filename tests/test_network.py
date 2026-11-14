"""Deterministic validation and localhost network tests; no external traffic."""

import http.server
import json
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from networkluki_cyberlab import network


class PortValidationTests(unittest.TestCase):
    def test_ranges_are_sorted_and_deduplicated(self):
        self.assertEqual(network.parse_ports("443,80,20-22,22"), [20, 21, 22, 80, 443])

    def test_rejects_invalid_ports(self):
        for value in ("", "0", "65536", "-p80", "80;id", "1-129", "80,", "2-1", "１", "1-128,129"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                network.parse_ports(value)

    def test_rejects_invalid_or_nonspecific_addresses(self):
        for value in ("localhost", "127.0.0.0/24", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:255.255.255.255", "fe80::1%eth0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                network.tcp_scan(value, "80")

    def test_local_open_and_closed_ports(self):
        with socket.socket() as listener, socket.socket() as closed:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            open_port = listener.getsockname()[1]
            # A bound socket without listen avoids a race with another process.
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
            report = network.tcp_scan("127.0.0.1", f"{open_port},{closed_port}")
        states = {item["port"]: item["state"] for item in report["ports"]}
        self.assertEqual(states[open_port], "open")
        self.assertEqual(states[closed_port], "closed_or_filtered")
        self.assertEqual(report["open_count"], 1)

    def test_cancelled_scan_sends_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with mock.patch.object(network.socket, "socket") as constructor:
            with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                network.tcp_scan("127.0.0.1", "80", cancel)
            constructor.assert_not_called()


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    requests = []

    def do_HEAD(self):
        self.__class__.requests.append((self.command, self.path, self.headers.get("Host")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://invalid.example/should-not-be-contacted")
        elif self.path == "/no-head":
            self.send_response(405)
        elif self.path.startswith("/privacy?"):
            self.send_response(302)
            self.send_header("Location", "https://secret-user:secret-password@example.invalid/next?token=redirect-secret#fragment-secret")
            self.send_header("Content-Location", "/resource?key=content-secret")
            self.send_header("X-Api-Key", "api-secret")
            self.send_header("X-Auth-Token", "auth-secret")
        else:
            self.send_response(200)
        self.send_header("Set-Cookie", "session=secret-token")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def log_message(self, *_args):
        pass


class WebProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)

    def setUp(self):
        ProbeHandler.requests.clear()

    def test_url_validation_before_connection(self):
        invalid = (
            "file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com",
            "https://example.com/#", "https://example.com:0", "https://example.com:65536",
            "http://0.0.0.0/", "http://224.0.0.1/", "http://[::]/", "http://[fe80::1%25eth0]/",
            "https://example.com/\r\nHost: evil", "https://bad_host.example", "http://example.com/has space",
        )
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(network.socket, "socket") as constructor:
                with self.assertRaises(ValueError):
                    network.web_probe(value)
                constructor.assert_not_called()

    def test_redirect_is_not_followed_and_cookie_is_redacted(self):
        report = network.web_probe(f"http://127.0.0.1:{self.port}/redirect")
        self.assertEqual(report["status"], 302)
        self.assertEqual(len(ProbeHandler.requests), 1)
        self.assertEqual(ProbeHandler.requests[0][0], "HEAD")
        cookies = [item["value"] for item in report["headers"] if item["name"].lower() == "set-cookie"]
        self.assertEqual(cookies, ["[redacted]"])
        self.assertNotIn("secret-token", str(report))

    def test_dns_is_resolved_once_and_ip_pinned(self):
        fake_answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", self.port))]
        with mock.patch.object(network.socket, "getaddrinfo", return_value=fake_answer) as resolver:
            report = network.web_probe(f"http://pinned.example:{self.port}/test")
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(report["resolved_ip"], "127.0.0.1")
        self.assertEqual(ProbeHandler.requests[0][2], f"pinned.example:{self.port}")

    def test_result_redaction_preserves_the_original_request(self):
        request_path = "/privacy?token=input-secret&value=a%2Bb%26c&duplicate=one&duplicate=two"
        report = network.web_probe(f"http://127.0.0.1:{self.port}{request_path}")
        self.assertEqual(ProbeHandler.requests, [("HEAD", request_path, f"127.0.0.1:{self.port}")])
        serialized = json.dumps(report)
        for secret in ("input-secret", "a%2Bb%26c", "secret-user", "secret-password", "redirect-secret", "fragment-secret", "content-secret", "api-secret", "auth-secret"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, serialized)
        headers = {item["name"].lower(): item["value"] for item in report["headers"]}
        self.assertEqual(headers["location"], "https://example.invalid/next?[redacted]#[redacted]")
        self.assertEqual(headers["content-location"], "/resource?[redacted]")
        self.assertEqual(headers["x-api-key"], "[redacted]")
        self.assertEqual(headers["x-auth-token"], "[redacted]")
        self.assertTrue(report["url"].endswith("/privacy?[redacted]"))

    def test_malformed_and_relative_credential_urls_fail_closed_in_results(self):
        for value in ("https://[bad-host?token=private", "secret:password@example.invalid/resource?token=private"):
            with self.subTest(value=value):
                self.assertEqual(network._redact_result_url(value), "[redacted URL]")
        self.assertEqual(
            network._redact_result_url("//secret-user:secret-password@example.invalid/x?token=private"),
            "//example.invalid/x?[redacted]",
        )

    def test_mixed_dns_answer_with_multicast_fails_closed(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", self.port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("224.0.0.1", self.port)),
        ]
        with mock.patch.object(network.socket, "getaddrinfo", return_value=answers):
            with self.assertRaises(ValueError):
                network.web_probe(f"http://mixed.example:{self.port}/")
        self.assertEqual(ProbeHandler.requests, [])

    def test_head_not_allowed_does_not_trigger_get(self):
        report = network.web_probe(f"http://127.0.0.1:{self.port}/no-head")
        self.assertEqual(report["status"], 405)
        self.assertEqual(len(ProbeHandler.requests), 1)

    def test_header_observations_do_not_claim_vulnerability(self):
        report = network.web_probe(f"http://127.0.0.1:{self.port}/")
        observations = {item["header"]: item["state"] for item in report["security_headers"]}
        self.assertEqual(observations["X-Content-Type-Options"], "present")
        self.assertEqual(observations["Content-Security-Policy"], "not_observed")
        self.assertNotIn("Strict-Transport-Security", observations)
        self.assertIsNone(report["tls"])

    def test_cancelled_probe_sends_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
            network.web_probe(f"http://127.0.0.1:{self.port}/", cancel)
        self.assertEqual(ProbeHandler.requests, [])

    def test_tls_uses_default_verification_and_correct_sni(self):
        fake_answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", self.port))]
        context = mock.Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("untrusted certificate")
        with mock.patch.object(network.socket, "getaddrinfo", return_value=fake_answer):
            with mock.patch.object(network.ssl, "create_default_context", return_value=context) as factory:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    network.web_probe(f"https://secure.example:{self.port}/")
        factory.assert_called_once_with()
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "secure.example")
        self.assertEqual(ProbeHandler.requests, [])

    def test_dns_wait_is_bounded_and_expired_job_never_connects(self):
        gate = threading.Event()

        def slow_dns(*_args, **_kwargs):
            gate.wait(timeout=1)
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", self.port))]

        try:
            with mock.patch.object(network.socket, "getaddrinfo", side_effect=slow_dns):
                with mock.patch.object(network, "WEB_TIMEOUT", 0.05):
                    with self.assertRaises(TimeoutError):
                        network.web_probe(f"http://slow.example:{self.port}/")
        finally:
            gate.set()
        self.assertEqual(ProbeHandler.requests, [])

    def test_response_header_limit(self):
        peer = mock.Mock()
        peer.recv.return_value = b"x" * 4096
        with self.assertRaisesRegex(OSError, "64 KiB"):
            network._read_headers(peer, time.monotonic() + 1, None)

    def test_header_read_deadline(self):
        peer = mock.Mock()
        peer.recv.side_effect = socket.timeout
        with self.assertRaises(TimeoutError):
            network._read_headers(peer, time.monotonic() + 0.02, None)


if __name__ == "__main__":
    unittest.main()
