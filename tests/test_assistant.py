"""AI contract and transport tests without model downloads or real inference."""

import hashlib
import json
import threading
import time
import unittest
from unittest import mock

from networkluki_cyberlab import assistant


LOCAL_MODEL = {"details": {"format": "gguf"}, "model_info": {"general.architecture": "qwen2"}}
ANSWER = {"done": True, "message": {"role": "assistant", "content": "Check the cited line manually."}}


class FakeResponse:
    def __init__(self, payload=None, *, raw=None, status=200, headers=None):
        self.body = raw if raw is not None else json.dumps(payload).encode()
        self.status = status
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}
        self.offset = 0
        self.closed = False

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read1(self, size):
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class AssistantTests(unittest.TestCase):
    def test_success_retains_reviewed_evidence_but_never_promotes_it_to_findings(self):
        evidence = '{"rule": "PY002", "line": 7}'
        with mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, ANSWER]) as post:
            result = assistant.explain(evidence, "Förklara risken", "qwen2.5-coder:7b")
        self.assertEqual(result["evidence"], evidence)
        self.assertEqual(result["evidence_sha256"], hashlib.sha256(evidence.encode()).hexdigest())
        self.assertEqual(result["verification"], "unverified_ai_interpretation")
        self.assertNotIn("findings", result)
        self.assertEqual([call.args[0] for call in post.call_args_list], ["/api/show", "/api/chat"])
        self.assertNotIn(evidence, json.dumps(post.call_args_list[0].args[1]))
        payload = post.call_args_list[1].args[1]
        self.assertFalse(payload["stream"])
        self.assertNotIn("tools", payload)
        self.assertEqual(json.loads(payload["messages"][1]["content"]),
                         {"question": "Förklara risken", "evidence": evidence})
        self.assertEqual(payload["options"]["num_predict"], 1024)

    def test_validation_rejects_empty_oversized_and_bad_inputs_before_network(self):
        invalid = [
            ("", "question", "model"), (None, "question", "model"),
            ("å" * 32769, "question", "model"),
            ("evidence", "x" * 4097, "model"),
            ("evidence", "\ud800", "model"),
            ("evidence", "question", "http://evil.example/model"),
            ("evidence", "question", "model\r\nInjected"),
            ("evidence", "question", "model:cloud"),
            ("evidence", "question", "model-cloud"),
            ("evidence", "question", "x" * 129),
        ]
        for args in invalid:
            with self.subTest(args=str(args)[:60]), mock.patch.object(assistant, "_post_json") as post:
                with self.assertRaises(ValueError):
                    assistant.explain(*args)
                post.assert_not_called()

    def test_cancelled_operation_sends_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with mock.patch.object(assistant, "_post_json") as post:
            with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                assistant.explain("evidence", "question", "model", cancel=cancel)
            post.assert_not_called()

    def test_remote_or_missing_local_metadata_never_sends_evidence(self):
        cases = [
            {**LOCAL_MODEL, "remote_model": "upstream"},
            {**LOCAL_MODEL, "remote_host": "https://ollama.com"},
            {**LOCAL_MODEL, "remote_host": False},
            {}, {"details": {"format": "gguf"}, "model_info": {}},
            {"details": {"format": "unknown"}, "model_info": {"x": 1}},
        ]
        for metadata in cases:
            with self.subTest(metadata=metadata), mock.patch.object(assistant, "_post_json", return_value=metadata) as post:
                with self.assertRaises(ValueError):
                    assistant.explain("private evidence", "question", "local-alias")
                self.assertEqual(post.call_count, 1)
                self.assertEqual(post.call_args.args[0], "/api/show")

    def test_remote_response_warns_of_possible_disclosure(self):
        with mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, {**ANSWER, "remote_host": "https://upstream"}]):
            with self.assertRaisesRegex(ValueError, "Evidence may have reached a remote service"):
                assistant.explain("evidence", "question", "local-alias")

    def test_rejects_incomplete_empty_tool_and_oversized_answers(self):
        cases = [
            {**ANSWER, "done": False},
            {"done": True, "message": {"role": "assistant", "content": ""}},
            {"done": True, "message": {"role": "tool", "content": "text"}},
            {"done": True, "message": {"role": "assistant", "content": "text", "tool_calls": [{"function": {"name": "delete"}}]}},
            {"done": True, "message": {"role": "assistant", "content": "x" * 65537}},
        ]
        for answer in cases:
            with self.subTest(answer=str(answer)[:50]), mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, answer]):
                with self.assertRaises(ValueError):
                    assistant.explain("evidence", "question", "model")

    def test_stop_reason_and_known_answer_truncation_are_preserved(self):
        for reason, truncated in (("length", True), ("stop", False), ("future_reason", False)):
            response = {**ANSWER, "done_reason": reason}
            with self.subTest(reason=reason), mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, response]):
                result = assistant.explain("evidence", "question", "model")
            self.assertEqual(result["done_reason"], reason)
            self.assertEqual(result["answer_truncated"], truncated)
        with mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, ANSWER]):
            result = assistant.explain("evidence", "question", "model")
        self.assertEqual(result["done_reason"], "unknown")
        self.assertFalse(result["answer_truncated"])

    def test_invalid_stop_reason_is_rejected(self):
        for reason in (None, 1, False, [], "", "x" * 65, "stop\n", "stóp"):
            with self.subTest(reason=reason), mock.patch.object(assistant, "_post_json", side_effect=[LOCAL_MODEL, {**ANSWER, "done_reason": reason}]):
                with self.assertRaisesRegex(ValueError, "invalid stop reason"):
                    assistant.explain("evidence", "question", "model")


class TransportTests(unittest.TestCase):
    def post(self, response, *, cancel=None):
        connection = mock.MagicMock()
        connection.getresponse.return_value = response
        with mock.patch.object(assistant.http.client, "HTTPConnection", return_value=connection) as constructor:
            result = assistant._post_json("/api/show", {"model": "model"}, time.monotonic() + 3, cancel)
        return result, connection, constructor

    def test_fixed_address_and_explicit_body_no_proxy_or_redirect_handler(self):
        result, connection, constructor = self.post(FakeResponse(LOCAL_MODEL))
        self.assertEqual(result, LOCAL_MODEL)
        self.assertEqual(constructor.call_args.args, ("127.0.0.1", 11434))
        self.assertEqual(connection.request.call_args.args, ("POST", "/api/show"))
        self.assertEqual(json.loads(connection.request.call_args.kwargs["body"]), {"model": "model"})
        connection.close.assert_called_once()

    def test_redirect_and_http_errors_are_not_echoed_or_followed(self):
        for status in (301, 302, 307, 404, 500, 503):
            response = FakeResponse({"error": "secret prompt"}, status=status)
            with self.subTest(status=status), self.assertRaises(ValueError) as caught:
                self.post(response)
            self.assertNotIn("secret prompt", str(caught.exception))
            self.assertEqual(response.offset, 0)
            self.assertTrue(response.closed)

    def test_malformed_nonobject_duplicate_and_nonstandard_json_rejected(self):
        for raw in (b"bad", b"[]", b'{"x":NaN}', b'{"x":1,"x":2}', b"\xff", b'{"error":"secret"}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.post(FakeResponse(raw=raw))

    def test_content_headers_and_short_body_are_validated(self):
        cases = [
            {"Content-Type": "text/html"},
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            {"Content-Type": "application/json", "Content-Length": "99999999"},
            {"Content-Type": "application/json", "Content-Length": "-1"},
            {"Content-Type": "application/json", "Content-Length": "900"},
        ]
        for headers in cases:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                self.post(FakeResponse({}, headers=headers))

    def test_unannounced_oversized_body_is_bounded(self):
        response = FakeResponse(raw=b"x" * (assistant.MAX_RESPONSE_BYTES + 50000))
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            self.post(response)
        self.assertEqual(response.offset, assistant.MAX_RESPONSE_BYTES + 1)

    def test_deadline_and_cancel_are_checked_before_connect(self):
        with mock.patch.object(assistant.http.client, "HTTPConnection") as constructor:
            with self.assertRaises(TimeoutError):
                assistant._post_json("/api/show", {}, time.monotonic() - 1, None)
            event = threading.Event()
            event.set()
            with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                assistant._post_json("/api/show", {}, time.monotonic() + 5, event)
            with self.assertRaises(ValueError):
                assistant._post_json("https://evil.example/", {}, time.monotonic() + 5, None)
            constructor.assert_not_called()

    def test_cancellation_interrupts_waiting_for_headers(self):
        cancelled = threading.Event()
        shutdown = threading.Event()
        connection = mock.MagicMock()
        connection.sock.shutdown.side_effect = lambda _mode: shutdown.set()

        def waiting_response():
            cancelled.set()
            if not shutdown.wait(1):
                self.fail("Cancellation watchdog did not shut down the socket")
            raise OSError("socket interrupted")

        connection.getresponse.side_effect = waiting_response
        with mock.patch.object(assistant.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                assistant._post_json("/api/show", {}, time.monotonic() + 5, cancelled)
        connection.sock.shutdown.assert_called_once()
        connection.close.assert_called_once()

    def test_absolute_deadline_interrupts_waiting_for_headers(self):
        shutdown = threading.Event()
        connection = mock.MagicMock()
        connection.sock.shutdown.side_effect = lambda _mode: shutdown.set()

        def waiting_response():
            if not shutdown.wait(1):
                self.fail("Deadline watchdog did not shut down the socket")
            raise OSError("socket interrupted")

        connection.getresponse.side_effect = waiting_response
        with mock.patch.object(assistant.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaises(TimeoutError):
                assistant._post_json("/api/show", {}, time.monotonic() + 0.05, None)

    def test_cancellation_interrupts_stalled_body_and_watcher_exits(self):
        cancelled = threading.Event()
        shutdown = threading.Event()
        connection = mock.MagicMock()
        connection.sock.shutdown.side_effect = lambda _mode: shutdown.set()
        response = FakeResponse({})
        connection.getresponse.return_value = response

        def waiting_read(_size):
            cancelled.set()
            if not shutdown.wait(1):
                self.fail("Cancellation watchdog did not interrupt the response body")
            raise OSError("socket interrupted")

        response.read1 = mock.Mock(side_effect=waiting_read)
        thread_type = threading.Thread
        watchers = []

        def capture_watcher(*args, **kwargs):
            watcher = thread_type(*args, **kwargs)
            watchers.append(watcher)
            return watcher

        with mock.patch.object(assistant.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(assistant.threading, "Thread", side_effect=capture_watcher):
            with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                assistant._post_json("/api/show", {}, time.monotonic() + 5, cancelled)
        self.assertEqual(len(watchers), 1)
        self.assertFalse(watchers[0].is_alive())
        self.assertTrue(response.closed)
        connection.sock.shutdown.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
