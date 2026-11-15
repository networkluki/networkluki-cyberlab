"""Read-only operations tests using generated fixtures, never a remote machine."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from networkluki_cyberlab import operations


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def snapshot(self):
        return {"schema_version": 1, "source_kind": "local_snapshot",
                "captured_at": datetime.now(timezone.utc).isoformat(), "hostname": "lab-server", "os": "Linux",
                "cpu_count": 4, "load_1m": 4, "memory_total_bytes": 1000, "memory_available_bytes": 50,
                "disk_total_bytes": 1000, "disk_free_bytes": 100, "uptime_seconds": 100.5}

    def import_payload(self, payload):
        path = self.root / "snapshot.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return operations.import_system_snapshot(str(path))

    def test_snapshot_evidence_provenance_and_imported_conclusions(self):
        payload = self.snapshot()
        payload["observations"] = [{"summary": "Untrusted imported conclusion"}]
        result = self.import_payload(payload)
        self.assertEqual(result["source_kind"], "imported_snapshot")
        self.assertEqual(result["freshness"]["status"], "recent")
        self.assertEqual({item["code"] for item in result["observations"]},
                         {"disk_usage_high", "memory_available_low", "load_per_core_high"})
        self.assertNotIn("Untrusted imported conclusion", json.dumps(result))
        self.assertEqual(result["sha256"], hashlib.sha256((self.root / "snapshot.json").read_bytes()).hexdigest())
        self.assertIn("not independently verified", result["provenance"])

    def test_stale_future_and_missing_metrics_are_explicit(self):
        payload = self.snapshot()
        payload.update(dict.fromkeys(operations.METRICS))
        payload["captured_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        result = self.import_payload(payload)
        self.assertEqual(result["freshness"]["status"], "stale")
        self.assertEqual(result["observations"], [])
        payload["captured_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.assertEqual(self.import_payload(payload)["freshness"]["status"], "clock_ahead")

    def test_invalid_schema_metrics_and_timestamps_are_rejected(self):
        bad = (("schema_version", True), ("schema_version", 2), ("source_kind", "verified_remote"),
               ("cpu_count", False), ("cpu_count", 0), ("load_1m", float("nan")), ("load_1m", 10**400),
               ("disk_free_bytes", 2000), ("memory_total_bytes", 0), ("memory_available_bytes", None),
               ("uptime_seconds", -1), ("hostname", "host\nforged"), ("captured_at", "2026-01-01T00:00:00"))
        for key, value in bad:
            with self.subTest(field=key, value=str(value)[:30]):
                payload = self.snapshot(); payload[key] = value
                with self.assertRaises(ValueError):
                    self.import_payload(payload)

    def test_duplicate_and_deep_json_are_rejected(self):
        path = self.root / "bad.json"
        for data in ('{"schema_version":1,"schema_version":1}', '[' * 2000 + ']' * 2000):
            path.write_text(data)
            with self.assertRaises(ValueError):
                operations.import_system_snapshot(str(path))

    def test_log_lines_counts_bounds_and_untrusted_controls(self):
        path = self.root / "log.txt"
        content = 'normal\nERROR failed password for user\nWARNING \x1b[31m' + 'x' * 500 + '\n'
        path.write_text(content, encoding="utf-8")
        result = operations.analyze_log(str(path))
        self.assertEqual(result["line_count"], 3)
        self.assertEqual(result["matched_lines"], 2)
        self.assertEqual(result["counts"], {"error": 1, "warning": 1, "failed": 1, "authentication_failure": 1})
        self.assertEqual(result["samples"][0]["line"], 2)
        self.assertTrue(result["samples"][1]["truncated"])
        self.assertLessEqual(len(result["samples"][1]["evidence"]), 240)
        self.assertNotIn('\x1b', result["samples"][1]["evidence"])
        self.assertEqual(path.read_text(), content)
        path.write_text('ERROR\n' * 110)
        result = operations.analyze_log(str(path))
        self.assertEqual(len(result["samples"]), 100)
        self.assertEqual(result["samples_omitted"], 10)

    def test_log_empty_invalid_utf8_and_line_limit(self):
        path = self.root / "log.txt"; path.write_bytes(b'')
        self.assertEqual(operations.analyze_log(str(path))["line_count"], 0)
        for data in (b'\xff', b'\n' * (operations.MAX_LOG_LINES + 1)):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                operations.analyze_log(str(path))

    def test_read_limits_and_cancellation(self):
        path = self.root / "large"; path.write_bytes(b'x' * (operations.MAX_INPUT_BYTES + 1))
        cancel = threading.Event(); cancel.set()
        for method in (operations.import_system_snapshot, operations.analyze_log):
            with self.subTest(method=method.__name__):
                with self.assertRaises(ValueError): method(str(path))
                with self.assertRaisesRegex(RuntimeError, "cancelled"): method(str(path), cancel=cancel)
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            operations.collect_system_snapshot(cancel=cancel)

    def test_symlink_is_rejected(self):
        source = self.root / "source"; source.write_text("ERROR")
        link = self.root / "link"
        try: link.symlink_to(source)
        except (OSError, NotImplementedError): self.skipTest("Symlinks unavailable")
        with self.assertRaises(ValueError): operations.analyze_log(str(link))

    def test_local_snapshot_never_spawns_commands_and_unsupported_metrics_are_null(self):
        with patch("subprocess.run", side_effect=AssertionError("No subprocess allowed")), patch.object(operations.platform, "system", return_value="Windows"), patch.object(operations.os, "getloadavg", side_effect=OSError, create=True):
            result = operations.collect_system_snapshot()
        self.assertIsNone(result["load_1m"])
        self.assertIsNone(result["memory_total_bytes"])
        self.assertIsNone(result["uptime_seconds"])
        self.assertEqual(result["source_kind"], "local_snapshot")

    def test_collector_creates_private_file_and_refuses_overwrite(self):
        output = self.root / "collected.json"
        script = Path(__file__).resolve().parents[1] / "tools" / "collect_snapshot.py"
        command = [sys.executable, str(script), "--output", str(output)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        before = output.read_bytes()
        result = operations.import_system_snapshot(str(output))
        self.assertEqual(result["hostname"], operations.socket.gethostname())
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=30).returncode, 1)
        self.assertEqual(output.read_bytes(), before)
        if os.name == "posix": self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
