import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from networkluki_cyberlab.storage import Store


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = Store(self.directory / "data")

    def test_project_is_parameterized_and_filter_is_exact(self):
        project = "lab'; DROP TABLE results; --"
        self.store.add_result(project, "network", {"open": [8080]})
        self.store.add_result("other", "files", {"name": "åäö"})
        records = self.store.list_results(project)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["result"], {"open": [8080]})
        self.assertEqual(len(self.store.list_results()), 2)

    def test_export_contains_record_and_replaces_complete_file(self):
        self.store.add_result("lab", "files", {"name": "åäö"})
        record = self.store.list_results()[0]
        path = self.directory / "report.json"
        path.write_text("previous export", encoding="utf-8")
        self.store.export_result(record, path)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["record"], record)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(list(self.directory.glob(".cyberlab-*")), [])

    def test_validation_and_database_overwrite_protection(self):
        for name in ("", "a\nb", "a" * 101):
            with self.assertRaises(ValueError):
                self.store.add_result(name, "files", {})
        with self.assertRaises(ValueError):
            self.store.export_result({}, self.store.path)
        with self.assertRaises(ValueError):
            self.store.add_result("lab", "files", {"invalid": float("nan")})
        with self.assertRaises(ValueError):
            self.store.list_results(limit=0)

    def test_export_cannot_replace_database_companions_or_evidence(self):
        for name in ("results.sqlite3-journal", "results.sqlite3-wal", "results.sqlite3-shm"):
            with self.assertRaises(ValueError):
                self.store.export_result({}, self.store.directory / name)
        source = self.directory / "evidence.bin"
        source.write_bytes(b"evidence")
        with self.assertRaises(ValueError):
            self.store.export_result({"result": {"source_path": str(source)}}, source)
        self.assertEqual(source.read_bytes(), b"evidence")

    def test_malformed_stored_data_rejected(self):
        self.store.add_result("lab", "files", {})
        for payload in ("[]", '{"value": NaN}', "X" * 100):
            connection = self.store._connect()
            try:
                with connection:
                    connection.execute("UPDATE results SET payload = ?", (payload,))
            finally:
                connection.close()
            with self.assertRaises(ValueError):
                self.store.list_results()

    def test_history_has_aggregate_limit(self):
        for i in range(10):
            self.store.add_result("lab", "files", {"index": i, "data": "a" * 50})
        with patch("networkluki_cyberlab.storage.MAX_HISTORY_BYTES", 200):
            records = self.store.list_results()
        self.assertGreater(len(records), 0)
        self.assertLess(len(records), 10)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_private_permissions(self):
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
