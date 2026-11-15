"""Task persistence, project boundaries and non-destructive migration checks."""

from concurrent.futures import ThreadPoolExecutor
from datetime import date
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from networkluki_cyberlab.storage import Store


class FixedDate(date):
    @classmethod
    def today(cls):
        return cls(2026, 11, 15)


class TaskTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "data"
        self.store = Store(self.directory)

    def legacy_database(self):
        legacy_directory = self.directory.parent / "legacy"
        legacy_directory.mkdir()
        with sqlite3.connect(legacy_directory / "results.sqlite3") as connection:
            connection.execute("CREATE TABLE results (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                               "project TEXT NOT NULL, module TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.execute("INSERT INTO results(project, module, created_at, payload) VALUES (?, ?, ?, ?)",
                               ("old lab", "web", "2026-11-14T12:00:00+00:00", json.dumps({"status": 200})))
        return legacy_directory

    def test_task_survives_restart_and_can_be_completed_then_reopened(self):
        source_id = self.store.add_result("lab", "system", {"host": "local"})
        task_id = self.store.add_task("lab", "Review disk space", "server", "2026-12-01", source_id)
        reopened = Store(self.directory)
        task = reopened.list_tasks("lab")[0]
        self.assertEqual(task["id"], task_id)
        self.assertEqual(task["title"], "Review disk space")
        self.assertEqual(task["category"], "server")
        self.assertEqual(task["due_date"], "2026-12-01")
        self.assertEqual(task["source_record_id"], source_id)
        self.assertEqual(task["status"], "open")
        self.assertTrue(task["created_at"].endswith("+00:00"))
        reopened.set_task_status("lab", task_id, "done")
        reopened.set_task_status("lab", task_id, "done")
        self.assertEqual(self.store.list_tasks("lab")[0]["status"], "done")
        reopened.set_task_status("lab", task_id, "open")
        self.assertEqual(self.store.list_tasks("lab")[0]["status"], "open")

    def test_old_results_only_database_is_migrated_without_losing_evidence(self):
        legacy_directory = self.legacy_database()
        migrated = Store(legacy_directory)
        backup = legacy_directory / "results.pre-workspace.sqlite3"
        backup_bytes = backup.read_bytes()
        if os.name == "posix":
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(backup) as connection:
            self.assertEqual(connection.execute("SELECT payload FROM results").fetchone()[0], json.dumps({"status": 200}))
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name = 'tasks'").fetchone())
        before = migrated.list_results("old lab")
        migrated.add_task("old lab", "Review saved response", source_record_id=before[0]["id"])
        self.assertEqual(Store(legacy_directory).list_results("old lab"), before)
        self.assertEqual(len(migrated.list_tasks("old lab")), 1)
        self.assertEqual(backup.read_bytes(), backup_bytes)
        self.assertEqual(list(legacy_directory.glob(".pre-workspace-*")), [])

    def test_fresh_database_does_not_create_migration_backup(self):
        self.assertFalse((self.directory / "results.pre-workspace.sqlite3").exists())
        Store(self.directory)
        self.assertFalse((self.directory / "results.pre-workspace.sqlite3").exists())

    def test_backup_includes_committed_wal_records(self):
        legacy_directory = self.legacy_database()
        writer = sqlite3.connect(legacy_directory / "results.sqlite3")
        try:
            writer.execute("PRAGMA journal_mode = WAL")
            writer.execute("INSERT INTO results(project, module, created_at, payload) VALUES (?, ?, ?, ?)",
                           ("old lab", "web", "2026-11-15T12:00:00+00:00", json.dumps({"status": 204})))
            writer.commit()
            self.assertTrue((legacy_directory / "results.sqlite3-wal").is_file())
            Store(legacy_directory)
            with sqlite3.connect(legacy_directory / "results.pre-workspace.sqlite3") as backup:
                payloads = [json.loads(row[0]) for row in backup.execute("SELECT payload FROM results ORDER BY id")]
                self.assertEqual(payloads, [{"status": 200}, {"status": 204}])
                self.assertIsNone(backup.execute("SELECT name FROM sqlite_master WHERE name = 'tasks'").fetchone())
        finally:
            writer.close()

    def test_failed_backup_publication_leaves_legacy_schema_and_records_unchanged(self):
        legacy_directory = self.legacy_database()
        with patch("networkluki_cyberlab.storage.os.link", side_effect=OSError("Backup storage unavailable")):
            with self.assertRaisesRegex(OSError, "Backup storage unavailable"):
                Store(legacy_directory)
        with sqlite3.connect(legacy_directory / "results.sqlite3") as connection:
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name = 'tasks'").fetchone())
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM results").fetchone()[0], 1)
        self.assertFalse((legacy_directory / "results.pre-workspace.sqlite3").exists())
        self.assertEqual(list(legacy_directory.glob(".pre-workspace-*")), [])

    def test_preexisting_reserved_backup_is_never_replaced(self):
        legacy_directory = self.legacy_database()
        backup = legacy_directory / "results.pre-workspace.sqlite3"
        backup.write_bytes(b"Existing backup to preserve")
        with self.assertRaises(FileExistsError):
            Store(legacy_directory)
        self.assertEqual(backup.read_bytes(), b"Existing backup to preserve")
        with sqlite3.connect(legacy_directory / "results.sqlite3") as connection:
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name = 'tasks'").fetchone())

    def test_symlinked_backup_is_rejected_without_following_it(self):
        legacy_directory = self.legacy_database()
        target = legacy_directory / "unrelated.txt"
        target.write_text("Keep me", encoding="utf-8")
        try:
            (legacy_directory / "results.pre-workspace.sqlite3").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable for this user/platform")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            Store(legacy_directory)
        self.assertEqual(target.read_text(encoding="utf-8"), "Keep me")

    def test_project_filter_and_updates_are_exact_and_parameterized(self):
        project = "lab'; DROP TABLE tasks; --"
        task_id = self.store.add_task(project, "Review configuration")
        self.store.add_task("other", "Independent task")
        self.assertEqual([t["id"] for t in self.store.list_tasks(project)], [task_id])
        with self.assertRaisesRegex(ValueError, "selected project"):
            self.store.set_task_status("other", task_id, "done")
        self.assertEqual(self.store.list_tasks(project)[0]["status"], "open")
        self.assertEqual(self.store.task_counts("other"), {"open": 1, "done": 0, "overdue": 0})

    def test_evidence_link_requires_an_existing_record_in_the_same_project(self):
        record = self.store.add_result("other", "web", {"status": 200})
        for source in (record, record + 1):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "selected project"):
                self.store.add_task("lab", "Review result", source_record_id=source)
        self.assertEqual(self.store.list_tasks("lab"), [])
        self.store.add_task("other", "Review result", source_record_id=record)

    def test_dates_counts_and_display_limit_use_all_tasks_in_project(self):
        with patch("networkluki_cyberlab.storage.date", FixedDate):
            self.assertEqual(self.store.task_counts("lab"), {"open": 0, "done": 0, "overdue": 0})
            self.store.add_task("lab", "Overdue", due_date="2026-11-14")
            self.store.add_task("lab", "Today", due_date="2026-11-15")
            self.store.add_task("lab", "Later", due_date="2026-11-16")
            self.store.add_task("lab", "No due date")
            completed = self.store.add_task("lab", "Finished", due_date="2026-11-01")
            self.store.set_task_status("lab", completed, "done")
            self.store.add_task("other", "Not counted", due_date="2026-11-01")
            self.assertEqual(len(self.store.list_tasks("lab", limit=1)), 1)
            self.assertEqual(self.store.task_counts("lab"), {"open": 4, "done": 1, "overdue": 1})

    def test_invalid_task_input_fails_without_inserting(self):
        invalid = [
            {"project": ""}, {"project": "a" * 101}, {"project": "bad\nproject"},
            {"title": ""}, {"title": "a" * 201}, {"title": "trailing\n"},
            {"title": "hidden\u202emark"}, {"title": 42},
            {"category": "admin"}, {"category": ["daily"]},
            {"due_date": "2026-02-29"}, {"due_date": "20261115"},
            {"due_date": "2026-W46-7"}, {"due_date": "2026-11-15T00:00:00"},
            {"due_date": ""}, {"due_date": True},
            {"source_record_id": True}, {"source_record_id": 0},
            {"source_record_id": -1}, {"source_record_id": "1"},
            {"source_record_id": 2**63},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.add_task(**({"project": "lab", "title": "Task"} | changes))
        self.assertEqual(self.store.list_tasks("lab"), [])
        self.store.add_task("lab", "Leap date", due_date="2028-02-29")

    def test_invalid_limits_statuses_and_ids_are_rejected(self):
        task_id = self.store.add_task("lab", "Task")
        for limit in (False, 0, -1, 1001, 1.5, "1"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.store.list_tasks("lab", limit=limit)
        for status in (None, "failed", "OPEN", ["done"]):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.store.set_task_status("lab", task_id, status)
        for identifier in (False, 0, -1, 2**63, "1"):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.store.set_task_status("lab", identifier, "done")
        with self.assertRaisesRegex(ValueError, "not found"):
            self.store.set_task_status("lab", task_id + 1, "done")

    def test_capacity_is_atomic_across_concurrent_writers_and_preserves_tasks(self):
        def add(index):
            try:
                return self.store.add_task("lab", f"Task {index}")
            except ValueError as error:
                return str(error)

        with patch("networkluki_cyberlab.storage.MAX_TASKS_PER_PROJECT", 1):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(add, (1, 2)))
            self.assertEqual(sum(isinstance(result, int) for result in results), 1)
            self.assertEqual(sum("at most 1 tasks" in str(result) for result in results), 1)
            task = self.store.list_tasks("lab")[0]
            self.store.set_task_status("lab", task["id"], "done")
            with self.assertRaisesRegex(ValueError, "at most"):
                self.store.add_task("lab", "No implicit deletion")
            self.store.add_task("other", "Separate project capacity")
            self.assertEqual(self.store.list_tasks("lab")[0]["id"], task["id"])


if __name__ == "__main__":
    unittest.main()
