"""Offscreen integration checks for the unified workspace and explicit AI input."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QT_AVAILABLE = importlib.util.find_spec("PySide6") is not None
if QT_AVAILABLE:
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication
    from networkluki_cyberlab.storage import Store
    from networkluki_cyberlab.ui import MainWindow, PAGE_NAMES


@unittest.skipUnless(QT_AVAILABLE, "Install project dependencies for GUI tests")
class WorkspaceGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "data")
        with patch("networkluki_cyberlab.ui.ai.list_models") as lookup, patch("networkluki_cyberlab.ui.ai.explain_evidence") as explain:
            self.window = MainWindow(self.store)
            self.window.show()
            self.app.processEvents()
            lookup.assert_not_called()
            explain.assert_not_called()

    def tearDown(self):
        if self.window.worker is not None:
            self.window.cancel_job()
            self.wait_idle()
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.window = None
        self.temp.cleanup()

    def wait_idle(self):
        deadline = time.monotonic() + 5
        while self.window.worker is not None and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.005)
        self.assertIsNone(self.window.worker, "Worker did not finish")

    def select_result(self, module="web", result=None):
        record_id = self.store.add_result("Local lab", module, result or {"status": 503, "evidence": "Observed HTTP response"})
        self.window.refresh_history()
        self.window.history.selectRow(0)
        self.app.processEvents()
        self.assertEqual(self.window.history_record["id"], record_id)
        return self.window.history_record

    def test_all_workspaces_keep_original_indices_and_footer(self):
        self.assertEqual(self.window.pages.count(), 12)
        self.assertEqual(tuple(self.window.navigation.item(row).text() for row in range(12)), PAGE_NAMES)
        self.assertEqual(PAGE_NAMES[5], "History")
        self.assertEqual(PAGE_NAMES[6:10], ("Daily tasks", "Servers", "Development", "AI assistant"))
        self.assertEqual(PAGE_NAMES[10:], ("Code review", "Utilities"))
        self.assertEqual(self.window.footer_author.text(), "Skapat av Luki Hackwell")
        self.assertEqual(self.window.footer_powered.text(), "Powered by networkluki.com")
        self.assertIsNone(self.window.worker)
        self.assertEqual(self.store.list_results(), [])

    def test_tasks_persist_and_complete_without_crossing_projects(self):
        self.window.task_title.setText("Review backup report")
        self.window.task_category.setCurrentIndex(1)
        self.window.add_task()
        tasks = Store(self.store.directory).list_tasks("Local lab")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["category"], "server")
        self.window.tasks.selectRow(0)
        self.app.processEvents()
        self.window.toggle_task()
        self.assertEqual(self.store.list_tasks("Local lab")[0]["status"], "done")
        self.window.tasks.selectRow(0)
        self.app.processEvents()
        self.window.toggle_task()
        self.assertEqual(self.store.list_tasks("Local lab")[0]["status"], "open")
        self.window.project.setText("Other project")
        self.assertEqual(self.window.tasks.rowCount(), 0)
        self.assertIsNone(self.window.task_record)
        self.assertFalse(self.window.task_toggle.isEnabled())
        self.assertEqual(self.store.list_tasks("Local lab")[0]["status"], "open")

    def test_selected_evidence_is_copied_only_on_request_and_links_review_task(self):
        record = self.select_result()
        self.assertEqual(self.window.ai_evidence.toPlainText(), "")
        with patch("networkluki_cyberlab.ui.ai.explain_evidence") as explain:
            self.window.use_history_in_ai()
            self.assertEqual(json.loads(self.window.ai_evidence.toPlainText()), record)
            self.assertEqual(self.window.navigation.currentRow(), 9)
            self.assertFalse(self.window.ai_consent.isChecked())
            explain.assert_not_called()
        self.window.create_review_task()
        task = self.store.list_tasks("Local lab")[0]
        self.assertEqual(task["source_record_id"], record["id"])
        self.assertEqual(task["category"], "server")
        self.assertEqual(task["status"], "open")
        self.assertEqual(self.window.navigation.currentRow(), 6)

    def test_project_change_clears_evidence_results_inputs_and_consent(self):
        record = self.select_result()
        self.window.use_history_in_ai()
        self.window.last_records["web"] = record
        self.window.result_views["web"].setPlainText("Sensitive first-project observation")
        self.window.snapshot_path.setText("first-project.json")
        self.window.source_path.setText("first-project.py")
        self.window.task_title.setText("First-project draft")
        self.window.ai_consent.setChecked(True)
        self.window.project.setText("Other project")
        self.assertEqual(self.window.ai_evidence.toPlainText(), "")
        self.assertEqual(self.window.ai_question.toPlainText(), "")
        self.assertEqual(self.window.task_title.text(), "")
        self.assertEqual(self.window.snapshot_path.text(), "")
        self.assertEqual(self.window.source_path.text(), "")
        self.assertFalse(self.window.ai_consent.isChecked())
        self.assertEqual(self.window.last_records, {})
        self.assertTrue(all(not view.toPlainText() for view in self.window.result_views.values()))
        self.assertIsNone(self.window.history_record)
        self.assertEqual(self.window.history.rowCount(), 0)
        self.assertEqual(self.store.list_results("Local lab")[0]["id"], record["id"])

    def test_ai_requires_consent_and_edits_invalidate_it(self):
        self.window.ai_model.addItems(["local-model:latest", "second-model:latest"])
        self.window.ai_question.setPlainText("Explain this observation")
        self.window.ai_evidence.setPlainText("metric: 95")
        with patch("networkluki_cyberlab.ui.show_message"), patch.object(self.window, "_start") as start:
            self.window.start_ai_explanation()
            start.assert_not_called()
        for edit in (lambda: self.window.ai_evidence.setPlainText("metric: 96"),
                     lambda: self.window.ai_question.setPlainText("Explain the updated metric"),
                     lambda: self.window.ai_model.setCurrentIndex(1),
                     lambda: self.window.ai_endpoint.setText("http://127.0.0.1:11435")):
            self.window.ai_consent.setChecked(True)
            edit()
            self.assertFalse(self.window.ai_consent.isChecked())
        self.assertEqual(self.window.ai_model.count(), 0)

    def test_explicit_ai_worker_saves_unverified_plain_text_not_model_inventory(self):
        with patch("networkluki_cyberlab.ui.ai.list_models", return_value={"models": ["local-model:latest"]}) as models:
            self.window.load_ai_models()
            self.wait_idle()
            models.assert_called_once()
        self.assertEqual(self.store.list_results(), [])
        self.window.ai_question.setPlainText("Explain this observation")
        self.window.ai_evidence.setPlainText("evidence_key: sample")
        self.window.ai_consent.setChecked(True)
        response = {"response": "<b>Unverified explanation</b>", "model": "local-model:latest", "verification": "unverified_ai", "input_sha256": "test-fixture"}
        with patch("networkluki_cyberlab.ui.ai.explain_evidence", return_value=response) as explain:
            self.window.start_ai_explanation()
            self.wait_idle()
            self.assertEqual(explain.call_args.args, ("http://127.0.0.1:11434", "local-model:latest", "Explain this observation", "evidence_key: sample"))
        self.assertFalse(self.window.ai_consent.isChecked())
        self.assertEqual(self.window.result_views["assistant"].toPlainText(), "<b>Unverified explanation</b>")
        self.assertIn("Unverified AI draft", self.window.result_summaries["assistant"].text())
        record = self.store.list_results("Local lab")[0]
        self.assertEqual(record["module"], "assistant")
        self.assertEqual(record["result"]["verification"], "unverified_ai")

    def test_server_snapshot_and_source_review_use_real_workers(self):
        self.window.start_system_snapshot()
        self.wait_idle()
        self.assertEqual(self.window.last_records["system"]["result"]["schema_version"], 1)
        path = self.root / "sample.py"
        path.write_text("answer = eval(user_input)\n", encoding="utf-8")
        self.window.source_path.setText(str(path))
        self.window.start_source_review()
        self.wait_idle()
        self.assertIn("source", self.window.last_records)
        self.assertEqual({record["module"] for record in self.store.list_results("Local lab")}, {"system", "source"})

    def test_late_worker_result_is_not_displayed_in_a_changed_project(self):
        released = threading.Event()

        def delayed(cancel):
            released.wait(2)
            return {"response": "Original-project draft", "verification": "unverified_ai"}

        self.window._start("assistant", delayed, ())
        self.window.project.setText("Other project")
        released.set()
        self.wait_idle()
        self.assertEqual(self.window.result_views["assistant"].toPlainText(), "")
        self.assertEqual(self.window.last_records, {})
        self.assertEqual(self.store.list_results("Other project"), [])
        self.assertEqual(self.store.list_results("Local lab")[0]["result"]["response"], "Original-project draft")


if __name__ == "__main__":
    unittest.main()
