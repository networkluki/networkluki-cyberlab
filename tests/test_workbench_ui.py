"""Exercise the merged Code review / Utilities flow with the 0.2.0 workspace AI page."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
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
class WorkbenchUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "data")
        self.window = MainWindow(self.store)
        self.window.show()
        self.app.processEvents()

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

    def test_combined_pages_append_without_moving_workspace_pages(self):
        self.assertEqual(self.window.pages.count(), 12)
        self.assertEqual(PAGE_NAMES[6:10], ("Daily tasks", "Servers", "Development", "AI assistant"))
        self.assertEqual(PAGE_NAMES[10:], ("Code review", "Utilities"))
        for index in (9, 10, 11):
            self.window.navigation.setCurrentRow(index)
            self.assertEqual(self.window.pages.currentIndex(), index)
        self.assertEqual(self.window.footer_author.text(), "Skapat av Luki Hackwell")
        self.assertEqual(self.window.footer_powered.text(), "Powered by networkluki.com")

    def test_review_uses_selected_source_without_changing_it(self):
        source = self.root / "review.py"
        original = "value = eval(user_input)\n"
        source.write_text(original, encoding="utf-8")
        self.window.code_path.setText(str(source))
        self.window.start_code_review()
        self.wait_idle()
        result = self.window.last_records["code_review"]["result"]
        self.assertTrue(result["findings"])
        self.assertIn("Review required", self.window.result_summaries["code_review"].text())
        self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_result_preview_to_ai_is_explicit_and_does_not_send(self):
        record = {"id": 12, "project": "Local lab", "module": "code_review",
                  "result": {"source_sha256": "a" * 64, "findings": []}}
        self.window.ai_consent.setChecked(True)
        with patch.object(self.window, "_start") as start:
            self.window.prepare_assistant(record)
            start.assert_not_called()
        self.assertEqual(json.loads(self.window.ai_evidence.toPlainText()), record)
        self.assertFalse(self.window.ai_consent.isChecked())
        self.assertEqual(self.window.navigation.currentRow(), 9)

    def test_ai_inputs_invalidate_consent(self):
        self.window.ai_model.addItems(["local-model:latest", "second-model:latest"])
        self.window.ai_question.setPlainText("Explain")
        self.window.ai_evidence.setPlainText("Evidence")
        for edit in (
            lambda: self.window.ai_evidence.setPlainText("Changed evidence"),
            lambda: self.window.ai_question.setPlainText("Changed question"),
            lambda: self.window.ai_model.setCurrentIndex(1),
            lambda: self.window.ai_endpoint.setText("http://127.0.0.1:11435"),
        ):
            self.window.ai_consent.setChecked(True)
            edit()
            self.assertFalse(self.window.ai_consent.isChecked())

    def test_ai_requires_consent_and_consumes_it_once(self):
        self.window.ai_model.addItem("local-model:latest")
        self.window.ai_question.setPlainText("Question")
        self.window.ai_evidence.setPlainText("Selected evidence")
        with patch("networkluki_cyberlab.ui.show_message"), patch.object(self.window, "_start") as start:
            self.window.start_ai_explanation()
            start.assert_not_called()
            self.window.ai_consent.setChecked(True)
            self.window.start_ai_explanation()
            self.assertEqual(start.call_args.args[0], "assistant")
            self.assertEqual(
                start.call_args.args[2],
                ("http://127.0.0.1:11434", "local-model:latest", "Question", "Selected evidence"),
            )
            self.assertFalse(self.window.ai_consent.isChecked())

    def test_json_result_can_be_previewed_for_ai(self):
        self.window.json_input.setPlainText('{"service":"apache","enabled":true}')
        self.window.start_json()
        self.wait_idle()
        record = self.window.last_records["utilities"]
        self.assertEqual(json.loads(self.window.result_views["utilities"].toPlainText()),
                         {"service": "apache", "enabled": True})
        self.window.explain_buttons["utilities"].click()
        self.assertEqual(json.loads(self.window.ai_evidence.toPlainText())["id"], record["id"])
        self.assertEqual(self.window.navigation.currentRow(), 9)

    def test_history_ai_transfer_is_disabled_for_ai_results(self):
        self.store.add_result("Local lab", "web", {"status": 200})
        self.window.refresh_history()
        self.window.history.selectRow(0)
        self.app.processEvents()
        self.assertTrue(self.window.history_ai.isEnabled())
        self.window.history_ai.click()
        self.assertEqual(self.window.navigation.currentRow(), 9)
        self.store.add_result("Local lab", "assistant", {"response": "Unverified"})
        self.window.refresh_history()
        self.window.history.selectRow(0)
        self.app.processEvents()
        self.assertFalse(self.window.history_ai.isEnabled())

    def test_diff_result_and_copy_preserve_actual_output(self):
        self.window.diff_before.setPlainText("before\n")
        self.window.diff_after.setPlainText("after\n")
        self.window.start_diff()
        self.wait_idle()
        output = self.window.last_records["utilities"]["result"]["diff"]
        self.assertIn("-before", output)
        self.assertIn("+after", output)
        self.window.copy_utility.click()
        self.assertEqual(QApplication.clipboard().text(), output)


if __name__ == "__main__":
    unittest.main()
