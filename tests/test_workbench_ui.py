"""Exercise the integrated evidence-to-AI flow without a live AI service."""

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
    from networkluki_cyberlab.ui import MainWindow


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

    def test_all_three_areas_share_navigation_and_original_footer(self):
        self.assertEqual(self.window.pages.count(), 9)
        self.assertEqual(self.window.navigation.item(5).text(), "History")
        for index, name in ((6, "Code review"), (7, "Utilities"), (8, "AI assistant")):
            self.assertEqual(self.window.navigation.item(index).text(), name)
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

    def test_selected_record_is_previewed_verbatim_without_sending(self):
        record = {"id": 12, "project": "Evidence project", "module": "code_review",
                  "result": {"source_sha256": "a" * 64, "findings": []}}
        self.window.ai_consent.setChecked(True)
        with patch.object(self.window, "_start") as start:
            self.window.prepare_assistant(record)
            start.assert_not_called()
        self.assertEqual(json.loads(self.window.ai_evidence.toPlainText()), record)
        self.assertFalse(self.window.ai_consent.isChecked())
        self.assertEqual(self.window.navigation.currentRow(), 8)

    def test_payload_and_model_edits_invalidate_ai_consent(self):
        for field, value in ((self.window.ai_model, "test:local"),
                             (self.window.ai_question, "Explain the warning.")):
            self.window.ai_consent.setChecked(True)
            field.setText(value)
            self.assertFalse(self.window.ai_consent.isChecked())
        self.window.ai_consent.setChecked(True)
        self.window.ai_evidence.setPlainText("Changed evidence")
        self.assertFalse(self.window.ai_consent.isChecked())

    def test_ai_is_blocked_without_consent_and_consumes_approval_once(self):
        with patch("networkluki_cyberlab.ui.show_message"), patch.object(self.window, "_start") as start:
            self.window.start_assistant()
            start.assert_not_called()
            self.window.ai_evidence.setPlainText("Selected evidence")
            self.window.ai_question.setText("Question")
            self.window.ai_model.setText("test:local")
            self.window.ai_consent.setChecked(True)
            self.window.start_assistant()
            self.assertEqual(start.call_args.args[0], "assistant")
            self.assertEqual(start.call_args.args[2], ("Selected evidence", "Question", "test:local"))
            self.assertFalse(self.window.ai_consent.isChecked())

    def test_json_result_to_ai_preserves_project_and_marks_interpretation(self):
        self.window.json_input.setPlainText('{"service":"apache","enabled":true}')
        self.window.start_json()
        self.wait_idle()
        record = self.window.last_records["utilities"]
        self.assertEqual(record["project"], "Local lab")
        self.assertEqual(json.loads(self.window.result_views["utilities"].toPlainText()),
                         {"service": "apache", "enabled": True})
        self.window.explain_buttons["utilities"].click()
        evidence = self.window.ai_evidence.toPlainText()
        self.assertEqual(json.loads(evidence)["id"], record["id"])
        self.window.ai_model.setText("test:local")
        self.window.ai_consent.setChecked(True)
        mocked_result = {"name": "AI explanation", "answer": "<script>untrusted()</script>",
                         "verification": "unverified_ai_interpretation", "evidence": evidence,
                         "answer_truncated": True, "done_reason": "length"}
        with patch("networkluki_cyberlab.ui.explain", return_value=mocked_result) as ai:
            self.window.start_assistant()
            self.wait_idle()
            self.assertEqual(ai.call_args.args[0], evidence)
        self.assertIn("Unverified AI interpretation", self.window.result_summaries["assistant"].text())
        self.assertIn("incomplete (generation limit)", self.window.result_summaries["assistant"].text())
        self.assertIn("INCOMPLETE: The generation limit was reached.",
                      self.window.result_views["assistant"].toPlainText())
        self.assertIn("<script>untrusted()</script>", self.window.result_views["assistant"].toPlainText())
        self.assertEqual(self.window.history.rowCount(), 2)
        self.assertEqual(self.window.last_records["assistant"]["result"]["verification"],
                         "unverified_ai_interpretation")
        self.assertNotIn("assistant", self.window.explain_buttons)

    def test_history_ai_transfer_is_explicit_and_disabled_for_ai_results(self):
        self.store.add_result("Local lab", "web", {"status": 200})
        self.window.refresh_history()
        self.window.navigation.setCurrentRow(5)
        self.window.history.selectRow(0)
        self.app.processEvents()
        selected = self.window.history_record
        self.assertTrue(self.window.history_explain.isEnabled())
        self.window.history_explain.click()
        self.assertEqual(json.loads(self.window.ai_evidence.toPlainText()), selected)
        self.assertFalse(self.window.ai_consent.isChecked())
        self.store.add_result("Local lab", "assistant", {"answer": "Unverified"})
        self.window.refresh_history()
        self.window.history.selectRow(0)
        self.app.processEvents()
        self.assertFalse(self.window.history_explain.isEnabled())

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
