"""Offscreen tests of the real worker, persistence and scope controls."""

import hashlib
import importlib.util
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
class GuiTests(unittest.TestCase):
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

    def test_real_hash_worker_persists_history_and_exports(self):
        source = self.root / "sample.bin"
        source.write_bytes(b"CyberLab test evidence\x00")
        self.window.start_file("forensics", str(source))
        self.assertFalse(self.window.project.isEnabled())
        self.wait_idle()
        record = self.window.last_records["forensics"]
        self.assertEqual(record["result"]["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(self.window.history.rowCount(), 1)
        self.assertTrue(self.window.project.isEnabled())
        self.assertIn(record["result"]["sha256"], self.window.result_views["forensics"].toPlainText())
        destination = self.root / "export.json"
        with patch("networkluki_cyberlab.ui.QFileDialog.getSaveFileName", return_value=(str(destination), "JSON (*.json)")):
            self.window.export_record(record)
        self.assertTrue(destination.exists())
        self.assertIn(record["result"]["sha256"], destination.read_text(encoding="utf-8"))

    def test_target_changes_reset_authorization_and_unapproved_job_is_blocked(self):
        self.window.network_authorized.setChecked(True)
        self.window.network_target.setText("127.0.0.2")
        self.assertFalse(self.window.network_authorized.isChecked())
        with patch("networkluki_cyberlab.ui.show_message"), patch.object(self.window, "_start") as start:
            self.window.start_network()
            start.assert_not_called()
        self.window.web_authorized.setChecked(True)
        self.window.web_url.setText("https://example.invalid/")
        self.assertFalse(self.window.web_authorized.isChecked())

    def test_history_is_scoped_to_selected_project(self):
        self.store.add_result("Local lab", "web", {"status": 200})
        self.store.add_result("Other", "web", {"status": 301})
        self.window.refresh_history()
        self.assertEqual(self.window.history.rowCount(), 1)
        self.window.project.setText("Other")
        self.window.refresh_history()
        self.window.history.selectRow(0)
        self.app.processEvents()
        self.assertEqual(self.window.history_record["result"]["status"], 301)

    def test_close_cancels_worker_without_saving_partial_result(self):
        def wait_for_cancel(cancel):
            cancel.wait(3)
            raise RuntimeError("Operation cancelled")

        self.window._start("forensics", wait_for_cancel, ())
        self.window.close()
        self.wait_idle()
        self.app.processEvents()
        self.assertFalse(self.window.isVisible())
        self.assertEqual(self.store.list_results(), [])


if __name__ == "__main__":
    unittest.main()
