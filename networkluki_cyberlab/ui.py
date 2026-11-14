"""Unprivileged desktop interface for the CyberLab research workbench."""

from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QCloseEvent, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from .forensics import analyze_file, inspect_binary
from .network import tcp_scan, web_probe
from .storage import Store
from . import __version__

LOGGER = logging.getLogger(__name__)
MODULE_NAMES = {
    "network": "Network", "web": "Web & TLS", "forensics": "File forensics",
    "binary": "Binary analysis",
}

STYLESHEET = """
QWidget { background: #0b1220; color: #dae5f2; font-size: 13px; }
QMainWindow { background: #0b1220; }
QFrame#sidebar { background: #101b2b; border-right: 1px solid #203148; }
QFrame#sidebar QLabel { background: transparent; }
QFrame#header { border-bottom: 1px solid #203148; }
QFrame#card { background: #111e30; border: 1px solid #263a52; border-radius: 12px; }
QFrame#card QLabel, QFrame#card QCheckBox { background: transparent; }
QLabel#wordmark { font-size: 19px; font-weight: 700; color: #f1f7ff; }
QLabel#logo { background: #173f48; color: #64e1cf; border: 1px solid #2d756e;
              border-radius: 12px; font-size: 21px; font-weight: 700; }
QLabel#muted { color: #93a8bf; }
QLabel#eyebrow { color: #65dcca; font-size: 11px; font-weight: 700; }
QLabel#title { font-size: 28px; font-weight: 700; color: #f1f7ff; }
QLabel#section { font-size: 16px; font-weight: 600; color: #eef5fd; }
QLabel#stat { font-size: 34px; font-weight: 700; color: #63decb; }
QLabel#status { color: #71dfca; background: #14332f; border-radius: 8px; padding: 7px 12px; }
QLabel#footer { color: #8398b0; font-size: 11px; }
QListWidget#navigation { background: transparent; border: none; outline: none; }
QListWidget#navigation::item { padding: 14px 12px; margin: 3px 0; border-radius: 7px;
                              color: #a8bbcf; }
QListWidget#navigation::item:selected { background: #173849; color: #87f2de; }
QListWidget#navigation::item:hover { background: #192b40; }
QLineEdit, QPlainTextEdit { background: #0b1625; border: 1px solid #30445d;
                          border-radius: 7px; padding: 9px; selection-background-color: #245b6e; }
QLineEdit:focus, QPlainTextEdit:focus { border: 1px solid #55cdbb; }
QLineEdit:disabled { color: #7c8da2; }
QPushButton { background: #1b3046; border: 1px solid #344c66; border-radius: 7px;
              padding: 10px 15px; color: #e4edf7; font-weight: 600; }
QPushButton:hover { background: #27435d; border-color: #4e728e; }
QPushButton:pressed { background: #15273a; }
QPushButton#primary { background: #60d9c3; border-color: #60d9c3; color: #071b21; }
QPushButton#primary:hover { background: #8ae8d7; border-color: #8ae8d7; }
QPushButton:disabled, QPushButton#primary:disabled { background: #17283b;
                                                  border-color: #26394e; color: #6e839b; }
QCheckBox { spacing: 9px; padding: 6px 0; }
QCheckBox::indicator { width: 17px; height: 17px; border: 1px solid #526b83;
                      background: #0d1827; border-radius: 4px; }
QCheckBox::indicator:checked { background: #5bd4be; border: 3px solid #285e5a; }
QTableWidget { background: #0d1928; alternate-background-color: #111f30;
               border: 1px solid #2a3d54; border-radius: 7px;
               gridline-color: #20334a; selection-background-color: #214456; }
QHeaderView::section { background: #17283b; color: #b6c9dc; border: none;
                       border-bottom: 1px solid #2d435d; padding: 9px; text-align: left; }
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical { background: #0c1727; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #314b65; border-radius: 4px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QSplitter::handle { background: #20344a; height: 2px; }
QToolTip { color: #edf7ff; background: #24394f; border: 1px solid #50708b; }
"""


def label(text: str, name: str | None = None, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(wrap)
    if name:
        widget.setObjectName(name)
    return widget


def card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(20, 18, 20, 18)
    layout.setSpacing(12)
    return frame, layout


def show_message(parent: QWidget | None, title: str, text: str,
            icon: QMessageBox.Icon = QMessageBox.Icon.Warning) -> None:
    dialog = QMessageBox(parent)
    dialog.setWindowTitle(title)
    dialog.setIcon(icon)
    dialog.setTextFormat(Qt.TextFormat.PlainText)
    dialog.setText(text)
    dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
    dialog.exec()


def scrollable(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(widget)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    return area


class Job(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, function: Callable, arguments: tuple, parent=None):
        super().__init__(parent)
        self.function = function
        self.arguments = arguments
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            result = self.function(*self.arguments, cancel=self.cancel_event)
            if self.cancel_event.is_set():
                self.failed.emit("Operation cancelled")
            else:
                self.succeeded.emit(result)
        except Exception as exc:
            LOGGER.warning("Analysis did not complete: %s", exc)
            self.failed.emit(str(exc) or type(exc).__name__)


class MainWindow(QMainWindow):
    """Single-job UI; every database access occurs on the main thread."""

    def __init__(self, store: Store | None = None):
        super().__init__()
        self.store = store if store is not None else Store()
        self.worker: Job | None = None
        self.active_module = ""
        self.active_project = ""
        self.close_pending = False
        self.last_records: dict[str, dict] = {}
        self.result_views: dict[str, QPlainTextEdit] = {}
        self.result_summaries: dict[str, QLabel] = {}
        self.export_buttons: dict[str, QPushButton] = {}
        self.run_buttons: list[QPushButton] = []
        self.input_widgets: list[QWidget] = []
        self.history_record: dict | None = None
        self.setWindowTitle(f"NetworkLuki CyberLab · v{__version__} MVP")
        self.resize(1240, 850)
        self.setMinimumSize(960, 700)
        self.setStyleSheet(STYLESHEET)
        self._build_layout()
        self.refresh_history()

    def _build_layout(self) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 28, 20, 20)
        brand = label("NL", "logo")
        brand.setFixedSize(49, 49)
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side.addWidget(brand)
        side.addSpacing(13)
        side.addWidget(label("NetworkLuki", "wordmark"))
        side.addWidget(label("CYBERLAB", "eyebrow"))
        side.addSpacing(24)
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        for name in ("Overview", "Network", "Web & TLS", "File forensics", "Binary analysis", "History"):
            self.navigation.addItem(QListWidgetItem(name))
        self.navigation.currentRowChanged.connect(self._navigate)
        side.addWidget(self.navigation, 1)
        side.addWidget(label(f"v{__version__}  ·  MVP", "eyebrow"))
        side.addWidget(label("Local results\nNo administrator privileges required", "footer", True))
        outer.addWidget(sidebar)

        body = QVBoxLayout()
        body.setSpacing(0)
        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(28, 18, 28, 18)
        header_layout.addWidget(label("PROJECT", "eyebrow"))
        self.project = QLineEdit("Local lab")
        self.project.setMaxLength(100)
        self.project.setFixedWidth(240)
        self.project.setAccessibleName("Project name")
        self.project.editingFinished.connect(self.refresh_history)
        header_layout.addWidget(self.project)
        header_layout.addStretch()
        self.status = label("Ready", "status")
        header_layout.addWidget(self.status)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_job)
        header_layout.addWidget(self.cancel_button)
        body.addWidget(header)

        self.pages = QStackedWidget()
        self.pages.addWidget(scrollable(self._overview_page()))
        self.pages.addWidget(scrollable(self._network_page()))
        self.pages.addWidget(scrollable(self._web_page()))
        self.pages.addWidget(scrollable(self._file_page(False)))
        self.pages.addWidget(scrollable(self._file_page(True)))
        self.pages.addWidget(scrollable(self._history_page()))
        body.addWidget(self.pages, 1)
        footer = QWidget()
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(28, 12, 20, 15)
        self.footer_author = label("Skapat av Luki Hackwell", "footer")
        self.footer_powered = label("Powered by networkluki.com", "footer")
        self.footer_powered.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        footer_layout.addWidget(self.footer_author)
        footer_layout.addStretch(1)
        footer_layout.addWidget(self.footer_powered)
        body.addWidget(footer)
        outer.addLayout(body, 1)
        self.setCentralWidget(root)
        self.navigation.setCurrentRow(0)

    def _page(self, eyebrow: str, title: str, description: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 25, 28, 18)
        layout.setSpacing(15)
        layout.addWidget(label(eyebrow, "eyebrow"))
        layout.addWidget(label(title, "title"))
        layout.addWidget(label(description, "muted", True))
        return page, layout

    def _overview_page(self) -> QWidget:
        page, layout = self._page(
            "SECURITY RESEARCH WORKBENCH", "Inspect. Document. Verify.",
            "One workspace for scoped network checks, file forensics and static binary analysis.",
        )
        stats = QHBoxLayout()
        self.stat_results = label("0", "stat")
        self.stat_network = label("0", "stat")
        self.stat_files = label("0", "stat")
        for value, caption in ((self.stat_results, "Project results shown"),
                               (self.stat_network, "Network and web results"),
                               (self.stat_files, "File and binary results")):
            frame, content = card()
            content.addWidget(value)
            content.addWidget(label(caption, "muted", True))
            stats.addWidget(frame)
        layout.addLayout(stats)
        layout.addWidget(label("Tools in this release", "section"))
        grid = QGridLayout()
        grid.setSpacing(13)
        tools = (
            ("01  /  NETWORK", "TCP connect", "Check selected ports on an explicitly specified IP address.", 1),
            ("02  /  WEB", "HTTP/TLS HEAD", "Read response headers and TLS details from a selected target.", 2),
            ("03  /  FORENSICS", "SHA-256 / SHA-512", "Calculate file hashes and record basic file information.", 3),
            ("04  /  BINARY ANALYSIS", "Strings / hex", "Inspect signatures, strings and hex without running the file.", 4),
        )
        for index, (eyebrow, title, description, destination) in enumerate(tools):
            frame, content = card()
            content.addWidget(label(eyebrow, "eyebrow"))
            content.addWidget(label(title, "section"))
            content.addWidget(label(description, "muted", True))
            button = QPushButton("Open tool")
            button.clicked.connect(lambda checked=False, row=destination: self.navigation.setCurrentRow(row))
            content.addWidget(button)
            grid.addWidget(frame, index // 2, index % 2)
        layout.addLayout(grid)
        layout.addWidget(label("MVP · Observations support further analysis; they do not certify that a system is secure.", "muted", True))
        layout.addStretch()
        return page

    def _network_page(self) -> QWidget:
        page, layout = self._page("NETWORK / TCP", "Network check",
                                  "One IP address and up to 128 ports per run. No automatic target discovery.")
        frame, content = card()
        row = QHBoxLayout()
        target_column = QVBoxLayout()
        target_column.addWidget(label("Target · IPv4 or IPv6", "muted"))
        self.network_target = QLineEdit("127.0.0.1")
        self.network_target.setMaxLength(64)
        target_column.addWidget(self.network_target)
        ports_column = QVBoxLayout()
        ports_column.addWidget(label("TCP ports · comma-separated or ranges", "muted"))
        self.network_ports = QLineEdit("22,80,443,8080,8443")
        self.network_ports.setMaxLength(1500)
        ports_column.addWidget(self.network_ports)
        row.addLayout(target_column)
        row.addLayout(ports_column, 2)
        content.addLayout(row)
        self.network_authorized = QCheckBox("I am authorized to check the specified IP address and ports.")
        self.network_target.textChanged.connect(lambda: self.network_authorized.setChecked(False))
        self.network_ports.textChanged.connect(lambda: self.network_authorized.setChecked(False))
        content.addWidget(self.network_authorized)
        button = self._run_button("Check TCP ports", self.start_network)
        content.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("network", layout)
        return page

    def _web_page(self) -> QWidget:
        page, layout = self._page("WEB / HTTP / TLS", "Web & TLS",
                                  "One HEAD request to the selected URL. Redirects are not followed and TLS certificates are verified.")
        frame, content = card()
        content.addWidget(label("URL · http:// or https://", "muted"))
        self.web_url = QLineEdit()
        self.web_url.setMaxLength(2048)
        self.web_url.setPlaceholderText("https://your-test-environment.example/")
        content.addWidget(self.web_url)
        self.web_authorized = QCheckBox("I am authorized to check the specified web target.")
        self.web_url.textChanged.connect(lambda: self.web_authorized.setChecked(False))
        content.addWidget(self.web_authorized)
        content.addWidget(self._run_button("Inspect HTTP and TLS", self.start_web), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("web", layout)
        return page

    def _file_page(self, binary: bool) -> QWidget:
        module = "binary" if binary else "forensics"
        page, layout = self._page(
            "STATIC / READ ONLY" if binary else "EVIDENCE / READ ONLY",
            "Static binary analysis" if binary else "File forensics",
            "View the file signature, ASCII strings and hex. The file is never executed. This is not a disassembler."
            if binary else "Calculate SHA-256 and SHA-512 in a single read. The source file content is not modified.",
        )
        frame, content = card()
        content.addWidget(label("Local file", "muted"))
        row = QHBoxLayout()
        field = QLineEdit()
        field.setReadOnly(True)
        field.setPlaceholderText("Select a regular file to inspect…")
        button = QPushButton("Choose file…")
        button.clicked.connect(lambda: self.choose_file(field))
        row.addWidget(field, 1)
        row.addWidget(button)
        content.addLayout(row)
        content.addWidget(label(
            "Reads up to 4 MiB. Displays a limited set of strings and a short hex preview."
            if binary else "Up to 2 GiB per file in this release. Files changed during inspection cannot produce a stable result.",
            "muted", True,
        ))
        content.addWidget(self._run_button(
            "Inspect binary file" if binary else "Calculate file hashes",
            lambda: self.start_file(module, field.text()),
        ), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area(module, layout)
        return page

    def _run_button(self, text: str, callback: Callable) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("primary")
        button.clicked.connect(callback)
        self.run_buttons.append(button)
        return button

    def _result_area(self, module: str, layout: QVBoxLayout) -> None:
        row = QHBoxLayout()
        row.addWidget(label("Results", "section"))
        row.addStretch()
        export = QPushButton("Export JSON")
        export.setEnabled(False)
        export.clicked.connect(lambda: self.export_record(self.last_records.get(module)))
        self.export_buttons[module] = export
        row.addWidget(export)
        layout.addLayout(row)
        layout.addWidget(label("Exports may contain sensitive file paths, strings and network details.", "muted", True))
        summary = label("No analysis has been run yet.", "muted", True)
        self.result_summaries[module] = summary
        layout.addWidget(summary)
        result = QPlainTextEdit()
        result.setReadOnly(True)
        result.setFont(QFont("monospace", 10))
        result.setPlaceholderText("Verifiable observations appear here after a run.")
        result.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        result.setMinimumHeight(140)
        self.result_views[module] = result
        layout.addWidget(result, 1)

    def _history_page(self) -> QWidget:
        page, layout = self._page("PROJECT / EVIDENCE", "History",
                                  "The latest 200 saved results for the selected project. Exports may contain sensitive file paths, strings and network details.")
        toolbar = QHBoxLayout()
        self.history_count = label("0 results", "muted")
        toolbar.addWidget(self.history_count)
        toolbar.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_history)
        toolbar.addWidget(refresh)
        self.history_export = QPushButton("Export JSON")
        self.history_export.setEnabled(False)
        self.history_export.clicked.connect(lambda: self.export_record(self.history_record))
        toolbar.addWidget(self.history_export)
        layout.addLayout(toolbar)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.history = QTableWidget(0, 4)
        self.history.setHorizontalHeaderLabels(["Time (UTC)", "Module", "Target / file", "ID"])
        self.history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history.setAlternatingRowColors(True)
        self.history.verticalHeader().setVisible(False)
        self.history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.history.itemSelectionChanged.connect(self._select_history)
        splitter.addWidget(self.history)
        self.history_preview = QPlainTextEdit()
        self.history_preview.setReadOnly(True)
        self.history_preview.setFont(QFont("monospace", 10))
        self.history_preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.history_preview.setPlaceholderText("Select a saved result above.")
        splitter.addWidget(self.history_preview)
        splitter.setSizes([250, 300])
        layout.addWidget(splitter, 1)
        return page

    def _navigate(self, index: int) -> None:
        if hasattr(self, "pages") and index >= 0:
            self.pages.setCurrentIndex(index)
            if index in (0, 5):
                self.refresh_history()

    def choose_file(self, field: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file for read-only analysis")
        if path:
            field.setText(path)

    def start_network(self) -> None:
        if not self.network_authorized.isChecked():
            show_message(self, "Confirm target", "Confirm that you are authorized to check the selected IP address and ports.")
            return
        self._start("network", tcp_scan, (self.network_target.text().strip(), self.network_ports.text().strip()))

    def start_web(self) -> None:
        if not self.web_authorized.isChecked():
            show_message(self, "Confirm target", "Confirm that you are authorized to check the specified web target.")
            return
        self._start("web", web_probe, (self.web_url.text().strip(),))

    def start_file(self, module: str, path: str) -> None:
        if not path:
            show_message(self, "Choose a file", "Choose a local file before starting the analysis.", QMessageBox.Icon.Information)
            return
        self._start(module, inspect_binary if module == "binary" else analyze_file, (path,))

    def _start(self, module: str, function: Callable, arguments: tuple) -> None:
        if self.worker is not None:
            return
        project = self.project.text().strip()
        if not project:
            show_message(self, "Project name required", "Enter a project name before starting the analysis.")
            self.project.setFocus()
            return
        self.active_module = module
        self.active_project = project
        self.project.setText(project)
        self.result_summaries[module].setText("Analysis in progress…")
        self.result_views[module].clear()
        self.last_records.pop(module, None)
        self.export_buttons[module].setEnabled(False)
        self._set_busy(True)
        self.worker = Job(function, arguments, self)
        self.worker.succeeded.connect(self._completed)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def _set_busy(self, busy: bool) -> None:
        self.project.setEnabled(not busy)
        for widget in self.input_widgets:
            widget.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.status.setText("Working…" if busy else "Ready")

    def cancel_job(self) -> None:
        if self.worker is not None:
            self.worker.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status.setText("Cancelling…")

    def _completed(self, result: dict) -> None:
        module = self.active_module
        record = {"project": self.active_project, "module": module, "result": result}
        saved = False
        try:
            record_id = self.store.add_result(self.active_project, module, result)
            record = next((item for item in self.store.list_results(self.active_project)
                           if item["id"] == record_id), {**record, "id": record_id})
            saved = True
        except Exception as exc:
            LOGGER.exception("Could not save analysis")
            show_message(self, "Could not save the result", str(exc))
        self.last_records[module] = record
        self.result_views[module].setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
        self.result_summaries[module].setText(
            f"Complete · saved to project {self.active_project}." if saved
            else "Complete · this result is only available in this window. Export it to keep a copy."
        )
        self.export_buttons[module].setEnabled(True)
        self.refresh_history()

    def _failed(self, message: str) -> None:
        cancelled = bool(self.worker and self.worker.cancel_event.is_set()) or message == "Operation cancelled"
        self.result_summaries[self.active_module].setText("Cancelled · no result was saved." if cancelled else "The analysis could not be completed.")
        self.result_views[self.active_module].setPlainText("Operation cancelled" if cancelled else message)
        if not cancelled and not self.close_pending:
            show_message(self, "Could not complete the analysis", message)

    def _finished(self) -> None:
        worker = self.worker
        self.worker = None
        if worker is not None:
            worker.deleteLater()
        self._set_busy(False)
        if self.close_pending:
            self.close()

    def refresh_history(self) -> None:
        if not hasattr(self, "history"):
            return
        try:
            records = self.store.list_results(self.project.text().strip(), limit=200)
        except Exception as exc:
            LOGGER.exception("Could not read history")
            self.status.setText("Read error")
            self.history_count.setText(f"Could not read history: {exc}")
            return
        self.history_record = None
        self.history_export.setEnabled(False)
        self.history_preview.clear()
        self.history.blockSignals(True)
        self.history.setRowCount(len(records))
        for row, record in enumerate(records):
            result = record.get("result", {})
            target = result.get("target") or result.get("url") or result.get("source_path") or result.get("path") or result.get("name") or "—"
            values = [str(record.get("created_at", "")), MODULE_NAMES.get(record.get("module", ""), str(record.get("module", ""))), str(target), str(record.get("id", ""))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record)
                self.history.setItem(row, column, item)
        self.history.blockSignals(False)
        self.history_count.setText(f"{len(records)} results · {self.project.text().strip() or 'no project'}")
        self.stat_results.setText(str(len(records)))
        self.stat_network.setText(str(sum(item.get("module") in ("network", "web") for item in records)))
        self.stat_files.setText(str(sum(item.get("module") in ("forensics", "binary") for item in records)))

    def _select_history(self) -> None:
        row = self.history.currentRow()
        item = self.history.item(row, 0) if row >= 0 else None
        self.history_record = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.history_export.setEnabled(self.history_record is not None)
        self.history_preview.setPlainText(json.dumps(self.history_record, ensure_ascii=False, indent=2) if self.history_record else "")

    def export_record(self, record: dict | None) -> None:
        if record is None:
            return
        filename = f"cyberlab-result-{record.get('id', 'unsaved')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export result", filename, "JSON (*.json)")
        if not path:
            return
        try:
            self.store.export_result(record, Path(path))
        except Exception as exc:
            LOGGER.exception("Could not export result")
            show_message(self, "Export failed", str(exc))
            return
        self.status.setText("Exported")

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.worker is not None:
            self.close_pending = True
            self.cancel_job()
            self.status.setText("Cancelling before closing…")
            event.ignore()
            return
        event.accept()


def launch() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("NetworkLuki CyberLab")
    app.setOrganizationName("NetworkLuki")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    try:
        window = MainWindow()
    except Exception as exc:
        LOGGER.exception("Could not initialize application")
        show_message(None, "Could not start CyberLab", str(exc), QMessageBox.Icon.Critical)
        return 1
    window.show()
    return app.exec()
