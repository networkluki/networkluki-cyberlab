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
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QWidget,
)

from .forensics import analyze_file, inspect_binary
from .code_review import review_python
from .network import tcp_scan, web_probe
from .storage import Store
from .utilities import compare_text, format_json
from . import ai, development, operations
from . import __version__

LOGGER = logging.getLogger(__name__)
PAGE_NAMES = ("Overview", "Network", "Web & TLS", "File forensics", "Binary analysis",
              "History", "Daily tasks", "Servers", "Development", "AI assistant",
              "Code review", "Utilities")
MODULE_NAMES = {
    "network": "Network", "web": "Web & TLS", "forensics": "File forensics",
    "binary": "Binary analysis", "system": "Server snapshot", "logs": "Log review",
    "project": "Project inspection", "source": "Python source review", "assistant": "AI draft",
    "code_review": "Code review", "utilities": "Utilities",
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
QListWidget#navigation::item { padding: 10px 12px; margin: 2px 0; border-radius: 7px;
                              color: #a8bbcf; }
QListWidget#navigation::item:selected { background: #173849; color: #87f2de; }
QListWidget#navigation::item:hover { background: #192b40; }
QLineEdit, QPlainTextEdit, QComboBox { background: #0b1625; border: 1px solid #30445d;
                          border-radius: 7px; padding: 9px; selection-background-color: #245b6e; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border: 1px solid #55cdbb; }
QComboBox QAbstractItemView { background: #14253a; color: #e4edf7; selection-background-color: #245b6e; }
QComboBox::drop-down { border: none; width: 22px; }
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
        self.explain_buttons: dict[str, QPushButton] = {}
        self.run_buttons: list[QPushButton] = []
        self.input_widgets: list[QWidget] = []
        self.history_record: dict | None = None
        self.task_record: dict | None = None
        self.visible_project = "Local lab"
        self.context_fields: list[QLineEdit] = []
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
        for name in PAGE_NAMES:
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
        self.pages.addWidget(scrollable(self._tasks_page()))
        self.pages.addWidget(scrollable(self._servers_page()))
        self.pages.addWidget(scrollable(self._development_page()))
        self.pages.addWidget(scrollable(self._assistant_page()))
        self.pages.addWidget(scrollable(self._code_review_page()))
        self.pages.addWidget(scrollable(self._utilities_page()))
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
        self.project.textChanged.connect(self._project_changed)
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
            "YOUR UNIFIED WORKSPACE", "Plan. Inspect. Understand.",
            "Daily work, server observations and development reviews — connected by project, evidence and optional AI assistance.",
        )
        focus = QHBoxLayout()
        for eyebrow, title, description, destination in (
            ("01 / EVERYDAY", "Daily tasks", "Track work, due dates and review tasks linked to evidence.", 6),
            ("02 / OPERATIONS", "Servers", "Inspect system snapshots and review bounded log evidence.", 7),
            ("03 / DEVELOPMENT", "Development", "Inventory a project and review Python source without executing it.", 8),
        ):
            frame, content = card()
            frame.setMinimumWidth(0)
            content.addWidget(label(eyebrow, "eyebrow"))
            content.addWidget(label(title, "section"))
            content.addWidget(label(description, "muted", True))
            button = QPushButton("Open workspace")
            button.clicked.connect(lambda checked=False, row=destination: self.navigation.setCurrentRow(row))
            content.addWidget(button)
            focus.addWidget(frame, 1)
        layout.addLayout(focus)
        assistant_frame, assistant_content = card()
        assistant_content.addWidget(label("AI ASSISTANT / EXPLICIT INPUT", "eyebrow"))
        assistant_content.addWidget(label("Review the evidence. Then ask for an explanation.", "section", True))
        assistant_content.addWidget(label("Use an installed Ollama model to draft explanations. You choose the text to send; AI output remains unverified and never runs commands.", "muted", True))
        ai_button = QPushButton("Open AI assistant")
        ai_button.clicked.connect(lambda: self.navigation.setCurrentRow(9))
        assistant_content.addWidget(ai_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(assistant_frame)
        self.workspace_task_summary = label("No tasks yet.", "muted", True)
        layout.addWidget(self.workspace_task_summary)
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
        layout.addWidget(label("Security research tools", "section"))
        grid = QGridLayout()
        grid.setSpacing(13)
        tools = (
            ("01  /  NETWORK", "TCP connect", "Check selected ports on an explicitly specified IP address.", 1),
            ("02  /  WEB", "HTTP/TLS HEAD", "Read response headers and TLS details from a selected target.", 2),
            ("03  /  FORENSICS", "SHA-256 / SHA-512", "Calculate file hashes and record basic file information.", 3),
            ("04  /  BINARY ANALYSIS", "Strings / hex", "Inspect signatures, strings and hex without running the file.", 4),
            ("05  /  CODE REVIEW", "Python AST review", "Find five bounded risky-code patterns without executing source.", 10),
            ("06  /  UTILITIES", "JSON / text comparison", "Format strict JSON and compare bounded text locally.", 11),
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
        self.context_fields.append(field)
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

    def _code_review_page(self) -> QWidget:
        page, layout = self._page(
            "SECURITY / STATIC REVIEW", "Python code review",
            "Read-only checks for risky Python constructs. Findings require human review; "
            "an empty result does not establish that code is safe.",
        )
        frame, content = card()
        content.addWidget(label("Python source · .py or .pyw · UTF-8 · up to 256 KiB", "muted", True))
        row = QHBoxLayout()
        self.code_path = QLineEdit()
        self.code_path.setReadOnly(True)
        self.code_path.setPlaceholderText("Select a Python source file…")
        self.code_path.setAccessibleName("Python source path")
        choose = QPushButton("Choose file…")
        choose.clicked.connect(lambda: self.choose_file(self.code_path))
        self.context_fields.append(self.code_path)
        row.addWidget(self.code_path, 1)
        row.addWidget(choose)
        content.addLayout(row)
        content.addWidget(self._run_button("Review Python source", self.start_code_review),
                          0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("code_review", layout)
        return page

    def _text_input(self, placeholder: str, accessible_name: str) -> QPlainTextEdit:
        field = QPlainTextEdit()
        field.setPlaceholderText(placeholder)
        field.setAccessibleName(accessible_name)
        field.setFont(QFont("monospace", 10))
        field.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        field.setMinimumHeight(130)
        field.setMaximumHeight(230)
        return field

    def _utilities_page(self) -> QWidget:
        page, layout = self._page(
            "EVERYDAY TOOLS / LOCAL", "JSON & text utilities",
            "Format JSON or compare two texts. Results are saved to the current project; "
            "avoid pasting secrets you do not want in local history.",
        )
        tabs = QTabWidget()
        json_page = QWidget()
        json_layout = QVBoxLayout(json_page)
        json_layout.addWidget(label("JSON · up to 128 KiB · nesting depth up to 64", "muted", True))
        self.json_input = self._text_input('Paste JSON, for example {"service": "apache"}', "JSON input")
        json_layout.addWidget(self.json_input)
        json_layout.addWidget(self._run_button("Validate & format JSON", self.start_json),
                              0, Qt.AlignmentFlag.AlignLeft)
        tabs.addTab(json_page, "JSON formatter")
        diff_page = QWidget()
        diff_layout = QVBoxLayout(diff_page)
        diff_layout.addWidget(label("Each text: up to 128 KiB and 1,000 lines. Output: up to 256 KiB.", "muted", True))
        row = QHBoxLayout()
        self.diff_before = self._text_input("Before", "Text before")
        self.diff_after = self._text_input("After", "Text after")
        row.addWidget(self.diff_before)
        row.addWidget(self.diff_after)
        diff_layout.addLayout(row)
        diff_layout.addWidget(self._run_button("Compare text", self.start_diff),
                              0, Qt.AlignmentFlag.AlignLeft)
        tabs.addTab(diff_page, "Text comparison")
        layout.addWidget(tabs)
        self.input_widgets.append(tabs)
        self._result_area("utilities", layout)
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
        if module != "assistant":
            explain_button = QPushButton("Use in AI")
            explain_button.setEnabled(False)
            explain_button.clicked.connect(lambda: self.prepare_assistant(self.last_records.get(module)))
            self.explain_buttons[module] = explain_button
            row.addWidget(explain_button)
        if module == "utilities":
            self.copy_utility = QPushButton("Copy output")
            self.copy_utility.setEnabled(False)
            self.copy_utility.clicked.connect(self.copy_utility_output)
            row.addWidget(self.copy_utility)
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
        self.history_count = label("0 results", "muted", True)
        self.history_count.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(self.history_count, 1)
        toolbar.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_history)
        toolbar.addWidget(refresh)
        self.history_export = QPushButton("Export JSON")
        self.history_export.setEnabled(False)
        self.history_export.clicked.connect(lambda: self.export_record(self.history_record))
        toolbar.addWidget(self.history_export)
        self.history_ai = QPushButton("Use in AI")
        self.history_ai.setEnabled(False)
        self.history_ai.clicked.connect(self.use_history_in_ai)
        toolbar.addWidget(self.history_ai)
        self.history_task = QPushButton("Create review task")
        self.history_task.setEnabled(False)
        self.history_task.clicked.connect(self.create_review_task)
        toolbar.addWidget(self.history_task)
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

    def _tasks_page(self) -> QWidget:
        page, layout = self._page("EVERYDAY / PROJECT TASKS", "Daily tasks",
                                  "Keep a project checklist and follow up on observations. Tasks never execute system changes.")
        frame, content = card()
        content.addWidget(label("Task", "muted"))
        self.task_title = QLineEdit()
        self.task_title.setMaxLength(200)
        self.task_title.setPlaceholderText("What needs attention?")
        self.task_title.setAccessibleName("Task title")
        content.addWidget(self.task_title)
        row = QHBoxLayout()
        self.task_category = QComboBox()
        for title, value in (("Daily work", "daily"), ("Server operations", "server"), ("Development", "development")):
            self.task_category.addItem(title, value)
        self.task_category.setAccessibleName("Task area")
        self.task_due = QLineEdit()
        self.task_due.setMaxLength(10)
        self.task_due.setPlaceholderText("Due date · YYYY-MM-DD · optional")
        self.task_due.setAccessibleName("Optional task due date")
        row.addWidget(self.task_category, 1)
        row.addWidget(self.task_due, 2)
        content.addLayout(row)
        content.addWidget(self._run_button("Add task", self.add_task), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        toolbar = QHBoxLayout()
        self.task_summary = label("No tasks yet.", "muted", True)
        toolbar.addWidget(self.task_summary, 1)
        self.task_toggle = QPushButton("Mark done")
        self.task_toggle.setEnabled(False)
        self.task_toggle.clicked.connect(self.toggle_task)
        toolbar.addWidget(self.task_toggle)
        layout.addLayout(toolbar)
        self.tasks = QTableWidget(0, 4)
        self.tasks.setHorizontalHeaderLabels(["Task", "Area", "Due", "Status"])
        self.tasks.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tasks.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.tasks.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tasks.setAlternatingRowColors(True)
        self.tasks.verticalHeader().setVisible(False)
        self.tasks.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            self.tasks.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.tasks.itemSelectionChanged.connect(self._select_task)
        self.tasks.setMinimumHeight(240)
        layout.addWidget(self.tasks, 1)
        self.task_evidence = label("Select a task to view its evidence reference. Showing up to 200 tasks.", "muted", True)
        layout.addWidget(self.task_evidence)
        return page

    def _path_field(self, content: QVBoxLayout, caption: str, *, directory: bool = False,
                    file_filter: str = "All files (*)") -> QLineEdit:
        content.addWidget(label(caption, "muted"))
        row = QHBoxLayout()
        field = QLineEdit()
        field.setReadOnly(True)
        field.setPlaceholderText("Choose a folder…" if directory else "Choose a file…")
        field.setAccessibleName(caption)
        button = QPushButton("Browse…")

        def choose() -> None:
            if directory:
                path = QFileDialog.getExistingDirectory(self, caption)
            else:
                path, _ = QFileDialog.getOpenFileName(self, caption, "", file_filter)
            if path:
                field.setText(path)

        button.clicked.connect(choose)
        row.addWidget(field, 1)
        row.addWidget(button)
        content.addLayout(row)
        self.context_fields.append(field)
        return field

    def _servers_page(self) -> QWidget:
        page, layout = self._page("OPERATIONS / READ-ONLY EVIDENCE", "Servers",
                                  "Collect a snapshot of this computer, import a server snapshot, or review a log. Imports are observations supplied by the file, not verified server identity.")
        frame, content = card()
        content.addWidget(label("System snapshot", "section"))
        content.addWidget(label("Snapshots are captured on demand. Remote machines can export JSON with the included collect_snapshot.py tool; no remote commands or agents are started by this page.", "muted", True))
        content.addWidget(self._run_button("Collect this computer", self.start_system_snapshot), 0, Qt.AlignmentFlag.AlignLeft)
        self.snapshot_path = self._path_field(content, "Server snapshot JSON", file_filter="JSON files (*.json);;All files (*)")
        content.addWidget(self._run_button("Import snapshot", self.start_snapshot_import), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("system", layout)
        frame, content = card()
        content.addWidget(label("Log review", "section"))
        self.log_path = self._path_field(content, "UTF-8 log file", file_filter="Log files (*.log *.txt);;All files (*)")
        content.addWidget(label("Reviews a bounded text file and reports matching lines. A warning or error keyword is a signal for investigation, not proof of an incident.", "muted", True))
        content.addWidget(self._run_button("Review log", self.start_log_review), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("logs", layout)
        return page

    def _development_page(self) -> QWidget:
        page, layout = self._page("DEVELOPMENT / READ-ONLY REVIEW", "Development",
                                  "Inventory local project files and review selected Python source. No project code, Git hooks, plugins or build commands are executed.")
        frame, content = card()
        content.addWidget(label("Project inventory", "section"))
        self.development_path = self._path_field(content, "Project folder", directory=True)
        content.addWidget(label("The bounded inventory identifies file types and common project files. Skipped paths and limits are included in the result.", "muted", True))
        content.addWidget(self._run_button("Inspect project", self.start_project_inspection), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("project", layout)
        frame, content = card()
        content.addWidget(label("Python source review", "section"))
        self.source_path = self._path_field(content, "Python source file", file_filter="Python files (*.py *.pyw)")
        content.addWidget(label("Static review signals require human investigation. They are not verified vulnerabilities or a complete security audit.", "muted", True))
        content.addWidget(self._run_button("Review Python source", self.start_source_review), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("source", layout)
        return page

    def _assistant_page(self) -> QWidget:
        page, layout = self._page("ASSISTANT / HUMAN REVIEW", "AI assistant",
                                  "Draft an explanation of text you choose. AI interpretations are unverified; the assistant cannot execute commands or make system changes.")
        frame, content = card()
        content.addWidget(label("Ollama service · loopback address only", "muted"))
        self.ai_endpoint = QLineEdit("http://127.0.0.1:11434")
        self.ai_endpoint.setMaxLength(256)
        self.ai_endpoint.setAccessibleName("Ollama loopback endpoint")
        content.addWidget(self.ai_endpoint)
        model_row = QHBoxLayout()
        self.ai_model = QComboBox()
        self.ai_model.setEditable(False)
        self.ai_model.setAccessibleName("Installed Ollama model")
        self.ai_model.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.ai_model.setMinimumContentsLength(12)
        model_row.addWidget(self.ai_model, 1)
        model_row.addWidget(self._run_button("Load models", self.load_ai_models))
        content.addLayout(model_row)
        self.ai_model_status = label("No connection has been made. Load the available models when you are ready.", "muted", True)
        content.addWidget(self.ai_model_status)
        content.addWidget(label("Ollama must use a downloaded local model. CyberLab cannot verify the server's privacy settings.", "muted", True))
        content.addWidget(label("Question", "muted"))
        self.ai_question = QPlainTextEdit()
        self.ai_question.setMaximumHeight(84)
        self.ai_question.setPlaceholderText("What should be explained or reviewed?")
        self.ai_question.setAccessibleName("Question for the AI assistant")
        content.addWidget(self.ai_question)
        content.addWidget(label("Evidence preview · edit or remove sensitive details before sending", "muted", True))
        self.ai_evidence = QPlainTextEdit()
        self.ai_evidence.setMinimumHeight(170)
        self.ai_evidence.setPlaceholderText("Paste the text to review, or select a saved result in History and choose Use in AI.")
        self.ai_evidence.setAccessibleName("Reviewed evidence to send to Ollama")
        content.addWidget(self.ai_evidence)
        self.ai_budget = label("Question: 0 / 2,000 characters · Evidence: 0 / 24,000 UTF-8 bytes", "muted", True)
        content.addWidget(self.ai_budget)
        content.addWidget(label("Your question, reviewed evidence and AI answer are saved in local history without encryption. Redact sensitive details before sending.", "muted", True))
        self.ai_consent = QCheckBox("I reviewed this text and configured Ollama with cloud features disabled.")
        self.ai_consent.setAccessibleName("Confirm evidence review and disabled Ollama cloud features")
        content.addWidget(self.ai_consent)
        content.addWidget(self._run_button("Generate explanation", self.start_ai_explanation), 0, Qt.AlignmentFlag.AlignLeft)
        self.ai_endpoint.textChanged.connect(self._ai_endpoint_changed)
        self.ai_model.currentIndexChanged.connect(self._invalidate_ai_consent)
        self.ai_question.textChanged.connect(self._ai_text_changed)
        self.ai_evidence.textChanged.connect(self._ai_text_changed)
        layout.addWidget(frame)
        self.input_widgets.append(frame)
        self._result_area("assistant", layout)
        self.result_views["assistant"].setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.result_views["assistant"].setPlaceholderText("Unverified AI draft. Review its claims against the original evidence.")
        return page

    def _project_changed(self, text: str) -> None:
        project = text.strip()
        if project == self.visible_project:
            return
        self.visible_project = project
        self.last_records.clear()
        for module, view in self.result_views.items():
            view.clear()
            self.result_summaries[module].setText("No analysis has been run in this project view.")
            self.export_buttons[module].setEnabled(False)
        for field in self.context_fields:
            field.clear()
        self.json_input.clear()
        self.diff_before.clear()
        self.diff_after.clear()
        self.copy_utility.setEnabled(False)
        for button in self.explain_buttons.values():
            button.setEnabled(False)
        self.task_title.clear()
        self.task_due.clear()
        self.ai_evidence.clear()
        self.ai_question.clear()
        self.ai_consent.setChecked(False)
        self.network_authorized.setChecked(False)
        self.web_authorized.setChecked(False)
        self.refresh_history()

    def add_task(self) -> None:
        if self.worker is not None:
            return
        try:
            self.store.add_task(self.project.text().strip(), self.task_title.text(),
                                self.task_category.currentData(), self.task_due.text().strip() or None)
        except Exception as exc:
            show_message(self, "Could not add task", str(exc))
            return
        self.task_title.clear()
        self.task_due.clear()
        self.refresh_tasks()
        self.status.setText("Task added")

    def refresh_tasks(self) -> None:
        if not hasattr(self, "tasks"):
            return
        self.task_record = None
        self.task_toggle.setEnabled(False)
        self.task_evidence.setText("Select a task to view its evidence reference. Showing up to 200 tasks.")
        self.tasks.blockSignals(True)
        self.tasks.setRowCount(0)
        try:
            project = self.project.text().strip()
            if not project:
                self.task_summary.setText("Enter a project name to show its tasks.")
                self.workspace_task_summary.setText("Choose a project to view its task summary.")
                return
            records = self.store.list_tasks(project)
            counts = self.store.task_counts(project)
            self.tasks.setRowCount(len(records))
            for row, task in enumerate(records):
                values = (task["title"], task["category"].title(), task.get("due_date") or "—", task["status"].title())
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, task)
                    self.tasks.setItem(row, column, item)
            summary = f"{counts['open']} open · {counts['done']} done · {counts['overdue']} overdue"
            self.task_summary.setText(summary)
            self.workspace_task_summary.setText(f"Project tasks · {summary}")
        except Exception as exc:
            LOGGER.exception("Could not read tasks")
            self.task_summary.setText(f"Could not read tasks: {exc}")
            self.workspace_task_summary.setText("Tasks could not be loaded.")
        finally:
            self.tasks.blockSignals(False)

    def _select_task(self) -> None:
        row = self.tasks.currentRow()
        item = self.tasks.item(row, 0) if row >= 0 else None
        self.task_record = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.task_toggle.setEnabled(self.task_record is not None and self.worker is None)
        if self.task_record is None:
            return
        self.task_toggle.setText("Reopen task" if self.task_record["status"] == "done" else "Mark done")
        source = self.task_record.get("source_record_id")
        self.task_evidence.setText(f"Linked evidence: history result #{source}. The task records follow-up work; it does not apply changes."
                                  if source else "This task has no linked evidence record.")

    def toggle_task(self) -> None:
        if self.worker is not None or self.task_record is None:
            return
        try:
            state = "open" if self.task_record["status"] == "done" else "done"
            self.store.set_task_status(self.project.text().strip(), self.task_record["id"], state)
        except Exception as exc:
            show_message(self, "Could not update task", str(exc))
            return
        self.refresh_tasks()

    def create_review_task(self) -> None:
        record = self.history_record
        if self.worker is not None or record is None or record.get("project") != self.project.text().strip():
            return
        module = record.get("module", "")
        category = "server" if module in ("network", "web", "system", "logs") else "development" if module in ("project", "source", "binary", "code_review") else "daily"
        title = f"Review {MODULE_NAMES.get(module, module)} result #{record['id']}"
        try:
            self.store.add_task(record["project"], title, category, source_record_id=record["id"])
        except Exception as exc:
            show_message(self, "Could not create review task", str(exc))
            return
        self.refresh_tasks()
        self.navigation.setCurrentRow(6)
        self.status.setText("Review task added")

    def start_system_snapshot(self) -> None:
        self._start("system", operations.collect_system_snapshot, ())

    def _start_path_job(self, module: str, function: Callable, field: QLineEdit) -> None:
        if not field.text():
            show_message(self, "Choose an input", "Choose the local file or folder before starting.", QMessageBox.Icon.Information)
            return
        self._start(module, function, (field.text(),))

    def start_snapshot_import(self) -> None:
        self._start_path_job("system", operations.import_system_snapshot, self.snapshot_path)

    def start_log_review(self) -> None:
        self._start_path_job("logs", operations.analyze_log, self.log_path)

    def start_project_inspection(self) -> None:
        self._start_path_job("project", development.inspect_project, self.development_path)

    def start_source_review(self) -> None:
        self._start_path_job("source", development.inspect_source, self.source_path)

    def _invalidate_ai_consent(self, *_args) -> None:
        self.ai_consent.setChecked(False)

    def _ai_endpoint_changed(self) -> None:
        self._invalidate_ai_consent()
        self.ai_model.clear()
        self.ai_model_status.setText("Endpoint changed. Load its models explicitly before generating an explanation.")

    def _ai_text_changed(self) -> None:
        self._invalidate_ai_consent()
        question_size = len(self.ai_question.toPlainText())
        try:
            evidence_size = len(self.ai_evidence.toPlainText().encode("utf-8"))
        except UnicodeEncodeError:
            self.ai_budget.setText("Evidence contains invalid Unicode text. Remove or replace it before sending.")
            return
        self.ai_budget.setText(f"Question: {question_size:,} / 2,000 characters · Evidence: {evidence_size:,} / 24,000 UTF-8 bytes")

    def use_history_in_ai(self) -> None:
        record = self.history_record
        if self.worker is not None or record is None or record.get("project") != self.project.text().strip():
            return
        self.ai_consent.setChecked(False)
        evidence = json.dumps(record, ensure_ascii=False, indent=2)
        if len(evidence.encode("utf-8")) > 24000:
            self.ai_evidence.clear()
            show_message(self, "Choose a smaller excerpt", "This result exceeds the AI evidence limit. Copy a relevant excerpt from History into the evidence preview and review it before sending.", QMessageBox.Icon.Information)
            return
        self.ai_evidence.setPlainText(evidence)
        self.ai_question.setPlainText("Explain these observations, distinguish facts from hypotheses, and suggest what I should verify next.")
        self.navigation.setCurrentRow(9)
        self.status.setText("Review AI input")

    def load_ai_models(self) -> None:
        self.ai_consent.setChecked(False)
        self.ai_model.clear()
        self._start("models", ai.list_models, (self.ai_endpoint.text().strip(),))

    def start_ai_explanation(self) -> None:
        if not self.ai_consent.isChecked():
            show_message(self, "Review required", "Review the evidence and confirm that Ollama cloud features are disabled before sending.", QMessageBox.Icon.Information)
            return
        if not self.ai_model.currentText():
            show_message(self, "Choose an installed model", "Load and select an installed local Ollama model first.", QMessageBox.Icon.Information)
            return
        self._start("assistant", ai.explain_evidence, (self.ai_endpoint.text().strip(), self.ai_model.currentText(),
                                                      self.ai_question.toPlainText(), self.ai_evidence.toPlainText()))
        self.ai_consent.setChecked(False)

    def _navigate(self, index: int) -> None:
        if hasattr(self, "pages") and index >= 0:
            self.pages.setCurrentIndex(index)
            if index in (0, 5):
                self.refresh_history()
            elif index == 6:
                self.refresh_tasks()

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

    def start_code_review(self) -> None:
        if not self.code_path.text():
            show_message(self, "Choose Python source", "Choose a Python source file before starting the review.")
            return
        self._start("code_review", review_python, (self.code_path.text(),))

    def start_json(self) -> None:
        self._start("utilities", format_json, (self.json_input.toPlainText(),))

    def start_diff(self) -> None:
        self._start("utilities", compare_text, (self.diff_before.toPlainText(), self.diff_after.toPlainText()))

    def prepare_assistant(self, record: dict | None) -> None:
        if self.worker is not None or record is None or record.get("module") == "assistant":
            return
        evidence = json.dumps(record, ensure_ascii=False, indent=2)
        if len(evidence.encode("utf-8")) > 24000:
            show_message(self, "Choose a smaller excerpt",
                         "This result exceeds the AI evidence limit. Copy a relevant excerpt into the AI evidence preview.",
                         QMessageBox.Icon.Information)
            return
        self.ai_consent.setChecked(False)
        self.ai_evidence.setPlainText(evidence)
        self.ai_question.setPlainText(
            "Explain these observations, distinguish facts from hypotheses, and suggest what I should verify next."
        )
        self.navigation.setCurrentRow(9)
        self.status.setText("Review AI input")

    def copy_utility_output(self) -> None:
        record = self.last_records.get("utilities")
        if record is None:
            return
        result = record["result"]
        output = result.get("formatted", result.get("diff", ""))
        if isinstance(output, str):
            QApplication.clipboard().setText(output)
            self.status.setText("Copied")

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
        if module == "models":
            self.ai_model_status.setText("Loading the selected Ollama service's models…")
        else:
            self.result_summaries[module].setText("Analysis in progress…")
            self.result_views[module].clear()
            self.last_records.pop(module, None)
            self.export_buttons[module].setEnabled(False)
            if module == "utilities":
                self.copy_utility.setEnabled(False)
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
        self.task_toggle.setEnabled(not busy and self.task_record is not None)
        for module, button in self.explain_buttons.items():
            button.setEnabled(not busy and module in self.last_records)
        self.history_ai.setEnabled(
            not busy and self.history_record is not None and self.history_record.get("module") != "assistant"
        )
        self.history_task.setEnabled(not busy and self.history_record is not None)
        self.cancel_button.setEnabled(busy)
        self.status.setText("Working…" if busy else "Ready")

    def cancel_job(self) -> None:
        if self.worker is not None:
            self.worker.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status.setText("Cancelling…")

    def _completed(self, result: dict) -> None:
        module = self.active_module
        if module == "models":
            self.ai_model.clear()
            self.ai_model.addItems(result["models"])
            self.ai_model_status.setText(f"{len(result['models'])} model(s) available. Select a downloaded local model; no evidence was sent.")
            self.ai_consent.setChecked(False)
            return
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
        # The UI normally locks the project field during a job. Still guard
        # programmatic changes so a completed result cannot cross project views.
        if self.project.text().strip() != self.active_project:
            self.refresh_history()
            return
        self.last_records[module] = record
        if module == "assistant":
            self.result_views[module].setPlainText(str(result.get("response", "")))
            self.result_summaries[module].setText(
                "Unverified AI draft · check its claims against the original evidence. "
                + (f"Saved to project {self.active_project}." if saved else "Not saved; export it to keep a copy.")
            )
        elif module == "utilities":
            output = result.get("formatted", result.get("diff", ""))
            if not output and result.get("changed") is False:
                output = "No differences."
            self.result_views[module].setPlainText(str(output))
            self.copy_utility.setEnabled(True)
            self.result_summaries[module].setText(
                f"Complete · saved to project {self.active_project}." if saved
                else "Complete · this result is only available in this window. Export it to keep a copy."
            )
        else:
            self.result_views[module].setPlainText(json.dumps(result, ensure_ascii=False, indent=2))
            qualifier = "Review required" if module == "code_review" and result.get("findings") else "Complete"
            self.result_summaries[module].setText(
                f"{qualifier} · saved to project {self.active_project}." if saved
                else f"{qualifier} · this result is only available in this window. Export it to keep a copy."
            )
        self.export_buttons[module].setEnabled(True)
        self.refresh_history()

    def _failed(self, message: str) -> None:
        cancelled = bool(self.worker and self.worker.cancel_event.is_set()) or message == "Operation cancelled"
        if self.active_module == "models":
            self.ai_model_status.setText("Model lookup cancelled." if cancelled else f"Could not load models: {message}")
        elif self.project.text().strip() == self.active_project:
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
        self.history_record = None
        self.history_export.setEnabled(False)
        self.history_ai.setEnabled(False)
        self.history_task.setEnabled(False)
        self.history_preview.clear()
        self.history.blockSignals(True)
        self.history.setRowCount(0)
        self.history.blockSignals(False)
        self.refresh_tasks()
        if not self.project.text().strip():
            self.history_count.setText("Enter a project name to show its history.")
            self.stat_results.setText("0")
            self.stat_network.setText("0")
            self.stat_files.setText("0")
            return
        try:
            records = self.store.list_results(self.project.text().strip(), limit=200)
        except Exception as exc:
            LOGGER.exception("Could not read history")
            self.status.setText("Read error")
            self.history_count.setText(f"Could not read history: {exc}")
            return
        self.history.blockSignals(True)
        self.history.setRowCount(len(records))
        for row, record in enumerate(records):
            result = record.get("result", {})
            target = result.get("target") or result.get("url") or result.get("source_path") or result.get("path") or result.get("name") or result.get("hostname") or "—"
            values = [str(record.get("created_at", "")), MODULE_NAMES.get(record.get("module", ""), str(record.get("module", ""))), str(target), str(record.get("id", ""))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record)
                self.history.setItem(row, column, item)
        self.history.blockSignals(False)
        self.history_count.setText(f"{len(records)} results · {self.project.text().strip() or 'no project'}")
        self.stat_results.setText(str(len(records)))
        self.stat_network.setText(str(sum(item.get("module") in ("network", "web", "system", "logs", "code_review") for item in records)))
        self.stat_files.setText(str(sum(item.get("module") in ("forensics", "binary", "project", "source", "utilities") for item in records)))

    def _select_history(self) -> None:
        row = self.history.currentRow()
        item = self.history.item(row, 0) if row >= 0 else None
        self.history_record = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.history_export.setEnabled(self.history_record is not None)
        self.history_ai.setEnabled(self.history_record is not None and self.worker is None
                                   and self.history_record.get("module") != "assistant")
        self.history_task.setEnabled(self.history_record is not None and self.worker is None)
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
