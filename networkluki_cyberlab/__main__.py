"""Desktop entry point and isolated packaged-runtime smoke check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from . import __version__


def smoke_test(report_path: Path) -> int:
    """Exercise Qt, file analysis, SQLite and export in temporary storage."""
    from PySide6.QtCore import QCoreApplication, QEvent, qVersion
    from PySide6.QtWidgets import QApplication
    from .forensics import analyze_file
    from .storage import Store
    from .ui import MainWindow

    report = {"ok": False, "version": __version__}
    app = QApplication.instance() or QApplication([])
    window = None
    try:
        with tempfile.TemporaryDirectory(prefix="cyberlab-smoke-") as temporary:
            root = Path(temporary)
            store = Store(root / "data")
            window = MainWindow(store)
            window.show()
            app.processEvents()
            if window.pages.count() != 6 or window.worker is not None:
                raise RuntimeError("Unexpected initial desktop state")
            if window.footer_author.text() != "Skapat av Luki Hackwell":
                raise RuntimeError("Author footer mismatch")
            if window.footer_powered.text() != "Powered by networkluki.com":
                raise RuntimeError("Powered-by footer mismatch")
            if window.footer_powered.geometry().left() <= window.footer_author.geometry().right():
                raise RuntimeError("Footer alignment mismatch")
            source = root / "evidence.bin"
            source.write_bytes(b"CyberLab packaged smoke test\n")
            result = analyze_file(str(source))
            if result["sha256"] != hashlib.sha256(source.read_bytes()).hexdigest():
                raise RuntimeError("Packaged hashing mismatch")
            store.add_result("Packaging verification", "forensics", result)
            store.export_result(store.list_results()[0], root / "report.json")
            if not json.loads((root / "report.json").read_text(encoding="utf-8"))["record"]["result"]["sha256"]:
                raise RuntimeError("Packaged export failed")
            window.close()
            window.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            window = None
            report.update({"ok": True, "qt_version": qVersion(), "platform": app.platformName(),
                           "checks": ["desktop", "footer", "hashing", "sqlite", "json_export"]})
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        if window is not None:
            window.close()
            window.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    # Never overwrite a user's report or follow a final-component symlink.
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return 0 if report["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="NetworkLuki CyberLab desktop workbench")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--smoke-test", type=Path, metavar="NEW_REPORT_JSON",
                        help="Run isolated runtime checks and write a new JSON report")
    args = parser.parse_args()
    if args.smoke_test is not None:
        return smoke_test(args.smoke_test)
    from .ui import launch
    return launch()

if __name__ == "__main__":
    raise SystemExit(main())
