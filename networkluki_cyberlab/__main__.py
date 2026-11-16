"""Desktop entry point and isolated packaged-runtime smoke check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from . import __version__


def smoke_test(report_path: Path) -> int:
    """Exercise Qt, file analysis, SQLite and export in temporary storage."""
    from PySide6.QtCore import QCoreApplication, QEvent, qVersion
    from PySide6.QtWidgets import QApplication
    from .forensics import analyze_file
    from .code_review import review_python
    from .utilities import compare_text, format_json
    from .storage import Store
    from .ui import MainWindow
    from .operations import collect_system_snapshot
    from .development import inspect_project, inspect_source

    report = {"ok": False, "version": __version__}
    app = QApplication.instance() or QApplication([])
    window = None
    try:
        with tempfile.TemporaryDirectory(prefix="cyberlab-smoke-") as temporary:
            root = Path(temporary).resolve()
            store = Store(root / "data")
            window = MainWindow(store)
            window.show()
            app.processEvents()
            if window.pages.count() != 12 or window.worker is not None:
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
            record_id = store.add_result("Packaging verification", "forensics", result)
            store.export_result(store.list_results()[0], root / "report.json")
            if not json.loads((root / "report.json").read_text(encoding="utf-8"))["record"]["result"]["sha256"]:
                raise RuntimeError("Packaged export failed")
            task_id = store.add_task("Packaging verification", "Review evidence", source_record_id=record_id)
            store.set_task_status("Packaging verification", task_id, "done")
            if store.task_counts("Packaging verification")["done"] != 1:
                raise RuntimeError("Packaged task storage failed")
            snapshot = collect_system_snapshot()
            if snapshot.get("schema_version") != 1:
                raise RuntimeError("Packaged system snapshot failed")
            script = root / "sample.py"
            script.write_text("print('packaging verification')\n", encoding="utf-8")
            inspect_project(str(root))
            inspect_source(str(script))
            review_source = root / "review.py"
            review_source.write_text("value = eval(user_input)\n", encoding="utf-8")
            review = review_python(str(review_source))
            if not review["findings"] or review["findings"][0]["status"] != "review_required":
                raise RuntimeError("Packaged code review failed")
            if json.loads(format_json('{"ready":true}')["formatted"]) != {"ready": True}:
                raise RuntimeError("Packaged JSON formatting failed")
            if not compare_text("before\n", "after\n")["changed"]:
                raise RuntimeError("Packaged text comparison failed")
            window.close()
            window.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            window = None
            report.update({"ok": True, "qt_version": qVersion(), "platform": app.platformName(),
                           "checks": ["desktop", "footer", "hashing", "sqlite", "json_export",
                                      "tasks", "system_snapshot", "development", "code_review",
                                      "json_formatting", "text_comparison"],
                           "ollama_inference_tested": False})
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
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--smoke-test", type=Path, metavar="NEW_REPORT_JSON",
                        help="Run isolated runtime checks and write a new JSON report")
    commands.add_argument("--collect-snapshot", type=Path, metavar="NEW_REPORT_JSON",
                          help="Write a read-only system snapshot without starting the GUI")
    args = parser.parse_args()
    if args.smoke_test is not None:
        return smoke_test(args.smoke_test)
    if args.collect_snapshot is not None:
        from .operations import collect_system_snapshot
        try:
            encoded = (json.dumps(collect_system_snapshot(), indent=2, allow_nan=False) + "\n").encode("utf-8")
            descriptor = os.open(args.collect_snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Snapshot failed: {exc}", file=sys.stderr)
            return 1
        print(f"Snapshot written: {args.collect_snapshot}")
        return 0
    from .ui import launch
    return launch()

if __name__ == "__main__":
    raise SystemExit(main())
