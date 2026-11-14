"""Local, parameterized result storage and atomic report export."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timezone
from . import __version__

MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BYTES = 16 * 1024 * 1024


def _invalid_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def data_directory() -> Path:
    """Return a platform-specific user directory, never the current directory."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        configured = os.environ.get("XDG_DATA_HOME", "")
        base = Path(configured) if configured and Path(configured).is_absolute() else Path.home() / ".local" / "share"
    if not base.is_absolute():
        raise ValueError("Application data directory must be absolute")
    return base / "NetworkLuki-CyberLab"


def _text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    value = value.strip()
    if not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{label} must be 1–{maximum} printable characters")
    return value


class Store:
    """Open a new database connection per operation, with short transactions."""

    def __init__(self, directory: Path | None = None):
        self.directory = Path(directory) if directory is not None else data_directory()
        if self.directory.is_symlink():
            raise ValueError("Application data directory cannot be a symbolic link")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            info = self.directory.stat()
            if info.st_uid != os.getuid():
                raise PermissionError("Application data directory must belong to the current user")
            self.directory.chmod(0o700)
        self.path = self.directory / "results.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Database cannot be a symbolic link")
        if self.path.exists():
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Database must be an ordinary file without hard links")
            if os.name == "posix" and info.st_uid != os.getuid():
                raise PermissionError("Database must belong to the current user")
        # Create with private permissions before SQLite opens the file.
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        connection = self._connect()
        try:
            with connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL,
                    module TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )""")
        finally:
            connection.close()
        if os.name == "posix":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def add_result(self, project: str, module: str, result: dict) -> int:
        project = _text(project, "Project", 100)
        module = _text(module, "Module", 50)
        if not isinstance(result, dict):
            raise ValueError("Result must be an object")
        payload = json.dumps(result, ensure_ascii=False, allow_nan=False)
        if len(payload.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ValueError("Result exceeds the 2 MiB storage limit")
        timestamp = datetime.now(timezone.utc).isoformat()
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO results(project, module, created_at, payload) VALUES (?, ?, ?, ?)",
                    (project, module, timestamp, payload),
                )
                return int(cursor.lastrowid)
        finally:
            connection.close()

    def list_results(self, project: str | None = None, limit: int = 200) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Result limit must be between 1 and 1000")
        connection = self._connect()
        try:
            selection = "SELECT id, project, module, created_at, CASE WHEN length(CAST(payload AS BLOB)) <= ? THEN payload ELSE NULL END AS payload FROM results"
            if project is None:
                rows = connection.execute(selection + " ORDER BY id DESC LIMIT ?", (MAX_RESULT_BYTES, limit))
            else:
                project = _text(project, "Project", 100)
                rows = connection.execute(
                    selection + " WHERE project = ? ORDER BY id DESC LIMIT ?", (MAX_RESULT_BYTES, project, limit)
                )
            records = []
            total_bytes = 0
            for row in rows:
                if not isinstance(row["payload"], str):
                    raise ValueError("Stored result is invalid or exceeds the size limit")
                total_bytes += len(row["payload"].encode("utf-8"))
                if total_bytes > MAX_HISTORY_BYTES:
                    break
                result = json.loads(row["payload"], parse_constant=_invalid_constant)
                if not isinstance(result, dict):
                    raise ValueError("Stored result must be a JSON object")
                records.append({
                    "id": row["id"], "project": row["project"], "module": row["module"],
                    "created_at": row["created_at"], "result": result,
                })
            return records
        finally:
            connection.close()

    def export_result(self, record: dict, path: Path) -> None:
        """Atomically replace a user-selected export; GUI confirms overwrites."""
        path = Path(path).absolute()
        resolved = path.resolve()
        if path.is_symlink() or resolved.is_relative_to(self.directory.resolve()):
            raise ValueError("Choose a report path outside the application data directory and symbolic links")
        source = record.get("result", {}).get("source_path")
        if source and resolved == Path(source).resolve():
            raise ValueError("An export cannot overwrite the analyzed source file")
        if path.exists() and not path.is_file():
            raise ValueError("Export destination must be a regular file")
        report = {
            "schema_version": 1,
            "application": "NetworkLuki CyberLab",
            "application_version": __version__,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "evidence_note": "Local observation; not a signed or tamper-evident chain of custody.",
            "record": record,
        }
        encoded = (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        if len(encoded) > 4 * MAX_RESULT_BYTES:
            raise ValueError("Export exceeds size limit")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".cyberlab-", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
