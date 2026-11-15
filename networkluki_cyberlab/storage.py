"""Local, parameterized result storage and atomic report export."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from datetime import date, datetime, timezone
from . import __version__

MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BYTES = 16 * 1024 * 1024
MAX_TASKS_PER_PROJECT = 1000
TASK_CATEGORIES = frozenset({"daily", "server", "development"})
TASK_STATUSES = frozenset({"open", "done"})


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


def _task_text(value: str, label: str, maximum: int) -> str:
    if isinstance(value, str) and not value.isprintable():
        raise ValueError(f"{label} must contain printable characters")
    return _text(value, label, maximum)


def _positive_id(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _task_due_date(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 10:
        raise ValueError("Due date must use YYYY-MM-DD or be omitted")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Due date must be a valid YYYY-MM-DD date") from exc
    if parsed.isoformat() != value:
        raise ValueError("Due date must use YYYY-MM-DD")
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
        created_database = False
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
            created_database = True
        connection = self._connect()
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('results', 'tasks')"
            )}
            if not created_database and "results" in tables and "tasks" not in tables:
                self._backup_before_task_migration(connection)
            with connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL,
                    module TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )""")
                connection.execute("""CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL CHECK(category IN ('daily', 'server', 'development')),
                    due_date TEXT,
                    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'done')),
                    source_record_id INTEGER REFERENCES results(id),
                    created_at TEXT NOT NULL
                )""")
                connection.execute("CREATE INDEX IF NOT EXISTS tasks_project_id ON tasks(project, id)")
        finally:
            connection.close()
        if os.name == "posix":
            self.path.chmod(0o600)

    def _backup_before_task_migration(self, connection: sqlite3.Connection) -> None:
        """Publish one private, complete pre-migration backup without overwriting."""
        backup = self.directory / "results.pre-workspace.sqlite3"
        if backup.is_symlink():
            raise ValueError("Pre-workspace database backup cannot be a symbolic link")
        if backup.exists():
            raise FileExistsError("Pre-workspace backup already exists; preserve or move it before migrating")
        descriptor, filename = tempfile.mkstemp(prefix=".pre-workspace-", suffix=".sqlite3", dir=self.directory)
        os.close(descriptor)
        temporary = Path(filename)
        try:
            target = sqlite3.connect(temporary, timeout=5)
            try:
                # SQLite backup includes committed WAL data; file copying would not.
                # This must run before entering the schema-write transaction.
                connection.backup(target)
            finally:
                target.close()
            with temporary.open("r+b") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            # Same-filesystem hard-link creation is atomic and fails if the
            # reserved destination appeared concurrently. Never replace it.
            os.link(temporary, backup)
        finally:
            temporary.unlink(missing_ok=True)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def add_task(self, project: str, title: str, category: str = "daily",
                 due_date: str | None = None, source_record_id: int | None = None) -> int:
        """Save a human-managed task; linking evidence never executes an action."""
        project = _task_text(project, "Project", 100)
        title = _task_text(title, "Task title", 200)
        if not isinstance(category, str) or category not in TASK_CATEGORIES:
            raise ValueError("Task category must be daily, server or development")
        due_date = _task_due_date(due_date)
        if source_record_id is not None:
            source_record_id = _positive_id(source_record_id, "Source record ID")
        timestamp = datetime.now(timezone.utc).isoformat()
        connection = self._connect()
        try:
            with connection:
                # Serialize the limit check and insertion across app instances.
                connection.execute("BEGIN IMMEDIATE")
                count = connection.execute("SELECT COUNT(*) FROM tasks WHERE project = ?", (project,)).fetchone()[0]
                if count >= MAX_TASKS_PER_PROJECT:
                    raise ValueError(f"A project can contain at most {MAX_TASKS_PER_PROJECT} tasks")
                if source_record_id is not None and connection.execute(
                    "SELECT id FROM results WHERE id = ? AND project = ?", (source_record_id, project)
                ).fetchone() is None:
                    raise ValueError("Source record does not belong to the selected project")
                cursor = connection.execute(
                    "INSERT INTO tasks(project, title, category, due_date, status, source_record_id, created_at) "
                    "VALUES (?, ?, ?, ?, 'open', ?, ?)",
                    (project, title, category, due_date, source_record_id, timestamp),
                )
                return int(cursor.lastrowid)
        finally:
            connection.close()

    def list_tasks(self, project: str, limit: int = 200) -> list[dict]:
        project = _task_text(project, "Project", 100)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Task limit must be between 1 and 1000")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT id, project, title, category, due_date, status, source_record_id, created_at "
                "FROM tasks WHERE project = ? ORDER BY id DESC LIMIT ?", (project, limit)
            )
            tasks = []
            for row in rows:
                task = dict(row)
                _positive_id(task["id"], "Stored task ID")
                _task_text(task["title"], "Stored task title", 200)
                _task_due_date(task["due_date"])
                if task["category"] not in TASK_CATEGORIES or task["status"] not in TASK_STATUSES:
                    raise ValueError("Stored task category or status is invalid")
                if task["source_record_id"] is not None:
                    _positive_id(task["source_record_id"], "Stored source record ID")
                tasks.append(task)
            return tasks
        finally:
            connection.close()

    def set_task_status(self, project: str, task_id: int, status: str) -> None:
        project = _task_text(project, "Project", 100)
        task_id = _positive_id(task_id, "Task ID")
        if not isinstance(status, str) or status not in TASK_STATUSES:
            raise ValueError("Task status must be open or done")
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute("UPDATE tasks SET status = ? WHERE id = ? AND project = ?",
                                            (status, task_id, project))
                if cursor.rowcount != 1:
                    raise ValueError("Task not found in the selected project")
        finally:
            connection.close()

    def task_counts(self, project: str) -> dict[str, int]:
        """Count all project tasks; overdue means an open due date before local today."""
        project = _task_text(project, "Project", 100)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0) AS open, "
                "COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0) AS done, "
                "COALESCE(SUM(CASE WHEN status = 'open' AND due_date < ? THEN 1 ELSE 0 END), 0) AS overdue "
                "FROM tasks WHERE project = ?", (date.today().isoformat(), project)
            ).fetchone()
            return {name: int(row[name]) for name in ("open", "done", "overdue")}
        finally:
            connection.close()

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
