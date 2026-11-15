"""Bounded project metadata inventory and non-executing Python source triage."""

from __future__ import annotations

import ast
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import stat
import threading

from .forensics import _check_cancel, _open_regular, _verify_unchanged


MAX_PROJECT_ENTRIES = 2000
MAX_PROJECT_DEPTH = 32
MAX_SOURCE_BYTES = 512 * 1024
MAX_AST_NODES = 30000
MAX_FINDINGS = 100
SKIP_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "build", "dist",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".next", "target",
})
LANGUAGES = {
    ".py": "Python", ".pyw": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".php": "PHP",
    ".c": "C", ".h": "C/C++ headers", ".cc": "C++", ".cpp": "C++", ".hpp": "C++",
    ".cs": "C#", ".java": "Java", ".kt": "Kotlin", ".swift": "Swift", ".lua": "Lua",
    ".rb": "Ruby", ".html": "HTML", ".css": "CSS", ".sql": "SQL",
}
MANIFESTS = frozenset({
    "pyproject.toml", "requirements.txt", "package.json", "go.mod", "Cargo.toml",
    "composer.json", "Gemfile", "Makefile", "CMakeLists.txt", "pom.xml", "build.gradle",
})
RULES = ("python_shell_true", "python_dynamic_execution", "python_tls_verify_false", "literal_credential")
_CREDENTIAL_NAME = re.compile(r"(?:^|_)(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)(?:$|_)")
_DIRECTORY_FDS = (os.name == "posix" and hasattr(os, "O_NOFOLLOW")
                  and hasattr(os, "O_DIRECTORY") and os.scandir in os.supports_fd
                  and os.open in os.supports_dir_fd)


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def inspect_project(path: str, cancel: threading.Event | None = None) -> dict:
    """Count metadata only; never run Git, build tools, plugins or project code."""
    _check_cancel(cancel)
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Choose a valid local project directory.")
    root = Path(os.path.abspath(os.path.expanduser(path)))
    info = root.lstat()
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("Choose an ordinary project directory, not a symbolic link or junction.")
    # Reject visible links in the user-selected path as well as inside the tree.
    if any(_is_link(parent.lstat()) for parent in root.parents):
        raise ValueError("Project directory parents cannot be symbolic links or junctions.")
    languages: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    manifests: list[str] = []
    state = {"entries_examined": 0, "files_count": 0, "directories_count": 0,
             "readme_found": False, "tests_found": False, "gitignore_found": False,
             "truncated": False, "manifest_list_truncated": False}

    def visit(directory: Path, relative: Path, depth: int, descriptor: int | None = None) -> None:
        _check_cancel(cancel)
        try:
            with os.scandir(descriptor if descriptor is not None else directory) as entries:
                for entry in entries:
                    _check_cancel(cancel)
                    if state["entries_examined"] >= MAX_PROJECT_ENTRIES:
                        state["truncated"] = True
                        return
                    state["entries_examined"] += 1
                    child = directory / entry.name
                    try:
                        # Windows DirEntry.stat caches zero device/inode values.
                        # Use fresh non-following path metadata on the fallback
                        # so both identity checks below describe real file IDs.
                        entry_info = entry.stat(follow_symlinks=False) if descriptor is not None else child.lstat()
                    except OSError:
                        skipped["unreadable_entries"] += 1
                        continue
                    if _is_link(entry_info):
                        skipped["links_or_junctions"] += 1
                        continue
                    item_relative = relative / entry.name
                    if stat.S_ISDIR(entry_info.st_mode):
                        if entry.name in SKIP_DIRECTORIES:
                            skipped["excluded_directories"] += 1
                            continue
                        state["directories_count"] += 1
                        if entry.name.lower() in {"test", "tests"}:
                            state["tests_found"] = True
                        if depth >= MAX_PROJECT_DEPTH:
                            skipped["depth_limit_directories"] += 1
                            state["truncated"] = True
                            continue
                        if descriptor is not None:
                            child_fd = None
                            try:
                                child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                                   dir_fd=descriptor)
                                opened = os.fstat(child_fd)
                                if (opened.st_dev, opened.st_ino) != (entry_info.st_dev, entry_info.st_ino):
                                    skipped["changed_directories"] += 1
                                    continue
                                visit(child, item_relative, depth + 1, child_fd)
                            except OSError:
                                skipped["unreadable_directories"] += 1
                            finally:
                                if child_fd is not None:
                                    os.close(child_fd)
                        else:
                            current = child.lstat()
                            if _is_link(current) or (current.st_dev, current.st_ino) != (entry_info.st_dev, entry_info.st_ino):
                                skipped["changed_directories"] += 1
                                continue
                            visit(child, item_relative, depth + 1)
                        if state["entries_examined"] >= MAX_PROJECT_ENTRIES:
                            state["truncated"] = True
                            return
                    elif stat.S_ISREG(entry_info.st_mode):
                        state["files_count"] += 1
                        lower = entry.name.lower()
                        if lower == "readme" or lower.startswith("readme."):
                            state["readme_found"] = True
                        if lower.startswith("test_") or lower.endswith(("_test.py", "_test.go", ".test.js", ".spec.ts")):
                            state["tests_found"] = True
                        if entry.name == ".gitignore":
                            state["gitignore_found"] = True
                        if entry.name in MANIFESTS:
                            if len(manifests) < 100:
                                manifests.append(item_relative.as_posix())
                            else:
                                state["manifest_list_truncated"] = True
                        language = LANGUAGES.get(Path(entry.name).suffix.lower())
                        if language:
                            languages[language] += 1
                    else:
                        skipped["special_files"] += 1
        except OSError:
            skipped["unreadable_directories"] += 1

    root_fd = None
    try:
        if _DIRECTORY_FDS:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened = os.fstat(root_fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise RuntimeError("Project directory changed before inspection.")
        visit(root, Path(), 0, root_fd)
    finally:
        if root_fd is not None:
            os.close(root_fd)
    _check_cancel(cancel)
    return {
        "kind": "project_inventory", "name": root.name, "source_path": str(root), **state,
        "languages": dict(sorted(languages.items())), "manifests": sorted(manifests),
        "skipped": dict(sorted(skipped.items())), "entry_limit": MAX_PROJECT_ENTRIES,
        "executed_project_code": False,
        "limitations": [
            "Only directory-entry metadata was inspected; file contents and Git configuration were not read.",
            "Presence indicators describe observed entries, not whether a project is complete or secure.",
            "Excluded, inaccessible and deeper directories are not inspected; counts are not repository totals.",
            "This is not an atomic filesystem snapshot. Concurrent changes can affect observed counts.",
        ],
    }


def _call_name(node: ast.expr) -> str:
    parts = []
    while isinstance(node, ast.Attribute) and len(parts) < 8:
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))[:100] or "call"


def _credential_target(node: ast.expr) -> str | None:
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
    if name is None:
        return None
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return name[:100] if _CREDENTIAL_NAME.search(normalized) else None


def inspect_source(path: str, cancel: threading.Event | None = None) -> dict:
    """Review Python syntax for four signals; findings always require human review."""
    _check_cancel(cancel)
    with _open_regular(path) as (source, stream, before):
        if source.suffix.lower() not in {".py", ".pyw"}:
            raise ValueError("Source review currently supports Python .py and .pyw files only.")
        if before.st_size > MAX_SOURCE_BYTES:
            raise ValueError("Source file exceeds the 512 KiB review limit.")
        data = stream.read(MAX_SOURCE_BYTES + 1)
        _check_cancel(cancel)
        if len(data) > MAX_SOURCE_BYTES or len(data) != before.st_size:
            raise RuntimeError("Source file changed or exceeded the review limit.")
        _verify_unchanged(source, stream, before)
    try:
        text = data.decode("utf-8-sig")
        tree = ast.parse(text, filename="selected-source.py")
    except (UnicodeError, SyntaxError, RecursionError, MemoryError):
        # SyntaxError can embed source text (including credentials); do not return it.
        raise ValueError("Source must be valid UTF-8 Python within parser complexity limits.") from None
    findings: list[dict] = []
    nodes = 0
    truncated = False

    def finding(node: ast.AST, rule: str, title: str, evidence: str, explanation: str) -> None:
        nonlocal truncated
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            return
        findings.append({"rule": rule, "title": title, "classification": "review_required",
                         "line": node.lineno, "evidence": evidence[:240], "explanation": explanation})

    for node in ast.walk(tree):
        _check_cancel(cancel)
        nodes += 1
        if nodes > MAX_AST_NODES:
            truncated = True
            break
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                finding(node, "python_dynamic_execution", "Dynamic execution call",
                        f"{name}(...) — arguments omitted",
                        "Review where input originates and whether executing it is necessary. A locally defined function can share this name.")
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    finding(node, "python_shell_true", "Shell execution option enabled",
                            f"{name}(..., shell=True) — other arguments omitted",
                            "Review command construction and untrusted input. The call's behavior depends on the actual function.")
                if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    finding(node, "python_tls_verify_false", "Verification option disabled",
                            f"{name}(..., verify=False) — other arguments omitted",
                            "For HTTP clients this can disable TLS certificate checks. Confirm the actual API and trust boundary.")
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                for target in targets:
                    name = _credential_target(target)
                    if name is not None:
                        finding(node, "literal_credential", "Credential-like literal assignment",
                                f"{name} = [literal value redacted]",
                                "Review whether this is a real credential, a placeholder or a test fixture. Literal values are not included in this report.")
    _check_cancel(cancel)
    findings.sort(key=lambda item: (item["line"], item["rule"]))
    return {
        "kind": "source_review", "name": source.name, "source_path": str(source), "language": "Python",
        "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
        "lines_in_file": len(text.splitlines()), "ast_nodes_examined": min(nodes, MAX_AST_NODES),
        "rules_checked": list(RULES), "findings": findings, "finding_count": len(findings),
        "truncated": truncated, "executed_project_code": False,
        "limitations": [
            "These syntax signals are review candidates, not verified vulnerabilities or an exhaustive security audit.",
            "No imports, functions, tests, project configuration or supplied code were executed.",
            "Only selected direct calls and literal assignments are checked; aliases and data flow are not resolved.",
            "Evidence contains structural summaries and line numbers; argument and credential values are omitted.",
        ],
    }
