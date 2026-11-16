"""Bounded Python AST observations; source is never imported or executed.

These rules identify constructs that need human review. They do not establish
whether an input is attacker-controlled or whether a vulnerability exists.
"""

from __future__ import annotations

import ast
import hashlib
import threading

from .forensics import _check_cancel, _open_regular, _verify_unchanged


MAX_SOURCE_BYTES = 256 * 1024
MAX_AST_NODES = 40_000
MAX_AST_DEPTH = 100
MAX_FINDINGS = 200

_RULES = {
    "PY001": {
        "title": "Dynamic Python execution",
        "severity": "high",
        "explanation": "An eval or exec call can execute Python supplied through its input. Input trust is not established by this check.",
        "remediation": "Use a constrained parser or explicit operation mapping; inspect every source of the input before retaining dynamic execution.",
    },
    "PY002": {
        "title": "Subprocess launched through a shell",
        "severity": "high",
        "explanation": "A subprocess call explicitly enables shell=True. Constructed shell input may allow command injection.",
        "remediation": "Prefer a validated argument list with shell=False, and check the executable and its arguments against the intended operation.",
    },
    "PY003": {
        "title": "Pickle deserialization",
        "severity": "high",
        "explanation": "Loading pickle data may execute arbitrary code. This check does not establish where the serialized data originated.",
        "remediation": "Do not unpickle untrusted data; use a non-executable data format with schema validation where possible.",
    },
    "PY004": {
        "title": "Unverified TLS context",
        "severity": "medium",
        "explanation": "This call requests an SSL context without certificate verification. The check does not establish how the context is subsequently used.",
        "remediation": "Use ssl.create_default_context and configure the intended certificate authority rather than disabling certificate verification.",
    },
    "PY005": {
        "title": "Requests certificate verification disabled",
        "severity": "medium",
        "explanation": "A requests API call explicitly sets verify=False, which disables certificate verification for HTTPS connections.",
        "remediation": "Retain certificate verification or supply the intended CA bundle; inspect whether this call can reach HTTPS destinations.",
    },
}

_SUBPROCESS_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}
_REQUESTS_CALLS = {
    f"requests.{name}" for name in
    ("request", "get", "post", "put", "patch", "delete", "head", "options")
}
_LIMITATIONS = [
    "Pattern matches require review and are not confirmed vulnerabilities; input trust and exploitability are not analyzed.",
    "Only five Python AST rules are checked. A result with no findings does not establish that the source is secure.",
    "Simple explicit imports and aliases are recognized. Names rebound or bound differently anywhere in the file are conservatively skipped; scope and data flow are not modeled.",
    "Dynamic imports, star imports, wrappers, object methods, alias assignments, positional configuration and computed keyword values may be missed.",
    "The source is parsed using the running Python interpreter's grammar. Only UTF-8 .py and .pyw regular files up to 256 KiB are accepted.",
    "Source text, string literals and snippets are not retained in the result; paths, line positions and a SHA-256 digest are retained.",
]


def _bounded_nodes(tree: ast.AST, cancel: threading.Event | None) -> list[ast.AST]:
    """Walk iteratively so unusual source cannot recurse through the analyzer."""
    nodes: list[ast.AST] = []
    pending = [(tree, 0)]
    while pending:
        _check_cancel(cancel)
        node, depth = pending.pop()
        if depth > MAX_AST_DEPTH or len(nodes) >= MAX_AST_NODES:
            raise ValueError("Source exceeds the AST complexity limit.")
        nodes.append(node)
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return nodes


def _bindings(nodes: list[ast.AST]) -> tuple[dict[str, str], set[str]]:
    """Resolve only unambiguous import bindings; skip conflicting bindings."""
    imported: dict[str, set[str]] = {}
    rebound: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                target = alias.name if alias.asname else alias.name.split(".")[0]
                imported.setdefault(name, set()).add(target)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.name != "*":
                    imported.setdefault(alias.asname or alias.name, set()).add(
                        f"{node.module}.{alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            rebound.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            rebound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            rebound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            rebound.add(node.rest)
    aliases = {
        name: next(iter(targets)) for name, targets in imported.items()
        if name not in rebound and len(targets) == 1
    }
    return aliases, rebound | set(imported)


def _call_name(node: ast.AST, aliases: dict[str, str], bound: set[str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    if node.id in aliases:
        root = aliases[node.id]
    elif node.id in ("eval", "exec") and node.id not in bound:
        root = f"builtins.{node.id}"
    else:
        return ""
    return ".".join((root, *reversed(parts)))


def _literal_keyword(call: ast.Call, name: str, value: bool) -> bool:
    return any(
        keyword.arg == name and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is value
        for keyword in call.keywords
    )


def review_python(path: str, *, cancel: threading.Event | None = None) -> dict:
    """Inspect one UTF-8 Python source file and return reviewable observations."""
    _check_cancel(cancel)
    with _open_regular(path) as (source, stream, before):
        if source.suffix.lower() not in (".py", ".pyw"):
            raise ValueError("Choose a Python source file with a .py or .pyw extension.")
        if before.st_size > MAX_SOURCE_BYTES:
            raise ValueError("Python source exceeds the 256 KiB limit.")
        raw = stream.read(MAX_SOURCE_BYTES + 1)
        _check_cancel(cancel)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError("Python source exceeds the 256 KiB limit.")
        if len(raw) != before.st_size:
            raise RuntimeError("File size changed during review; result discarded.")
        try:
            source_text = raw.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("Python source must be valid UTF-8 text.") from exc
        try:
            tree = ast.parse(source_text)
        except SyntaxError as exc:
            # Do not echo parser messages: they can contain source string values.
            raise ValueError(
                f"Python source cannot be parsed at line {exc.lineno or 0}, "
                f"column {exc.offset or 0}; check syntax and interpreter compatibility."
            ) from None
        except (RecursionError, MemoryError) as exc:
            raise ValueError("Source exceeds the parser complexity limit.") from exc
        nodes = _bounded_nodes(tree, cancel)
        aliases, bound = _bindings(nodes)
        findings: list[dict] = []
        total_findings = 0
        # Source order ensures bounded output consistently retains earliest findings.
        calls = sorted((node for node in nodes if isinstance(node, ast.Call)),
                       key=lambda node: (node.lineno, node.col_offset))
        for call in calls:
            _check_cancel(cancel)
            name = _call_name(call.func, aliases, bound)
            rule = ""
            if name in ("builtins.eval", "builtins.exec"):
                rule = "PY001"
            elif name in _SUBPROCESS_CALLS and _literal_keyword(call, "shell", True):
                rule = "PY002"
            elif name in ("pickle.load", "pickle.loads"):
                rule = "PY003"
            elif name == "ssl._create_unverified_context":
                rule = "PY004"
            elif name in _REQUESTS_CALLS and _literal_keyword(call, "verify", False):
                rule = "PY005"
            if rule:
                total_findings += 1
                if len(findings) < MAX_FINDINGS:
                    findings.append({
                        "rule_id": rule,
                        **_RULES[rule],
                        "status": "review_required",
                        "confidence": "syntax_pattern_match",
                        "line": call.lineno,
                        "column": call.col_offset + 1,
                    })
        _check_cancel(cancel)
        _verify_unchanged(source, stream, before)
        return {
            "name": source.name,
            "source_path": str(source),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "language": "Python",
            "assessment": "Review required" if total_findings else "No supported patterns found; security is not established",
            "findings": findings,
            "total_findings": total_findings,
            "findings_truncated": total_findings > MAX_FINDINGS,
            "column_unit": "1-based UTF-8 byte offset",
            "rules_checked": list(_RULES),
            "limitations": list(_LIMITATIONS),
        }
