"""Bounded text utilities; inputs are never evaluated or written to source files."""

from __future__ import annotations

import difflib
import hashlib
import json
import threading
from collections.abc import Iterator

MAX_INPUT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_DIFF_LINES = 1000


class _Number(str):
    """Keep validated JSON number tokens exact, including large integers."""


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise RuntimeError("Operation cancelled")


def _input(text: str, name: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError(f"{name} must be text")
    if len(text) > MAX_INPUT_BYTES:
        raise ValueError(f"{name} exceeds the 128 KiB limit")
    try:
        data = text.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{name} must contain valid Unicode") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"{name} exceeds the 128 KiB limit")
    return data


def _depth_guard(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON exceeds the maximum nesting depth of 64")
        elif character in "]}":
            depth -= 1


def _constant(value: str) -> None:
    raise ValueError("NaN and Infinity are not valid JSON numbers")


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object keys are not accepted")
        result[key] = value
    return result


def _pretty(value: object, depth: int = 0) -> Iterator[str]:
    if isinstance(value, _Number):
        yield str(value)
    elif isinstance(value, (dict, list)):
        is_object = isinstance(value, dict)
        opening, closing = ("{", "}") if is_object else ("[", "]")
        yield opening
        if value:
            yield "\n"
            pairs = value.items() if is_object else enumerate(value)
            for index, (key, item) in enumerate(pairs):
                if index:
                    yield ",\n"
                yield "  " * (depth + 1)
                if is_object:
                    yield json.dumps(key, ensure_ascii=False) + ": "
                yield from _pretty(item, depth + 1)
            yield "\n" + "  " * depth
        yield closing
    else:
        yield json.dumps(value, ensure_ascii=False, allow_nan=False)


def _bounded_join(parts: Iterator[str], cancel: threading.Event | None) -> str:
    output = []
    size = 0
    for part in parts:
        _check_cancel(cancel)
        try:
            size += len(part.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError("JSON contains an unpaired Unicode surrogate") from exc
        if size > MAX_OUTPUT_BYTES:
            raise ValueError("Formatted output exceeds the 256 KiB limit; use a smaller input")
        output.append(part)
    return "".join(output)


def format_json(text: str, *, cancel: threading.Event | None = None) -> dict:
    """Validate and format JSON without rounding number tokens or dropping keys."""
    _check_cancel(cancel)
    data = _input(text, "JSON input")
    _depth_guard(text)
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_constant,
                           parse_int=_Number, parse_float=_Number)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc
    formatted = _bounded_join(_pretty(value), cancel)
    root_type = ("number" if isinstance(value, _Number) else "null" if value is None
                 else "boolean" if isinstance(value, bool) else "object" if isinstance(value, dict)
                 else "array" if isinstance(value, list) else "string")
    return {
        "name": "JSON formatting", "formatted": formatted,
        "input_sha256": hashlib.sha256(data).hexdigest(), "input_bytes": len(data),
        "root_type": root_type,
        "limitations": ["Syntax validation does not validate an application schema.",
                        "Formatted content is stored in local history and may contain secrets.",
                        "Duplicate keys, nonstandard numbers and unpaired surrogates are rejected."],
    }


def _diff_parts(before: list[str], after: list[str]) -> Iterator[str]:
    # difflib preserves missing final newlines; make them explicit for the reader.
    for part in difflib.unified_diff(before, after, fromfile="before", tofile="after", n=3):
        yield part
        if not part.endswith("\n"):
            yield "\n\\ No newline at end of file\n"


def compare_text(before: str, after: str, *, cancel: threading.Event | None = None) -> dict:
    """Return a bounded unified diff, including final-newline differences."""
    _check_cancel(cancel)
    before_data = _input(before, "Before input")
    after_data = _input(after, "After input")
    # Split only on LF: other line separators and CR must remain observable data.
    def lines(text: str) -> list[str]:
        chunks = text.split("\n")
        return [chunk + "\n" for chunk in chunks[:-1]] + ([chunks[-1]] if chunks[-1] else [])
    before_lines, after_lines = lines(before), lines(after)
    if max(len(before_lines), len(after_lines)) > MAX_DIFF_LINES:
        raise ValueError("Text comparison accepts at most 1000 lines per input")
    result = _bounded_join(_diff_parts(before_lines, after_lines), cancel)
    _check_cancel(cancel)
    return {
        "name": "Text comparison", "diff": result, "changed": before != after,
        "before_sha256": hashlib.sha256(before_data).hexdigest(),
        "after_sha256": hashlib.sha256(after_data).hexdigest(),
        "before_bytes": len(before_data), "after_bytes": len(after_data),
        "limitations": ["A textual diff does not establish semantic equivalence or correctness.",
                        "Diff content is stored in local history and may contain secrets.",
                        "Neither input is modified and this diff is never applied automatically."],
    }
