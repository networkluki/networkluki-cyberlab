"""Read-only machine snapshots and bounded log signals, without remote execution."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import threading

from .forensics import _check_cancel, _open_regular, _verify_unchanged

MAX_INPUT_BYTES = 1024 * 1024
MAX_LOG_LINES = 10_000
MAX_SAMPLES = 100
METRICS = ("cpu_count", "load_1m", "memory_total_bytes", "memory_available_bytes",
           "disk_total_bytes", "disk_free_bytes", "uptime_seconds")
PATTERNS = {
    "error": re.compile(r"\berror\b", re.IGNORECASE),
    "warning": re.compile(r"\b(?:warn|warning)\b", re.IGNORECASE),
    "failed": re.compile(r"\b(?:fail|failed|failure)\b", re.IGNORECASE),
    "authentication_failure": re.compile(r"\b(?:authentication fail(?:ed|ure)|failed password|invalid user)\b", re.IGNORECASE),
}


def _read_input(path: str, cancel: threading.Event | None) -> tuple[Path, bytes]:
    _check_cancel(cancel)
    with _open_regular(path) as (source, stream, before):
        if before.st_size > MAX_INPUT_BYTES:
            raise ValueError("Choose a file no larger than 1 MiB; export a smaller excerpt first.")
        data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError("Input exceeds the 1 MiB limit.")
        _check_cancel(cancel)
        _verify_unchanged(source, stream, before)
    return source, data


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or not value.isprintable():
        raise ValueError(f"Invalid snapshot {name}.")
    return value


def _number(value: object, name: str, maximum: int, *, integer: bool = False) -> int | float | None:
    if value is None:
        return None
    allowed = (int,) if integer else (int, float)
    if type(value) not in allowed or not 0 <= value <= maximum or not math.isfinite(value):
        raise ValueError(f"Invalid snapshot {name}.")
    return value


def _validate_snapshot(payload: object, *, imported: bool) -> dict:
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise ValueError("Snapshot must use schema_version 1.")
    if payload.get("source_kind") not in ("local_snapshot", "imported_snapshot"):
        raise ValueError("Unknown snapshot source_kind.")
    result = {"schema_version": 1, "source_kind": "imported_snapshot" if imported else "local_snapshot"}
    for field, maximum in (("hostname", 255), ("os", 200), ("captured_at", 64)):
        result[field] = _text(payload.get(field), field, maximum)
    try:
        captured = datetime.fromisoformat(result["captured_at"])
    except ValueError as exc:
        raise ValueError("Snapshot captured_at must be an ISO timestamp with a timezone.") from exc
    if captured.tzinfo is None or not 1970 <= captured.year <= 2100:
        raise ValueError("Snapshot captured_at requires a timezone and a year from 1970 to 2100.")
    for name in METRICS:
        if name not in payload:
            raise ValueError(f"Missing snapshot field: {name}; use null for unavailable metrics.")
        maximum = 1_048_576 if name == "cpu_count" else (1 << 60) if name.endswith("_bytes") else 3_200_000_000
        result[name] = _number(payload[name], name, maximum, integer=name == "cpu_count" or name.endswith("_bytes"))
    if result["cpu_count"] == 0:
        raise ValueError("Snapshot cpu_count must be positive or null.")
    for total, available in (("memory_total_bytes", "memory_available_bytes"), ("disk_total_bytes", "disk_free_bytes")):
        if (result[total] is None) != (result[available] is None):
            raise ValueError(f"Both {total} and {available} must be present or null.")
        if result[total] is not None and (result[total] <= 0 or result[available] > result[total]):
            raise ValueError(f"Invalid snapshot relationship: {available} / {total}.")
    age = (datetime.now(timezone.utc) - captured.astimezone(timezone.utc)).total_seconds()
    result["freshness"] = {"age_seconds": round(age), "status": "clock_ahead" if age < -300 else "stale" if age > 900 else "recent",
                           "stale_after_seconds": 900, "note": "Age uses the reported timestamp; it does not authenticate the source."}
    observations = []
    def signal(code: str, summary: str, evidence: dict, threshold: str) -> None:
        observations.append({"code": code, "type": "threshold_signal", "summary": summary,
                             "evidence": evidence, "threshold": threshold, "verified_vulnerability": False})
    if result["disk_total_bytes"] and (result["disk_total_bytes"] - result["disk_free_bytes"]) / result["disk_total_bytes"] >= .85:
        signal("disk_usage_high", "Reported filesystem usage meets the review threshold.",
               {key: result[key] for key in ("disk_total_bytes", "disk_free_bytes")}, "Used space >= 85%")
    if result["memory_total_bytes"] and result["memory_available_bytes"] / result["memory_total_bytes"] < .10:
        signal("memory_available_low", "Reported available memory is below the review threshold.",
               {key: result[key] for key in ("memory_total_bytes", "memory_available_bytes")}, "Available memory < 10%")
    if result["cpu_count"] and result["load_1m"] is not None and result["load_1m"] / result["cpu_count"] >= 1:
        signal("load_per_core_high", "Reported one-minute load per logical CPU meets the review threshold.",
               {key: result[key] for key in ("cpu_count", "load_1m")}, "One-minute load / logical CPUs >= 1; this is not CPU utilization")
    result["observations"] = observations
    result["provenance"] = "User-supplied snapshot; host identity and reported metrics are not independently verified." if imported else "Collected on the computer running this command, using unprivileged OS observations."
    result["limitations"] = "A point-in-time snapshot, not continuous monitoring or a security assessment. Null means unavailable. Threshold signals need investigation. The collector measures only its root filesystem; logical CPU count may not reflect container CPU quotas."
    return result


def collect_system_snapshot(cancel: threading.Event | None = None) -> dict:
    """Capture this computer only; never execute commands or contact another host."""
    _check_cancel(cancel)
    payload = {"schema_version": 1, "source_kind": "local_snapshot",
               "captured_at": datetime.now(timezone.utc).isoformat(), "hostname": socket.gethostname(),
               "os": f"{platform.system()} {platform.release()}", **dict.fromkeys(METRICS)}
    payload["cpu_count"] = os.cpu_count()
    try:
        payload["load_1m"] = os.getloadavg()[0]
    except (AttributeError, OSError):
        pass
    try:
        disk = shutil.disk_usage(Path.home().anchor or os.path.abspath(os.sep))
        payload.update(disk_total_bytes=disk.total, disk_free_bytes=disk.free)
    except OSError:
        pass
    if platform.system() == "Linux":
        try:
            with Path("/proc/meminfo").open(encoding="ascii") as stream:
                values = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+) kB$", stream.read(65536), re.MULTILINE))
            if len(values) == 2:
                payload.update(memory_total_bytes=int(values["MemTotal"]) * 1024,
                               memory_available_bytes=int(values["MemAvailable"]) * 1024)
        except (OSError, ValueError):
            pass
        try:
            with Path("/proc/uptime").open(encoding="ascii") as stream:
                payload["uptime_seconds"] = float(stream.read(128).split()[0])
        except (OSError, ValueError, IndexError):
            pass
    _check_cancel(cancel)
    return _validate_snapshot(payload, imported=False)


def import_system_snapshot(path: str, cancel: threading.Event | None = None) -> dict:
    """Validate imported claims and recompute observations instead of trusting supplied conclusions."""
    source, data = _read_input(path, cancel)
    def reject(value):
        raise ValueError(f"Invalid JSON constant: {value}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate snapshot field.")
            result[key] = value
        return result
    try:
        payload = json.loads(data.decode("utf-8"), parse_constant=reject, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Snapshot must be bounded, valid UTF-8 JSON.") from exc
    result = _validate_snapshot(payload, imported=True)
    result.update(source_path=str(source), sha256=hashlib.sha256(data).hexdigest())
    _check_cancel(cancel)
    return result


def analyze_log(path: str, cancel: threading.Event | None = None) -> dict:
    """Count literal log signals with line evidence; never infer an incident from keywords alone."""
    source, data = _read_input(path, cancel)
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Log excerpt must be UTF-8 text.") from exc
    lines = text.split("\n") if text else []
    if lines and not lines[-1]:
        lines.pop()
    if len(lines) > MAX_LOG_LINES:
        raise ValueError("Log excerpt exceeds 10,000 lines; choose a smaller excerpt.")
    counts = dict.fromkeys(PATTERNS, 0)
    samples = []
    matched = 0
    for number, line in enumerate(lines, 1):
        _check_cancel(cancel)
        categories = [category for category, pattern in PATTERNS.items() if pattern.search(line)]
        if not categories:
            continue
        matched += 1
        for category in categories:
            counts[category] += 1
        if len(samples) < MAX_SAMPLES:
            excerpt = line.removesuffix("\r")[:240]
            safe = "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in excerpt)
            samples.append({"line": number, "categories": categories, "evidence": safe[:240],
                            "truncated": len(line.removesuffix("\r")) > 240 or len(safe) > 240,
                            "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest()})
    return {"source_path": str(source), "sha256": hashlib.sha256(data).hexdigest(), "bytes_examined": len(data),
            "line_count": len(lines), "matched_lines": matched, "counts": counts, "samples": samples,
            "samples_omitted": matched - len(samples), "verified_vulnerability": False,
            "limitations": "Keyword matches are review signals, not confirmed errors or attacks. Only this UTF-8 excerpt was examined; categories overlap. Line numbers count LF delimiters. Evidence controls are escaped and excerpts are capped at 240 display characters."}
