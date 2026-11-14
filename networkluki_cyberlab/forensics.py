"""Bounded, read-only file inspection. Input files are never executed or loaded.

Hash consistency checks catch observable changes, but do not replace a forensic
image, write blocker, or independently recorded chain of custody.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import struct
import threading
from typing import BinaryIO, Iterator


MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_INSPECT_BYTES = 4 * 1024 * 1024
MAX_STRINGS = 200
MAX_STRING_CHARS = 240
MIN_STRING_CHARS = 6
CHUNK_BYTES = 1024 * 1024
SIGNATURE_BYTES = 4096


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise RuntimeError("Operation cancelled")


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def _open_regular(path: str) -> Iterator[tuple[Path, BinaryIO, os.stat_result]]:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Choose a valid file path.")
    # abspath preserves the last component for explicit symlink checks.
    source = Path(os.path.abspath(os.path.expanduser(path)))
    before = source.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise ValueError("Symbolic links are not accepted; select the original file.")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Only regular files can be analyzed.")
    if before.st_size > MAX_FILE_BYTES:
        raise ValueError("File exceeds the MVP limit of 2 GiB.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    # Prevent blocking if a regular path is replaced with a FIFO before open.
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("Only regular files can be analyzed.")
        if _snapshot(opened) != _snapshot(before):
            raise RuntimeError("File changed before analysis; select it again.")
        # On Windows O_NOFOLLOW is unavailable; the lstat/fstat check is best
        # effort and does not establish a symlink-free parent directory chain.
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            yield source, stream, opened
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_unchanged(source: Path, stream: BinaryIO, before: os.stat_result) -> None:
    after = os.fstat(stream.fileno())
    try:
        current_path = source.lstat()
    except OSError as exc:
        raise RuntimeError("File path changed during analysis; result discarded.") from exc
    if _snapshot(after) != _snapshot(before) or _snapshot(current_path) != _snapshot(before):
        raise RuntimeError("File changed during analysis; result discarded.")


def detect_type(prefix: bytes) -> str:
    """Return a signature hint, not a guarantee that a file is valid or safe."""
    if prefix.startswith(b"\x7fELF"):
        return "ELF"
    if prefix.startswith(b"MZ"):
        if len(prefix) >= 64:
            pe_offset = struct.unpack_from("<I", prefix, 60)[0]
            if pe_offset >= 64 and prefix[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                return "PE"
        return "MZ/DOS or PE candidate"
    mach_signatures = {
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit (big endian)",
        b"\xce\xfa\xed\xfe": "Mach-O 32-bit (little endian)",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit (big endian)",
        b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (little endian)",
        b"\xca\xfe\xba\xbe": "Mach-O fat or Java class candidate",
        b"\xbe\xba\xfe\xca": "Mach-O fat (little endian) candidate",
        b"\xca\xfe\xba\xbf": "Mach-O fat64 (big endian) candidate",
        b"\xbf\xba\xfe\xca": "Mach-O fat64 (little endian) candidate",
    }
    if prefix[:4] in mach_signatures:
        return mach_signatures[prefix[:4]]
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP container"
    if prefix.startswith(b"%PDF-"):
        return "PDF"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    return "Unknown"


def _metadata(source: Path, info: os.stat_result, prefix: bytes) -> dict:
    return {
        "source_path": str(source),
        "name": source.name,
        "size_bytes": info.st_size,
        "modified_utc": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
        "detected_type": detect_type(prefix[:SIGNATURE_BYTES]),
        "type_detection": "Magic-byte hint; file structure and safety are not validated.",
        "file_changed": False,
        "consistency_check": "Opened-file and path metadata matched before and after inspection.",
    }


def analyze_file(path: str, cancel: threading.Event | None = None) -> dict:
    """Hash one regular file in bounded chunks; discard detectably changed files."""
    _check_cancel(cancel)
    with _open_regular(path) as (source, stream, before):
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        count = 0
        prefix = b""
        while True:
            _check_cancel(cancel)
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_FILE_BYTES or count > before.st_size:
                raise RuntimeError("File grew during analysis; result discarded.")
            if not prefix:
                prefix = chunk[:SIGNATURE_BYTES]
            sha256.update(chunk)
            sha512.update(chunk)
        _check_cancel(cancel)
        if count != before.st_size:
            raise RuntimeError("File size changed during analysis; result discarded.")
        _verify_unchanged(source, stream, before)
        result = _metadata(source, before, prefix)
        result.update({
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
            "bytes_hashed": count,
        })
        return result


def _strings(data: bytes, cancel: threading.Event | None) -> list[dict]:
    found: list[dict] = []
    run_start = 0
    run_length = 0
    preview = bytearray()

    def finish() -> None:
        if run_length >= MIN_STRING_CHARS:
            found.append({
                "offset": run_start,
                "text": preview.decode("ascii"),
                "length_bytes": run_length,
                "preview_truncated": run_length > MAX_STRING_CHARS,
            })

    for offset, byte in enumerate(data):
        if offset % 65536 == 0:
            _check_cancel(cancel)
        if 32 <= byte <= 126:
            if run_length == 0:
                run_start = offset
            run_length += 1
            if len(preview) < MAX_STRING_CHARS:
                preview.append(byte)
        else:
            finish()
            if len(found) >= MAX_STRINGS:
                break
            run_length = 0
            preview.clear()
    else:
        finish()
    return found[:MAX_STRINGS]


def _hex_preview(data: bytes) -> str:
    lines = []
    for offset in range(0, min(len(data), 512), 16):
        block = data[offset:offset + 16]
        hexadecimal = " ".join(f"{byte:02x}" for byte in block)
        printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in block)
        lines.append(f"{offset:08x}  {hexadecimal:<47}  |{printable}|")
    return "\n".join(lines)


def inspect_binary(path: str, cancel: threading.Event | None = None) -> dict:
    """Inspect a bounded prefix without loading, importing, or executing it."""
    _check_cancel(cancel)
    with _open_regular(path) as (source, stream, before):
        remaining = min(before.st_size, MAX_INSPECT_BYTES)
        chunks = []
        while remaining:
            _check_cancel(cancel)
            chunk = stream.read(min(CHUNK_BYTES, remaining))
            if not chunk:
                raise RuntimeError("File size changed during analysis; result discarded.")
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        extracted = _strings(data, cancel)
        _check_cancel(cancel)
        _verify_unchanged(source, stream, before)
        result = _metadata(source, before, data)
        result.update({
            "analysis": "Static signature, hexadecimal and ASCII preview; not a disassembler.",
            "bytes_examined": len(data),
            "truncated": before.st_size > len(data),
            "strings": extracted,
            "strings_limit": MAX_STRINGS,
            "string_min_length": MIN_STRING_CHARS,
            "strings_note": "First 200 printable ASCII runs only; final run may end at the inspection boundary.",
            "hex_preview": _hex_preview(data),
        })
        return result
