"""Deterministic forensic tests with generated local fixtures only."""

import hashlib
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from networkluki_cyberlab import forensics


class ForensicTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, content=b"example", name="sample.bin"):
        path = self.root / name
        path.write_bytes(content)
        return path

    def test_hashes_match_reference_and_no_writes(self):
        content = b"\x7fELF\x00" + bytes(range(256)) * 8193
        path = self.fixture(content)
        before = path.stat().st_mtime_ns
        result = forensics.analyze_file(str(path))
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["sha512"], hashlib.sha512(content).hexdigest())
        self.assertEqual(result["size_bytes"], len(content))
        self.assertEqual(result["bytes_hashed"], len(content))
        self.assertEqual(result["detected_type"], "ELF")
        self.assertFalse(result["file_changed"])
        self.assertEqual(path.stat().st_mtime_ns, before)
        self.assertEqual(path.read_bytes(), content)

    def test_empty_file(self):
        result = forensics.analyze_file(str(self.fixture(b"")))
        self.assertEqual(result["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(result["size_bytes"], 0)
        self.assertEqual(result["detected_type"], "Unknown")

    def test_rejects_directory_and_invalid_paths(self):
        for path in (str(self.root), "", "\x00bad", None):
            with self.subTest(path=path), self.assertRaises(ValueError):
                forensics.analyze_file(path)

    def test_rejects_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            forensics.analyze_file(str(self.root / "missing.bin"))

    def test_rejects_symbolic_link(self):
        target = self.fixture()
        link = self.root / "link.bin"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable for this user/platform")
        with self.assertRaises(ValueError):
            forensics.analyze_file(str(link))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_rejects_fifo_without_blocking(self):
        path = self.root / "pipe"
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            forensics.analyze_file(str(path))

    def test_file_size_cap(self):
        path = self.fixture(b"123456")
        with mock.patch.object(forensics, "MAX_FILE_BYTES", 5):
            with self.assertRaisesRegex(ValueError, "2 GiB"):
                forensics.analyze_file(str(path))

    def test_observable_change_discards_evidence(self):
        path = self.fixture()
        with forensics._open_regular(str(path)) as (source, stream, before):
            with path.open("ab") as writer:
                writer.write(b"changed")
            with self.assertRaisesRegex(RuntimeError, "changed"):
                forensics._verify_unchanged(source, stream, before)

    def test_windows_ctime_semantics_preserve_descriptor_change_detection(self):
        path = self.fixture()
        actual = path.lstat()
        values = {field: getattr(actual, field) for field in forensics._SNAPSHOT_FIELDS}
        values["st_birthtime_ns"] = 100
        by_path = SimpleNamespace(**(values | {"st_ctime_ns": 100}))
        by_handle = SimpleNamespace(**(values | {"st_ctime_ns": 200}))
        changed_handle = SimpleNamespace(**(values | {"st_ctime_ns": 300}))
        with (
            mock.patch.object(forensics, "_IS_WINDOWS", True),
            mock.patch.object(Path, "lstat", return_value=by_path),
            mock.patch.object(forensics.os, "fstat", side_effect=[by_handle, by_handle, changed_handle]),
        ):
            with forensics._open_regular(str(path)) as (source, stream, before):
                forensics._verify_unchanged(source, stream, before)
                with self.assertRaisesRegex(RuntimeError, "File changed during analysis"):
                    forensics._verify_unchanged(source, stream, before)

    def test_change_before_open_is_rejected_with_numeric_diagnostics(self):
        path = self.fixture()
        original_open = os.open

        def change_then_open(*args, **kwargs):
            path.write_bytes(b"replacement content")
            return original_open(*args, **kwargs)

        with mock.patch.object(forensics.os, "open", side_effect=change_then_open):
            with self.assertRaisesRegex(RuntimeError, r"st_size=7->19"):
                forensics.analyze_file(str(path))

    def test_cancelled_before_io(self):
        cancel = threading.Event()
        cancel.set()
        for operation in (forensics.analyze_file, forensics.inspect_binary):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                    operation(str(self.root / "does-not-exist"), cancel)

    def test_signature_hints(self):
        pe = bytearray(132)
        pe[:2] = b"MZ"
        pe[60:64] = (128).to_bytes(4, "little")
        pe[128:] = b"PE\0\0"
        cases = [
            (bytes(pe), "PE"),
            (b"MZ", "MZ/DOS or PE candidate"),
            (b"\x7fELF", "ELF"),
            (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (little endian)"),
            (b"\xca\xfe\xba\xbe", "Mach-O fat or Java class candidate"),
            (b"PK\x03\x04", "ZIP container"),
            (b"%PDF-1.7", "PDF"),
            (b"\xff\xd8\xff", "JPEG"),
            (b"\x89PNG\r\n\x1a\n", "PNG"),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(forensics.detect_type(data), expected)

    def test_binary_offsets_hex_and_long_string(self):
        path = self.fixture(b"\x7fELF\0Hello world\0" + b"A" * 300 + b"\0")
        result = forensics.inspect_binary(str(path))
        first, second = result["strings"]
        self.assertEqual(first, {"offset": 5, "text": "Hello world", "length_bytes": 11, "preview_truncated": False})
        self.assertEqual(second["offset"], 17)
        self.assertEqual(len(second["text"]), 240)
        self.assertEqual(second["length_bytes"], 300)
        self.assertTrue(second["preview_truncated"])
        self.assertIn("00000000  7f 45 4c 46 00", result["hex_preview"])
        self.assertFalse(result["truncated"])

    def test_binary_preview_bounds(self):
        data = b"abcdef\0" * 210 + b"\0" * (forensics.MAX_INSPECT_BYTES + 1)
        result = forensics.inspect_binary(str(self.fixture(data)))
        self.assertEqual(len(result["strings"]), 200)
        self.assertEqual(result["bytes_examined"], forensics.MAX_INSPECT_BYTES)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["hex_preview"].splitlines()), 32)


if __name__ == "__main__":
    unittest.main()
