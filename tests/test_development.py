"""Generated fixtures for bounded, non-executing development inspection."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from networkluki_cyberlab import development


class DevelopmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def source(self, text, name="sample.py"):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_inventory_reads_no_file_contents_and_skips_dependencies(self):
        self.source("raise RuntimeError('must never run')\n")
        self.source("untrusted build manifest", "pyproject.toml")
        self.source("documentation", "README.md")
        self.source("ignored", ".gitignore")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_example.py").write_text("raise AssertionError()")
        for name in (".git", ".venv", "node_modules", "build", "dist"):
            (self.root / name).mkdir()
            (self.root / name / "hidden.py").write_text("raise AssertionError()")
        with patch.object(Path, "read_text", side_effect=AssertionError("read content")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("read content")):
            result = development.inspect_project(str(self.root))
        self.assertEqual(result["languages"], {"Python": 2})
        self.assertEqual(result["manifests"], ["pyproject.toml"])
        self.assertTrue(result["readme_found"])
        self.assertTrue(result["tests_found"])
        self.assertTrue(result["gitignore_found"])
        self.assertEqual(result["skipped"]["excluded_directories"], 5)
        self.assertFalse(result["executed_project_code"])

    def test_inventory_does_not_follow_directory_or_file_links(self):
        external = self.root / "outside"
        external.mkdir()
        (external / "secret.py").write_text("password = 'unseen'")
        project = self.root / "project"
        project.mkdir()
        try:
            (project / "linked").symlink_to(external, target_is_directory=True)
            (project / "linked.py").symlink_to(external / "secret.py")
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        result = development.inspect_project(str(project))
        self.assertEqual(result["languages"], {})
        self.assertEqual(result["files_count"], 0)
        self.assertEqual(result["skipped"]["links_or_junctions"], 2)
        with self.assertRaises(ValueError):
            development.inspect_project(str(project / "linked"))

    def test_fallback_traverses_when_cached_entry_identity_is_zero(self):
        nested = self.root / "src" / "tests"
        nested.mkdir(parents=True)
        (nested.parent / "main.py").write_text("pass")
        (nested / "test_example.py").write_text("pass")
        original_scandir = os.scandir

        def windows_entry(entry):
            def cached_stat(*, follow_symlinks=True):
                current = entry.stat(follow_symlinks=follow_symlinks)
                return SimpleNamespace(st_mode=current.st_mode, st_dev=0, st_ino=0,
                                       st_nlink=0, st_file_attributes=getattr(current, "st_file_attributes", 0))
            return SimpleNamespace(name=entry.name, stat=cached_stat)

        @contextmanager
        def windows_scandir(path):
            with original_scandir(path) as entries:
                yield (windows_entry(entry) for entry in entries)

        with patch.object(development, "_DIRECTORY_FDS", False), \
             patch.object(development.os, "scandir", windows_scandir):
            result = development.inspect_project(str(self.root))
            with patch.object(development, "MAX_PROJECT_DEPTH", 1):
                bounded = development.inspect_project(str(self.root))
        self.assertEqual(result["languages"], {"Python": 2})
        self.assertEqual(result["directories_count"], 2)
        self.assertEqual(result["skipped"].get("changed_directories", 0), 0)
        self.assertTrue(result["tests_found"])
        self.assertEqual(bounded["languages"], {"Python": 1})
        self.assertTrue(bounded["truncated"])
        self.assertEqual(bounded["skipped"]["depth_limit_directories"], 1)

    def test_fallback_rejects_directory_replaced_by_link_before_recheck(self):
        project = self.root / "project"
        nested = project / "nested"
        nested.mkdir(parents=True)
        external = self.root / "external"
        external.mkdir()
        (external / "outside.rs").write_text("must not be inventoried")
        prepared_link = self.root / "prepared-link"
        try:
            prepared_link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        original_lstat = Path.lstat
        checks = 0

        def swap_before_recheck(path, *args, **kwargs):
            nonlocal checks
            if path == nested:
                checks += 1
                if checks == 2:
                    nested.rename(self.root / "previous")
                    prepared_link.rename(nested)
            return original_lstat(path, *args, **kwargs)

        with patch.object(development, "_DIRECTORY_FDS", False), \
             patch.object(Path, "lstat", swap_before_recheck):
            result = development.inspect_project(str(project))
        self.assertEqual(checks, 2)
        self.assertNotIn("Rust", result["languages"])
        self.assertEqual(result["skipped"]["changed_directories"], 1)

    def test_inventory_entry_and_depth_limits_are_explicit(self):
        for index in range(5):
            self.source("pass", f"file{index}.py")
        with patch.object(development, "MAX_PROJECT_ENTRIES", 3):
            result = development.inspect_project(str(self.root))
        self.assertEqual(result["entries_examined"], 3)
        self.assertTrue(result["truncated"])
        nested = self.root / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "deep.go").write_text("package main")
        with patch.object(development, "MAX_PROJECT_DEPTH", 1):
            result = development.inspect_project(str(self.root))
        self.assertTrue(result["truncated"])
        self.assertEqual(result["skipped"]["depth_limit_directories"], 1)
        self.assertNotIn("Go", result["languages"])

    @unittest.skipUnless(development._DIRECTORY_FDS, "POSIX descriptor-relative traversal")
    def test_directory_swapped_to_link_before_open_is_not_followed(self):
        nested = self.root / "nested"
        nested.mkdir()
        original_open = os.open
        replaced = False
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside).resolve()
            (external / "outside.rs").write_text("must not be inventoried")

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if path == "nested" and not replaced:
                    replaced = True
                    nested.rename(self.root / "previous")
                    nested.symlink_to(external, target_is_directory=True)
                return original_open(path, flags, *args, **kwargs)

            with patch.object(development.os, "open", side_effect=swap_then_open):
                result = development.inspect_project(str(self.root))
        self.assertTrue(replaced)
        self.assertNotIn("Rust", result["languages"])
        self.assertGreaterEqual(result["skipped"].get("unreadable_directories", 0), 1)

    def test_source_signals_include_lines_and_never_literal_values(self):
        text = (
            "import non_existent_package\n"
            "password = 'DO-NOT-EXPOSE-PASSWORD'\n"
            "subprocess.run('DO-NOT-EXPOSE-COMMAND', shell=True)\n"
            "eval('DO-NOT-EXPOSE-EXPRESSION')\n"
            "requests.get('DO-NOT-EXPOSE-URL', verify=False)\n"
        )
        path = self.source(text)
        source_bytes = path.read_bytes()
        before = path.stat().st_mtime_ns
        result = development.inspect_source(str(path))
        self.assertEqual(result["sha256"], hashlib.sha256(source_bytes).hexdigest())
        self.assertEqual(result["finding_count"], 4)
        self.assertEqual([f["line"] for f in result["findings"]], [2, 3, 4, 5])
        self.assertEqual({f["classification"] for f in result["findings"]}, {"review_required"})
        self.assertNotIn("DO-NOT-EXPOSE", json.dumps(result))
        self.assertTrue(all(len(f["evidence"]) <= 240 for f in result["findings"]))
        self.assertFalse(result["executed_project_code"])
        self.assertEqual(path.read_text(), text)
        self.assertEqual(path.read_bytes(), source_bytes)
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_source_preserves_crlf_bytes_in_hash_and_line_references(self):
        source_bytes = b"password = 'REDACT-ME'\r\neval('REDACT-THIS-TOO')\r\n"
        path = self.root / "windows-newlines.py"
        path.write_bytes(source_bytes)
        result = development.inspect_source(str(path))
        self.assertEqual(result["sha256"], hashlib.sha256(source_bytes).hexdigest())
        self.assertEqual(result["size_bytes"], len(source_bytes))
        self.assertEqual([finding["line"] for finding in result["findings"]], [1, 2])
        self.assertNotIn("REDACT-", json.dumps(result))
        self.assertEqual(path.read_bytes(), source_bytes)

    def test_comments_strings_and_lookalike_names_are_not_calls(self):
        path = self.source(
            "# subprocess.run('test', shell=True)\n"
            "description = 'eval(s) and verify=False'\n"
            "evaluate('a')\n"
            "shell = True\n"
            "verify = False\n"
            "tokenizer = 'ordinary text'\n"
            "password = ''\n"
        )
        self.assertEqual(development.inspect_source(str(path))["findings"], [])

    def test_annotated_camel_case_and_attribute_credentials_are_redacted(self):
        path = self.source("apiKey: str = 'FIRST_SECRET'\nself.access_token = 'SECOND_SECRET'\n")
        result = development.inspect_source(str(path))
        self.assertEqual(result["finding_count"], 2)
        self.assertNotIn("FIRST_SECRET", json.dumps(result))
        self.assertNotIn("SECOND_SECRET", json.dumps(result))

    def test_source_rejects_oversize_and_unsupported_files(self):
        path = self.source("x" * (development.MAX_SOURCE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "512 KiB"):
            development.inspect_source(str(path))
        path = self.source("eval('example')", "sample.js")
        with self.assertRaisesRegex(ValueError, "Python"):
            development.inspect_source(str(path))
        with self.assertRaises(ValueError):
            development.inspect_source(str(self.root))

    def test_source_links_are_rejected(self):
        path = self.source("pass")
        link = self.root / "link.py"
        try:
            link.symlink_to(path)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        with self.assertRaises(ValueError):
            development.inspect_source(str(link))

    def test_parser_errors_do_not_disclose_source(self):
        path = self.source("password = 'SECRET-IN-BROKEN-SOURCE\n")
        with self.assertRaises(ValueError) as error:
            development.inspect_source(str(path))
        self.assertNotIn("SECRET", str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_ast_and_finding_limits_are_explicit(self):
        path = self.source("password='a'\ntoken='b'\neval('c')\n")
        with patch.object(development, "MAX_FINDINGS", 1):
            result = development.inspect_source(str(path))
        self.assertEqual(result["finding_count"], 1)
        self.assertTrue(result["truncated"])
        with patch.object(development, "MAX_AST_NODES", 3):
            result = development.inspect_source(str(path))
        self.assertEqual(result["ast_nodes_examined"], 3)
        self.assertTrue(result["truncated"])

    def test_changed_source_discards_result(self):
        path = self.source("pass")
        with patch.object(development, "_verify_unchanged", side_effect=RuntimeError("changed")):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                development.inspect_source(str(path))

    def test_cancellation_prevents_all_io(self):
        cancelled = threading.Event()
        cancelled.set()
        missing = str(self.root / "does-not-exist")
        for operation in (development.inspect_project, development.inspect_source):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
                    operation(missing, cancelled)


if __name__ == "__main__":
    unittest.main()
