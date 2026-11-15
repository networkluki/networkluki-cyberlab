"""Read-only source review tests using generated local fixtures."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from networkluki_cyberlab import code_review


class CodeReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, text="pass\n", name="sample.py"):
        path = self.root / name
        path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
        return path

    def review(self, text):
        return code_review.review_python(str(self.fixture(text)))

    def test_five_rule_patterns_and_locations(self):
        source = (
            "import subprocess, pickle, ssl, requests\n"
            "eval(user_input)\n"
            "subprocess.run(command, shell=True)\n"
            "pickle.loads(data)\n"
            "ssl._create_unverified_context()\n"
            "requests.get(url, verify=False)\n"
        )
        result = self.review(source)
        self.assertEqual([f["rule_id"] for f in result["findings"]],
                         ["PY001", "PY002", "PY003", "PY004", "PY005"])
        self.assertEqual([f["line"] for f in result["findings"]], [2, 3, 4, 5, 6])
        self.assertTrue(all(f["column"] == 1 for f in result["findings"]))
        self.assertTrue(all(f["status"] == "review_required" for f in result["findings"]))
        self.assertEqual(result["total_findings"], 5)

    def test_simple_import_aliases(self):
        result = self.review(
            "import subprocess as sp\n"
            "from pickle import loads as deserialize\n"
            "from ssl import _create_unverified_context as context\n"
            "import builtins as b\n"
            "from requests import get as fetch\n"
            "sp.Popen(command, shell=True)\n"
            "deserialize(data)\ncontext()\nb.exec(code)\nfetch(url, verify=False)\n"
        )
        self.assertEqual([f["rule_id"] for f in result["findings"]],
                         ["PY002", "PY003", "PY004", "PY001", "PY005"])

    def test_safe_variants_comments_strings_and_unknown_objects(self):
        result = self.review(
            "import ast, subprocess, ssl, json, requests\n"
            "# eval(input())\n"
            "text = 'pickle.loads(data)'\n"
            "ast.literal_eval(text)\nsubprocess.run(['whoami'], shell=False)\n"
            "ssl.create_default_context()\njson.loads(text)\n"
            "requests.get(url, verify=True)\ncustom.eval(text)\n"
        )
        self.assertEqual(result["findings"], [])
        self.assertIn("security is not established", result["assessment"])

    def test_rebound_names_are_conservatively_skipped(self):
        result = self.review(
            "import subprocess as sp\nsp = custom\nsp.run(x, shell=True)\n"
            "def wrapper(eval):\n    return eval(x)\n"
            "from first import value\nfrom pickle import loads as value\nvalue(x)\n"
        )
        self.assertEqual(result["findings"], [])

    def test_dynamic_flags_are_not_treated_as_literal_values(self):
        result = self.review(
            "import subprocess, requests\n"
            "subprocess.run(command, shell=flag)\n"
            "subprocess.run(command, shell=1)\n"
            "requests.get(url, verify=0)\n"
        )
        self.assertEqual(result["findings"], [])

    def test_source_never_executed_and_literals_not_retained(self):
        marker = self.root / "should-not-exist"
        source = f"open({str(marker)!r}, 'w').write('data')\neval('TOP_SECRET_VALUE')\n"
        path = self.fixture(source)
        modified = path.stat().st_mtime_ns
        result = code_review.review_python(str(path))
        self.assertFalse(marker.exists())
        self.assertNotIn("TOP_SECRET_VALUE", json.dumps(result))
        self.assertEqual(result["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(result["size_bytes"], len(source.encode()))
        self.assertEqual(path.read_text(), source)
        self.assertEqual(path.stat().st_mtime_ns, modified)

    def test_invalid_syntax_error_does_not_echo_source(self):
        with self.assertRaisesRegex(ValueError, "line 1") as raised:
            self.review("TOP_SECRET_VALUE = 'unfinished")
        self.assertNotIn("TOP_SECRET_VALUE", str(raised.exception))

    def test_utf8_required_bom_accepted_and_pyw_accepted(self):
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            self.review(b"# \xff\npass\n")
        result = code_review.review_python(str(self.fixture(b"\xef\xbb\xbfeval(x)\n", "script.pyw")))
        self.assertEqual(result["total_findings"], 1)

    def test_extension_and_size_bounds(self):
        with self.assertRaisesRegex(ValueError, "extension"):
            code_review.review_python(str(self.fixture("eval(x)", "script.txt")))
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            self.review("#" + "x" * code_review.MAX_SOURCE_BYTES)
        self.assertEqual(self.review("#" + "x" * (code_review.MAX_SOURCE_BYTES - 1))["findings"], [])

    def test_ast_complexity_and_bounded_findings(self):
        with mock.patch.object(code_review, "MAX_AST_NODES", 5):
            with self.assertRaisesRegex(ValueError, "complexity"):
                self.review("eval(x)\neval(y)\n")
        with mock.patch.object(code_review, "MAX_FINDINGS", 2):
            result = self.review("eval(x)\neval(y)\neval(z)\n")
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["total_findings"], 3)
        self.assertTrue(result["findings_truncated"])
        self.assertEqual([f["line"] for f in result["findings"]], [1, 2])

    def test_cancellation_before_file_access_and_during_walk(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
            code_review.review_python(str(self.root / "missing.py"), cancel=cancel)
        cancel = mock.Mock()
        cancel.is_set.side_effect = [False, False, True]
        with self.assertRaisesRegex(RuntimeError, "Operation cancelled"):
            code_review.review_python(str(self.fixture()), cancel=cancel)

    def test_changed_file_result_is_discarded(self):
        path = self.fixture("eval(x)\n")
        original = code_review.ast.parse

        def modify_then_parse(text):
            path.write_text("pass\n")
            return original(text)

        with mock.patch.object(code_review.ast, "parse", side_effect=modify_then_parse):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                code_review.review_python(str(path))

    def test_nonregular_and_symbolic_link_rejected(self):
        with self.assertRaises(ValueError):
            code_review.review_python(str(self.root))
        target = self.fixture()
        link = self.root / "linked.py"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable for this user/platform")
        with self.assertRaisesRegex(ValueError, "Symbolic links"):
            code_review.review_python(str(link))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_fifo_rejected_without_blocking(self):
        path = self.root / "pipe.py"
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            code_review.review_python(str(path))


if __name__ == "__main__":
    unittest.main()
