"""The snapshot entry point must work without Qt or an interactive desktop."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from networkluki_cyberlab.operations import import_system_snapshot


class SnapshotCommandTests(unittest.TestCase):
    def test_headless_snapshot_without_site_packages_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "snapshot.json"
            command = [sys.executable, "-S", "-m", "networkluki_cyberlab",
                       "--collect-snapshot", str(output)]
            root = Path(__file__).resolve().parents[1]
            environment = {**os.environ, "QT_QPA_PLATFORM": "deliberately-unavailable"}
            first = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr.decode(errors="replace"))
            original = output.read_bytes()
            self.assertEqual(json.loads(original)["schema_version"], 1)
            self.assertEqual(import_system_snapshot(str(output))["source_kind"], "imported_snapshot")
            second = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=30)
            self.assertEqual(second.returncode, 1)
            self.assertIn(b"Snapshot failed:", second.stderr)
            self.assertEqual(output.read_bytes(), original)
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
