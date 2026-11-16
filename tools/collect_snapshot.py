#!/usr/bin/env python3
"""Collect a local CyberLab system snapshot as a normal user; never overwrite a file."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from networkluki_cyberlab.operations import collect_system_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, metavar="NEW_JSON")
    args = parser.parse_args()
    try:
        encoded = (json.dumps(collect_system_snapshot(), ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Snapshot failed: {exc}", file=sys.stderr)
        return 1
    print(f"Snapshot written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
