#!/usr/bin/env python3
"""Stage pinned corresponding Qt/PySide sources and their license materials.

SHA-256 values were read from the exact official download.qt.io .sha256
sidecars on 2026-11-14. Fixed mirrors were supplied by the official Qt
redirector and verified on that date. Unknown redirect hosts are rejected.
No source is executed and no complete archive is extracted.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request


LOGGER = logging.getLogger("prepare_sources")
ROOT = Path(__file__).resolve().parents[1]
QT_VERSION = "6.12.0"
QT_BASE = "https://download.qt.io/official_releases/qt/6.12/6.12.0/submodules/"
QT_MIRROR = "https://mirrors.20i.com/pub/qt.io/archive/qt/6.12/6.12.0/submodules/"
PYSIDE_BASE = "https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/"
PYSIDE_MIRROR = "https://www.mirrorservice.org/sites/download.qt-project.org/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/"
ALLOWED_HOSTS = frozenset({"download.qt.io", "mirrors.20i.com", "www.mirrorservice.org"})
SOURCE_HASHES = {
    "qtbase": "a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307",
    "qtsvg": "e4ab39534ec97987b1b9b60ef7f4d3253d5912a69f8c713a01753174a4029331",
    "qtimageformats": "0943132b5db8de6b6a7f1d162682173e8763c7ed94e80fd39113292845f67762",
    "qtwayland": "ae14d9bcf1bb3c300a3ab2e6a53f50284e5c6c966a4ac4cc5aedcb1bc74e4d02",
    "qttranslations": "85929c0c30d6f273f23bd879bb69803ea17b010ab73cab2f8abf95357f6f6bbb",
    "pyside-setup": "099c1a597cf33c1b000e11cf68a0b82d216fb802bf81726efc720394f10c7751",
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024
MAX_LICENSE_BYTES = 1024 * 1024
MAX_LICENSE_TOTAL = 32 * 1024 * 1024
MAX_LICENSE_FILES = 4096
MAX_MEMBERS = 200000
DOWNLOAD_BUDGET = 600


def source_manifest() -> list[dict[str, str]]:
    sources = []
    for module, sha256 in SOURCE_HASHES.items():
        filename = f"{module}-everywhere-src-{QT_VERSION}.tar.xz"
        official = PYSIDE_BASE if module == "pyside-setup" else QT_BASE
        mirror = PYSIDE_MIRROR if module == "pyside-setup" else QT_MIRROR
        sources.append({"module": module, "version": QT_VERSION, "filename": filename,
                        "sha256": sha256, "official_url": official + filename,
                        "checksum_url": official + filename + ".sha256",
                        "download_url": mirror + filename})
    return sources


def validate_url(url: str, filename: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment
            or PurePosixPath(parsed.path).name != filename):
        raise ValueError("Source URL is outside the fixed HTTPS source allowlist")


class SourceRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.filename)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ordinary_directory(path: Path) -> Path:
    path = path.absolute()
    # Do not redirect generated license files through caller-provided symlinks.
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError(f"Output directories cannot contain symbolic links: {candidate}")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")
    return path


def atomic_write(path: Path, data: bytes) -> None:
    ordinary_directory(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Output must be a regular file: {path}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".sources-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def download_source(source: dict[str, str], output: Path) -> Path:
    path = output / source["filename"]
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Source destination is not a regular file: {path}")
    if path.exists():
        if path.stat().st_size > MAX_ARCHIVE_BYTES or digest_file(path) != source["sha256"]:
            raise ValueError(f"Existing source archive fails its pinned digest; preserved: {path}")
        LOGGER.info("Reusing verified %s", path.name)
        return path
    validate_url(source["download_url"], source["filename"])
    opener = urllib.request.build_opener(SourceRedirectHandler(source["filename"]))
    deadline = time.monotonic() + DOWNLOAD_BUDGET
    last_error = None
    for attempt in range(1, 4):
        temporary = None
        try:
            request = urllib.request.Request(source["download_url"], headers={
                "User-Agent": "NetworkLuki-CyberLab-source-packaging/0.1.2",
                "Accept-Encoding": "identity",
            })
            with opener.open(request, timeout=45) as response:
                validate_url(response.url, source["filename"])
                if response.status != 200:
                    raise ValueError(f"Unexpected HTTP status {response.status}")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > MAX_ARCHIVE_BYTES):
                    raise ValueError("Source download exceeds the archive size limit")
                digest = hashlib.sha256()
                received = 0
                with tempfile.NamedTemporaryFile(dir=output, prefix=".source-download-", delete=False) as stream:
                    temporary = Path(stream.name)
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Source download deadline expired")
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        received += len(chunk)
                        if received > MAX_ARCHIVE_BYTES:
                            raise ValueError("Source download exceeds the archive size limit")
                        digest.update(chunk)
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
            if digest.hexdigest() != source["sha256"]:
                raise ValueError(f"Pinned SHA-256 mismatch for {source['filename']}")
            temporary.chmod(0o644)
            os.replace(temporary, path)
            LOGGER.info("Verified %s (%s bytes)", path.name, received)
            return path
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt == 3 or time.monotonic() >= deadline:
                raise
            LOGGER.warning("Download attempt %s failed for %s: %s", attempt, path.name, exc)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    raise RuntimeError(f"Source download failed: {last_error}")


def license_member(name: str) -> bool:
    path = PurePosixPath(name)
    filename = path.name.upper()
    return (filename.startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"))
            or filename == "QT_ATTRIBUTION.JSON"
            or "LICENSES" in (part.upper() for part in path.parts[:-1]))


def attribution_license_members(archive: Path) -> set[str]:
    """Read bounded attribution metadata to include differently named license texts."""
    required = set()
    expanded = 0
    metadata_bytes = 0
    with tarfile.open(archive, mode="r|xz") as source:
        for index, member in enumerate(source, start=1):
            expanded += max(0, member.size)
            if index > MAX_MEMBERS or expanded > MAX_UNPACKED_BYTES:
                raise ValueError(f"Source archive inventory exceeds limits: {archive.name}")
            if PurePosixPath(member.name).name != "qt_attribution.json":
                continue
            if not member.isfile() or not 0 <= member.size <= MAX_LICENSE_BYTES:
                raise ValueError("Attribution metadata is not a bounded regular file")
            metadata_bytes += member.size
            if metadata_bytes > MAX_LICENSE_TOTAL:
                raise ValueError("Attribution metadata exceeds its aggregate limit")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("Could not read attribution metadata")
            with stream:
                # Qt's verified attribution files contain literal newlines in
                # some copyright/description strings. License paths below still
                # reject every control character and are never executed.
                records = json.loads(stream.read(MAX_LICENSE_BYTES + 1), strict=False)
            if isinstance(records, dict):
                records = [records]
            if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
                raise ValueError("Attribution metadata has an unexpected structure")
            parent = PurePosixPath(member.name).parent
            for item in records:
                reference = item.get("LicenseFile")
                if reference is None:
                    continue
                if (not isinstance(reference, str) or not reference or "\\" in reference
                        or re.search(r"[\x00-\x1f:]", reference) or PurePosixPath(reference).is_absolute()):
                    raise ValueError("Unsafe license reference in attribution metadata")
                # Upstream references may contain ../; normalize only within their source tree.
                normalized = PurePosixPath(posixpath.normpath((parent / reference).as_posix()))
                if (normalized.is_absolute() or ".." in normalized.parts
                        or not normalized.parts or normalized.parts[0] != parent.parts[0]):
                    raise ValueError("Attribution license reference escapes the source tree")
                required.add(normalized.as_posix())
                if len(required) > MAX_LICENSE_FILES:
                    raise ValueError("Attribution references exceed their file count limit")
    return required


def collect_licenses(archive: Path, module: str, destination: Path) -> list[dict]:
    records = []
    total = 0
    expanded = 0
    seen: set[str] = set()
    required = attribution_license_members(archive)
    found_references = set()
    with tarfile.open(archive, mode="r|xz") as source:
        for index, member in enumerate(source, start=1):
            expanded += max(0, member.size)
            if index > MAX_MEMBERS or expanded > MAX_UNPACKED_BYTES:
                raise ValueError(f"Source archive inventory exceeds limits: {archive.name}")
            if not license_member(member.name) and member.name not in required:
                continue
            relative = PurePosixPath(member.name)
            if (relative.is_absolute() or ".." in relative.parts or "\\" in member.name
                    or any(re.search(r"[\x00-\x1f:]", part) for part in relative.parts)):
                raise ValueError("Unsafe license member path in source archive")
            # Links and special files are never extracted or followed.
            if not member.isfile():
                continue
            if not 0 <= member.size <= MAX_LICENSE_BYTES:
                raise ValueError("License member exceeds its size limit")
            total += member.size
            if len(records) >= MAX_LICENSE_FILES or total > MAX_LICENSE_TOTAL:
                raise ValueError("License extraction exceeds its aggregate limit")
            output_relative = PurePosixPath(module) / relative
            if str(output_relative) in seen:
                raise ValueError("Duplicate license member in source archive")
            seen.add(str(output_relative))
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("Could not read regular license file")
            with stream:
                data = stream.read(MAX_LICENSE_BYTES + 1)
            if len(data) != member.size:
                raise ValueError("License member has an invalid size")
            atomic_write(destination.joinpath(*output_relative.parts), data)
            if member.name in required:
                found_references.add(member.name)
            records.append({"path": output_relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": len(data), "source_archive": archive.name})
    if not records:
        raise ValueError(f"No license materials found in {archive.name}")
    if required - found_references:
        raise ValueError(f"Referenced license files missing from {archive.name}: {sorted(required - found_references)}")
    LOGGER.info("Collected %s license/attribution files from %s", len(records), archive.name)
    return records


def prepare(release_dir: Path, licenses_dir: Path) -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"].get("dependencies", [])
    if f"PySide6-Essentials=={QT_VERSION}" not in dependencies:
        raise ValueError("The application dependency no longer matches the pinned Qt source version")
    release_dir = ordinary_directory(release_dir)
    licenses_dir = ordinary_directory(licenses_dir)
    sources = source_manifest()
    with ThreadPoolExecutor(max_workers=2) as workers:
        archives = list(workers.map(lambda item: download_source(item, release_dir), sources))
    license_records = []
    for source, archive in zip(sources, archives, strict=True):
        license_records.extend(collect_licenses(archive, source["module"], licenses_dir))
    # Include the complete standard license texts in an obvious top-level location.
    for filename in ("LGPL-3.0-only.txt", "GPL-3.0-only.txt"):
        candidates = [r for r in license_records if PurePosixPath(r["path"]).name == filename]
        if not candidates:
            raise ValueError(f"Required full license text missing: {filename}")
        atomic_write(licenses_dir / filename, (licenses_dir / candidates[0]["path"]).read_bytes())
    manifest = {
        "schema_version": 1, "qt_version": QT_VERSION, "checksums_verified_on": "2026-11-14",
        "coverage": ["qtbase", "qtsvg", "qtimageformats", "qtwayland", "qttranslations", "PySide6", "Shiboken6"],
        "sources": sources, "license_files": license_records,
        "note": "Publish all listed source archive assets alongside the application binaries. Preserve these license materials. This manifest covers Qt/PySide sources; other bundled components retain their own notices.",
    }
    encoded = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write(release_dir / "third-party-sources.json", encoded)
    atomic_write(licenses_dir / "third-party-sources.json", encoded)
    notice = (
        "NetworkLuki CyberLab uses Qt and Qt for Python (PySide6/Shiboken6) 6.12.0.\n"
        "Qt libraries are Copyright (C) The Qt Company Ltd. and other contributors.\n"
        "Applicable LGPL/GPL and third-party license texts are included in this directory.\n"
        "Exact corresponding source archive filenames and SHA-256 values are in third-party-sources.json.\n"
        "The application release includes those archives as separate downloadable assets.\n"
        "The packaged application uses replaceable shared libraries in its _internal directory.\n"
        "Keep the library filenames and architecture; use interface-compatible replacement builds.\n"
        "Modification and reverse engineering for debugging changes to LGPL components are permitted.\n"
        "Application source and packaging tools are distributed in the project's public repository.\n"
    )
    atomic_write(licenses_dir / "README.txt", notice.encode("utf-8"))
    LOGGER.info("Prepared %s source archives and %s license/attribution files", len(sources), len(license_records))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, default=ROOT / "dist" / "release")
    parser.add_argument("--licenses-dir", type=Path, default=ROOT / "build" / "third-party-licenses")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        prepare(arguments.release_dir, arguments.licenses_dir)
    except (OSError, ValueError, tarfile.TarError, urllib.error.URLError) as exc:
        LOGGER.error("Source preparation failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
