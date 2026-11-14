"""Publish validated artifacts from the exact CI checkout; never replace a release."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != "networkluki/networkluki-cyberlab":
        raise SystemExit("Publishing is restricted to the project's GitHub Actions workflow")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Release version must contain three numeric components")
    commit = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("A complete source commit SHA is required")
    release = ROOT / "dist" / "release"
    required = [release / f"NetworkLuki-CyberLab-{version}-Setup-x64.exe",
                release / f"networkluki-cyberlab_{version}_amd64.deb"]
    for asset in required:
        if not asset.is_file() or asset.stat().st_size < 1024:
            raise RuntimeError(f"Missing release package: {asset.name}")
    for target in ("windows", "deb"):
        report = json.loads((release / f"installation-verification-{target}.json").read_text(encoding="utf-8"))
        if report.get("ok") is not True or report.get("installer_verified") is not True or report.get("version") != version:
            raise RuntimeError(f"Missing successful installer verification for {target}")
    source_manifest = json.loads((release / "third-party-sources.json").read_text(encoding="utf-8"))
    if not source_manifest.get("sources"):
        raise RuntimeError("Corresponding dependency source manifest is empty")
    for source in source_manifest["sources"]:
        filename = source["filename"]
        if Path(filename).name != filename or not filename.endswith(".tar.xz"):
            raise RuntimeError("Invalid source archive filename")
        archive = release / filename
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != source["sha256"]:
            raise RuntimeError(f"Corresponding source checksum mismatch: {filename}")
    (release / "SOURCE_COMMIT.txt").write_text(commit + "\n", encoding="utf-8")
    assets = sorted(p for p in release.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    manifest = []
    for path in assets:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest.append(f"{digest.hexdigest()}  {path.name}\n")
    checksums = release / "SHA256SUMS"
    checksums.write_text("".join(manifest), encoding="utf-8")
    assets.append(checksums)
    tag = f"v{version}"
    notes = ROOT / "packaging" / "release-notes.md"
    # Create the tag explicitly. GitHub rejects an existing ref, so an old tag
    # cannot silently point this release at a different commit.
    repository = os.environ["GITHUB_REPOSITORY"]
    subprocess.run(["gh", "api", f"repos/{repository}/git/refs", "--method", "POST",
                    "--raw-field", f"ref=refs/tags/{tag}", "--raw-field", f"sha={commit}"],
                   check=True, timeout=60, stdout=subprocess.DEVNULL)
    tag_query = ["gh", "api", f"repos/{repository}/git/ref/tags/{tag}"]
    tag_state = json.loads(subprocess.check_output(tag_query, timeout=60, text=True))
    if tag_state.get("object", {}).get("sha") != commit or tag_state["object"].get("type") != "commit":
        raise RuntimeError("Release tag does not identify the exact built commit")
    command = ["gh", "release", "create", tag, *map(str, assets), "--verify-tag",
               "--title", f"NetworkLuki CyberLab {version}", "--notes-file", str(notes), "--draft"]
    subprocess.run(command, check=True, timeout=600)
    tag_state = json.loads(subprocess.check_output(tag_query, timeout=60, text=True))
    if tag_state.get("object", {}).get("sha") != commit:
        raise RuntimeError("Release tag changed while uploading; draft retained")
    subprocess.run(["gh", "release", "edit", tag, "--draft=false", "--latest"], check=True, timeout=60)
    print(f"Published {tag} from {commit}", flush=True)


if __name__ == "__main__":
    main()
