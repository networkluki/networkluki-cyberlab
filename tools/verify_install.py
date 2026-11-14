"""Install and verify release packages on disposable CI runners only."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(arguments: list[str], **kwargs) -> None:
    print("Running:", arguments[0], flush=True)
    subprocess.run(arguments, check=True, timeout=180, **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("windows", "deb"), required=True)
    target = parser.parse_args().target
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Installer integration is restricted to disposable GitHub Actions runners.")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    output = ROOT / "dist" / "release"
    with tempfile.TemporaryDirectory(prefix="cyberlab-install-test-") as temporary:
        temp = Path(temporary)
        report = temp / "installed-smoke.json"
        if target == "windows":
            if platform.system() != "Windows":
                raise SystemExit("Windows installer must be tested on Windows")
            setup = output / f"NetworkLuki-CyberLab-{version}-Setup-x64.exe"
            destination = temp / "installed"
            run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", f"/DIR={destination}"])
            uninstaller = destination / "unins000.exe"
            try:
                run([str(destination / "networkluki-cyberlab.exe"), "--smoke-test", str(report)])
            finally:
                if uninstaller.is_file():
                    run([str(uninstaller), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
        else:
            if platform.system() != "Linux":
                raise SystemExit("DEB installer must be tested on Linux")
            package = output / f"networkluki-cyberlab_{version}_amd64.deb"
            run(["sudo", "apt-get", "install", "-y", "--no-install-recommends", str(package)])
            try:
                environment = {**os.environ, "QT_QPA_PLATFORM": "xcb"}
                run(["xvfb-run", "-a", "/usr/bin/networkluki-cyberlab", "--smoke-test", str(report)], env=environment)
            finally:
                run(["sudo", "apt-get", "remove", "-y", "networkluki-cyberlab"])
        result = json.loads(report.read_text(encoding="utf-8"))
        if result.get("ok") is not True or result.get("version") != version:
            raise RuntimeError(f"Installed application failed verification: {result}")
        result.update({"installer_verified": True, "target": target, "runner_os": platform.platform()})
        (output / f"installation-verification-{target}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Installed {target} application verified.", flush=True)


if __name__ == "__main__":
    main()
