#!/usr/bin/env python3
"""Build native, unprivileged CyberLab installers using installed build tools.

Run tools/prepare_sources.py first to prepare corresponding sources and notices.
This script never downloads dependencies or installs anything on the host.
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
APP = "networkluki-cyberlab"
EXPECTED_PYINSTALLER = "6.22.3"
EXPECTED_QT = "6.12.0"
QT_SOURCE_MODULES = {
    "Core", "Gui", "Widgets", "Concurrent", "DBus", "Network", "OpenGL",
    "OpenGLWidgets", "PrintSupport", "Sql", "Test", "Xml", "XcbQpa",
    "EglFSDeviceIntegration", "EglFsKmsSupport", "FbSupport", "KmsSupport",
    "Svg", "SvgWidgets", "WaylandClient", "WaylandCompositor",
    "WaylandEglClientHwIntegration", "WaylandEglCompositorHwIntegration",
    "WaylandClientHardwareIntegration", "WaylandCompositorHardwareIntegration",
    "WaylandWlShellIntegration", "WlShellIntegration",
}
LINUX_DEPENDS = [
    "libgcc-s1", "libstdc++6", "libgl1", "libegl1", "libfontconfig1",
    "libfreetype6", "libdbus-1-3", "libx11-6", "libx11-xcb1", "libxcb1",
    "libxcb-cursor0", "libxcb-icccm4", "libxcb-image0", "libxcb-keysyms1",
    "libxcb-randr0", "libxcb-render0", "libxcb-render-util0", "libxcb-shape0",
    "libxcb-shm0", "libxcb-sync1", "libxcb-xfixes0", "libxcb-xkb1",
    "libxkbcommon0", "libxkbcommon-x11-0", "libsm6", "libice6",
]


def run(arguments: list[str | Path], *, cwd: Path = ROOT, timeout: int = 900,
        env: dict[str, str] | None = None) -> None:
    command = [str(argument) for argument in arguments]
    print("Running:", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True, timeout=timeout, env=env)


def read_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Release version must be an explicit major.minor.patch")
    initializer = ast.parse((ROOT / "networkluki_cyberlab" / "__init__.py").read_text(encoding="utf-8"))
    package_version = next((ast.literal_eval(node.value) for node in initializer.body
                            if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == "__version__"
                                    for target in node.targets)), None)
    if version != package_version:
        raise ValueError("pyproject.toml and package versions differ")
    return version


def ensure_directory(path: Path) -> None:
    """Only create directories within this checkout; reject redirected build paths."""
    if not path.is_relative_to(ROOT):
        raise ValueError("Build directories must stay within this checkout")
    for component in (path, *path.parents):
        if component == ROOT:
            break
        if component.is_symlink():
            raise ValueError(f"Build path cannot contain a symbolic link: {component}")
    path.mkdir(parents=True, exist_ok=True)


def check_environment(target: str) -> None:
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"} or sys.maxsize <= 2**32:
        raise RuntimeError("Native releases require a 64-bit x86 Python interpreter")
    if target == "windows" and sys.platform != "win32":
        raise RuntimeError("The Windows installer must be built on Windows")
    if target == "deb" and sys.platform != "linux":
        raise RuntimeError("The Debian package must be built on Linux")
    for package, expected in (("pyinstaller", EXPECTED_PYINSTALLER),
                              ("PySide6-Essentials", EXPECTED_QT),
                              ("shiboken6", EXPECTED_QT)):
        actual = metadata.version(package)
        if actual != expected:
            raise RuntimeError(f"Expected {package}=={expected}, found {actual}")
    if not (ROOT / "build" / "third-party-licenses").is_dir():
        raise RuntimeError("Run python tools/prepare_sources.py before building installers")


def copy_notices(bundle: Path) -> list[dict]:
    notices = bundle / "licenses"
    notices.mkdir()
    shutil.copy2(ROOT / "LICENSE", notices / "CyberLab-MIT.txt")
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", notices / "THIRD_PARTY_NOTICES.md")
    shutil.copytree(ROOT / "build" / "third-party-licenses", notices / "upstream")
    python_candidates = [
        Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE",
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sysconfig.get_path("stdlib")) / "LICENSE",
    ]
    if sys.platform == "linux":
        runtime = f"python{sys.version_info.major}.{sys.version_info.minor}"
        python_candidates.extend([
            Path("/usr/share/doc") / runtime / "copyright",
            Path("/usr/share/doc") / f"lib{runtime}-stdlib" / "copyright",
            Path("/usr/share/doc") / f"{runtime}-minimal" / "copyright",
        ])
    python_license = next((p for p in python_candidates if p.is_file()), None)
    if python_license is None:
        raise RuntimeError("The Python runtime license could not be located")
    shutil.copy2(python_license, notices / "Python-LICENSE.txt")
    inventory = []
    for name in ("PySide6-Essentials", "shiboken6", "pyinstaller", "pyinstaller-hooks-contrib"):
        distribution = metadata.distribution(name)
        destination = notices / name
        destination.mkdir()
        license_files = []
        for relative in distribution.files or []:
            lowered = str(relative).lower()
            if not any(term in lowered for term in ("license", "copying", "notice")):
                continue
            source = Path(distribution.locate_file(relative))
            if not source.is_file():
                continue
            # Dist-info filenames may include ../ paths. Store under a safe basename.
            filename = hashlib.sha256(str(relative).encode()).hexdigest()[:10] + "-" + source.name
            shutil.copy2(source, destination / filename)
            license_files.append(str(relative))
        for filename in ("METADATA", "WHEEL"):
            text = distribution.read_text(filename)
            if text is not None:
                (destination / filename).write_text(text, encoding="utf-8")
        inventory.append({"name": name, "version": distribution.version,
                          "license_files_from_distribution": license_files})
    (notices / "runtime-inventory.json").write_text(
        json.dumps({"python": platform.python_version(), "distributions": inventory}, indent=2) + "\n",
        encoding="utf-8",
    )
    (notices / "LIBRARY-REPLACEMENT.txt").write_text(
        "This application dynamically loads Qt/PySide shared libraries from _internal.\n"
        "You may replace them with compatible modified builds and rebuild the application\n"
        "from its public source. No signature check or application lock forbids replacement.\n"
        "The application's MIT license does not restrict debugging or reverse engineering\n"
        "of modifications to these libraries. The upstream licenses remain applicable.\n"
        "Corresponding third-party source archives accompany this GitHub release.\n",
        encoding="utf-8",
    )
    return inventory


def qt_modules(bundle: Path) -> list[str]:
    modules = set()
    for path in bundle.rglob("*"):
        match = re.fullmatch(r"(?:lib)?Qt6([A-Za-z0-9]+)(?:\.dll|\.so(?:\.[0-9]+)*)", path.name)
        if match:
            modules.add(match.group(1))
    if not {"Core", "Gui", "Widgets"}.issubset(modules):
        raise RuntimeError("The frozen bundle is missing expected Qt libraries")
    unknown = modules - QT_SOURCE_MODULES
    if unknown:
        raise RuntimeError("Missing corresponding-source coverage for Qt modules: " + ", ".join(sorted(unknown)))
    return sorted(modules)


def _package_owners(soname: str) -> list[str]:
    """Resolve a real system library to installed Debian package owners."""
    if not re.fullmatch(r"[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)*", soname):
        raise ValueError(f"Invalid system-library name: {soname}")
    query = shutil.which("dpkg-query")
    if not query:
        raise RuntimeError("dpkg-query is required to resolve system-library dependencies")

    def owners(pattern: str) -> set[str]:
        result = subprocess.run([query, "-S", pattern], check=False, capture_output=True,
                                text=True, timeout=30)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"dpkg-query failed for {soname}: {result.stderr.strip()}")
        packages = set()
        for line in result.stdout.splitlines():
            package, separator, filename = line.partition(": ")
            if not separator or not Path(filename).is_absolute():
                continue
            # A glob lookup must match the exact observed library name.
            if pattern.startswith("*/") and Path(filename).name != soname:
                continue
            package = package.split(":", 1)[0]
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package):
                continue
            packages.add(package)
        return packages

    found = owners("*/" + soname)
    if not found:
        ldconfig = shutil.which("ldconfig")
        if ldconfig:
            result = subprocess.run([ldconfig, "-p"], check=True, capture_output=True,
                                    text=True, timeout=30)
            for line in result.stdout.splitlines():
                pieces = line.strip().split()
                if len(pieces) < 4 or pieces[0] != soname or pieces[-2] != "=>":
                    continue
                installed = Path(pieces[-1])
                if not installed.is_absolute() or not installed.is_file():
                    continue
                found.update(owners(str(installed)))
                found.update(owners(str(installed.resolve(strict=True))))
    if not found:
        raise RuntimeError(f"Cannot identify an installed Debian package for {soname}; refusing to bundle it")
    return sorted(found)


def unbundle_system_libraries(bundle: Path) -> list[dict]:
    """Use distro libraries at runtime instead of redistributing their copies."""
    internal = bundle / "_internal"
    if internal.is_symlink() or not internal.is_dir():
        raise RuntimeError("The frozen bundle has no ordinary _internal directory")
    planned = []
    for path in sorted(internal.iterdir()):
        if not re.fullmatch(r"[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)*", path.name):
            continue
        if re.fullmatch(r"libpython[0-9]+\.[0-9]+(?:[a-z]*)?\.so(?:\.[0-9]+)*", path.name):
            continue
        if path.is_symlink():
            target = path.readlink()
            if target.is_absolute():
                raise RuntimeError(f"Unexpected absolute bundle symlink: {path.name}")
            lexical = Path(os.path.abspath(internal / target))
            if not lexical.is_relative_to(internal):
                raise RuntimeError(f"Bundle symlink leaves _internal: {path.name}")
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(internal):
                raise RuntimeError(f"Bundle symlink resolves outside _internal: {path.name}")
            # PyInstaller places links here for Qt/PySide and Qt-shipped ICU libraries.
            if resolved.relative_to(internal).parts[0] in {"PySide6", "shiboken6"}:
                continue
        elif not path.is_file():
            raise RuntimeError(f"Unexpected nonregular shared library: {path.name}")
        qt = re.fullmatch(r"libQt6([A-Za-z0-9]+)\.so(?:\.[0-9]+)*", path.name)
        if qt and qt.group(1) in QT_SOURCE_MODULES:
            continue
        packages = _package_owners(path.name)
        planned.append({"library": path.name, "packages": packages})
    # Resolve every dependency before removing a single file.
    for entry in planned:
        (internal / entry["library"]).unlink()
    print(f"Using system packages for {len(planned)} shared libraries", flush=True)
    return planned


def smoke_test(executable: Path, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    report = work / "packaged-smoke.json"
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    run([executable, "--smoke-test", report], timeout=60, env=environment)
    payload = json.loads(report.read_text(encoding="utf-8"))
    if payload.get("ok") is not True:
        raise RuntimeError("Packaged application smoke test did not report success")
    return payload


def find_inno() -> Path:
    candidates = [shutil.which("iscc"), shutil.which("ISCC.exe")]
    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(variable)
        if base:
            candidates.append(str(Path(base) / "Inno Setup 6" / "ISCC.exe"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise RuntimeError("Inno Setup 6 ISCC.exe is not installed or cannot be located")


def build_windows(bundle: Path, release_dir: Path, work: Path, version: str) -> Path:
    values = {"VERSION": version, "SOURCE": str(bundle), "OUTPUT": str(release_dir),
              "LICENSE": str(ROOT / "LICENSE")}
    content = (ROOT / "packaging" / "windows.iss.in").read_text(encoding="utf-8")
    for key, value in values.items():
        if any(character in value for character in ('"', '\r', '\n', '\x00')):
            raise ValueError("Installer paths cannot contain quotes or control characters")
        content = content.replace(f"@{key}@", value)
    installer = work / "cyberlab.iss"
    installer.write_text(content, encoding="utf-8-sig")
    run([find_inno(), installer], timeout=900)
    return release_dir / f"NetworkLuki-CyberLab-{version}-Setup-x64.exe"


def build_deb(bundle: Path, release_dir: Path, work: Path, version: str,
              system_libraries: list[dict]) -> tuple[Path, str]:
    tool = shutil.which("dpkg-deb")
    if not tool:
        raise RuntimeError("dpkg-deb is required to build a Debian package")
    libc_name, libc_version = platform.libc_ver()
    if libc_name != "glibc" or not re.fullmatch(r"[0-9]+\.[0-9]+", libc_version):
        raise RuntimeError("Debian packaging requires a detected glibc version")
    if tuple(map(int, libc_version.split("."))) < (2, 35):
        raise RuntimeError("This release expects glibc 2.35 or newer")
    stage = work / "deb-root"
    app_dir = stage / "opt" / APP
    app_dir.parent.mkdir(parents=True)
    shutil.copytree(bundle, app_dir, symlinks=True)
    commands = stage / "usr" / "bin"
    commands.mkdir(parents=True)
    (commands / APP).symlink_to(f"/opt/{APP}/{APP}")
    desktop = stage / "usr" / "share" / "applications"
    desktop.mkdir(parents=True)
    shutil.copy2(ROOT / "packaging" / f"{APP}.desktop", desktop)
    icons = stage / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps"
    icons.mkdir(parents=True)
    shutil.copy2(ROOT / "packaging" / f"{APP}.svg", icons)
    documentation = stage / "usr" / "share" / "doc" / APP
    documentation.mkdir(parents=True)
    shutil.copy2(ROOT / "LICENSE", documentation / "copyright")
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", documentation)
    control = stage / "DEBIAN"
    control.mkdir()
    installed_size = sum(path.stat().st_size for path in stage.rglob("*")
                         if path.is_file() and not path.is_symlink()) // 1024 + 1
    system_packages = {name for entry in system_libraries for name in entry["packages"]}
    depends = ", ".join([f"libc6 (>= {libc_version})", *sorted(set(LINUX_DEPENDS) | system_packages)])
    (control / "control").write_text(
        f"Package: {APP}\nVersion: {version}\nSection: utils\nPriority: optional\n"
        f"Architecture: amd64\nInstalled-Size: {installed_size}\n"
        "Maintainer: Luki Hackwell <83667327+networkluki@users.noreply.github.com>\n"
        f"Depends: {depends}\nHomepage: https://github.com/networkluki/networkluki-cyberlab\n"
        "Description: Desktop security research and static file analysis workbench\n"
        " Scoped TCP checks, HTTP/TLS observations, file hashes and static binary inspection.\n"
        " The application runs as a normal desktop user and stores results locally.\n",
        encoding="utf-8",
    )
    for path in stage.rglob("*"):
        if path.is_symlink():
            continue
        executable = path.is_dir() or bool(path.stat().st_mode & 0o111)
        path.chmod(0o755 if executable else 0o644)
    stage.chmod(0o755)
    package = release_dir / f"{APP}_{version}_amd64.deb"
    run([tool, "--root-owner-group", "--build", stage, package], timeout=900)
    run([tool, "--info", package], timeout=60)
    # Test the packaged bytes after extracting the actual archive, without installing.
    unpacked = work / "deb-extracted"
    run([tool, "--extract", package, unpacked], timeout=120)
    smoke_test(unpacked / "opt" / APP / APP, work / "deb-smoke")
    return package, libc_version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("windows", "deb"), required=True)
    arguments = parser.parse_args()
    version = read_version()
    check_environment(arguments.target)
    build_dir = ROOT / "build"
    release_dir = ROOT / "dist" / "release"
    native_dir = ROOT / "dist" / "native" / arguments.target
    for directory in (build_dir, release_dir, native_dir):
        ensure_directory(directory)
    package_name = (f"NetworkLuki-CyberLab-{version}-Setup-x64.exe" if arguments.target == "windows"
                    else f"{APP}_{version}_amd64.deb")
    if (release_dir / package_name).exists() or (native_dir / APP).exists():
        raise FileExistsError("Build outputs already exist; use a clean checkout or move previous outputs aside")
    with tempfile.TemporaryDirectory(prefix=f"native-{arguments.target}-", dir=build_dir) as temporary:
        work = Path(temporary)
        command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
                   "--name", APP, "--paths", str(ROOT), "--distpath", str(native_dir),
                   "--workpath", str(work / "pyinstaller"), "--specpath", str(work),
                   "--noupx"]
        if arguments.target == "windows":
            command.append("--windowed")
        command.append(str(ROOT / "packaging" / "launcher.py"))
        run(command)
        bundle = native_dir / APP
        inventory = copy_notices(bundle)
        modules = qt_modules(bundle)
        system_libraries = unbundle_system_libraries(bundle) if arguments.target == "deb" else []
        executable = bundle / (APP + (".exe" if arguments.target == "windows" else ""))
        smoke = smoke_test(executable, work)
        libc_version = None
        if arguments.target == "windows":
            package = build_windows(bundle, release_dir, work, version)
        else:
            package, libc_version = build_deb(bundle, release_dir, work, version, system_libraries)
        if not package.is_file() or package.stat().st_size == 0:
            raise RuntimeError("Packaging did not produce the expected installer")
        with package.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        report = {"version": version, "target": arguments.target, "architecture": "x86_64",
                  "python": platform.python_version(), "platform": platform.platform(),
                  "glibc_minimum": libc_version, "qt_modules": modules, "distributions": inventory,
                  "system_libraries": system_libraries,
                  "smoke_test": smoke, "artifact": package.name, "sha256": digest,
                  "bytes": package.stat().st_size, "created_at": datetime.now(timezone.utc).isoformat(),
                  "signed": False}
        report_text = json.dumps(report, indent=2) + "\n"
        (build_dir / f"native-{arguments.target}.json").write_text(report_text, encoding="utf-8")
        (release_dir / f"build-verification-{arguments.target}.json").write_text(report_text, encoding="utf-8")
        print(f"Built {package.name} ({package.stat().st_size} bytes), SHA-256 {digest}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, metadata.PackageNotFoundError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        raise SystemExit(1)
