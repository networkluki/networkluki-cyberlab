# Native release builds

Build each target on its own operating system. The workflow uses Windows Server 2025 x64 with Python 3.14.10 and a Debian 13 amd64 container with its distribution Python 3.13. The Linux package records the builder's glibc baseline, so building on a newer distribution can produce a package requiring that newer glibc.

```text
python -m pip install . pyinstaller==6.22.3 pyinstaller-hooks-contrib==2026.10
python tools/prepare_sources.py
python -m unittest discover -s tests -v
```

Then run the appropriate native build:

```text
python tools/build_release.py --target windows
python tools/build_release.py --target deb
```

Windows requires Inno Setup 6. Linux requires `dpkg-deb` and the Qt desktop libraries declared by the package. The script refuses existing release/native outputs; use a fresh checkout for a repeat build. It never installs packages on the build host.

`tools/prepare_sources.py` downloads the exact third-party archives, checks pinned SHA-256 digests and prepares license materials. The release workflow retains these source archives alongside the installers. PyInstaller uses an onedir layout, keeping Qt/PySide shared libraries replaceable.

Each build executes the bundled application's isolated `--smoke-test NEW_REPORT_JSON` command. The workflow also runs `tools/verify_install.py` on disposable GitHub Actions runners: it installs the actual artifact, tests the installed app, and uninstalls it. The Linux installed check runs with the xcb platform under Xvfb. These CI installer checks are deliberately unavailable on ordinary workstations.

The publishing job requires both installer verification reports, uploads a draft release, and publishes only after all asset uploads succeed. It does not overwrite an existing release. Build artifacts include checksums, the source commit and verification reports. Binaries are not code-signed by this workflow.
