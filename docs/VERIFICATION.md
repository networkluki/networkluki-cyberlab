# Verification — 0.1.1 MVP

Performed on 2026-11-14 in Linux x86_64 (kernel 6.18.57), Python 3.12.14 and PySide6 6.12.0. The complete test suite was rerun after translating the interface and documentation into English.

## Executed checks

- `python -m unittest discover -s tests -v`: **41 tests passed**, exit status 0, no skips in the final run.
- 12 file-analysis tests: reference hashes, empty files, bounded previews, signatures, cancellation, changed-file rejection, size cap, symlink/FIFO/directory rejection.
- 18 network tests: IP/port validation, local open/closed ports, cancellation and expired DNS prevent connections, DNS pinning, HEAD-only behavior, no redirect following, header size/deadline limits, TLS verification failure/SNI, result redaction while preserving the actual request.
- 7 storage tests: project filters and SQL parameter binding, atomic export, private POSIX permissions, database/source overwrite protection, malformed JSON rejection, aggregate history limits.
- 4 GUI integration tests using Qt offscreen: real file hashing in a worker through SQLite history and JSON export, target changes reset scope confirmation, project filtering, closing cancels active work without saving partial output.
- `python -m pip install .`: successfully built and installed `networkluki-cyberlab==0.1.1` from `pyproject.toml`.
- Launched the installed English 0.1.1 package outside the source directory with temporary user data. All six pages were registered, the English navigation was confirmed, startup ran no analysis, and closing returned 0. The English overview screenshot was captured separately from the source build.
- Visually inspected the overview layout. GUI checks used offscreen rendering, not a native Windows/macOS desktop session.
- Compared the old and translated UI abstract syntax trees with string constants normalized: program logic is unchanged.

Network tests use local fixtures or mocks. TLS rejection/SNI are mocked regression checks; an internet TLS scan was not tested. No third-party target was scanned.

## Not verified

- Windows/macOS runtime behavior or other OS/CPU combinations.
- A packaged EXE, DMG, AppImage, installer, signing, notarization or updates.
- External Nmap, TShark, YARA or Ghidra integrations: not implemented.
- Full penetration testing, exhaustive vulnerability detection, decompilation, malware detonation or a forensic chain of custody.
- All IPv6 deployments, desktop-driver compatibility, network-mounted files or cryptographic protection of stored results.

These checks support an initial MVP, not a production-certification claim.

## Reproduce

From the extracted project directory after installing its dependencies:

```bash
python -m unittest discover -s tests -v
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on Windows when the environment is not activated. GUI tests select Qt offscreen unless `QT_QPA_PLATFORM` is already set. If PySide6 is absent, GUI tests are skipped; such a run does not verify the interface.
