# Verification

## 0.2.0 unified workspace preview

Executed on 2026-11-15 with Linux x86_64, Python 3.12.14 and PySide6 6.12.0:

- `python -m unittest discover -s tests -v`: **106 tests passed**, no skips. This includes the previous 43 regressions and 63 added tests across tasks/migration, operations, development, AI, headless CLI and workspace UI.
- Task persistence, project boundaries, state changes, record links, date validation and capacity are covered. The migration tests verify a private SQLite backup including committed WAL records, no overwrite, and unchanged legacy schema when backup publication fails.
- Operations tests use generated snapshot/log fixtures and a real local system snapshot; no remote machine is contacted. The headless CLI runs with site packages disabled and an invalid Qt platform setting, then refuses to overwrite its output.
- Development tests exercise bounded inventory, Python AST signals, redacted evidence, cancellation, changed-file rejection and a directory-to-symlink swap. Inspected source is never executed.
- AI tests use actual HTTP servers bound to loopback and controlled responses, not a real Ollama model. They cover direct connections without DNS/proxies, redirects, input/output bounds, invalid JSON, cancellation, slow headers, cloud-tag rejection, and the retained evidence/hash.
- Eight new offscreen GUI integration tests cover task persistence, explicit evidence preview, consent invalidation, model-list isolation, unverified plain-text output, real snapshot/source workers and project switching.
- `--smoke-test` passed desktop startup, both footer labels/placement, hashing, SQLite, JSON export, tasks, system snapshot and development checks.
- Visually inspected the rendered overview at 1200 × 850 and all four new workspaces at 960 × 700. Pages scroll vertically; the footer remains visible. These were Qt offscreen renders, not a native desktop session.

The first native preview run passed Debian installation checks and exposed Windows issues. The follow-up fixes use fresh non-following path metadata instead of Windows' zero-valued cached directory identities, close SQLite test fixture connections explicitly, hash actual CRLF file bytes, and poll response reads for portable AI cancellation/deadlines. Six new regressions cover fallback traversal/link substitution, CRLF source evidence, stalled responses, delayed reads and socket ownership. The final local suite above includes these fixes. See [Python DirEntry.stat documentation](https://docs.python.org/3.14/library/os.html#os.DirEntry.stat), checked 2026-11-15.

The branch build workflow separately builds and installs Windows x64 and Debian 13 amd64 packages. Until its result is recorded, these local checks do not establish that the new installers pass. Branch builds upload CI artifacts and do not publish a 0.2.0 release automatically. The published 0.1.2 installers remain a separate version.

Not verified for 0.2.0: real-model answer quality, Ollama server privacy configuration, remote server identity, continuous monitoring, macOS execution, or every Linux/Windows desktop configuration. No SSH execution, automatic remediation or tool-calling agent is implemented. The checks support a workspace preview, not a security-certification claim.

### PR #4 pre-merge verification evidence

Before conflict resolution, the `codex/combined-workbench-20261115` branch independently reported **90 passing tests with no skips** on Linux x86_64, Python 3.12.14 and PySide6-Essentials 6.12.0. Those checks covered the five-rule Python review, strict JSON/text utilities, the branch's Ollama fixtures and its combined-workbench GUI. They apply to the pre-merge branch, not automatically to this merged tree.

The conflict resolution keeps the newer 0.2.0 workspace implementation from `main`, adds the dedicated Code review and Utilities pages, and reuses the newer workspace AI client instead of retaining a second parallel Ollama adapter. The merged state must be verified again by the repository test/workflow checks; pre-merge counts are historical evidence only.


## 0.1.2 release checks

On 2026-11-14, all 41 existing tests passed locally after the footer and version changes, using Linux x86_64, Python 3.12.14 and PySide6 6.12.0. The new isolated `--smoke-test` passed, and the footer screenshot was visually inspected. A local PyInstaller 6.22.3 build also passed the packaged desktop/footer/hash/SQLite/export smoke checks.

The Windows CI run exposed differing path/descriptor ctime semantics. Cross-method comparisons now use Windows creation time while descriptor-before/after comparisons retain change time; two added regressions bring the locally passing suite to **43 tests**. See [CPython issue 157671](https://github.com/python/cpython/issues/157671).

The native release workflow separately builds Windows x64 and Debian 13 amd64 packages. Publication is gated on source tests, frozen-runtime checks, and successful installation checks on both runners. The Linux installed-app check uses xcb under Xvfb. The release assets `build-verification-*.json` and `installation-verification-*.json` record the actual native outcomes; do not treat an uncompleted workflow as a passing test. These checks do not establish compatibility with every Windows/Linux desktop configuration. macOS is not tested by this workflow, and the binaries are unsigned.

## Historical 0.1.1 MVP checks

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
