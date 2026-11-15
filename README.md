# NetworkLuki CyberLab

**Version 0.1.2 — desktop MVP**

**Unreleased workbench expansion:** this branch adds Python code review, everyday
JSON/text utilities, and optional Ollama explanations in the same project
workspace. These additions are available from source; the existing 0.1.2
installers do not include them. See [the combined workflow](docs/WORKBENCH.md).

![NetworkLuki CyberLab combined workbench](docs/workbench-overview.png)

An open-source desktop workbench with an English interface for security observations, developer utilities, and optional AI explanations. Results are grouped by project and exported as JSON. AI requests are sent only after reviewing the evidence and confirming the request to a trusted Ollama service on your computer.

The intended desktop targets are **Windows, Linux, and macOS**, using Python and Qt for Python. This release is an initial implementation, not a complete penetration-testing suite or a claim of being the “most advanced” security tool. The release workflow builds Windows x64 and Debian 13 amd64 installers and verifies the installed applications before publishing them. macOS remains a source-only target without platform verification. See the [verification notes](docs/VERIFICATION.md) and the JSON reports attached to each release.

## Native installers

Download the `.exe` or `.deb` from [GitHub Releases](https://github.com/networkluki/networkluki-cyberlab/releases). These packages include Python and Qt. The Windows installer is unsigned and installs for the current user. The Debian package requires administrator privileges to install, then runs as a normal desktop application.

```bash
sudo apt install ./networkluki-cyberlab_0.1.2_amd64.deb
networkluki-cyberlab
```

The footer displays `Skapat av Luki Hackwell` on the left and `Powered by networkluki.com` on the right. The rest of the application interface is English.

## Implemented modules

| Module | Available in 0.1.2 | Boundaries |
| --- | --- | --- |
| Network | TCP connection checks against one explicit IPv4 or IPv6 address | Up to 128 selected ports, at most 8 workers, 0.6-second connection timeout per port; no host discovery or service identification |
| Web / TLS | One HTTP `HEAD` request, response headers, contextual security-header observations, verified HTTPS metadata | No redirects, body analysis, proxy inheritance, authentication, or `GET` fallback; first validated DNS address is pinned for the connection |
| File analysis | SHA-256 and SHA-512, size, modification time, file-type signature hints | Regular files up to 2 GiB; detectable changes during inspection discard the result |
| Static binary inspection | Signature hints, initial hex preview, printable ASCII strings and offsets | First 4 MiB examined, at most 200 strings of at least 6 characters, 240-character string previews, first 512 bytes as hex; no execution or disassembly |
| Results | Local SQLite history, project labels, JSON export | History displays the latest 200 entries, with a combined 16 MiB payload limit; local observations, not signed reports or a forensic chain of custody |

An open port is not proof of a vulnerability. A header's presence or absence does not establish whether an application's configuration is secure. File signatures identify possible formats; they do not validate a file or establish that it is safe.

### Added on this branch

| Area | Implemented | Boundaries |
| --- | --- | --- |
| Code review | Five Python AST checks, source hash, line/column references and remediation guidance | One UTF-8 `.py`/`.pyw` file up to 256 KiB; observations require review; no source execution or automatic fixes |
| Utilities | JSON validation/formatting and unified text comparison | 128 KiB per input; exact JSON number tokens retained; duplicate keys rejected; 64 nesting levels; 1,000 lines per diff input; 256 KiB output |
| AI assistant | Explain selected current or historical results through Ollama | Optional; review editable evidence and confirm each request; no commands, file writes, model downloads or automatic actions |

All three areas use the existing project, worker, history and export workflow.
Utilities and reviewed AI evidence may contain secrets and are stored in the
unencrypted local history. Inspect the evidence before sending it.

## Run from source

Use **Python 3.11 or newer** with a compatible `PySide6-Essentials` wheel. The application currently pins `PySide6-Essentials==6.12.0`. Platform availability also depends on that dependency's supported OS and CPU architecture. A desktop graphical session is required.

Extract the project, then open a terminal in the directory containing `pyproject.toml`. Installation downloads the declared build and runtime dependencies. Use a virtual environment; administrative privileges and system policy changes are unnecessary.

### Windows PowerShell

The following example uses an installed Python 3.12 interpreter and the Python launcher:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m networkluki_cyberlab
```

### Linux and macOS

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m networkluki_cyberlab
```

The Python interpreter must provide `venv` and `pip`. On Linux, Qt also needs the desktop libraries required by the installed distribution and Qt platform plugin; this source bundle does not install system packages.

## Use

1. Set the project label for the work you are performing.
2. Select a module and enter the target IP/URL or choose a local file.
3. For network operations, confirm that the selected target is within your authorized scope, then start the check.
4. Review the returned observations and their limitations. Completed results are stored locally.
5. Open the result history and export a selected result as JSON when needed.

Network checks make real connections to the selected destination. They may appear in its logs or monitoring. The app does not verify ownership of a target, and the authorization control is not a technical authorization service.

## Local data

The database filename is `results.sqlite3` under:

| Platform | Directory |
| --- | --- |
| Windows | `%LOCALAPPDATA%\NetworkLuki-CyberLab` |
| macOS | `~/Library/Application Support/NetworkLuki-CyberLab` |
| Linux | `$XDG_DATA_HOME/NetworkLuki-CyberLab` when `XDG_DATA_HOME` is absolute; otherwise `~/.local/share/NetworkLuki-CyberLab` |

Results and exports are **not encrypted**. They can contain target addresses, URL paths, response headers, file paths, and extracted strings. Stored URL query data is redacted. `Location` and `Content-Location` additionally have embedded credentials and fragments redacted; cookie-setting and selected authentication headers are also redacted. Arbitrary headers, URL paths, and other text can still contain secrets. This redaction affects recorded results, not the request sent to the target. Inspect exports before sharing them. Back up the data directory while the application is closed.

Each stored result must be a JSON object and fit within 2 MiB. History loading validates JSON objects and rejects nonstandard JSON constants. The history display limit does not delete older database entries or impose a total database-size limit. JSON export rejects destinations inside the application data directory, including SQLite companion files, and rejects overwriting the analyzed source file.

The application has no telemetry or remote result-storage service. DNS lookups and the requested target connections occur when a web/network job runs. Optional AI uses the fixed loopback Ollama endpoint only after confirmation. The Ollama service must be trusted and configured with cloud features disabled; loopback alone does not prove where inference happens. Installing dependencies requires access to the configured Python package index.

## Development and verification

The core analysis and storage modules use the Python standard library. The UI uses `PySide6.QtCore`, `PySide6.QtGui`, and `PySide6.QtWidgets`. Long-running jobs run outside the GUI thread and support cooperative cancellation.

With the virtual environment's Python selected, run the tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

On Windows, replace `python` with `.\.venv\Scripts\python.exe`; on Linux/macOS, use `.venv/bin/python` if the environment is not activated. Automated tests do not substitute for a desktop smoke test on each target OS. See [security boundaries](docs/SECURITY.md) and the [development roadmap](docs/ROADMAP.md).

## License and dependencies

Original project code is licensed under the [MIT License](LICENSE). Qt for Python and its included components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Nmap, TShark, YARA, and Ghidra are planned integrations and are not bundled or executed by this release.

## Primary documentation

Checked on **2026-11-14**:

- [Qt for Python](https://doc.qt.io/qtforpython-6/)
- [Qt for Python desktop deployment](https://doc.qt.io/qtforpython-6/deployment/index.html)
- [Python project configuration](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [PyInstaller platform-specific builds](https://pyinstaller.org/en/stable/operating-mode.html)

