# NetworkLuki CyberLab — development roadmap

## Unreleased combined workbench

This branch implements a shared project workflow for bounded Python code
observations, JSON/text utilities and optional explanations through a trusted
local Ollama service. Evidence can move from a current or historical result
into an editable AI request preview; sending requires explicit confirmation.
The assistant has no execution capability. These source additions are described
in [WORKBENCH.md](WORKBENCH.md) and are not included in 0.1.2 installers.

## Starting point

Version 0.1.2 is an initial desktop application with an English interface and a shared codebase intended for Windows, Linux, and macOS. It includes TCP connection checks, HTTP/TLS observations, file hashing, basic binary inspection, and local result history. The goal is a unified workspace for penetration testing, security research, digital forensics, and reverse engineering.

Version 0.1.2 adds a native Windows x64 and Debian/Ubuntu amd64 build workflow with installer verification and release assets. macOS remains unverified. Use the release's JSON verification reports to distinguish actual tested configurations from intended platform support.

## Architecture

| Component | Current implementation | Responsibility |
| --- | --- | --- |
| Interface | Python and PySide6-Essentials; QtCore, QtGui, and QtWidgets | Input, project labels, job status, and result display |
| Analysis core | Python standard library | Validate input and perform bounded network and file checks |
| Background jobs | Worker threads with cooperative cancellation | Keep the interface responsive without giving the whole application extra privileges |
| Results | Local SQLite and JSON export | Store observations with project labels and timestamps |
| External tools | Not implemented | Future adapters with documented arguments, limits, and version requirements |

The analysis core should continue to work without GUI dependencies. Validation belongs in the core so that the same limits apply to future GUI, CLI, and test calls. External tools should use separate adapters that return structured results.

## Prioritized development

| Priority | Deliverable | Implementation and verification |
| --- | --- | --- |
| 1 | Verified platform support | Install and launch on Windows, Linux, and macOS; test file dialogs, threads, cancellation, data directories, and export. Document tested operating systems, CPU architectures, and dependencies. |
| 2 | Explicit projects and scope | Store project descriptions, approved IP addresses and domains, allowed ports, and scope boundaries. Enforce scope in the core before each connection. Saved scope records the user's declared authorization; it does not prove permission. |
| 3 | Tool adapters | Start with Nmap XML import. Then add optional Nmap jobs with fixed argument profiles, time and output limits, and cancellation. Do not accept arbitrary shell commands. |
| 4 | Deeper file analysis | Add optional local YARA analysis, more detailed metadata, and file comparison. Run parsers with resource limits; record rule versions, file hashes, and analysis limitations. |
| 5 | Network forensics | Import PCAP/PCAPNG through a separate TShark adapter. Start with existing files; live capture will require OS-specific handling and least-privilege access. |
| 6 | Reverse engineering | Integrate Ghidra as an optional external tool. Start by linking file hashes, projects, and exported static analysis; clearly distinguish string inspection, disassembly, and decompilation. |
| 7 | Reviewable reports | Define a common observation schema with analyst interpretation, reproduction steps, raw-data references, and comparisons between runs. Distinguish observations from verified vulnerabilities. |
| 8 | Distribution | Build packages on each target OS, inventory dependencies and licenses, publish checksums, and introduce signing. Test installation, updates, and rollback before a stable release. |

All integrations in this table are **planned**. Nmap, TShark, YARA, and Ghidra are not bundled with version 0.1.1.

## Boundaries to keep visible

- Run the app as a normal user. A future feature requiring elevated privileges should use a separate, narrowly scoped component.
- Files, network responses, and imported reports are untrusted data. Their contents must not be automatically executed or loaded as code.
- A JSON report is not a tamper-evident chain of custody. A future forensic workflow needs separate documentation of collection, integrity, and handling.
- Version 0.1.1 does not encrypt the local database. Sensitive results need protection on the computer and when exported.
- A working Linux build does not establish that Windows or macOS packages work; each release needs platform-specific checks.

## Primary sources

Checked on **2026-11-14**:

- [Qt for Python: desktop deployment](https://doc.qt.io/qtforpython-6/deployment/index.html)
- [PyPA: pyproject.toml](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [PyInstaller: builds are platform-specific](https://pyinstaller.org/en/stable/operating-mode.html)
