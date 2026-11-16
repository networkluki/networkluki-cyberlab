# NetworkLuki CyberLab — development roadmap

## Current workspace preview

Version 0.2.0 brings daily tasks, server observations, development review, bounded Python code review, local JSON/text utilities, and an optional AI assistant into the existing English desktop workbench. Network checks, web/TLS observations, file hashing, static binary inspection, project labels, and JSON history remain available. The intended targets are Windows, Linux, and macOS; intended support is distinct from verified behavior.

The workspace branch builds Windows x64 and Debian 13 amd64 installers as CI artifacts, without automatically publishing a release. The existing published release is 0.1.2 and does not contain the new workspace pages. macOS remains source-only and unverified. See [VERIFICATION.md](VERIFICATION.md) for evidence of actual checks and [BUILDING.md](BUILDING.md) for build mechanics.

## Architecture

| Component | Current implementation | Boundary |
| --- | --- | --- |
| Interface | Python and PySide6-Essentials; QtCore, QtGui, QtWidgets | Twelve pages share project selection and background job status |
| Daily work | SQLite checklist with due dates, open/done status, optional evidence links | Human-managed tasks; no scheduled actions |
| Server observations | Standard-library snapshot collector, validated JSON import, bounded log keyword review | No SSH, agents, continuous polling, or server changes |
| Development | Metadata inventory and bounded Python AST review | No project code, tests, builds, Git configuration, or plugins executed |
| Code review / utilities | Five-rule Python AST review, strict JSON formatting and bounded text comparison | Review candidates and local transformations only; no source execution or automatic fixes |
| AI | Optional loopback Ollama API client, explicitly reviewed evidence | External downloaded model with cloud disabled; unverified text only |
| Background jobs | Worker threads and cooperative cancellation | Core limits remain independent of UI validation |
| Results | Local SQLite and JSON export; pre-workspace migration backup | Unencrypted observations, not signed reports or a forensic chain of custody |

The core and headless snapshot collector use the Python standard library without GUI dependencies. See [WORKSPACE.md](WORKSPACE.md) for implemented limits. Real-model inference has not been tested; AI validation currently uses fixtures.

## Next development

The following work is **planned**, not implemented:

| Priority | Deliverable | Acceptance boundary |
| --- | --- | --- |
| 1 | Broader platform verification and release readiness | Verify native installation, updates, rollback, dialogs, cancellation, and all workspace pages; document exact OS/architecture coverage; add signing and macOS packaging |
| 2 | Real-model AI evaluation | Test a downloaded local model with Ollama cloud disabled; measure evidence-grounded accuracy, invented references, latency, privacy controls, and behavior under hostile evidence |
| 3 | Richer daily workflows | Review task editing, retention, filtering, and optional reminders without turning tasks into autonomous system actions |
| 4 | Server history and controlled collection | Compare authenticated observations over time; design credentials, host identity, least privilege, and resource limits before introducing any remote connector or polling |
| 5 | Deeper development review | Add documented language-specific rules and optional external analyzers, with explicit versions, resource limits, and separate observed findings from verified vulnerabilities |
| 6 | Persistent scope | Store declared target/port boundaries and enforce them in the analysis core; a scope record does not prove authorization |
| 7 | Security tool adapters | Start with Nmap XML import, then bounded optional Nmap profiles, YARA analysis, TShark file imports, and Ghidra static-analysis links; no arbitrary shell-command field |
| 8 | Reviewable reports | Link source hashes, collection context, analyst interpretation, reproduction steps, and comparisons; define a separate forensic handling procedure where required |

Nmap, TShark, YARA, and Ghidra are not bundled or executed. The current binary page displays static signatures, bytes, and strings; it does not disassemble or decompile files.

## Boundaries to preserve

- Run as an ordinary user. Any future privileged feature needs a separate narrowly scoped component.
- Treat imported reports, logs, files, network responses, and model output as untrusted data; never automatically execute their contents.
- Keep operations and model suggestions reviewable. A task or AI answer does not authorize or implement a system change.
- Preserve explicit resource limits and report skips, missing metrics, and truncation.
- A loopback connection constrains CyberLab's destination, not the backend's inference location. Retain cloud-disable instructions and avoid privacy claims the client cannot verify.
- A Linux build does not validate Windows or macOS. Publish only the validation evidence actually produced.
