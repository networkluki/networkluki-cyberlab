# Security model

NetworkLuki CyberLab 0.2.0 is a local, unprivileged workspace preview. Use network functions only within your authorized scope. The application does not establish ownership or authorization and does not provide a security boundary against another process running as the same user.

## Network and file boundaries

- The TCP module accepts one explicit IP address and at most 128 selected ports. Unspecified addresses, multicast addresses, and the IPv4 limited-broadcast address are rejected. Subnet-directed broadcast addresses cannot be inferred without subnet metadata and are not separately detected. It uses at most 8 workers and a 0.6-second connection timeout per port. No exploitation, credential testing, or service detection is implemented.
- The web module accepts HTTP/HTTPS URLs without embedded credentials or fragments. It resolves a hostname once, validates returned addresses, and connects to the first address directly. HTTPS uses normal certificate and hostname verification. Redirects are not followed and environment proxy settings are not used.
- A web job sends one `HEAD` request, limits received header data to 64 KiB, and has an eight-second overall deadline. OS DNS resolution cannot be interrupted portably; an abandoned resolver may finish in a background daemon thread without making a subsequent target connection.
- File operations read regular files only and reject a selected final-component symbolic link. Hashing is limited to 2 GiB. Static binary inspection examines at most 4 MiB and bounds string and hex output. Files are never executed, imported as code, loaded as libraries, or automatically extracted.
- Opened-file identity and metadata are checked before and after inspection. Detectable changes discard the result. These are best-effort checks, not proof against every hostile concurrent modification.
- Core validation is independent of UI validation. Background tasks support cooperative cancellation; completion can wait for a bounded OS operation.

## Workspace input boundaries

Server snapshots are collected on demand from the local computer, or imported from a selected JSON file. There is no SSH client, remote agent, continuous polling, privileged helper, or system-change runner. Imported snapshot hostnames, timestamps, and metrics are user-supplied claims. Strict schema/type/range validation and recomputed threshold signals do not authenticate them. Unavailable metrics are explicit `null` values; the collector measures only its root filesystem.

Snapshot imports and UTF-8 log excerpts are limited to 1 MiB. Logs are limited to 10,000 lines, with at most 100 matching samples and 240 display characters per sample. Keyword matches are signals for review, not verified incidents. Log excerpts are not automatically redacted for secrets. File and line hashes identify bytes; they do not establish authenticity or a chain of custody.

Project inventory reads metadata only, with a 2,000-entry limit, depth limit of 32, explicit skips, and at most 100 manifest paths. It skips links/junctions and common dependency/build/cache directories. The selected directory and visible parent paths cannot be links/junctions. On supported POSIX systems, descriptor-relative traversal rejects link substitution. This is not an atomic filesystem snapshot. No Git configuration, manifest contents, tests, builds, plugins, or project code are loaded or executed.

Python source review accepts UTF-8 `.py`/`.pyw` files up to 512 KiB and bounds AST traversal to 30,000 nodes and 100 findings. It identifies four limited syntax patterns, documented in [WORKSPACE.md](WORKSPACE.md#development). Findings are `review_required`, not verified vulnerabilities. Evidence omits literal arguments and redacts credential-assignment values; no source line is automatically copied wholesale into a finding. This does not make arbitrary source, filenames, logs, or manually pasted AI evidence secret-free. No other source language, data-flow analysis, or complete audit is implemented.

## Dedicated code review and utilities

The **Code review** page is separate from the Development page's broader source triage. It accepts UTF-8 `.py`/`.pyw` regular files up to 256 KiB and checks five bounded AST rule groups: dynamic `eval`/`exec`, subprocess calls with literal `shell=True`, pickle deserialization, explicitly unverified TLS contexts, and Requests calls with literal `verify=False`. Findings include source hashes and locations but omit source snippets and string values. Every finding is `review_required`; data flow, exploitability and complete vulnerability coverage are not established. Source is never imported or executed.

The **Utilities** page formats strict JSON and compares two text inputs locally. Each input is capped at 128 KiB. JSON duplicate keys and nonstandard numeric constants are rejected and nesting is limited to 64 levels. Text comparison is capped at 1,000 LF-delimited lines per input and 256 KiB of output. Utilities do not write back to source files, but successful outputs are stored in the unencrypted project history and can therefore retain sensitive pasted content.

Tasks are project-scoped checklist records, with at most 1,000 tasks per project. Evidence links must refer to a result in the same project. Creating a task, completing it, or storing an AI suggestion never executes an action.

## Optional AI boundary

The AI client accepts only literal loopback HTTP endpoints (`127.0.0.1` or `[::1]`). It does not use DNS, inherited proxies, or redirects. Model listing and generation are initiated explicitly; selecting **Use in AI** only copies a saved result to the editable preview. Confirmation is cleared when AI inputs change.

**Loopback does not guarantee local inference.** Before using the assistant, set `OLLAMA_NO_CLOUD=1` in the Ollama process/service environment, restart Ollama, and use a downloaded local model. Ollama documents cloud models reachable through its local API. Cloud-tagged model names are rejected, but the client cannot verify aliases, server configuration, inference location, or backend data handling. See the [Ollama FAQ](https://docs.ollama.com/faq) and [cloud documentation](https://docs.ollama.com/cloud), checked 2026-11-15.

Questions are capped at 2,000 characters and evidence at 24,000 UTF-8 bytes. Requests are bounded to 60 seconds overall and 3 seconds to connect, with 64 KiB response headers, a 1 MiB JSON body, and 64,000 answer characters. Model lists are capped at 128 entries. Invalid, duplicate-key, incomplete, compressed, or oversized responses are rejected.

The system prompt treats evidence as untrusted and asks for evidence-grounded answers. This is not a guarantee against prompt injection, hallucination, or leaked secrets. The assistant has no command execution, file-write, download, or remediation tool. Review every suggestion before acting outside the application. Successful results store the exact `input_evidence`, `question`, and `response` unencrypted. Their hash identifies the submitted evidence, not factual correctness. Real-model inference has not been tested; current AI checks use fixtures.

## Data handling and migration

SQLite uses parameterized queries. Result payloads must be JSON objects, are limited to 2 MiB each, and are validated again on load; nonstandard JSON constants are rejected. History loads at most the latest 200 results and 16 MiB of combined payloads. These are loading limits, not retention or total disk-usage limits.

POSIX application-data directory and database permissions are restricted to the current user; Windows relies on the account's application-data permissions. Before an existing results-only database receives the tasks table, SQLite's backup API creates `results.pre-workspace.sqlite3`, including committed WAL data, with private POSIX permissions (`0600`). Migration fails if a backup cannot be created or its reserved path already exists; the backup is never overwritten. Already-migrated or newly created databases do not generate another pre-workspace backup.

Export uses a temporary file and atomic replacement of the selected destination. Destinations inside the application data directory, including SQLite companion files and the migration backup, are rejected. Export also rejects overwriting the analyzed source file and selected symbolic links. Headless snapshot collection instead creates a new file exclusively and refuses overwriting; an interrupted write can leave an incomplete new file, which should be discarded.

The database, tasks, backups, and JSON reports are **not encrypted, signed, or tamper evident**. Stored URL query data is redacted; `Location` and `Content-Location` also omit embedded credentials and fragments. Cookie-setting and selected authentication headers are redacted. This affects recorded results, not the request sent to the target. URL paths, arbitrary headers, logs, local paths, extracted strings, manually entered evidence, and model output can contain secrets. Review before sharing or sending to AI; protect backups and keep the app closed during manual data-directory backup or restoration.

No telemetry or remote result-storage service is implemented. Requested DNS lookups, target connections, and explicit AI requests are network activity. Dependency/model installation contacts their configured sources. A local model service may itself have separate network behavior that CyberLab cannot constrain.

## Interpretation and distribution

An open port, missing header, threshold crossing, keyword match, syntax pattern, signature match, extracted string, or AI response is not a confirmed vulnerability. TLS success records one connection's validation outcome, not a full TLS audit. File hashing and metadata are not disk acquisition, malware detonation, or a forensic chain of custody.

The app is not a malware sandbox. No dynamic plugin loading or third-party security-tool execution is included. Keep untrusted-file handling appropriately isolated.

The 0.2.0 workspace branch builds Windows x64 and Debian 13 amd64 preview artifacts without automatically publishing a release. Consult [VERIFICATION.md](VERIFICATION.md) for actual checks. Windows installers are unsigned; macOS remains source-only and unverified. Code signing, notarization, automatic update verification, and automatic rollback are not implemented.
