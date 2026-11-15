# Workspace guide — 0.2.0 preview

The workspace brings daily work, server observations, and development review into one project context. The existing Network, Web / TLS, File analysis, Binary analysis, and History pages remain available. The interface is English; the footer retains `Skapat av Luki Hackwell` and `Powered by networkluki.com`.

This guide describes the preview source and its configured CI builds. The published 0.1.2 release does not contain these workspace features. Check [VERIFICATION.md](VERIFICATION.md) and the relevant CI reports for actual validation status.

## Daily tasks

Choose a project label, enter a title, select Daily work, Server operations, or Development, and optionally enter a due date as `YYYY-MM-DD`. Add the task explicitly, then mark it done or reopen it as work progresses. Due dates are calendar dates; overdue counts use the computer's local date.

A project can contain at most **1,000 tasks**, including completed tasks. The table displays the latest 200. Tasks are local checklist records, without reminders, scheduled execution, or automatic system changes.

In **History**, select a result and choose **Create review task** to record a follow-up item linked to that result in the same project. Creating or completing the task does not verify a finding or perform remediation.

## Servers

**Collect this computer** reads an unprivileged snapshot of the machine running CyberLab. **Import snapshot** validates a JSON snapshot collected elsewhere. The page does not establish a remote connection, use SSH, install an agent, poll continuously, or execute server commands.

Snapshots include a hostname, OS description, capture timestamp, logical CPU count, one-minute load average, root-filesystem capacity and free space, and available memory and uptime where supported. Linux memory and uptime are read from `/proc`; unavailable values are `null`. The root filesystem may not represent a server's application/data mounts, and logical CPU count may not reflect a container's CPU quota.

The following fixed thresholds produce review signals:

| Metric | Signal threshold | Interpretation limit |
| --- | --- | --- |
| Root-filesystem space | Used space at least 85% | Other mounts are not inspected |
| Available memory | Less than 10% of total | Requires both memory values to be available |
| One-minute load / logical CPUs | At least 1 | Load average is not CPU utilization |
| Reported snapshot age | Older than 900 seconds is stale; more than 300 seconds in the future is clock-ahead | Timestamp and host identity are not authenticated |

Imported snapshots must be UTF-8 JSON with `schema_version: 1`, a recognized `source_kind`, a timezone-bearing capture timestamp, and valid metric types/ranges. Use the supplied collector rather than inventing a schema. Duplicate fields, nonstandard numeric constants, and inconsistent metric pairs are rejected. Incoming conclusions are not trusted; the app recomputes its threshold signals. A source-file SHA-256 identifies imported bytes, not the truth of the reported metrics.

### Headless collection

With Python 3.11 or newer, run this from the project checkout on the machine to inspect:

```bash
python -m networkluki_cyberlab --collect-snapshot server-snapshot.json
```

This entry point does not import Qt or open the GUI. The alternative repository tool uses the same standard-library collector:

```bash
python tools/collect_snapshot.py --output server-snapshot.json
```

Use one command, with a **new output filename**. Both refuse to overwrite an existing file and create private files on POSIX (`0600`). Run as an ordinary user. The collector needs the source package from the checkout; `collect_snapshot.py` alone is not a standalone script to copy to another machine. Transfer the resulting JSON using your existing trusted process, then choose **Import snapshot** in CyberLab. CyberLab does not perform that transfer.

### Log review

Choose a local UTF-8 log excerpt of at most **1 MiB and 10,000 lines**. Review counts of `error`, `warn`/`warning`, `fail`/`failed`/`failure`, and selected authentication-failure phrases. Categories overlap, so their counts are not a count of distinct incidents.

Results retain at most **100 matching line samples**, each limited to **240 display characters**, with line numbers and hashes. Control characters are escaped and omitted-sample counts are explicit. Keyword matches can occur in benign text and do not establish an outage, intrusion, or verified vulnerability. Only the selected excerpt is inspected; no journal, service, firewall, or log-rotation configuration is changed. Log text is not automatically stripped of secrets.

## Development

**Project inventory** counts filenames and directory metadata in a selected local folder. It identifies language extensions, selected manifest filenames, and observed README, test, and gitignore presence. It reads no manifest contents or Git configuration and runs no Git command, test, build tool, plugin, or project code.

The inventory examines at most **2,000 entries**, limits directory depth to **32**, and returns at most **100 manifest paths**. It skips symbolic links/junctions and common version-control, dependency, build, and cache directories, including `.git`, `.venv`, `node_modules`, `build`, and `dist`. The result records skips and truncation. The selected directory and visible parent paths must not be symbolic links or junctions. Counts are observations of a changing filesystem, not an atomic snapshot, dependency audit, or quality score.

**Python source review** parses one selected `.py` or `.pyw` file as a Python AST. Input must be UTF-8 or UTF-8 with a BOM and no larger than **512 KiB**. The review is capped at **30,000 AST nodes** and **100 findings**. Unsupported languages and invalid Python are rejected. Project inventory's broader language counts do not imply source-review support for those languages.

| Rule | Syntax reviewed | Why human review is needed |
| --- | --- | --- |
| `python_shell_true` | A call with `shell=True` | Argument construction and actual API behavior determine risk |
| `python_dynamic_execution` | Direct `eval(...)` or `exec(...)` calls | Input provenance and whether the name refers to the builtin are not resolved |
| `python_tls_verify_false` | A call with `verify=False` | The keyword may belong to an unrelated API |
| `literal_credential` | Nonempty literal-string assignments to credential-like variable/attribute names | Test data and placeholders can match; obfuscated or dynamically built credentials can be missed |

Findings are classified **`review_required`**, with line references and structural evidence. Evidence omits literal argument values; credential-assignment evidence replaces the value with a redaction marker. The original source hash is retained and the file is not edited or executed. This is limited syntax triage, without data-flow analysis, a complete security audit, performance analysis, or proof that unmatched code is safe.

## Optional AI assistant

AI is optional. Install Ollama separately and download a model appropriate for your hardware and its license. CyberLab does not install Ollama, download models, or manage the inference service.

Before sending evidence, set **`OLLAMA_NO_CLOUD=1` in the environment of the Ollama process/service and restart Ollama**. Check Ollama's logs for its cloud-disabled confirmation. Setting the variable only in CyberLab's environment does not reconfigure an already-running Ollama service. Follow Ollama's [platform-specific environment instructions and cloud-disable FAQ](https://docs.ollama.com/faq), checked **2026-11-15**.

The default endpoint is `http://127.0.0.1:11434`. Only literal loopback HTTP addresses (`127.0.0.1` or `[::1]`) are accepted; redirects and inherited HTTP proxies are not used. **A loopback endpoint does not guarantee local inference**: Ollama can serve cloud models through its local API, as documented in its [cloud guide](https://docs.ollama.com/cloud), checked **2026-11-15**. The app rejects recognizable cloud-tagged model names, but cannot attest to model aliases, backend settings, inference location, or the service's data handling. Use a downloaded local model with cloud features disabled.

1. Open **AI assistant**, confirm the loopback endpoint, and choose **Load models**. This contacts the selected service only when requested; it does not download a model or generate an answer.
2. Select an installed model. Enter a question and evidence, or select a result in **History** and choose **Use in AI**. That action only copies the result into an editable preview.
3. Review the exact evidence and remove secrets, personal data, irrelevant fields, or instructions embedded in untrusted input. If a History result is too large, select a smaller excerpt yourself; the app does not silently truncate it for AI.
4. Confirm that you reviewed the text and disabled Ollama cloud features, then choose **Generate explanation**. Editing the endpoint, model, question, or evidence clears confirmation.
5. Treat the answer as an unverified draft and check its factual claims and references against the original evidence. Prompts and model output never execute commands or make changes.

Questions are limited to **2,000 characters** and evidence to **24,000 UTF-8 bytes**. Requests have a **60-second overall limit**, a **3-second connection limit**, **64 KiB** of response-header budget, and a **1 MiB** response-body limit. Responses must be complete JSON with at most **64,000 answer characters**. A cold or large model may exceed these limits. Listing models accepts at most 128 entries.

Successful AI results save the exact `input_evidence`, `question`, `response`, model, endpoint, and evidence SHA-256 in the local database **without encryption**. The hash identifies submitted evidence text, not its accuracy. Sending sanitized evidence does not remove an unsanitized original result from History. The model can still be wrong or influenced by malicious source text; the system prompt is guidance, not a proof against prompt injection. **A real model has not been tested for this preview; AI protocol and error handling were exercised with fixtures.**

## Upgrading an existing installation

Close CyberLab and preserve a copy of its application-data directory before trying the preview. On the first open of an existing results-only database, the app creates **`results.pre-workspace.sqlite3`** before adding the tasks table. The backup uses SQLite's backup API, includes committed WAL data, and has private POSIX permissions (`0600`). Existing results remain in the active database.

The backup name is reserved and never overwritten. If that path already exists, migration stops; preserve or move the earlier backup while the app is closed, then retry. A failure to create the backup also stops migration. New databases and already-migrated databases do not create another pre-workspace backup.

This backup is unencrypted and predates subsequent tasks/results. To roll back, close all app instances, preserve the current data directory separately, and restore the pre-workspace database into a clean application-data directory without carrying over the newer SQLite companion files. This discards later workspace data from the restored active database; retain your copy if you need it. An automatic rollback or merge is not implemented.

For boundaries that apply across all pages, see [SECURITY.md](SECURITY.md). To verify the source with your selected Python environment:

```bash
python -m unittest discover -s tests -v
```
