# Security, utilities and AI in one workspace

This guide describes the Code review and Utilities additions integrated into the
0.2.0 workspace preview. The published 0.1.2 installers do not include these
pages. The interface remains English and the author/powered-by footer is unchanged.

## One connected workflow

1. Enter a project name and run a scoped network/web check, file analysis or
   Python code review.
2. Use Utilities to validate/format JSON or compare two pieces of text. Inputs
   are pasted into the app; original files are not changed.
3. Choose **Explain with AI** on a result, or select a saved result in History.
   The selected record becomes editable evidence in the AI assistant.
4. Inspect the evidence, remove anything private, enter a question, load the
   available models from the configured loopback Ollama service and select an
   already downloaded local model. Confirm the request before sending.
5. Review the explanation as an unverified AI interpretation. Results and their
   evidence are stored under the active project and can be exported as JSON.

The app never applies a suggestion, runs a generated command or changes a
firewall/service configuration. Hashing, source checks and utilities work
without Ollama. This release does not generate or deploy complete apps.

## Python code observations

The five rule groups check dynamic `eval`/`exec`, subprocess calls with literal
`shell=True`, pickle deserialization, explicitly unverified TLS contexts, and
Requests calls with literal `verify=False`. Imports and uncomplicated aliases
are recognized. Findings include a rule, line, UTF-8 byte column, explanation,
remediation and source SHA-256; source snippets and string values are omitted.

Every finding is `review_required`, not a confirmed vulnerability. Input trust,
data flow, scope-sensitive name resolution, computed configuration, wrappers,
dynamic imports and dependency vulnerabilities are not fully analyzed. Zero
matches does not establish safety. Parsing uses the current interpreter grammar.

Only UTF-8 regular `.py`/`.pyw` files up to 256 KiB are accepted. Final-component
symlinks, invalid syntax and detectable changes during reading are rejected.
AST complexity is bounded; at most 200 findings are retained, with truncation
explicitly reported. No source code is executed or imported.

## Developer utilities

JSON formatting preserves exact number tokens, including long decimal values,
large integers and exponents. Duplicate keys and nonstandard numeric constants
are rejected to avoid silent data loss. Validation checks syntax, not an
application schema. Text comparison preserves differences in line endings and
marks missing final newlines. Neither operation writes back to a source file.

Each input is limited to 128 KiB. JSON nesting is limited to 64 levels. Each diff
input may contain at most 1,000 LF-delimited lines. Output is limited to 256 KiB.
Successful formatted content and diffs are saved in local history, so do not
paste secrets you do not want retained.

## Optional Ollama setup and trust

The workspace AI page accepts only literal loopback HTTP endpoints (`127.0.0.1`
or `[::1]`). It does not use DNS, inherited proxies or redirects. Load the model
list explicitly and select an already downloaded local model. CyberLab does not
install or download models.

Configure Ollama with `OLLAMA_NO_CLOUD=1` in the service environment and restart
it before using sensitive evidence. Cloud-tagged model names are rejected, but
loopback and metadata checks do not attest to the backend's actual inference
location or privacy configuration.

Questions are capped at 2,000 characters and evidence at 24,000 UTF-8 bytes.
Requests have bounded connect/overall deadlines and bounded headers/body/output.
Evidence and model responses remain untrusted text. The assistant has no command
execution, file-write, download or remediation tool. Review consent is cleared
when endpoint, model, question or evidence changes.

Successful AI results store the reviewed evidence, its hash, the question and
response in the unencrypted local history. Do not treat model output as a
verified finding, and remove secrets before sending.

## Primary references

Checked on 2026-11-15:

- [Ollama chat API](https://docs.ollama.com/api/chat)
- [Ollama model details](https://docs.ollama.com/api-reference/show-model-details)
- [Ollama FAQ and local-only configuration](https://docs.ollama.com/faq)
- [Qt for Python QThread](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html)

See [verification notes](VERIFICATION.md) for executed checks and remaining
platform and model verification gaps.
