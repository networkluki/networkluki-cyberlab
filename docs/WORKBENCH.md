# Security, utilities and AI in one workspace

This unreleased source expansion builds on the 0.1.2 desktop app. The published
0.1.2 installers do not include these additions. The interface remains English
and the author/powered-by footer is unchanged.

## One connected workflow

1. Enter a project name and run a scoped network/web check, file analysis or
   Python code review.
2. Use Utilities to validate/format JSON or compare two pieces of text. Inputs
   are pasted into the app; original files are not changed.
3. Choose **Explain with AI** on a result, or select a saved result in History.
   The selected record becomes editable evidence in the AI assistant.
4. Inspect the evidence, remove anything private, enter a question and the name
   of an already available local Ollama model. Confirm the request before sending.
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

Use an existing trusted Ollama service bound to `127.0.0.1:11434`, with a local
model already installed. CyberLab does not install, download or select a model
automatically. It does not accept arbitrary endpoint URLs, inherit HTTP proxies
or follow redirects.

Configure the Ollama service with `OLLAMA_NO_CLOUD=1` using the service's normal
configuration procedure before using sensitive evidence. The adapter inspects
the model metadata and rejects reported remote models. This is a check of the
service's response, not attestation: a modified service or a model changed after
the check can invalidate the result. Loopback does not prove local inference.

Evidence and model responses are untrusted text. The assistant has no tool or
command execution capability. Instructions embedded in the evidence are not
authorized actions; generated conclusions still require independent review.
Review consent is cleared when the request inputs change. Cancelling discards
the result but cannot undo evidence already sent or guarantee that the service
immediately stops inference.

The local SQLite database and exports are unencrypted. AI results retain the
reviewed evidence, its hash, the question and the response so interpretations
can be traced back to what was submitted. Do not treat them as verified findings.

## Primary references

Checked on 2026-11-15:

- [Ollama chat API](https://docs.ollama.com/api/chat)
- [Ollama model details](https://docs.ollama.com/api-reference/show-model-details)
- [Ollama FAQ and local-only configuration](https://docs.ollama.com/faq)
- [Qt for Python QThread](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html)

See [verification notes](VERIFICATION.md) for executed checks and remaining
platform and model verification gaps.
