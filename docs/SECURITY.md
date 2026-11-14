# Security model

NetworkLuki CyberLab 0.1.1 is a local, unprivileged desktop MVP. Use network functions only within your authorized scope. The application does not establish ownership or authorization and does not provide a security boundary against another process running as the same user.

## Input and execution boundaries

- The TCP module accepts one explicit IP address and at most 128 selected ports. Unspecified addresses, multicast addresses, and the IPv4 limited-broadcast address are rejected. Subnet-directed broadcast addresses cannot be inferred without subnet metadata and are not separately detected. It makes ordinary TCP connections with bounded concurrency and timeouts. No exploitation, credential testing, or service detection is implemented.
- The web module accepts HTTP/HTTPS URLs without embedded credentials or fragments. It resolves a hostname once, validates returned addresses, and connects to the first address directly. HTTPS uses normal certificate and hostname verification. Redirects are not followed and environment proxy settings are not used.
- A web job sends one `HEAD` request and limits received header data to 64 KiB. It has an eight-second overall deadline. OS DNS resolution cannot be interrupted portably; an abandoned resolver may finish in a background daemon thread without making a subsequent target connection.
- File operations read regular files only and reject a selected final-component symbolic link. Hashing is limited to 2 GiB. Static inspection examines at most 4 MiB and bounds string and hex output. Files are never executed, imported, loaded as libraries, or automatically extracted.
- File identity and metadata are checked before and after inspection using the opened file and its path. Detectable changes discard the result. These checks are best effort and cannot prove that hostile concurrent modifications did not occur.
- Core validation is independent of UI validation. Background tasks use cooperative cancellation; completion may wait for a bounded OS operation to return.

## Data handling

Results are stored in a local SQLite database using parameterized queries. Payloads must be JSON objects, are limited to 2 MiB each, and are checked again when loaded; nonstandard JSON constants are rejected. The GUI history is limited to the latest 200 entries and at most 16 MiB of combined payloads. These are loading limits, not database retention or total disk-usage limits.

POSIX data-directory and database permissions are restricted to the current user; Windows relies on the account's application-data permissions. Export uses a temporary file and atomic replacement of the selected destination. Destinations inside the application data directory, including SQLite companion files, are rejected. Export also rejects overwriting the analyzed source file and selected symbolic links.

The database and JSON reports are not encrypted, signed, or tamper evident. Stored URL query data and fragments are redacted; `Location` and `Content-Location` also omit embedded credentials. Cookie-setting and selected authentication headers are redacted. This affects recorded results, not the actual request sent to the target. URL paths, arbitrary headers, local paths, extracted strings, and other response text can still contain secrets. Review reports before sharing and keep backups protected.

No telemetry or remote result-storage service is implemented. Requested DNS lookups and target connections are still network activity. Package installation contacts the configured dependency source.

## Interpretation and limits

An open port, missing header, signature match, or extracted string is an observation, not a confirmed vulnerability. TLS success records one connection's validation outcome; it is not a complete TLS configuration audit. File hashing and metadata checks are not disk acquisition, malware detonation, or a forensic chain of custody.

The application is not a malware sandbox. Untrusted files and reports should be examined in an appropriately isolated environment, and future third-party parsers must be treated as additional attack surface. No dynamic plugin loading or privileged helper is included in this release.

Windows and macOS are intended targets, but have not been validated for this release. Native installation, code signing, notarization, update verification, and rollback are future release work.

