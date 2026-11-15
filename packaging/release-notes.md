## NetworkLuki CyberLab 0.2.0 — workspace preview

This preview combines daily tasks, server observations, development review, and an optional AI assistant in the existing English desktop application. **The published release remains 0.1.2.** The `codex/workspace-0.2.0` branch is configured to produce native installers as CI artifacts, without automatically publishing a release. Download preview artifacts only from a successful run and review its verification reports.

### Workspace additions

- **Daily tasks:** project-scoped checklist, due dates, open/done state, and explicit links to History evidence; at most 1,000 tasks per project.
- **Servers:** on-demand local snapshots, validated JSON import, and bounded UTF-8 log keyword review. No SSH, remote agent, continuous polling, or server changes.
- **Development:** bounded project metadata inventory and Python AST source triage. Findings require human review; no project commands, tests, or source code are executed.
- **AI assistant:** optional Ollama integration for explicitly reviewed evidence. History's **Use in AI** copies a preview; **Generate explanation** sends it only after confirmation. AI output is unverified and never executes actions.
- **History:** **Create review task** explicitly records follow-up work without applying a fix. Existing network, web/TLS, hashing, and static binary tools remain available.
- **Headless snapshots:** `python -m networkluki_cyberlab --collect-snapshot NEW_JSON`, or `python tools/collect_snapshot.py --output NEW_JSON` from the checkout. Both use the standard library, avoid Qt startup, and refuse to overwrite an existing file.

The footer remains `Skapat av Luki Hackwell` on the left and `Powered by networkluki.com` on the right. See the [workspace guide](../docs/WORKSPACE.md) for exact limits and usage.

### Upgrade and AI data handling

Back up the application-data directory with the app closed before trying the preview. The first migration of an existing results-only database creates `results.pre-workspace.sqlite3` before adding tasks. The SQLite backup includes committed WAL data, has private POSIX permissions (`0600`), and is never overwritten. Migration stops on a backup-path collision or backup failure. Existing results are retained; new and already-migrated databases do not create another migration backup.

Ollama and model weights are not bundled. Configure **`OLLAMA_NO_CLOUD=1` in Ollama's environment, restart Ollama, and use a downloaded local model** before sending evidence. Loopback access alone does not guarantee local inference, and CyberLab cannot verify the backend's data handling. Successful AI history stores the exact reviewed evidence, question, and answer **without encryption**, alongside other local results. Redact sensitive data before sending.

AI protocol behavior has been checked with fixtures; **inference with a real model has not been tested**. Logs, metric thresholds, and source patterns are review signals, not verified incidents or vulnerabilities. See [security boundaries](../docs/SECURITY.md) and [verification notes](../docs/VERIFICATION.md).

### Native packages

The preview build targets Windows x64 and Debian 13 amd64. Windows setup installs for the current user without requesting administrator privileges. The Debian package installs under `/opt/networkluki-cyberlab` with a launcher and desktop entry. Python and Qt are bundled; the application runs as an ordinary user. Windows executables remain unsigned and there is no macOS installer.

After a successful preview build, install its downloaded Debian package with:

```bash
sudo apt install ./networkluki-cyberlab_0.2.0_amd64.deb
networkluki-cyberlab
```

This is a local package installation, not a claim that 0.2.0 has been published to the APT repository. CI artifacts and their reports establish only the checks actually performed in that run. Corresponding Qt/PySide source archives and license materials remain separate from the application's MIT license; `SOURCE_COMMIT.txt` records the build source commit. Nmap, TShark, YARA, and Ghidra integrations remain planned.
