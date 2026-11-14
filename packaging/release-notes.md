## NetworkLuki CyberLab 0.1.2

This MVP release adds native Windows x64 and Debian 13 amd64 installation packages.

- Footer: `Skapat av Luki Hackwell` on the left and `Powered by networkluki.com` on the right.
- Windows setup installs for the current user without requesting administrator privileges.
- The Debian package installs the bundled application under `/opt/networkluki-cyberlab`, adds a launcher and desktop entry, and declares its system library dependencies.
- Python and Qt are bundled; users do not need to install Python separately.
- The application continues to run as an ordinary user. Network jobs remain manually scoped.

Both build jobs must pass source tests, packaged-runtime checks, and installation verification before this release is published. JSON verification records and SHA-256 checksums accompany the packages. These checks cover startup, footer placement, file hashing, local storage and export; they are not exhaustive validation of every desktop or network environment.

The Windows executable is unsigned. Windows x64 and Linux amd64 are the binary targets for this release; no macOS installer is included. Local results remain unencrypted. The feature set is still an MVP and does not include decompilation or external Nmap/TShark/YARA/Ghidra integrations.

Corresponding Qt/PySide source archives are included as separate assets for the bundled third-party components. Their licenses remain separate from the application's MIT license. `SOURCE_COMMIT.txt` identifies the exact application source commit.

### Install on Debian 13

From the directory containing the downloaded package:

```bash
sudo apt install ./networkluki-cyberlab_0.1.2_amd64.deb
networkluki-cyberlab
```

Installing the system package requires administrator privileges; running the app does not.
