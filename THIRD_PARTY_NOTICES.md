# Third-party components

The [MIT License](LICENSE) applies to original NetworkLuki CyberLab source code. It does not relicense Python, Qt, PySide6, Shiboken6, build tools, or other dependencies.

## Runtime dependency

`pyproject.toml` declares `PySide6-Essentials==6.12.0`. The application uses the `QtCore`, `QtGui`, and `QtWidgets` modules. Installing the package also installs its declared dependencies, including the corresponding Shiboken6 component.

Qt for Python is offered under LGPLv3/GPLv3 and commercial licensing options. Qt and Qt for Python also contain components with their own third-party notices. Native packages include a `licenses` directory with dependency metadata, Python and packaging-tool notices, full LGPL/GPL texts, and license/attribution materials collected from the verified Qt/PySide sources. Keep these materials with the binaries.

The release includes corresponding source archives for Qt Base, SVG, Wayland, Translations, Image Formats, and PySide/Shiboken. `third-party-sources.json` records exact archive names and pinned SHA-256 digests. The runtime uses external shared libraries under `_internal`; compatible modified libraries can be substituted, and the public application/build source supports rebuilding. The application's MIT terms do not prohibit reverse engineering for debugging changes to LGPL components. System-provided libraries remain subject to their own package licenses.

Primary references, checked **2026-11-14**:

- [Qt for Python](https://doc.qt.io/qtforpython-6/)
- [Licenses used in Qt for Python](https://doc.qt.io/qtforpython-6/licenses.html)
- [Qt licensing](https://doc.qt.io/qt-6/licensing.html)
- [Python license](https://docs.python.org/3/license.html)

## Planned integrations

Nmap, TShark, YARA, and Ghidra are mentioned in the roadmap only. They are not bundled, required, or executed by version 0.1.2. Their dependency, licensing, and distribution requirements must be reviewed before an integration is released.

## Rebuilding binary releases

Before distributing a self-contained executable, inventory the exact bundled Python, Qt, binding, and packaging components and include their applicable notices and source/relinking materials as required. A project-level MIT file alone is not a complete notice set for a bundled application.
