# Third-party components

The [MIT License](LICENSE) applies to original NetworkLuki CyberLab source code. It does not relicense Python, Qt, PySide6, Shiboken6, build tools, or other dependencies.

## Runtime dependency

`pyproject.toml` declares `PySide6-Essentials==6.12.0`. The application uses the `QtCore`, `QtGui`, and `QtWidgets` modules. Installing the package also installs its declared dependencies, including the corresponding Shiboken6 component.

Qt for Python is offered under LGPLv3/GPLv3 and commercial licensing options. Qt and Qt for Python also contain components with their own third-party notices. Retain the applicable license and copyright materials from the actual dependency distributions when distributing packaged applications. This source bundle does not include a standalone Qt runtime or native installers.

Primary references, checked **2026-11-14**:

- [Qt for Python](https://doc.qt.io/qtforpython-6/)
- [Licenses used in Qt for Python](https://doc.qt.io/qtforpython-6/licenses.html)
- [Qt licensing](https://doc.qt.io/qt-6/licensing.html)
- [Python license](https://docs.python.org/3/license.html)

## Planned integrations

Nmap, TShark, YARA, and Ghidra are mentioned in the roadmap only. They are not bundled, required, or executed by version 0.1.1. Their dependency, licensing, and distribution requirements must be reviewed before an integration is released.

## Future binary releases

Before distributing a self-contained executable, inventory the exact bundled Python, Qt, binding, and packaging components and include their applicable notices and source/relinking materials as required. A project-level MIT file alone is not a complete notice set for a bundled application.
