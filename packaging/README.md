# Packaging Mailove

## Debian package (.deb)

CPack is configured in the top-level `CMakeLists.txt`:

```sh
cmake -B build -S . && cmake --build build --target package-deb
```

That leaves `mailove_<version>_<arch>.deb` — the version being the one in
`project()` — in the **project root**, not inside the build tree, and removes
CPack's `_CPack_Packages` staging directory afterwards. `cd build && cpack -G DEB`
still works and produces the same package, but leaves both where CPack put them.

Shared-library `Depends` are computed by `dpkg-shlibdeps` from the machine
that builds the package, so the .deb targets distros with the same-or-newer
Qt6/KF6/KPim6 library versions as the build host. The QML modules, the
`org.kde.desktop` style, and the Breeze icon theme are runtime-only
dependencies invisible to the linker; they're listed manually via
`CPACK_DEBIAN_PACKAGE_DEPENDS`.

For unrelated distros (or no KDE packages at all), ship the AppImage instead.

### Author, licence and docs

Debian has no `License` control field — the author and licence live elsewhere:

| Where | What |
|-------|------|
| `Maintainer:` control field | `CPACK_PACKAGE_CONTACT` in `CMakeLists.txt` |
| `Homepage:` control field | `CPACK_DEBIAN_PACKAGE_HOMEPAGE` |
| `/usr/share/doc/mailove/copyright` | `packaging/copyright` (DEP-5, LGPL-3.0-or-later) |
| `/usr/share/doc/mailove/changelog.gz` | `packaging/changelog` — mandatory for a native package |
| `/usr/share/man/man1/mailove.1.gz` | `packaging/mailove.1` |
| Software-centre "developer" | `<developer>` in the AppStream metainfo |

Bumping the version means editing `project(mailove VERSION …)` **and** adding a
`packaging/changelog` entry plus a `<release>` line in the metainfo.

The package is lintian-clean; check after changes with:

```sh
lintian build/mailove_1.0_amd64.deb
```

# Packaging Mailove as an AppImage

## Files here

| File | Purpose |
|------|---------|
| `org.mailove.Mailove.desktop` | Desktop entry (required by AppImage). |
| `org.mailove.Mailove.svg` | Application icon (scalable). |
| `org.mailove.Mailove.metainfo.xml` | AppStream metadata. |
| `build-appimage.sh` | Builds the AppImage end to end. |

All three data files are installed by CMake into the standard XDG locations
(`share/applications`, `share/icons/hicolor/scalable/apps`, `share/metainfo`).

## Build

```sh
packaging/build-appimage.sh          # → <project root>/Mailove-<version>-x86_64.AppImage
cmake --build build --target packages   # both the .deb and the AppImage
```

The version comes from `project()` in `CMakeLists.txt`, which the configure step
writes to `mailove-version.txt` in the AppImage build tree — the script reads it
from there rather than keeping a second copy of the number. The artifact lands
in the project root whichever directory the script is run from.

Environment overrides: `OUTPUT`, `BUILD_DIR`, `JOBS`, and the Qt path vars
(`QML_DIR`, `QT_LIBEXEC`, `QT_RESOURCES`, `QT_TRANSLATIONS`) if autodetection is
wrong for your distro.

## Prerequisites

- Full build toolchain and Mailove's build deps: Qt6 (Core, Gui, Network, Qml,
  Quick, QuickControls2, Sql, **WebEngineQuick**), KPim6 IMAP/Mime/SMTP, qtkeychain.
- **Internet on first run** — the script downloads `linuxdeploy` and
  `linuxdeploy-plugin-qt` into `./tools` (cached afterwards).
- **FUSE** to *run* the produced AppImage (not needed to build it).

## Why the script does extra work

`linuxdeploy-plugin-qt` handles most Qt deployment, but three things need manual
bundling for this app:

1. **QtWebEngine** — the `QtWebEngineProcess` helper, `icudtl.dat`, `*.pak`
   resources and per-language locales. The AppRun hook also sets
   `QTWEBENGINE_DISABLE_SANDBOX=1` (the Chromium sandbox needs a user namespace
   that many AppImage host environments don't provide) and points the
   `QTWEBENGINEPROCESS_PATH` / `..._RESOURCES_PATH` / `..._LOCALES_PATH` at the
   bundled copies.
2. **`org.kde.desktop` QtQuick Controls style** — `main.cpp` forces this style
   via `QQuickStyle::setStyle`, so it's loaded by name at runtime and the import
   scanner can't see it. The script copies the `org/kde/desktop`, `org/kde/kirigami`
   and `org/kde/kirigamiaddons` QML trees wholesale, and the hook exports
   `QT_QUICK_CONTROLS_STYLE=org.kde.desktop`.
3. **Breeze icon theme** — the UI uses named icons (`mail-attachment`, etc.);
   without a bundled theme they render blank. The hook prepends the bundled
   `share` to `XDG_DATA_DIRS`.

## Runtime notes

- **Secrets**: qtkeychain talks to the host's Secret Service / KWallet over
  D-Bus. That stays on the host — nothing to bundle — but the host must have a
  keyring/wallet running for "remember password" to work.
