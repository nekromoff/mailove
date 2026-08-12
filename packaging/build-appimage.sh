#!/usr/bin/env bash
#
# Build a self-contained AppImage for Mailove.
#
# Prerequisites (not installed by this script):
#   - A working build toolchain + all of Mailove's build deps (Qt6, KPim6*, qtkeychain).
#   - Internet access on first run to download the linuxdeploy tools into ./tools.
#   - FUSE (for the resulting AppImage to run; not needed to build it).
#
# Usage:
#   packaging/build-appimage.sh            # release build, downloads tools if missing
#   OUTPUT=mailove.AppImage packaging/build-appimage.sh
#
# The result is written to the project root as Mailove-<version>-x86_64.AppImage,
# whatever directory the script is invoked from — the version comes from
# project() in CMakeLists.txt via the file the configure step writes.
#
# The heavy lifting is done by linuxdeploy + its Qt plugin, but three things
# need manual help because the plugin does not cover them for this app:
#   1. QtWebEngine       — helper process, ICU data, *.pak resources, locales.
#   2. org.kde.desktop   — the QtQuick Controls style the app forces in main.cpp,
#                          plus Kirigami and the QQC2 desktop implementation.
#   3. Breeze icons      — the UI references named icons (mail-attachment, …).
#
set -euo pipefail

# --- paths ---------------------------------------------------------------
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # project root
build_dir="${BUILD_DIR:-$here/build-appimage}"
appdir="$here/AppDir"
tools_dir="$here/tools"
jobs="${JOBS:-$(nproc)}"
# $output is settled after the configure step below, which is what writes the
# version file the default name is built from.

# linuxdeploy-plugin-qt queries qmake; the bare `qmake` wrapper may point at
# Qt5, so force the Qt6 one unless the caller overrides it.
export QMAKE="${QMAKE:-qmake6}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# Where Qt keeps its bits varies per distro (Debian buries libs under an arch
# triplet, Fedora/Arch do not), so ask qmake instead of hardcoding a layout.
# Every value stays overridable for the cases where the answer is wrong.
qt_query() { "$QMAKE" -query "$1" 2>/dev/null || true; }
command -v "$QMAKE" >/dev/null || { echo "$QMAKE not found in PATH" >&2; exit 1; }

qml_dir="${QML_DIR:-$(qt_query QT_INSTALL_QML)}"
qt_libexec="${QT_LIBEXEC:-$(qt_query QT_INSTALL_LIBEXECS)}"
qt_translations="${QT_TRANSLATIONS:-$(qt_query QT_INSTALL_TRANSLATIONS)}"
qt_plugins="${QT_PLUGINS:-$(qt_query QT_INSTALL_PLUGINS)}"
# There is no QT_INSTALL_RESOURCES; WebEngine's *.pak/ICU data sit next to the
# rest of Qt's arch-independent data.
qt_resources="${QT_RESOURCES:-$(qt_query QT_INSTALL_DATA)/resources}"

# --- 1. fetch tooling ----------------------------------------------------
mkdir -p "$tools_dir"
fetch() { # url dest
  local url="$1" dest="$2"
  if [[ ! -x "$dest" ]]; then
    log "Downloading $(basename "$dest")"
    curl -fL# "$url" -o "$dest"
    chmod +x "$dest"
  fi
}
# linuxdeploy and its plugin are AppImages themselves and self-mount through
# FUSE to run. Containers, CI images and hardened desktops routinely cannot,
# where they fail with "Cannot mount AppImage" before doing any work — so fall
# back to their built-in extract-and-run mode. Costs one unpack per tool; the
# alternative is not building at all.
#
# /dev/fuse is checked as well as the binaries, and it is the one that actually
# decides: a container image commonly ships fusermount while the kernel device
# is not passed through, which looks like FUSE support right up to the mount.
if [[ -z "${APPIMAGE_EXTRACT_AND_RUN:-}" ]] \
   && { [[ ! -e /dev/fuse ]] \
        || ! { command -v fusermount3 >/dev/null || command -v fusermount >/dev/null; }; }; then
  log "No usable FUSE — running the packaging tools in extract-and-run mode"
  export APPIMAGE_EXTRACT_AND_RUN=1
fi

base="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous"
qtbase="https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous"
fetch "$base/linuxdeploy-x86_64.AppImage"                 "$tools_dir/linuxdeploy"
fetch "$qtbase/linuxdeploy-plugin-qt-x86_64.AppImage"     "$tools_dir/linuxdeploy-plugin-qt"
export PATH="$tools_dir:$PATH"

# --- 2. configure + build + install into AppDir --------------------------
log "Configuring (Release)"
cmake -S "$here" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr

# Written by the configure step above, so the AppImage carries the same version
# as the .deb and neither is a copy of the number kept somewhere else.
version="$(cat "$build_dir/mailove-version.txt" 2>/dev/null || true)"
[[ -n "$version" ]] || { echo "no version from $build_dir/mailove-version.txt" >&2; exit 1; }
# Absolute: linuxdeploy writes into the working directory, and the artifact
# belongs in the project root however the script was invoked. An OUTPUT that is
# already a path is taken as given — the rooting is a default, not a rule.
output="${OUTPUT:-Mailove-$version-x86_64.AppImage}"
[[ "$output" == /* ]] || output="$here/$output"

log "Building"
# mailove-docs too: `install` pulls in the gzipped man page, and building only
# the mailove target left it missing so the install step below failed.
cmake --build "$build_dir" --parallel "$jobs" --target mailove mailove-docs

log "Installing into AppDir"
rm -rf "$appdir"
DESTDIR="$appdir" cmake --install "$build_dir" --component "" >/dev/null

# --- 3. bundle the pieces linuxdeploy-plugin-qt misses -------------------
# 3a. QtWebEngine helper process + data. It must live next to the Qt libexec
#     path the loader expects; we place it under usr/libexec and point to it.
log "Bundling QtWebEngine"
install -Dm755 "$qt_libexec/QtWebEngineProcess" "$appdir/usr/libexec/QtWebEngineProcess"
mkdir -p "$appdir/usr/resources" "$appdir/usr/translations"
cp -a "$qt_resources/." "$appdir/usr/resources/" 2>/dev/null || true
# WebEngine locales (.pak per language) live under translations/qtwebengine_locales
if [[ -d "$qt_translations/qtwebengine_locales" ]]; then
  cp -a "$qt_translations/qtwebengine_locales" "$appdir/usr/translations/"
fi

# 3b. The org.kde.desktop QtQuick Controls style + Kirigami + QQC2 impl.
#     linuxdeploy-plugin-qt scans imports it can see, but the style is loaded
#     by string at runtime (QQuickStyle::setStyle) so copy the trees wholesale.
log "Bundling KDE QML style + Kirigami"
# usr/qml is where linuxdeploy-plugin-qt puts imports and what the qt.conf it
# generates points Qml2Imports at, so land in the same tree — no arch triplet.
dest_qml="$appdir/usr/qml"
mkdir -p "$dest_qml/org/kde"
for mod in org/kde/desktop org/kde/kirigami org/kde/kirigamiaddons; do
  if [[ -d "$qml_dir/$mod" ]]; then
    mkdir -p "$dest_qml/$(dirname "$mod")"
    cp -a "$qml_dir/$mod" "$dest_qml/$(dirname "$mod")/"
  fi
done

# 3c. The SVG *icon engine*. Breeze ships SVGs, and rendering them as icons
#     needs iconengines/libqsvgicon.so — imageformats/libqsvg.so is a different
#     plugin and does not cover it. linuxdeploy-plugin-qt bundles the latter
#     but not the former, so every named icon in the UI came out as an empty
#     square no matter how the theme was configured.
log "Bundling the SVG icon engine"
if [[ -d "$qt_plugins/iconengines" ]]; then
  mkdir -p "$appdir/usr/plugins/iconengines"
  cp -a "$qt_plugins/iconengines/." "$appdir/usr/plugins/iconengines/"
fi

# 3d. Breeze icon theme so named icons in the UI actually render.
# Search the XDG data dirs rather than one fixed prefix: the theme lives under
# a different root on distros that install KDE outside /usr/share.
log "Bundling Breeze icons"
icon_roots="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
for theme in breeze breeze-dark; do
  IFS=: read -r -a _roots <<< "$icon_roots"
  for root in "${_roots[@]}"; do
    [[ -d "$root/icons/$theme" ]] || continue
    dest="$appdir/usr/share/icons/$theme"
    mkdir -p "$dest"
    cp -a "$root/icons/$theme/." "$dest/"
    break
  done
done

# --- 4. runtime hook: env for the bundled Qt/WebEngine/style -------------
# linuxdeploy runs apprun-hooks/*.sh before launching the app.
log "Writing AppRun hooks"
hooks="$appdir/apprun-hooks"
mkdir -p "$hooks"
cat > "$hooks/mailove-env.sh" <<'HOOK'
#!/bin/bash
here="$(dirname "$(readlink -f "$0")")"
# WebEngine sandbox needs a userns; AppImages often run where it's unavailable.
export QTWEBENGINE_DISABLE_SANDBOX=1
export QTWEBENGINEPROCESS_PATH="$here/usr/libexec/QtWebEngineProcess"
export QTWEBENGINE_RESOURCES_PATH="$here/usr/resources"
export QTWEBENGINE_LOCALES_PATH="$here/usr/translations/qtwebengine_locales"
# Force the bundled KDE style; without a KDE session it would fall back to Basic.
export QT_QUICK_CONTROLS_STYLE="org.kde.desktop"
export QML2_IMPORT_PATH="$here/usr/qml${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
# Prefer the bundled Breeze icons.
export XDG_DATA_DIRS="$here/usr/share${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}"
HOOK
chmod +x "$hooks/mailove-env.sh"

# --- 5. deploy Qt + pack the AppImage ------------------------------------
log "Running linuxdeploy + Qt plugin"
# EXTRA_QT_MODULES ensures WebEngine/QuickControls2 libs are pulled even if the
# import scanner can't see them. QML_SOURCES_PATHS points the Qt plugin at our
# QML so it can trace imports.
export EXTRA_QT_MODULES="waylandcompositor"   # harmless if unused; helps on wayland
export QML_SOURCES_PATHS="$here/src/qml"
# linuxdeploy drops the AppImage in the working directory; make that the
# project root rather than wherever the caller happened to be standing.
cd "$here"
"$tools_dir/linuxdeploy" \
  --appdir "$appdir" \
  --plugin qt \
  --desktop-file "$appdir/usr/share/applications/org.mailove.Mailove.desktop" \
  --icon-file "$appdir/usr/share/icons/hicolor/scalable/apps/org.mailove.Mailove.svg" \
  --output appimage

# linuxdeploy names it from the desktop file, unversioned; normalise to $output.
produced="$(ls -t "$here"/Mailove*.AppImage 2>/dev/null | head -1 || true)"
if [[ -n "$produced" && "$produced" != "$output" ]]; then
  mv -f "$produced" "$output"
fi
log "Done: $output"
