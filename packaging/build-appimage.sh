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
# It also carries its own C library (step 6), which linuxdeploy never bundles:
# without it the AppImage ran only on hosts with the build system's glibc or
# newer, and exited before showing a window on anything older.
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
# Packs the AppDir. linuxdeploy's --output appimage cannot be used: the C
# library goes in after linuxdeploy has deployed (step 6), and a second
# linuxdeploy pass would rewrite the bundled loader and libc like any other ELF.
fetch "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
      "$tools_dir/appimagetool"
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

# 3e. The Wayland platform plugin. linuxdeploy-plugin-qt bundles xcb only, so
#     on a Plasma Wayland session (which sets QT_QPA_PLATFORM=wayland) the
#     AppImage died with 'Could not find the Qt platform plugin "wayland"'.
#     The plugin is one file under platforms/ (libqwayland.so since Qt 6.7;
#     libqwayland-generic.so and -egl.so before) plus the client-side helper
#     plugins it loads by directory — shell integration, decorations, graphics
#     integration. The server-side directory is a compositor's and stays out.
#     linuxdeploy resolves the libraries these pull in (QtWaylandClient, …)
#     because it deploys dependencies for every ELF already in the AppDir.
log "Bundling the Wayland platform plugin"
wayland_found=0
for plugin in libqwayland.so libqwayland-generic.so libqwayland-egl.so; do
  if [[ -f "$qt_plugins/platforms/$plugin" ]]; then
    install -Dm644 "$qt_plugins/platforms/$plugin" "$appdir/usr/plugins/platforms/$plugin"
    wayland_found=1
  fi
done
if [[ $wayland_found == 1 ]]; then
  for dir in wayland-shell-integration wayland-decoration-client \
             wayland-graphics-integration-client; do
    [[ -d "$qt_plugins/$dir" ]] || continue
    mkdir -p "$appdir/usr/plugins/$dir"
    cp -a "$qt_plugins/$dir/." "$appdir/usr/plugins/$dir/"
  done
else
  echo "warning: no Wayland platform plugin under $qt_plugins/platforms —" \
       "install qt6-wayland; the AppImage will run on X11/XWayland only" >&2
fi

# 3f. Cyrus SASL mechanism plugins. KIMAP authenticates through libsasl2,
#     which linuxdeploy bundles — but the library finds its mechanisms by a
#     path compiled in at build time (Debian: /usr/lib/<triplet>/sasl2), and
#     on Fedora/openSUSE that directory does not exist. Every login then died
#     with 'SASL(-4): no mechanism available: No worthy mechs found'. The
#     plugins ship inside, and the hook below points SASL_PATH at them.
#     Kerberos (gssapiv2, gs2) and sasldb are left out: nobody logs in to a
#     mail server that way from here, and they would drag krb5/db in.
log "Bundling SASL mechanisms"
sasl_dir=""
for cand in /usr/lib/x86_64-linux-gnu/sasl2 /usr/lib64/sasl2 /usr/lib/sasl2; do
  [[ -d "$cand" ]] && { sasl_dir="$cand"; break; }
done
if [[ -n "$sasl_dir" ]]; then
  mkdir -p "$appdir/usr/lib/sasl2"
  for mech in plain login crammd5 digestmd5 scram ntlm anonymous kdexoauth2; do
    cp -a "$sasl_dir"/lib"$mech".so* "$appdir/usr/lib/sasl2/" 2>/dev/null || true
  done
  [[ -f "$appdir/usr/lib/sasl2/libplain.so" ]] \
    || echo "warning: no PLAIN mechanism found in $sasl_dir" >&2
  [[ -f "$appdir/usr/lib/sasl2/libkdexoauth2.so" ]] \
    || echo "warning: kdexoauth2 SASL plugin missing — OAuth logins will fail" >&2
else
  echo "warning: no sasl2 plugin directory found; IMAP logins will fail" >&2
fi

# 3g. Sonnet spell-check backend. The compose window asks Sonnet for a
#     speller; the backends are KF6 plugins linuxdeploy-plugin-qt does not
#     know about, so the AppImage had none ('No speller backends available').
#     hunspell only — its dictionaries live on the target system under
#     /usr/share/hunspell, which every distro has; the other backends need
#     libraries nobody installs by default.
log "Bundling the Sonnet hunspell backend"
if [[ -f "$qt_plugins/kf6/sonnet/sonnet_hunspell.so" ]]; then
  install -Dm644 "$qt_plugins/kf6/sonnet/sonnet_hunspell.so" \
                 "$appdir/usr/plugins/kf6/sonnet/sonnet_hunspell.so"
fi

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
# The bundled libsasl2 must find the bundled mechanisms, not the build
# distro's compiled-in directory (absent on Fedora/openSUSE: "no worthy
# mechs found" on every IMAP login).
export SASL_PATH="$here/usr/lib/sasl2"
# Never die on a missing platform plugin: Qt walks a ;-separated list and
# takes the first that loads. A session that pins QT_QPA_PLATFORM=wayland
# (Plasma does) gets xcb as the fallback; one that pins nothing gets Wayland
# first when there is a compositor to talk to, and X11 otherwise.
case "${QT_QPA_PLATFORM:-}" in
  "")            [[ -n "${WAYLAND_DISPLAY:-}" ]] && export QT_QPA_PLATFORM="wayland;xcb" ;;
  wayland|wayland-egl) export QT_QPA_PLATFORM="$QT_QPA_PLATFORM;xcb" ;;
esac
HOOK
chmod +x "$hooks/mailove-env.sh"

# --- 5. deploy Qt --------------------------------------------------------
log "Running linuxdeploy + Qt plugin"
# QML_SOURCES_PATHS points the Qt plugin at our QML so it can trace imports.
# (EXTRA_QT_MODULES="waylandcompositor" used to be set here "for wayland" —
# that is the server-side module and never helped a client; the client plugin
# is bundled in 3e above.)
export QML_SOURCES_PATHS="$here/src/qml"
# linuxdeploy drops the AppImage in the working directory; make that the
# project root rather than wherever the caller happened to be standing.
cd "$here"
"$tools_dir/linuxdeploy" \
  --appdir "$appdir" \
  --plugin qt \
  --desktop-file "$appdir/usr/share/applications/org.mailove.Mailove.desktop" \
  --icon-file "$appdir/usr/share/icons/hicolor/scalable/apps/org.mailove.Mailove.svg"

# --- 6. bundle the C library ---------------------------------------------
# linuxdeploy leaves glibc (and libstdc++, freetype, … — its excludelist) to
# the host. The bundle is linked against this build system's versions, so a
# host with older ones cannot load it at all: on Ubuntu 22.04 / Debian 12 the
# AppImage exited at once with "GLIBC_2.38 not found". It now carries them in
# usr/lib/compat, and the AppRun hook (below) loads them through the bundled
# dynamic loader — but only on a host too old for the bundle, since a newer
# host's GPU drivers need its own, newer glibc.
#
# usr/lib/compat is deliberately not on any RUNPATH: under the host's loader
# (the newer-host case) a libc.so.6 found through $ORIGIN/../lib would be
# loaded into a process whose loader belongs to another glibc, and crash.
log "Bundling the C library"
# The glibc the bundle needs, read before compat/ exists to skew it.
# objdump fails on the scripts and data among them; that is not an error here.
glibc_needed="$({ find "$appdir/usr" -type f \( -name '*.so*' -o -perm -u+x \) \
                    -exec objdump -T {} + 2>/dev/null || true; } \
                | grep -o 'GLIBC_2\.[0-9]*' | sed 's/GLIBC_//' | sort -uV | tail -1)"
[[ -n "$glibc_needed" ]] || { echo "could not work out the glibc the bundle needs" >&2; exit 1; }

compat="$appdir/usr/lib/compat"
rm -rf "$compat"; mkdir -p "$compat"
# One read of the cache: piping ldconfig into an awk that exits early trips
# pipefail on the SIGPIPE.
ldcache="$(ldconfig -p)"
syslib() { awk -v l="$1" '$1==l && /x86-64/{print $NF; exit}' <<<"$ldcache"; }
libc_dir="$(dirname "$(syslib libc.so.6)")"

# glibc itself. The stub libraries (libpthread, libdl, …) are empty since 2.34
# but must still come from here: an older host library that links them would
# otherwise pull the host's full, older copies in next to this libc.
for l in libc.so.6 libm.so.6 libmvec.so.1 libresolv.so.2 libpthread.so.0 libdl.so.2 \
         librt.so.1 libutil.so.1 libanl.so.1 libnss_files.so.2 libnss_dns.so.2; do
  cp -L "$libc_dir/$l" "$compat/"
done
# The loader goes in usr/bin, not compat/: run through it, /proc/self/exe is
# the loader, and Qt takes the application directory — where it looks for
# qt.conf — from that. Next to the app it finds the same qt.conf as before.
install -Dm755 "$(readlink -f "$libc_dir/ld-linux-x86-64.so.2")" \
               "$appdir/usr/bin/ld-linux-x86-64.so.2"
# iconv modules use glibc-private symbols, so the host's do not load under this
# libc; the hook points GCONV_PATH here.
cp -a "$libc_dir/gconv" "$compat/gconv"

# The rest of what linuxdeploy leaves to the host and the bundle was linked
# against newer versions of, plus whatever of their dependencies the AppDir does
# not already have. Graphics drivers and the X11/Wayland/ALSA client libraries
# stay the host's however old: they must match the running system, and their
# ABI does not move.
keep_host='^(libGL|libEGL|libGLX|libGLdispatch|libOpenGL|libgbm|libdrm|libX|libxcb|libwayland|libasound|libICE|libSM|libcom_err|libvulkan)'
declare -A seen=()
queue=()
for l in libstdc++.so.6 libgcc_s.so.1 libfreetype.so.6 libharfbuzz.so.0 libfontconfig.so.1 \
         libexpat.so.1 libz.so.1 libgmp.so.10 libgpg-error.so.0; do
  p="$(syslib "$l")"
  [[ -n "$p" ]] || { echo "$l not found on the build system" >&2; exit 1; }
  queue+=("$p")
done
while ((${#queue[@]})); do
  p="${queue[0]}"; queue=("${queue[@]:1}")
  n="$(basename "$p")"
  [[ -n "${seen[$n]:-}" ]] && continue
  seen[$n]=1
  cp -L "$p" "$compat/$n"
  while read -r dep path; do
    [[ -e "$compat/$dep" || -e "$appdir/usr/lib/$dep" ]] && continue
    [[ "$dep" =~ $keep_host || "$dep" =~ ^(libc|libm|libpthread|libdl|librt|ld-linux)[.-] ]] && continue
    queue+=("$path")
  done < <(ldd "$p" | awk '$2=="=>" && $3 ~ /^\//{print $1, $3}')
done

# WebEngine starts its helper by path, as a new program, so it would get the
# host's loader; this wrapper runs it the way the hook runs the app.
cat > "$appdir/usr/libexec/QtWebEngineProcess.compat" <<'WRAP'
#!/bin/sh
# QtWebEngineProcess through the bundled loader. QTWEBENGINEPROCESS_PATH points
# here only when the app itself runs that way (see apprun-hooks/mailove-env.sh).
usr="$(dirname "$(readlink -f "$0")")/.."
exec "$usr/bin/ld-linux-x86-64.so.2" \
     --library-path "$usr/lib/compat:$usr/lib" \
     --argv0 "$usr/libexec/QtWebEngineProcess" \
     "$usr/libexec/QtWebEngineProcess" "$@"
WRAP
chmod +x "$appdir/usr/libexec/QtWebEngineProcess.compat"

# Appended to the hook from step 4, which linuxdeploy's AppRun already sources:
# a hook added now would not be in its list. It execs, so it must stay last.
sed "s/@GLIBC_NEEDED@/$glibc_needed/g" >> "$hooks/mailove-env.sh" <<'HOOK'

# Bundled C library (usr/lib/compat). The libraries here need glibc
# @GLIBC_NEEDED@; an older host cannot load them, so on one the app runs on the
# bundled glibc through the bundled loader. A host at least as new keeps its own:
# its GPU drivers are built against it and would not load under an older one.
# getconf reports the running glibc, and is absent on musl, which has none to
# use. MAILOVE_BUNDLED_GLIBC=1 or 0 forces the choice.
_glibc_have="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
_glibc_need="@GLIBC_NEEDED@"
case "${MAILOVE_BUNDLED_GLIBC:-}" in
  1) _use_bundled=1 ;;
  0) _use_bundled=0 ;;
  *) if [[ -n "$_glibc_have" ]] \
        && [[ "$(printf '%s\n%s\n' "$_glibc_need" "$_glibc_have" | sort -V | head -1)" == "$_glibc_need" ]]; then
       _use_bundled=0
     else
       _use_bundled=1
     fi ;;
esac
if [[ $_use_bundled == 1 ]]; then
  # --library-path, not LD_LIBRARY_PATH: the variable would reach every host
  # program the app starts (xdg-open, the browser) and load this glibc under
  # the host's loader. --argv0 keeps the name the app sees its own.
  export GCONV_PATH="$here/usr/lib/compat/gconv"
  export QTWEBENGINEPROCESS_PATH="$here/usr/libexec/QtWebEngineProcess.compat"
  exec "$here/usr/bin/ld-linux-x86-64.so.2" \
       --library-path "$here/usr/lib/compat:$here/usr/lib" \
       --argv0 "$here/usr/bin/mailove" \
       "$here/usr/bin/mailove" "$@"
fi
unset _glibc_have _glibc_need _use_bundled
HOOK

# --- 7. metadata for AppImage checkers -----------------------------------
# AppImageHub's checker and appimagetool look for AppStream data under the
# older .appdata.xml name only, and reported it missing next to our
# .metainfo.xml. Same file, both names.
ln -sf org.mailove.Mailove.metainfo.xml \
       "$appdir/usr/share/metainfo/org.mailove.Mailove.appdata.xml"

# .DirIcon is what file managers use as the AppImage's thumbnail, and it has
# to be a PNG — linuxdeploy points it at the SVG. Render one; the SVG stays for
# the desktop entry. Whichever renderer the build system has.
log "Rendering the PNG icon"
svg="$appdir/usr/share/icons/hicolor/scalable/apps/org.mailove.Mailove.svg"
png="$appdir/usr/share/icons/hicolor/256x256/apps/org.mailove.Mailove.png"
mkdir -p "$(dirname "$png")"
if command -v rsvg-convert >/dev/null; then
  rsvg-convert -w 256 -h 256 "$svg" -o "$png"
elif command -v inkscape >/dev/null; then
  inkscape "$svg" -w 256 -h 256 -o "$png" >/dev/null 2>&1
elif command -v convert >/dev/null; then
  convert -background none -density 384 "$svg" -resize 256x256 "$png"
fi
if [[ -s "$png" ]]; then
  cp "$png" "$appdir/org.mailove.Mailove.png"
  ln -sf org.mailove.Mailove.png "$appdir/.DirIcon"
else
  echo "warning: no SVG renderer (rsvg-convert, inkscape or convert) —" \
       ".DirIcon stays an SVG" >&2
fi

# --- 8. pack the AppImage ------------------------------------------------
log "Packing $(basename "$output")"
# Update information, so AppImageUpdate and friends can fetch the next release
# by delta. It points at the .zsync of the latest GitHub release, which
# appimagetool writes next to the AppImage — upload both to the release.
# UPDATE_INFORMATION overrides it (as with linuxdeploy); empty leaves it out.
update_info="${UPDATE_INFORMATION-gh-releases-zsync|nekromoff|mailove|latest|Mailove-*-x86_64.AppImage.zsync}"
ARCH=x86_64 "$tools_dir/appimagetool" ${update_info:+-u "$update_info"} "$appdir" "$output"
log "Done: $output (hosts below glibc $glibc_needed run on the bundled one)"
