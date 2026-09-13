#!/bin/sh
#
# rpmbuild's dependency generator for the RPM, minus one line.
#
# The QML type registration that qt_add_qml_module() generates links against
# QQmlPrivate, which Qt exports under the Qt_6_PRIVATE_API symbol version, and
# find-requires faithfully turns that into
#
#     libQt6Qml.so.6(Qt_6_PRIVATE_API)(64bit)
#
# Fedora and openSUSE deliberately never provide that symbol version (their
# Qt packages filter it out and expect an exact versioned dependency instead),
# so the package could not be installed at all: "nothing provides ...". Every
# other requirement — including the libQt6*.so.6(Qt_6.<minor>) ones, which are
# what really pins the package to the Qt minor it was built against — passes
# through untouched.
#
# A wrapper rather than %__requires_exclude because the rpm shipped by Debian
# ignores that macro for ELF dependencies (tested on rpm 4.18.2: the
# requirement stayed whether the macro was set in the spec or on the command
# line). Wired in from CMakeLists.txt via CPACK_RPM_SPEC_MORE_DEFINE.
set -eu
"$(rpm --eval '%{_rpmconfigdir}')/find-requires" "$@" | grep -v 'Qt_6_PRIVATE_API' || true
