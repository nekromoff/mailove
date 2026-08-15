cmake_minimum_required(VERSION 3.20)
project(mailove VERSION 2.6 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Debian policy wants 0755 on packaged directories; without this CMake creates
# them with the build user's umask (0775 here) and lintian complains.
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Network Qml Quick QuickControls2 Sql Widgets WebEngineQuick)
find_package(KPim6IMAP REQUIRED)
find_package(KPim6Mime REQUIRED)
find_package(KPim6SMTP REQUIRED)
find_package(Qt6Keychain REQUIRED)
# Attachment payloads are stored compressed on disk (see attachmentstore.cpp).
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
# DKIM signature verification (see dkimverifier.cpp). Only libcrypto is needed —
# no TLS — and it is already in the process via Qt Network.
pkg_check_modules(LIBCRYPTO REQUIRED IMPORTED_TARGET libcrypto)
# OpenPGP key handling (see doc/openpgp.md). Optional on purpose: the AppImage
# has no gnupg to talk to, and everything else in mailove works without it. When
# it is missing the encryption UI is hidden and PgpEngine reports why — see
# MAILOVE_HAVE_OPENPGP below and PgpEngine::available().
option(MAILOVE_OPENPGP "Build OpenPGP support (needs Gpgmepp and QGpgmeQt6)" ON)
if(MAILOVE_OPENPGP)
    find_package(Gpgmepp QUIET)
    find_package(QGpgmeQt6 QUIET)
    if(Gpgmepp_FOUND AND QGpgmeQt6_FOUND)
        set(MAILOVE_HAVE_OPENPGP ON)
    else()
        set(MAILOVE_HAVE_OPENPGP OFF)
        # All three: the Gpgmepp and QGpgmeQt6 configs both resolve a Gpgme
        # dependency, which comes from the C library's own dev package — with
        # only the two C++ ones installed, both find_packages fail here.
        message(STATUS "OpenPGP support disabled: Gpgmepp/QGpgmeQt6 not found "
                       "(install libgpgme-dev libgpgmepp-dev libqgpgmeqt6-dev)")
    endif()
else()
    set(MAILOVE_HAVE_OPENPGP OFF)
    message(STATUS "OpenPGP support disabled by MAILOVE_OPENPGP=OFF")
endif()

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(mailove
    src/main.cpp
    src/mailclient.cpp
    src/mailclient.h
    src/accountstore.cpp
    src/accountstore.h
    src/mimeutils.cpp
    src/mimeutils.h
    src/maintenancescheduler.cpp
    src/maintenancescheduler.h
    src/messagepresenter.cpp
    src/messagepresenter.h
    src/messageverifier.cpp
    src/messageverifier.h
    src/syncengine.cpp
    src/syncengine.h
    src/dkimverifier.cpp
    src/dkimverifier.h
    src/publicsuffixlist.cpp
    src/publicsuffixlist.h
    src/spamheuristics.cpp
    src/spamheuristics.h
    src/messagecontext.cpp
    src/messagecontext.h
    src/foldermodel.cpp
    src/foldermodel.h
    src/messagelistmodel.cpp
    src/messagelistmodel.h
    src/mailstore.cpp
    src/mailstore.h
    src/mailbackend.h
    src/imapbackend.cpp
    src/imapbackend.h
    src/jmapsession.cpp
    src/jmapsession.h
    src/jmaprequest.cpp
    src/jmaprequest.h
    src/jmapbackend.cpp
    src/jmapbackend.h
    src/attachmentstore.cpp
    src/attachmentstore.h
    src/documenthandler.cpp
    src/documenthandler.h
    src/oauthhelper.cpp
    src/oauthhelper.h
    src/viewersecurity.cpp
    src/viewersecurity.h
    src/securewipe.cpp
    src/securewipe.h
    src/pgpengine.cpp
    src/pgpengine.h
    src/pgpmime.cpp
    src/pgpmime.h
    src/keydiscovery.cpp
    src/keydiscovery.h
    src/pgpkeymodel.cpp
    src/pgpkeymodel.h
)

# Must be set before qt_add_qml_module(), which bakes the autogen path into the
# metatypes dependency. Keeps mailove_autogen/ out of the build root.
set_target_properties(mailove PROPERTIES
    AUTOGEN_BUILD_DIR "${CMAKE_BINARY_DIR}/autogen/mailove_autogen")

set_source_files_properties(src/qml/Main.qml PROPERTIES QT_RESOURCE_ALIAS Main.qml)
set_source_files_properties(src/qml/AccountSheet.qml PROPERTIES QT_RESOURCE_ALIAS AccountSheet.qml)
set_source_files_properties(src/qml/MessageViewer.qml PROPERTIES QT_RESOURCE_ALIAS MessageViewer.qml)
set_source_files_properties(src/qml/ComposeSheet.qml PROPERTIES QT_RESOURCE_ALIAS ComposeSheet.qml)
set_source_files_properties(src/qml/ComposeWindow.qml PROPERTIES QT_RESOURCE_ALIAS ComposeWindow.qml)
set_source_files_properties(src/qml/MessageWindow.qml PROPERTIES QT_RESOURCE_ALIAS MessageWindow.qml)
set_source_files_properties(src/qml/KeyManagerSheet.qml PROPERTIES QT_RESOURCE_ALIAS KeyManagerSheet.qml)
set_source_files_properties(src/qml/NewKeyDialog.qml PROPERTIES QT_RESOURCE_ALIAS NewKeyDialog.qml)
set_source_files_properties(src/qml/Spinner.qml PROPERTIES QT_RESOURCE_ALIAS Spinner.qml)
set_source_files_properties(src/qml/HoverToolTip.qml PROPERTIES QT_RESOURCE_ALIAS HoverToolTip.qml)
set_source_files_properties(src/qml/SelectableValue.qml PROPERTIES QT_RESOURCE_ALIAS SelectableValue.qml)
set_source_files_properties(src/qml/SandboxedWebView.qml PROPERTIES QT_RESOURCE_ALIAS SandboxedWebView.qml)
set_source_files_properties(src/qml/ExpandableValue.qml PROPERTIES QT_RESOURCE_ALIAS ExpandableValue.qml)

qt_add_qml_module(mailove
    URI Mailove
    VERSION 1.0
    QML_FILES
        src/qml/Main.qml
        src/qml/AccountSheet.qml
        src/qml/KeyManagerSheet.qml
        src/qml/NewKeyDialog.qml
        src/qml/MessageViewer.qml
        src/qml/ComposeSheet.qml
        src/qml/ComposeWindow.qml
        src/qml/MessageWindow.qml
        src/qml/HoverToolTip.qml
        src/qml/Spinner.qml
        src/qml/SelectableValue.qml
        src/qml/SandboxedWebView.qml
        src/qml/ExpandableValue.qml
)

# Compile ABOUT.md into the binary (shown in Settings → About). Editing
# ABOUT.md and rebuilding always bakes the new text in — it is never read
# from disk at runtime.
qt_add_resources(mailove "about"
    PREFIX "/"
    FILES ABOUT.md
)

target_link_libraries(mailove PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Qml Qt6::Quick Qt6::QuickControls2 Qt6::Sql
    # Widgets: for KDE's native, widget-based file pickers only (see main.cpp).
    Qt6::Widgets
    Qt6::WebEngineQuick
    KPim6::IMAP
    KPim6::Mime
    KPim6::SMTP
    Qt6Keychain::Qt6Keychain
    PkgConfig::ZSTD
    PkgConfig::LIBCRYPTO
)

if(MAILOVE_HAVE_OPENPGP)
    target_link_libraries(mailove PRIVATE Gpgmepp QGpgmeQt6)
    target_compile_definitions(mailove PRIVATE MAILOVE_HAVE_OPENPGP)
endif()

target_compile_definitions(mailove PRIVATE MAILOVE_VERSION="${PROJECT_VERSION}")

install(TARGETS mailove RUNTIME DESTINATION bin)

# Desktop integration files — installed into the standard XDG locations so
# linuxdeploy (and normal system installs) pick them up for packaging.
include(GNUInstallDirs)
install(FILES packaging/org.mailove.Mailove.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES packaging/org.mailove.Mailove.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
install(FILES packaging/org.mailove.Mailove.metainfo.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)

# Debian has no "License" control field — the licence and copyright holder
# belong in the DEP-5 copyright file under share/doc/<package>, alongside a
# gzipped changelog (mandatory for a native package).
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/changelog.gz
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/changelog
            ${CMAKE_CURRENT_BINARY_DIR}/changelog
    COMMAND gzip -9nf ${CMAKE_CURRENT_BINARY_DIR}/changelog
    DEPENDS packaging/changelog
    COMMENT "Compressing Debian changelog"
    VERBATIM)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/mailove.1.gz
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/mailove.1
            ${CMAKE_CURRENT_BINARY_DIR}/mailove.1
    COMMAND gzip -9nf ${CMAKE_CURRENT_BINARY_DIR}/mailove.1
    DEPENDS packaging/mailove.1
    COMMENT "Compressing man page"
    VERBATIM)
add_custom_target(mailove-docs ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/changelog.gz
            ${CMAKE_CURRENT_BINARY_DIR}/mailove.1.gz)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mailove.1.gz
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

install(FILES packaging/copyright
              ${CMAKE_CURRENT_BINARY_DIR}/changelog.gz
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/mailove)

# Debian packaging: `cmake --build build --target package-deb`, which leaves
# mailove_<version>_<arch>.deb in the project root (see the target below).
# Shared-library Depends are computed by dpkg-shlibdeps; the extra Depends
# below are runtime-only QML/data packages the linker can't see (QML modules
# are loaded by name, the org.kde.desktop style is forced in main.cpp, and
# icons come from the Breeze theme).
set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_NAME mailove)
set(CPACK_PACKAGE_VENDOR "Daniel Duris")
set(CPACK_PACKAGE_CONTACT "Daniel Duris <dusoft@staznosti.sk>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The fast KDE email client")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/nekromoff/mailove")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Mailove is an IMAP and JMAP mail client focused on speed and safe message viewing.
It caches headers, bodies and the folder tree in SQLite for instant,
offline-capable browsing and full-text search, and renders HTML mail in a
sandboxed QtWebEngine view that blocks all remote content until you opt in. Built for KDE.

Licensed under the LGPL-3.0-or-later; see /usr/share/doc/mailove/copyright.")
set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_DEBIAN_PACKAGE_SECTION mail)
# Spelled out rather than DEB-DEFAULT, which produces this exact name but never
# tells us what it was — and package-deb below has to know which file to move.
execute_process(COMMAND dpkg --print-architecture
                OUTPUT_VARIABLE MAILOVE_DEB_ARCH
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
if(NOT MAILOVE_DEB_ARCH)
    set(MAILOVE_DEB_ARCH amd64)
endif()
set(CPACK_DEBIAN_FILE_NAME "mailove_${PROJECT_VERSION}_${MAILOVE_DEB_ARCH}.deb")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "\
qml6-module-org-kde-kirigami, \
qml6-module-org-kde-qqc2desktopstyle, \
breeze-icon-theme, \
qml6-module-qtcore, \
qml6-module-qtquick-controls, \
qml6-module-qtquick-layouts, \
qml6-module-qtquick-dialogs, \
qml6-module-qtwebengine")
# Recommends, not Depends: without gnupg mailove runs exactly as before, with the
# encryption settings hidden and PgpEngine saying why. Anyone who wants
# OpenPGP wants gpg-agent's passphrase handling with it, which is why the agent
# is named rather than left to gnupg's own dependencies.
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "gnupg, gpg-agent")
include(CPack)

# The version, for anything outside CMake that needs it — packaging/build-appimage.sh
# names the AppImage from this rather than parsing project() out of this file.
file(WRITE "${CMAKE_BINARY_DIR}/mailove-version.txt" "${PROJECT_VERSION}\n")

# Every release artifact lands in the project root, named with its version, so
# builds are never hunted for inside a build tree:
#
#   cmake --build build --target package-deb   → mailove_<version>_<arch>.deb
#   cmake --build build --target packages      → both, via build-appimage.sh
#
# Named "packages", not "package": include(CPack) above already defines that
# one, and it is the plain cpack run these targets wrap.
#
# CPack is run here rather than by hand because it also leaves _CPack_Packages
# behind — a staging tree it repopulates from scratch every run, worth nothing
# once the .deb exists. Removing it before and after keeps a stale layout from
# a previous version out of the package and the build tree tidy afterwards.
set(MAILOVE_CPACK_SCRATCH "${CMAKE_BINARY_DIR}/_CPack_Packages")
add_custom_target(package-deb
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${MAILOVE_CPACK_SCRATCH}"
    COMMAND ${CMAKE_CPACK_COMMAND} --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
    COMMAND ${CMAKE_COMMAND} -E rename
            "${CMAKE_BINARY_DIR}/${CPACK_DEBIAN_FILE_NAME}"
            "${CMAKE_SOURCE_DIR}/${CPACK_DEBIAN_FILE_NAME}"
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${MAILOVE_CPACK_SCRATCH}"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Packaging ${CPACK_DEBIAN_FILE_NAME} into the project root"
    VERBATIM)
add_dependencies(package-deb mailove mailove-docs)

# The AppImage has its own build tree (build-appimage/, a Release configure of
# its own) because it bundles Qt and must not inherit this one's flags. The
# script is the whole recipe; this target only makes it reachable the same way.
add_custom_target(package-appimage
    COMMAND ${CMAKE_COMMAND} -E env
            "${CMAKE_SOURCE_DIR}/packaging/build-appimage.sh"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building the AppImage into the project root"
    USES_TERMINAL
    VERBATIM)

add_custom_target(packages)
add_dependencies(packages package-deb package-appimage)

qt_add_executable(attachmenttest tests/attachmenttest.cpp
    src/attachmentstore.cpp src/attachmentstore.h)
target_link_libraries(attachmenttest PRIVATE Qt6::Core PkgConfig::ZSTD)

qt_add_executable(viewertest tests/viewertest.cpp src/viewersecurity.cpp src/viewersecurity.h)
target_link_libraries(viewertest PRIVATE Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::WebEngineQuick)

# Checks DKIM canonicalization against the vectors published in RFC 6376 3.4.5.
# Self-contained: no network, no fixtures. Exit 0 = all vectors match.
qt_add_executable(dkimtest tests/dkimtest.cpp src/dkimverifier.cpp src/dkimverifier.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_link_libraries(dkimtest PRIVATE Qt6::Core Qt6::Network PkgConfig::LIBCRYPTO)

# Diagnostic, not a pass/fail test: runs the real verifier over .eml files and
# prints a verdict per message. Needs working DNS. Used to establish that our
# stored bodies are not byte-identical to what arrived — see doc/roadmap.md.
#   ./dkimchecktool msg1.eml msg2.eml
qt_add_executable(dkimchecktool tests/dkimchecktool.cpp
    src/dkimverifier.cpp src/dkimverifier.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_link_libraries(dkimchecktool PRIVATE
    Qt6::Core Qt6::Network KPim6::Mime PkgConfig::LIBCRYPTO)

# Diagnostic: does a message survive the KMime parse/re-encode path byte for
# byte? With no argument it uses a built-in nested multipart; with a file
# argument it checks that message.
qt_add_executable(rawfidelitytest tests/rawfidelitytest.cpp)
target_link_libraries(rawfidelitytest PRIVATE Qt6::Core KPim6::Mime)

# Diagnostic: where do the octets of a stored message diverge from the octets
# that arrived? Refetches sampled UIDs with its own minimal IMAP client (using
# KIMAP would beg the question) and compares wire / KMime round-trip / cache,
# with a DKIM verdict for each. Needs the wallet password and DNS.
#   ./fidelitytool --account 0 --folder INBOX --count 30
qt_add_executable(fidelitytool tests/fidelitytool.cpp
    src/dkimverifier.cpp src/dkimverifier.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_link_libraries(fidelitytool PRIVATE
    Qt6::Core Qt6::Network Qt6::Sql KPim6::Mime KPim6::IMAP
    Qt6Keychain::Qt6Keychain PkgConfig::LIBCRYPTO)

# Diagnostic, not a pass/fail test: scores .eml files with the real heuristics
# and prints every rule that fired, plus a confusion matrix over a ham and a
# spam corpus. The weights in spamheuristics.cpp are only defensible against
# numbers this produces.
#   ./spamtool --ham good/ --spam junk/ --quiet
#
# Links MimeUtils (and so the cache sources it sits on) rather than carrying its
# own copy of the body and attachment collectors: a tool that reads a message
# differently from the client measures a filter the client does not run.
qt_add_executable(spamtool tests/spamtool.cpp
    src/spamheuristics.cpp src/spamheuristics.h
    src/mimeutils.cpp src/mimeutils.h
    src/mailstore.cpp src/mailstore.h
    src/messagelistmodel.cpp src/messagelistmodel.h
    src/attachmentstore.cpp src/attachmentstore.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_link_libraries(spamtool PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Sql KPim6::Mime PkgConfig::ZSTD)

# Checks the backend-neutral message identity the JMAP work needs (remote_id,
# per-folder sync_state) against a throwaway database of its own — never the
# real mail cache. Exit 0 = every check passed.
qt_add_executable(storetest tests/storetest.cpp
    src/mailstore.cpp src/mailstore.h
    src/messagelistmodel.cpp src/messagelistmodel.h
    src/attachmentstore.cpp src/attachmentstore.h
    src/spamheuristics.cpp src/spamheuristics.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_include_directories(storetest PRIVATE src)
target_link_libraries(storetest PRIVATE Qt6::Core Qt6::Gui Qt6::Network Qt6::Sql PkgConfig::ZSTD)

# Checks JMAP session discovery (RFC 8620 §2) against recorded session objects,
# with no server involved — see the file's own comment for why that is the
# right boundary. Exit 0 = every check passed.
qt_add_executable(jmapsessiontest tests/jmapsessiontest.cpp
    src/jmapsession.cpp src/jmapsession.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h
    src/mailbackend.h)
target_include_directories(jmapsessiontest PRIVATE src)
target_compile_definitions(jmapsessiontest PRIVATE
    JMAP_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
target_link_libraries(jmapsessiontest PRIVATE Qt6::Core Qt6::Network)

# Checks the JMAP method-call batch: back-references, the server's call limit,
# and reading a response — including the error responses JMAP delivers inside a
# successful POST. Exit 0 = every check passed.
qt_add_executable(jmaprequesttest tests/jmaprequesttest.cpp
    src/jmaprequest.cpp src/jmaprequest.h
    src/jmapsession.cpp src/jmapsession.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h
    src/mailbackend.h)
target_include_directories(jmaprequesttest PRIVATE src)
target_compile_definitions(jmaprequesttest PRIVATE
    JMAP_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
target_link_libraries(jmaprequesttest PRIVATE Qt6::Core Qt6::Network)

# Checks the JMAP-to-MailBackend translations, above all that the header block
# rebuilt from Email/get is byte-identical to the message's own blob — the
# claim the DKIM and spam paths rest on. Exit 0 = every check passed.
qt_add_executable(jmapbackendtest tests/jmapbackendtest.cpp
    src/jmapbackend.cpp src/jmapbackend.h
    src/jmaprequest.cpp src/jmaprequest.h
    src/jmapsession.cpp src/jmapsession.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h
    src/mailbackend.h)
target_include_directories(jmapbackendtest PRIVATE src)
target_compile_definitions(jmapbackendtest PRIVATE
    JMAP_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
target_link_libraries(jmapbackendtest PRIVATE Qt6::Core Qt6::Network KPim6::Mime)

set(_mailove_tests attachmenttest viewertest dkimtest dkimchecktool rawfidelitytest
                 fidelitytool pgpmimetest securewipetest spamtool storetest
                 jmapsessiontest jmaprequesttest jmapbackendtest)

# Checks what SecureWipe guarantees, and pins the one thing it deliberately
# refuses to do (overwrite a shared buffer, which would wipe a private copy and
# look like protection). Also checks that core-dump suppression is reversible.
# How accounts are stored, migrated and re-read. Links Qt6Keychain because
# AccountStore writes secrets; the test itself never starts a wallet job.
qt_add_executable(accountstoretest tests/accountstoretest.cpp
    src/accountstore.cpp src/accountstore.h
    src/mailbackend.h)
target_include_directories(accountstoretest PRIVATE src)
target_link_libraries(accountstoretest PRIVATE
    Qt6::Core Qt6::Network Qt6Keychain::Qt6Keychain KPim6::Mime)
set_target_properties(accountstoretest PROPERTIES RUNTIME_OUTPUT_DIRECTORY tests)

# The attachment split/restore pair the offline cache is built on. Needs
# MailStore only for PartRef, and that pulls in the models it is declared with.
qt_add_executable(mimeutilstest tests/mimeutilstest.cpp
    src/mimeutils.cpp src/mimeutils.h
    src/mailstore.cpp src/mailstore.h
    src/messagelistmodel.cpp src/messagelistmodel.h
    src/attachmentstore.cpp src/attachmentstore.h
    src/spamheuristics.cpp src/spamheuristics.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_include_directories(mimeutilstest PRIVATE src)
target_link_libraries(mimeutilstest PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Sql KPim6::Mime PkgConfig::ZSTD)
set_target_properties(mimeutilstest PROPERTIES RUNTIME_OUTPUT_DIRECTORY tests)

# Pass/fail companion to spamtool: every rule fires on the shape it was written
# for, and none of the ham corpus below the unsure threshold moves. The second
# half is the one that must not be relaxed to fit a new rule.
qt_add_executable(spamheuristicstest tests/spamheuristicstest.cpp
    src/spamheuristics.cpp src/spamheuristics.h
    src/publicsuffixlist.cpp src/publicsuffixlist.h)
target_include_directories(spamheuristicstest PRIVATE src)
target_link_libraries(spamheuristicstest PRIVATE Qt6::Core Qt6::Network)
set_target_properties(spamheuristicstest PROPERTIES RUNTIME_OUTPUT_DIRECTORY tests)

qt_add_executable(securewipetest tests/securewipetest.cpp
    src/securewipe.cpp src/securewipe.h)
target_include_directories(securewipetest PRIVATE src)
target_link_libraries(securewipetest PRIVATE Qt6::Core PkgConfig::LIBCRYPTO)

# Checks the RFC 3156 structure parser against fixed vectors — including the
# MIME-mixing shapes it must refuse to treat as encrypted. Self-contained: no
# keyring, no network, no gpg, so it runs anywhere. Exit 0 = all matched.
qt_add_executable(pgpmimetest tests/pgpmimetest.cpp src/pgpmime.cpp src/pgpmime.h)
target_include_directories(pgpmimetest PRIVATE src)
target_link_libraries(pgpmimetest PRIVATE Qt6::Core KPim6::Mime)

# Diagnostic: drives PgpEngine against a real keyring without the GUI — key
# listing, identity matching, import/export, and the two lookup paths.
# Set GNUPGHOME to a throwaway directory first.
#   GNUPGHOME=/tmp/kr ./pgpkeytool --for me@example.com
if(MAILOVE_HAVE_OPENPGP)
    qt_add_executable(pgpkeytool tests/pgpkeytool.cpp
        src/pgpengine.cpp src/pgpengine.h
        src/pgpmime.cpp src/pgpmime.h
        src/keydiscovery.cpp src/keydiscovery.h)
    target_include_directories(pgpkeytool PRIVATE src)
    target_link_libraries(pgpkeytool PRIVATE
        Qt6::Core Qt6::Network KPim6::Mime Gpgmepp QGpgmeQt6)
    target_compile_definitions(pgpkeytool PRIVATE MAILOVE_HAVE_OPENPGP)
    list(APPEND _mailove_tests pgpkeytool)
endif()

# Keep the test and diagnostic targets out of the build root: both the
# binaries and the AUTOMOC/AUTOUIC scratch dirs land under build/tests/.
foreach(_test ${_mailove_tests})
    set_target_properties(${_test} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOGEN_BUILD_DIR "${CMAKE_BINARY_DIR}/tests/${_test}_autogen")
endforeach()
