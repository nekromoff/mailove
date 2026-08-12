// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtCore
import QtQuick
import QtQuick.Window
import Mailove.Core

/// The composer as a top-level window, for people who would rather write next
/// to the mailbox than in front of it (Look and feel → Compose in). The
/// composer itself is the same ComposeSheet the tab strip hosts; this only
/// supplies the window around it, and forwards the open*()/present()/title
/// contract so Main.qml can treat the two placements alike.
Window {
    id: win

    /// The uiSettings object from Main.qml.
    property var ui: null

    /// Emitted once the window is really gone, so Main.qml can drop its handle.
    signal finished()

    title: sheet.windowTitle
    flags: Qt.Window
    transientParent: null // own taskbar entry

    // Last compose geometry, restored on every opening and across restarts.
    // x/y are best effort (Wayland places windows itself); -1 = never saved.
    Settings {
        id: windowState
        category: "composeWindow"
        property int width: 700
        property int height: 600
        property int x: -1
        property int y: -1
        property bool maximized: false
    }
    width: windowState.width
    height: windowState.height
    minimumWidth: 400
    minimumHeight: 300
    Component.onCompleted: {
        if (windowState.x >= 0) {
            x = windowState.x
            y = windowState.y
        }
    }
    function saveGeometry() {
        windowState.maximized = win.visibility === Window.Maximized
        // Keep the last windowed geometry — maximized dimensions would make
        // un-maximizing on the next run a no-op.
        if (win.visibility === Window.Windowed) {
            windowState.width = win.width
            windowState.height = win.height
            windowState.x = win.x
            windowState.y = win.y
        }
    }

    color: sheet.panelColor

    /// Set once the composer has agreed to close, so the second, real close
    /// goes straight through instead of asking again.
    property bool allowClose: false

    // The title bar's X is a close request like any other: it goes to the
    // composer, which may want to ask about unsaved work first.
    onClosing: close => {
        // Remember the geometry even when the discard prompt cancels the close
        // below — a no-op then, the window is still on screen.
        saveGeometry()
        if (allowClose)
            return
        close.accepted = false
        sheet.close()
    }

    // The forwarded half of the page contract. Main.qml calls these without
    // caring whether it is holding a tab page or a window.
    function present() { sheet.present() }
    function close() { sheet.close() }
    function openNew() { sheet.openNew() }
    function openDraft(d) { sheet.openDraft(d) }
    function openReply(r) { sheet.openReply(r) }
    function openForward(r) { sheet.openForward(r) }

    ComposeSheet {
        id: sheet
        anchors.fill: parent
        ui: win.ui
        inTab: false

        onPresentRequested: {
            if (windowState.maximized)
                win.showMaximized()
            else
                win.show()
            win.raise()
            win.requestActivate()
        }
        onCloseRequested: {
            win.allowClose = true
            win.close()
            win.finished()
            // Deferred: tearing the window down from inside its own close is
            // asking for trouble.
            Qt.callLater(function() { win.destroy() })
        }
    }
}
