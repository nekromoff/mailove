// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailove.Core

/// A message opened in its own tab (double-click in the list). Owns a
/// MessageContext, so it keeps showing — and serving inline images,
/// attachments, Reply/Forward — whatever the main window moves on to.
///
/// A tab page, not a window: the tab strip in Main.qml hosts it. See the page
/// contract there — title, present(), closeRequested.
Item {
    id: win

    /// The MessageContext this page owns; released when the tab closes.
    property var context: null

    /// The uiSettings object from Main.qml (for the bgColor override).
    property var ui: null

    /// Marks this page as showing a message, so the host can route the mail
    /// shortcuts (Reply, Forward) at whatever is actually on screen instead of
    /// assuming the reading pane.
    readonly property bool isMessageTab: true

    signal replyRequested(bool replyAll)
    signal forwardRequested()

    /// Tab page contract (see Main.qml).
    property string title: context && context.subject.length > 0
                           ? context.subject : "Message"
    signal presentRequested()
    signal closeRequested()
    function present() { presentRequested() }
    function close() { closeRequested() }

    /// Called by the host once the tab is gone: free the context (scheme-
    /// handler slot, KMime message) and this page's WebEngine view.
    function releaseResources() {
        if (win.context)
            win.context.release()
    }

    // Same panel treatment as the compose page: chrome-gray Window color set,
    // with the user's bgColor override winning.
    Rectangle {
        anchors.fill: parent
        color: win.ui && win.ui.bgColor !== ""
               ? win.ui.bgColor : messageViewer.Kirigami.Theme.backgroundColor
    }

    Shortcut {
        sequence: "Esc"
        // Only the visible tab may act on a window-wide shortcut, or every
        // open message page would answer the same keystroke.
        enabled: win.StackLayout.isCurrentItem && !messageViewer.findActive
        // While the find bar is open Esc belongs to it — closing the whole
        // tab on a dismissed search would be a nasty surprise.
        onActivated: win.close()
    }

    MessageViewer {
        id: messageViewer
        anchors.fill: parent
        context: win.context
        ui: win.ui
        // Find and View source belong to the tab in front; see MessageViewer.
        shortcutsActive: win.StackLayout.isCurrentItem
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false
        onReplyRequested: replyAll => win.replyRequested(replyAll)
        onForwardRequested: win.forwardRequested()
    }
}
