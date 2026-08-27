// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtWebEngine
import Mailove.Core

/// WebEngineView locked down for hostile mail content — the one place the
/// sandbox lives, shared by the message viewer and the composer's quote
/// preview: no scripts, no plugins, nothing local. Remote requests are
/// additionally blocked by the C++ interceptor and each page's CSP.
WebEngineView {
    id: view

    settings.javascriptEnabled: false
    settings.pluginsEnabled: false
    settings.localContentCanAccessFileUrls: false
    settings.localContentCanAccessRemoteUrls: false
    settings.localStorageEnabled: false
    settings.autoLoadImages: true
    settings.hyperlinkAuditingEnabled: false

    // Defining this handler replaces WebEngine's default console logging.
    // Chromium reports a CSP refusal once per occurrence of the same URL in
    // the page and ends each message with the source snippet's own newline —
    // a newsletter full of one blocked arrow icon floods the log with
    // identical lines and blank lines between them. Log each distinct
    // message once per document instead, trimmed.
    property var loggedConsoleLines: ({})
    onJavaScriptConsoleMessage: function (level, message, lineNumber, sourceID) {
        const line = message.trim()
        if (view.loggedConsoleLines[line])
            return
        view.loggedConsoleLines[line] = true
        console.warn("viewer js:", line)
    }
    onLoadingChanged: function (loadInfo) {
        if (loadInfo.status === WebEngineView.LoadStartedStatus)
            view.loggedConsoleLines = ({}) // new document, fresh slate
    }

    // Scripts are off and Chromium's status bubble does not exist here, so
    // without this a reader has no way to see where a link goes before
    // clicking it — and in hostile mail content the destination is exactly
    // what they need to check. The engine reports the link under the pointer;
    // the HoverHandler supplies the pointer position the tooltip follows.
    property string hoveredLink: ""
    onLinkHovered: function (hoveredUrl) {
        view.hoveredLink = hoveredUrl.toString()
    }
    HoverHandler {
        id: linkHover
    }
    HoverToolTip {
        hover: linkHover
        text: view.hoveredLink
    }

    // Our own context menu in place of Chromium's default, whose entries
    // (Back, Reload, View page source…) do nothing useful inside a mail
    // sandbox. Only what acts on mail content: copying — plain, as Markdown
    // (the interchange format issue trackers and notes speak), a link's
    // address — and Select all.
    onContextMenuRequested: function (request) {
        request.accepted = true
        contextMenu.hasSelection = request.selectedText.length > 0
        contextMenu.linkUrl = request.linkUrl
        contextMenu.popup()
    }
    QQC2.Menu {
        id: contextMenu
        property bool hasSelection: false
        property url linkUrl: ""

        // First, and the only entry that works without a selection: the
        // common case is wanting the message, not part of it, and reaching
        // that through Select all → Copy made the reader do the renderer's
        // work. Converted from the sanitized HTML part directly, so it needs
        // no selection and no round trip through the clipboard. Named for
        // the common case; the selection variant below carries the qualifier.
        QQC2.MenuItem {
            text: "Copy as Markdown"
            icon.name: "edit-copy"
            onTriggered: Mail.copyMessageAsMarkdown()
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: "Copy"
            icon.name: "edit-copy"
            enabled: contextMenu.hasSelection
            onTriggered: view.triggerWebAction(WebEngineView.Copy)
        }
        QQC2.MenuItem {
            text: "Copy selection as Markdown"
            icon.name: "edit-copy"
            enabled: contextMenu.hasSelection
            // The renderer's Copy puts the selection's HTML flavour on the
            // clipboard beside the text; the C++ side converts that to
            // Markdown once it lands.
            onTriggered: {
                view.triggerWebAction(WebEngineView.Copy)
                Mail.clipboardSelectionToMarkdown()
            }
        }
        QQC2.MenuItem {
            visible: contextMenu.linkUrl.toString().length > 0
            height: visible ? implicitHeight : 0
            text: "Copy link address"
            icon.name: "edit-copy"
            onTriggered: view.triggerWebAction(WebEngineView.CopyLinkToClipboard)
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: "Select all"
            icon.name: "edit-select-all"
            onTriggered: view.triggerWebAction(WebEngineView.SelectAll)
        }
    }
}
