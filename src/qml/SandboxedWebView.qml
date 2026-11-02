// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
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
    // sandbox. Only what acts on mail content: an image's copy and save
    // (first, when the click is on one), a link's address, copying plain or
    // as Markdown (the interchange format issue trackers and notes speak) —
    // and Select all.
    onContextMenuRequested: function (request) {
        request.accepted = true
        contextMenu.hasSelection = request.selectedText.length > 0
        contextMenu.linkUrl = request.linkUrl
        contextMenu.onImage = request.mediaType === ContextMenuRequest.MediaTypeImage
            && request.mediaUrl.toString().length > 0
        contextMenu.imageUrl = contextMenu.onImage ? request.mediaUrl : ""
        // Which images the page shows, for Save all images — read from the
        // body the page was served, since scripts cannot run in here to ask
        // the page itself.
        contextMenu.images = contextMenu.onImage ? Mail.pageImages(view.url) : []
        contextMenu.popup()
    }

    // A file name for the image under the pointer. Inline parts arrive as
    // mailove:cid/<slot>/<content-id>, whose id is often "image001.png@…";
    // pasted ones as data: URIs, which name only a type.
    function imageFileName(url) {
        const s = url.toString()
        const data = /^data:image\/([a-z0-9.+-]+)/i.exec(s)
        if (data)
            return "image." + (data[1].toLowerCase() === "jpeg" ? "jpg"
                               : data[1].toLowerCase().replace("svg+xml", "svg"))
        let name = s.split(/[?#]/)[0].split("/").pop() || ""
        try {
            name = decodeURIComponent(name)
        } catch (e) {
            // a malformed escape in a sender's content-id: keep it as written
        }
        name = name.split("@")[0].replace(/[\\/:*?"<>|]/g, "_").trim()
        if (name.length === 0)
            name = "image"
        if (name.indexOf(".") < 0)
            name += ".png"
        return name
    }

    // Save image as: the path is chosen first, then the renderer is asked to
    // download the image it already has — the same bytes on screen, whichever
    // way they arrived (an inline part, a data: URI, an allowed remote load),
    // with no second fetch of our own. A download request must be accepted
    // while its signal is being handled, which is why the dialog comes first.
    // The profile is shared by every view (the composer's quote preview too),
    // so only the view that asked answers it.
    property url pendingImageSave: ""
    FileDialog {
        id: saveImageDialog
        fileMode: FileDialog.SaveFile
        nameFilters: ["Images (*.png *.jpg *.jpeg *.gif *.webp *.bmp *.svg)", "All files (*)"]
        onAccepted: {
            view.pendingImageSave = selectedFile
            view.triggerWebAction(WebEngineView.DownloadImageToDisk)
        }
    }
    Connections {
        target: view.profile
        function onDownloadRequested(download) {
            const target = view.pendingImageSave.toString()
            if (target.length === 0)
                return
            view.pendingImageSave = ""
            const path = decodeURIComponent(target.replace(/^file:\/\//, ""))
            const slash = path.lastIndexOf("/")
            download.downloadDirectory = path.substring(0, slash)
            download.downloadFileName = path.substring(slash + 1)
            download.accept()
        }
    }

    QQC2.Menu {
        id: contextMenu
        property bool hasSelection: false
        property url linkUrl: ""
        property bool onImage: false
        property url imageUrl: ""
        property var images: [] ///< every image the page shows, for Save all
        readonly property bool onLink: linkUrl.toString().length > 0
        readonly property bool onMailto: linkUrl.toString().toLowerCase().indexOf("mailto:") === 0

        // On an image, the image comes first: that is what the right click
        // was aimed at, even when the image is also a link.
        QQC2.MenuItem {
            visible: contextMenu.onImage
            height: visible ? implicitHeight : 0
            text: "Copy image"
            icon.name: "edit-copy"
            // The decoded bitmap, as the renderer holds it — pastes as a
            // picture into editors, chats and image tools.
            onTriggered: view.triggerWebAction(WebEngineView.CopyImageToClipboard)
        }
        QQC2.MenuItem {
            visible: contextMenu.onImage
            height: visible ? implicitHeight : 0
            text: "Save image as…"
            icon.name: "document-save-as"
            onTriggered: {
                saveImageDialog.selectedFile = Mail.imageSaveFolder() + "/"
                    + view.imageFileName(contextMenu.imageUrl)
                saveImageDialog.open()
            }
        }
        // Straight into the save folder (Downloads unless Advanced settings
        // say otherwise) — no dialog per image; the status bar says where.
        QQC2.MenuItem {
            visible: contextMenu.onImage && contextMenu.images.length > 1
            height: visible ? implicitHeight : 0
            text: "Save all images (" + contextMenu.images.length + ")"
            icon.name: "document-save-all"
            onTriggered: Mail.saveImages(contextMenu.images)
        }
        QQC2.MenuSeparator {
            visible: contextMenu.onImage
            height: visible ? implicitHeight : 0
        }

        // On a link, the link comes first: that is what the right click was
        // aimed at. A mail address copies as the address alone — the
        // "mailto:" and any subject the link carries are the link's
        // business, not what anyone pastes into an address field.
        QQC2.MenuItem {
            visible: contextMenu.onLink
            height: visible ? implicitHeight : 0
            text: contextMenu.onMailto ? "Copy email address" : "Copy link address"
            icon.name: "edit-copy"
            onTriggered: {
                if (contextMenu.onMailto)
                    Mail.copyToClipboard(Mail.mailtoData(contextMenu.linkUrl).to)
                else
                    view.triggerWebAction(WebEngineView.CopyLinkToClipboard)
            }
        }
        QQC2.MenuSeparator {
            visible: contextMenu.onLink
            height: visible ? implicitHeight : 0
        }
        // Then the entry that works without a selection: the
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
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: "Select all"
            icon.name: "edit-select-all"
            onTriggered: view.triggerWebAction(WebEngineView.SelectAll)
        }
    }
}
