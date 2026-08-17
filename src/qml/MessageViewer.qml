// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import QtQuick.Window
import QtWebEngine
import org.kde.kirigami as Kirigami
import Mailove.Core

ColumnLayout {
    id: viewer
    spacing: 0

    /// The MessageContext this viewer renders. The reading pane binds
    /// Mail.readingContext; a detached message window owns its own context.
    /// All message state (bodies, attachments, junk flag, view URLs) comes
    /// from here, so several viewers can be on screen at once.
    property var context: null

    /// Whether this viewer is the one the user is looking at. Shortcut objects
    /// are window-wide, so with a message tab open there are several viewers
    /// alive at once and every one of them would answer Find or View source —
    /// Qt sees that as an ambiguous overload and fires none of them. The host
    /// sets this on the visible viewer only.
    property bool shortcutsActive: true

    /// The uiSettings object from Main.qml (for the configurable shortcuts).
    /// Null is tolerated everywhere: the built-in defaults are used then.
    property var ui: null

    readonly property bool hasMessage: context ? context.hasMessage : false
    property string viewMode: "html"
    // The mode buttons' checked states are synced here, not bound: a click on
    // a checkable button overwrites (and thereby severs) a declarative
    // binding, which is how the active mode once showed unchecked while its
    // content stayed on screen. Assignment survives any amount of clicking.
    onViewModeChanged: {
        modeHtmlButton.checked = viewMode === "html"
        modeTextButton.checked = viewMode === "text"
        modeSourceButton.checked = viewMode === "source"
    }

    /// True while the find bar is open. The message window checks this so its
    /// Esc-closes-the-window shortcut does not swallow Esc-closes-the-find-bar.
    readonly property bool findActive: findBar.visible
    // Match counters, filled from findTextFinished (Chromium counts for us).
    property int findMatches: 0
    property int findCurrent: 0

    /// Reply / Reply all was clicked for the shown message.
    signal replyRequested(bool replyAll)
    /// Forward was clicked for the shown message.
    signal forwardRequested()
    /// The full-fidelity forward: original bytes as a message/rfc822
    /// attachment (the Forward button's press-and-hold option).
    signal forwardAsAttachmentRequested()

    // Reset to the "Select a message" placeholder (e.g. the shown message was
    // deleted and the list is now empty).
    function clear() {
        if (context)
            context.clear()
    }

    function showCurrent() {
        if (!context || !context.hasMessage) {
            web.url = "about:blank"
            return
        }
        // Junk folders open as plain text; the HTML button is the explicit
        // opt-in to render the (still sandboxed) HTML.
        viewMode = context.junkTextOnly ? "text" : "html"
        context.quotePlainText = viewMode === "text"
        web.url = context.bodyUrl
    }

    /// How the OpenPGP signature is stated on the badge.
    ///
    /// A name appears only when the signature is valid *and* the signing key
    /// carries the From address — signerTrusted. A valid signature from an
    /// unrelated key is exactly what a forger's own key produces, so it gets
    /// the warning wording instead of a reassuring one. And nothing here ever
    /// says "invalid": Mailove cannot prove it is checking the octets that were
    /// signed, so a mismatch is reported as unverified (doc/openpgp.md §3).
    function signatureText() {
        if (!context)
            return ""
        if (context.cryptoChecking)
            return "Checking signature…"
        switch (context.signatureStatus) {
        case "valid":
            if (context.signerTrusted) {
                const who = context.signerName.length > 0 ? context.signerName
                                                          : context.signerEmail
                return "✓ Signed by " + who
            }
            return "⚠ Signed by another address"
        case "modified":
            // Established against octets we know are original: the signed part
            // is not the part that arrived. After a mailing list or forwarder
            // that is ordinary, so this states what happened rather than
            // accusing anyone — the same wording rule the DKIM badge follows.
            return "⚠ Modified after OpenPGP signing"
        case "unverified":
            // We could not reproduce what was signed, so this claims nothing
            // about the message at all.
            return "Signature not verified"
        case "unknownKey":
            return "Signed with a key you do not have"
        case "expired":
            return "⚠ Signed with an expired key"
        case "revoked":
            return "⚠ Signed with a revoked key"
        case "error":
            return "Signature not checked"
        default:
            return "Signed"
        }
    }

    /// The key manager, opened from the badge. One per viewer: a detached
    /// message window has no settings page to borrow one from.
    KeyManagerSheet {
        id: viewerKeyManager
        accountAddress: viewer.senderAddress()
    }

    /// The key this message's badge is about, for the key manager: the signer
    /// when there is a signature to attribute, otherwise the sender's own key
    /// if we hold one. Empty when neither is known, which is when the badge is
    /// not clickable.
    ///
    /// Deliberately never the key the message was encrypted *to*. That one is
    /// the reader's own, and opening it from a badge that describes where the
    /// message came from answers a question nobody asked — the reader wants
    /// the other party's key, not their own.
    function inspectableKey() {
        if (!context)
            return ""
        if (context.signerFingerprint.length > 0)
            return context.signerFingerprint
        // Unsigned: no key was used on the sender's side, so there is nothing
        // this message can attribute. Their public key is still the useful
        // thing to open if the keyring has one.
        const addr = viewer.senderAddress()
        if (addr.length > 0) {
            const found = Pgp.encryptionKeysFor([addr])
            if (found[addr] !== undefined && found[addr].length > 0)
                return found[addr]
        }
        return ""
    }

    /// The bare address of the sender, for a key lookup. The From header is
    /// "Name <addr>" as often as not.
    function senderAddress() {
        if (!context)
            return ""
        const m = /<([^>]+)>/.exec(context.from)
        return (m ? m[1] : context.from).trim()
    }

    /// Switch the rendered representation. Shared by the HTML/Text/Source
    /// buttons and the view-source shortcut so both stay in step.
    function showMode(mode) {
        if (!context || !context.hasMessage)
            return
        if (viewMode === mode)
            return // clicking the active mode is a no-op, not a reload
        viewMode = mode
        // Reply/Forward quote what the reader is looking at: reading the
        // plain text quotes the plain text. (Source view is a way of
        // inspecting the message, not a way of reading it — it changes
        // nothing here.)
        if (mode !== "source")
            context.quotePlainText = mode === "text"
        web.url = mode === "text" ? context.textViewUrl()
                : mode === "source" ? context.sourceViewUrl()
                                    : context.htmlViewUrl()
    }

    /// Ctrl+U: source on, and off again back to the rendered message.
    function toggleSource() {
        if (!hasMessage)
            return
        showMode(viewMode === "source"
                 ? (context.junkTextOnly ? "text" : "html")
                 : "source")
    }

    function openFind() {
        if (!hasMessage)
            return
        findBar.visible = true
        findField.forceActiveFocus()
        findField.selectAll() // repeat presses replace the old term
        if (findField.text.length > 0)
            findRun(false)
    }

    function closeFind() {
        findBar.visible = false
        web.findText("") // drop the highlighting
        findMatches = 0
        findCurrent = 0
        web.forceActiveFocus()
    }

    // Chromium's find-in-page advances to the next match on every repeated
    // call with the same term, so next/previous is the same call as the
    // initial search — only the direction flag differs.
    function findRun(backward) {
        if (findField.text.length === 0) {
            web.findText("")
            findMatches = 0
            findCurrent = 0
            return
        }
        let flags = 0
        if (findCase.checked)
            flags |= WebEngineView.FindCaseSensitively
        if (backward)
            flags |= WebEngineView.FindBackward
        web.findText(findField.text, flags)
    }

    Shortcut {
        sequences: [viewer.ui ? viewer.ui.shortcutFind : "Ctrl+F"]
        enabled: viewer.shortcutsActive && viewer.hasMessage
        onActivated: viewer.openFind()
    }
    Shortcut {
        sequences: [viewer.ui ? viewer.ui.shortcutSource : "Ctrl+U"]
        enabled: viewer.shortcutsActive && viewer.hasMessage
        onActivated: viewer.toggleSource()
    }
    // Esc closes the bar wherever focus sits (the field handles it itself, but
    // focus is usually back in the page after a jump to a match). The message
    // window disables its own Esc-closes-the-window while the bar is open, so
    // the two never compete for the key.
    Shortcut {
        sequence: "Esc"
        enabled: viewer.shortcutsActive && viewer.findActive
        onActivated: viewer.closeFind()
    }
    Shortcut {
        sequences: ["F3", "Ctrl+G"]
        enabled: viewer.shortcutsActive && viewer.findActive
        onActivated: viewer.findRun(false)
    }
    Shortcut {
        sequences: ["Shift+F3", "Ctrl+Shift+G"]
        enabled: viewer.shortcutsActive && viewer.findActive
        onActivated: viewer.findRun(true)
    }

    // The context outlives any one message: re-render whenever it presents a
    // different one (reading pane), and once at startup for a window whose
    // context was filled before the viewer existed.
    Connections {
        target: viewer.context
        function onMessageChanged() {
            viewer.showCurrent()
        }
    }
    Component.onCompleted: showCurrent()

    // "purelymail.com; spf=pass …; dkim=fail …" → "spf=pass · dkim=fail ❗"
    // Only the leading method=result of each ';'-delimited field is a verdict.
    // Everything after it echoes sender-supplied data — smtp.mailfrom=,
    // header.from=, reason= — so scanning the whole header would let a sender
    // put "dkim=pass" in this badge by putting it in their own envelope
    // address. Quoted strings and (comments) are dropped first for the same
    // reason: both can carry a ';' and hide a verdict behind it.
    // One terse line per abbreviation that actually appears, appended to the
    // server tooltip: the badge speaks in acronyms, and a reader should not
    // need to look one up to know what just failed.
    // The verdict as a word, answering the question-form explainers below:
    // pass answers Yes, a failure No, softfail and the odd results Warning.
    function verdictWord(r) {
        if (r === "pass")
            return "Yes"
        if (/(fail|permerror)$/.test(r))
            return r === "softfail" ? "Warning" : "No"
        if (r === "none")
            return "Not checked"
        return "Warning" // neutral, temperror, softpass, bestguesspass…
    }

    // One block per method: the question-form explainer with its answer as a
    // word, and directly under it that method's own slice of the raw header —
    // the evidence sits beneath the sentence that explains it. Blocks are
    // blank-line separated; the authserv-id leads the whole thing.
    function authLegend(authInfo) {
        if (!authInfo || authInfo.length === 0)
            return ""
        const explain = ({
            "spf":      "SPF: Is the sending server allowed to send for this domain?",
            "dkim":     "DKIM: Does the domain's cryptographic signature on the message hold?",
            "dmarc":    "DMARC: Does the visible From match what SPF or DKIM verified?",
            "arc":      "ARC: Did the original verdict survive forwarders and mailing lists intact?",
            "compauth": "COMPAUTH: Does Microsoft's combined sender verification pass?"
        })
        const trusted = Mail.trustedAuthMethods()
        // Split the raw value, not a stripped copy — the comments are part of
        // the evidence shown. A ';' inside a comment starts a fragment that
        // matches no method; such fragments re-join the block above them.
        const parts = authInfo.split(";")
        let order = []
        let blocks = ({})
        let answers = ({})
        let current = ""
        for (let i = 1; i < parts.length; ++i) {
            const part = parts[i].trim()
            const m = /^(dkim|spf|dmarc|arc|compauth)\s*=\s*([a-z]+)/i.exec(part)
            if (m) {
                const method = m[1].toLowerCase()
                if (trusted.indexOf(method) === -1
                    || (method === "dkim" && dkimLabel.text.length > 0)) {
                    // dkim moved to the big label's tooltip; see condenseAuth.
                    current = ""
                    continue
                }
                if (!blocks[method]) {
                    blocks[method] = []
                    answers[method] = []
                    order.push(method)
                }
                blocks[method].push(part)
                const word = viewer.verdictWord(m[2].toLowerCase())
                if (answers[method].indexOf(word) === -1)
                    answers[method].push(word)
                current = method
            } else if (current.length > 0 && part.length > 0) {
                // A comment's severed tail: it belongs to the field above.
                blocks[current][blocks[current].length - 1] += "; " + part
            }
        }
        const rendered = order.map(method =>
            explain[method] + " " + answers[method].join(", ") + "\n"
            + blocks[method].join("\n"))
        return ["Reported by " + parts[0].trim()].concat(rendered).join("\n\n")
    }

    // The server's own dkim= evidence, as one block ("Reported by mx...:"
    // plus the raw fields) — appended to the big DKIM tooltip when the small
    // line stops showing dkim, so the server's say-so stays findable exactly
    // where the reader is already looking.
    function serverDkimEvidence(authInfo) {
        if (!authInfo || authInfo.length === 0)
            return ""
        if (Mail.trustedAuthMethods().indexOf("dkim") === -1)
            return ""
        const parts = authInfo.split(";")
        let lines = []
        let inDkim = false
        for (let i = 1; i < parts.length; ++i) {
            const part = parts[i].trim()
            if (/^dkim\s*=/i.test(part)) {
                lines.push(part)
                inDkim = true
            } else if (/^(spf|dmarc|arc|compauth)\s*=/i.test(part)) {
                inDkim = false
            } else if (inDkim && part.length > 0 && lines.length > 0) {
                lines[lines.length - 1] += "; " + part // a comment's severed tail
            }
        }
        if (lines.length === 0)
            return ""
        return "Reported by " + parts[0].trim() + ":\n" + lines.join("\n")
    }

    function condenseAuth(authInfo) {
        if (!authInfo || authInfo.length === 0)
            return ""
        const cleaned = authInfo
            .replace(/"(?:[^"\\]|\\.)*"/g, '""')
            .replace(/\([^()]*\)/g, " ")
        // A message may carry several DKIM signatures — the sender's and a
        // forwarder's, say — and the server reports one verdict per signature.
        // Grouped by method rather than listed one per signature: repeating
        // "dkim=pass · dkim=pass" tells the reader nothing, and spelling a
        // disagreement as "dkim=pass · dkim=fail" reads like a contradiction
        // rather than like two signatures. "dkim=pass, fail" says what it is.
        const fields = cleaned.split(";")
        // A method distrusted in advanced.conf (spam/trustSpf and friends) is
        // not shown: the badge and the score read the same switches, so what
        // is displayed is always what was counted.
        const trusted = Mail.trustedAuthMethods()
        let order = []      // methods in the order the server listed them
        let results = ({})  // method → its distinct results, in order
        for (let i = 1; i < fields.length; ++i) { // field 0 is the authserv-id
            // arc and compauth ride along when the server stamped them:
            // arc explains why spf/dkim may say fail, and compauth is
            // Microsoft's own composite verdict, only ever present on
            // Microsoft 365 accounts.
            const m = /^\s*(dkim|spf|dmarc|arc|compauth)\s*=\s*([a-z]+)/i.exec(fields[i])
            if (!m)
                continue
            const method = m[1].toLowerCase()
            if (trusted.indexOf(method) === -1)
                continue
            // Our own DKIM verdict is on the big label beside this line and is
            // strictly better informed (it checks alignment, not just
            // validity); showing the server's beside it read as two verdicts
            // disagreeing. Its evidence moves to the big label's tooltip.
            if (method === "dkim" && dkimLabel.text.length > 0)
                continue
            const result = m[2].toLowerCase()
            if (!results[method]) {
                results[method] = []
                order.push(method)
            }
            if (results[method].indexOf(result) === -1)
                results[method].push(result)
        }
        // The same glyph and colour language the DKIM/ARC labels above speak:
        // ✓ green pass, ✗ red fail, ⚠ orange for anything odd, – for nothing
        // checked. A method with several signatures keeps the comma grouping
        // ("DKIM ✓, ✗") — the comma is what says "two signatures", so it is
        // never collapsed to one glyph.
        const glyph = r => {
            if (r === "pass")
                return "<font color='" + Kirigami.Theme.positiveTextColor + "'>✓</font>"
            // softfail is the domain's own hedge (~all): "probably not ours,
            // but do not bounce it". The glyph stays ✗ — something did fail —
            // but in orange, a step below the outright fail's red. The raw
            // wording is in the tooltip.
            if (r === "softfail")
                return "<font color='" + Kirigami.Theme.neutralTextColor + "'>✗</font>"
            if (/(fail|permerror)$/.test(r))
                return "<font color='" + Kirigami.Theme.negativeTextColor + "'>✗</font>"
            if (r === "none")
                return "–"
            // neutral, temperror, softpass, bestguesspass, policy…
            return "<font color='" + Kirigami.Theme.neutralTextColor + "'>⚠</font>"
        }
        // Glyph before name, matching the large badges beside this line
        // ("✗ ARC chain broken"), so the eye parses both the same way. The
        // non-breaking space keeps each glyph glued to its own name, and the
        // wide gap between pairs is what says where one method ends —
        // StyledText collapses runs of ordinary spaces, hence the entities.
        return order.map(method => {
            const list = results[method]
            return list.map(glyph).join(", ") + " " + method.toUpperCase()
        }).join("&nbsp;&nbsp;&nbsp;")
    }

    // Envelope header block above the preview
    GridLayout {
        Layout.fillWidth: true
        Layout.margins: Kirigami.Units.largeSpacing
        visible: viewer.hasMessage
        columns: 2
        columnSpacing: Kirigami.Units.largeSpacing
        rowSpacing: Kirigami.Units.smallSpacing / 2

        QQC2.Label { text: "From:"; opacity: 0.8 }
        RowLayout {
            Layout.fillWidth: true
            // The sender's picture, when there is one and they are switched on.
            // Image.Error is the ordinary answer — most addresses have no
            // Gravatar — and it takes the row back to text with no gap.
            Image {
                id: senderAvatar
                readonly property int px: Mail.avatarSize()
                source: viewer.context ? Mail.avatarSource(viewer.context.from) : ""
                visible: status === Image.Ready
                Layout.preferredWidth: visible ? px : 0
                Layout.preferredHeight: visible ? px : 0
                fillMode: Image.PreserveAspectFit
                asynchronous: true
                // Twice the displayed size, matching what avatarSource() asks
                // Gravatar for — the surplus is what keeps it sharp on HiDPI,
                // and mipmap is what keeps the downscale clean on 1x screens.
                sourceSize: Qt.size(px * 2, px * 2)
                mipmap: true
            }
            SelectableValue {
                id: fromLabel
                text: viewer.context ? viewer.context.from : ""
            }
            // Explicit arrow glyphs — theme icons for reply/forward are not
            // reliably recognizable as arrows.
            QQC2.ToolButton {
                text: "← Reply"
                onClicked: viewer.replyRequested(false)
                QQC2.ToolTip.text: "Reply to the sender"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                text: "⇇ Reply all"
                onClicked: viewer.replyRequested(true)
                QQC2.ToolTip.text: "Reply to the sender and all recipients"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                id: forwardButton
                text: "Forward →"
                onClicked: viewer.forwardRequested()
                // Holding to the end IS the other forward: the original
                // bytes as a message/rfc822 attachment, full fidelity. The
                // filling line below counts down to it.
                onPressAndHold: viewer.forwardAsAttachmentRequested()
                QQC2.ToolTip.text: "Forward this message (hold to forward as attachment)"
                QQC2.ToolTip.visible: hovered

                // The hold made visible: a thin line filling left to right,
                // timed to the press-and-hold interval, so reaching the far
                // edge and the menu opening are the same moment. Releasing
                // early snaps it away (the Behavior only animates the grow).
                Rectangle {
                    anchors.left: parent.left
                    anchors.bottom: parent.bottom
                    anchors.leftMargin: 3
                    anchors.bottomMargin: 2
                    height: 2
                    radius: 1
                    color: Kirigami.Theme.highlightColor
                    width: forwardButton.pressed ? forwardButton.width - 6 : 0
                    Behavior on width {
                        enabled: forwardButton.pressed
                        NumberAnimation {
                            duration: Qt.styleHints.mousePressAndHoldInterval
                        }
                    }
                }

            }
            QQC2.ToolButton {
                icon.name: "image-x-generic"
                text: "Load remote content"
                checkable: true
                checked: viewer.context ? viewer.context.remoteContentAllowed : false
                visible: viewer.viewMode === "html"
                onToggled: {
                    viewer.context.remoteContentAllowed = checked
                    web.url = viewer.context.htmlViewUrl() // re-render with the new policy
                }
                QQC2.ToolTip.text: "Allow this message to load remote images, styles and fonts (JavaScript stays off)"
                QQC2.ToolTip.visible: hovered
            }
            SelectableValue {
                id: dateLabel
                // Fixed trailing item: it is short enough to always fit, so it
                // keeps its own width instead of competing for the row's.
                Layout.fillWidth: false
                Layout.preferredWidth: -1
                opacity: 0.8
                text: viewer.context ? viewer.context.date : ""
            }
        }

        // Captions stay on the first line of a recipient list that unfolds.
        QQC2.Label { text: "To:"; opacity: 0.8; Layout.alignment: Qt.AlignTop }
        ExpandableValue {
            id: toLabel
            // Lines the caret up under the date: the From row and this one are
            // the same grid column, so the date's x is the same offset here.
            caretX: dateLabel.x
            text: viewer.context ? viewer.context.to : ""
        }

        QQC2.Label {
            text: "Cc:"
            opacity: 0.8
            Layout.alignment: Qt.AlignTop
            visible: ccLabel.text.length > 0
        }
        ExpandableValue {
            id: ccLabel
            caretX: dateLabel.x
            visible: text.length > 0
            text: viewer.context ? viewer.context.cc : ""
        }

        QQC2.Label { text: "Subject:"; opacity: 0.8 }
        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            SelectableValue {
                id: subjectLabel
                font.bold: true
                text: viewer.context
                      ? (viewer.context.subject.length > 0 ? viewer.context.subject
                                                           : (viewer.hasMessage ? "(no subject)" : ""))
                      : ""
            }
            // One representation is always showing, so these are radio-like,
            // not toggles: the exclusive group means the active mode cannot
            // be clicked "off" — only checking another moves it. The checked
            // states are kept in step by onViewModeChanged below rather than
            // by bindings, which a user click would silently break.
            QQC2.ButtonGroup { id: viewModeGroup }
            QQC2.ToolButton {
                id: modeHtmlButton
                text: "HTML"
                checkable: true
                checked: viewer.viewMode === "html"
                QQC2.ButtonGroup.group: viewModeGroup
                onClicked: viewer.showMode("html")
            }
            QQC2.ToolButton {
                id: modeTextButton
                text: "Text"
                checkable: true
                checked: viewer.viewMode === "text"
                QQC2.ButtonGroup.group: viewModeGroup
                onClicked: viewer.showMode("text")
            }
            QQC2.ToolButton {
                id: modeSourceButton
                text: "Source"
                checkable: true
                checked: viewer.viewMode === "source"
                QQC2.ButtonGroup.group: viewModeGroup
                onClicked: viewer.showMode("source")
                QQC2.ToolTip.text: "Show the raw message source ("
                                   + (viewer.ui ? viewer.ui.shortcutSource : "Ctrl+U") + ")"
                QQC2.ToolTip.visible: hovered
            }
        }

        // One security line: encryption first, then what we can say about who
        // sent it. Encryption leads because it answers the question the reader
        // asks first — who else could read this — and because it is shown
        // whether or not sender authentication is switched on, which the
        // badges after it are not.
        Item { visible: securityRow.visible } // caption column stays empty
        RowLayout {
            id: securityRow
            Layout.fillWidth: true
            spacing: Kirigami.Units.largeSpacing
            // The crypto half stands alone (it carries the attached-key offer,
            // which any message may have); the authentication half is gated on
            // the setting, so a verdict left over from before the switch was
            // flipped can never stay on screen.
            visible: cryptoLabel.text.length > 0 || importKeyButton.visible
                     || (Mail.authVerification
                         && (dkimLabel.text.length > 0 || arcLabel.text.length > 0
                             || serverAuthLabel.text.length > 0))

            QQC2.Label {
                id: cryptoLabel
                // Baseline-aligned, not centred: the row mixes font sizes and
                // glyphs whose fallback fonts are taller than the text, and
                // centring made every neighbour hop when one label's height
                // changed. Text sits still on a shared baseline.
                Layout.alignment: Qt.AlignBaseline
                visible: text.length > 0
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                color: {
                    if (!viewer.context || viewer.context.cryptoChecking)
                        return Kirigami.Theme.textColor
                    const sig = viewer.context.signatureStatus
                    // A signature that does not hold up outranks the lock: a
                    // message can be perfectly encrypted and still not be from
                    // whom it claims.
                    if (sig === "revoked" || sig === "expired" || sig === "modified"
                        || (sig === "valid" && !viewer.context.signerTrusted))
                        return Kirigami.Theme.neutralTextColor
                    if (viewer.context.cryptoState === "encrypted"
                        || (sig === "valid" && viewer.context.signerTrusted))
                        return Kirigami.Theme.positiveTextColor
                    // Neither "could not decrypt" nor "partly encrypted" is an
                    // accusation — nothing here says the message was tampered
                    // with, only that we cannot show all of it. Red is reserved
                    // for a signature we can prove is bad, which — until the
                    // octets are known-original — is never.
                    if (viewer.context.cryptoState === "failed"
                        || viewer.context.cryptoState === "partial")
                        return Kirigami.Theme.neutralTextColor
                    return Kirigami.Theme.textColor
                }
                opacity: viewer.context && viewer.context.cryptoChecking ? 0.6 : 1
                text: {
                    if (!viewer.context)
                        return ""
                    switch (viewer.context.cryptoState) {
                    case "decrypting":
                        return "decrypting…"
                    case "encrypted":
                        return "🔒 Encrypted"
                    case "signedEncrypted":
                        return "🔒 Encrypted, " + viewer.signatureText()
                    case "signed":
                        return viewer.signatureText()
                    case "failed":
                        return "🔓 Could not decrypt"
                    case "partial":
                        return "⚠ Partly encrypted — not decrypted"
                    default:
                        return ""
                    }
                }
                // Clicking the badge opens the key manager on whichever key
                // this message actually involved — the signer's if it was
                // signed, otherwise the one it was encrypted to. Underlined on
                // hover so it reads as something to click rather than a label.
                font.underline: cryptoHover.hovered && viewer.inspectableKey() !== ""
                HoverHandler {
                    id: cryptoHover
                    cursorShape: viewer.inspectableKey() !== "" ? Qt.PointingHandCursor
                                                                : Qt.ArrowCursor
                }
                TapHandler {
                    enabled: viewer.inspectableKey() !== ""
                    onTapped: {
                        viewerKeyManager.focusKey = viewer.inspectableKey()
                        viewerKeyManager.open()
                    }
                }
                HoverToolTip {
                    hover: cryptoHover
                    text: {
                        if (!viewer.context)
                            return ""
                        const detail = viewer.context.cryptoDetail
                        return viewer.inspectableKey() === ""
                            ? detail
                            : detail + "\n\nClick to inspect the key."
                    }
                }
            }

            // Offered only where it is the actual next step: we have a
            // signature and no key to check it against. Asks the signer's own
            // domain (WKD) — never a keyserver without a further, separate
            // click, which the key manager provides.
            QQC2.ToolButton {
                visible: viewer.context
                         && viewer.context.signatureStatus === "unknownKey"
                         && Pgp.available && !Pgp.busy
                text: "Look up signer's key"
                icon.name: "download"
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                onClicked: Pgp.lookupWkd(viewer.senderAddress())
                QQC2.ToolTip.text: "Ask the sender's own domain for their public "
                                   + "key (Web Key Directory), then check the "
                                   + "signature again"
                QQC2.ToolTip.visible: hovered
            }

            // A key attached to the message. Import is a button, never
            // automatic: the key is a claim by whoever sent the message.
            QQC2.ToolButton {
                id: importKeyButton
                visible: viewer.context && viewer.context.attachedKeyName.length > 0
                         && Pgp.available
                text: "Import attached key"
                icon.name: "application-pgp-keys"
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                onClicked: viewer.context.importAttachedKey()
                QQC2.ToolTip.text: "Add " + (viewer.context ? viewer.context.attachedKeyName : "")
                                   + " to your keyring. Check the fingerprint with "
                                   + "its owner by some other means before you rely on it."
                QQC2.ToolTip.visible: hovered
            }

            // Only for mail that was actually decrypted, and only while the
            // HTML view is what would issue the requests. Remote content in
            // decrypted mail is how plaintext leaves the machine: the sender
            // picks the URL, so a fetch of it can carry the decrypted content
            // to a third party (doc/openpgp.md §5).
            QQC2.Label {
                visible: viewer.context && viewer.context.showingDecrypted
                         && viewer.viewMode === "html"
                         && viewer.context.remoteContentAllowed
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                font.bold: true
                color: Kirigami.Theme.neutralTextColor
                text: "⚠ Remote content is on — requests can carry this "
                      + "decrypted message to a third party"
            }

            // --- Sender authentication, on the same line, after encryption ---
            // Each of these hides itself when empty, and the C++ side leaves
            // them all empty when authVerification is off.

            // What *we* verified, cryptographically. Deliberately separate from
            // the server's say-so next to it: one is a signature checked against
            // a key we fetched, the other is a header we chose to believe.
            QQC2.Label {
                id: dkimLabel
                // Baseline-aligned, not centred: the row mixes font sizes and
                // glyphs whose fallback fonts are taller than the text, and
                // centring made every neighbour hop when one label's height
                // changed. Text sits still on a shared baseline.
                Layout.alignment: Qt.AlignBaseline
                visible: Mail.authVerification && text.length > 0
                // Standard size, unlike the server line below: this is what
                // mailove verified itself, and the type hierarchy is the
                // reader's cue for which claim carries more weight.
                font.bold: viewer.context && viewer.context.dkimStatus === "fail"
                color: {
                    if (!viewer.context || viewer.context.dkimChecking)
                        return Kirigami.Theme.textColor
                    if (viewer.context.dkimTrusted)
                        return Kirigami.Theme.positiveTextColor
                    if (viewer.context.dkimStatus === "fail")
                        return Kirigami.Theme.negativeTextColor
                    // Never negative: a body that changed after signing is what
                    // every mailing list produces. Red here would train the
                    // reader to ignore the one time it matters.
                    if (viewer.context.dkimStatus === "modified")
                        return Kirigami.Theme.neutralTextColor
                    if (viewer.context.dkimStatus === "pass")
                        return Kirigami.Theme.neutralTextColor // valid but unaligned
                    if (viewer.context.dkimStatus === "partial")
                        return Kirigami.Theme.neutralTextColor // valid over part of the body
                    return Kirigami.Theme.textColor // "unverified" reads as neutral
                }
                opacity: viewer.context && viewer.context.dkimChecking ? 0.6 : 1
                text: {
                    if (!viewer.context)
                        return ""
                    if (viewer.context.dkimChecking)
                        return "Checking DKIM signature…"
                    switch (viewer.context.dkimStatus) {
                    case "pass":
                        // "verified" only when the signing domain matches the
                        // sender — a valid signature from some other domain is
                        // exactly what a forgery looks like.
                        return viewer.context.dkimTrusted
                            ? "✓ DKIM verified" : "⚠ DKIM signed by another domain"
                    case "partial":
                        // A valid signature over a stated length of the body
                        // (l=), which leaves everything after it unsigned and
                        // appendable by anyone who handled the message. The
                        // tooltip gives the length.
                        return "⚠ DKIM covers only part of this message"
                    case "fail":
                        // The only accusation this badge ever makes: we fetched
                        // the key and the signature does not match it.
                        return "✗ DKIM signature invalid"
                    case "permerror":
                        // Usually the signer rotated the key out of DNS, which
                        // is what happens to every archived message eventually.
                        // The tooltip names the actual reason.
                        return "⚠ DKIM cannot be checked"
                    case "temperror":
                        return "DKIM not checked"
                    case "unsupported":
                        // Neither verified nor broken: obsolete crypto we will
                        // not lend credibility to by checking it.
                        return "⚠ DKIM uses obsolete crypto"
                    case "modified":
                        // The body is not the one that was signed, established
                        // against octets we know are original. After a mailing
                        // list or a forwarder that is ordinary, so this states
                        // what happened rather than accusing anyone. ARC does
                        // not overrule the signature — an attacker can seal a
                        // chain of their own — but an intact one names a party
                        // that saw the message earlier, which is the whole
                        // reason the protocol exists. The sealer is on the
                        // badge beside this one, so it is not repeated here.
                        return viewer.context.arcStatus === "pass"
                            ? "⚠ Modified after DKIM signing, per ARC"
                            : "⚠ Modified after DKIM signing"
                    case "unverified":
                        // Body hash mismatch we cannot attribute: the copy we
                        // hashed came from the cache and may not be byte-exact,
                        // so we do not even claim the message was modified.
                        return "DKIM not verified"
                    default:
                        return "" // no signature at all — say nothing
                    }
                }
                HoverHandler { id: dkimHover }
                HoverToolTip {
                    hover: dkimHover
                    markFailures: true
                    text: {
                        if (!viewer.context || viewer.context.dkimDetail.length === 0)
                            return ""
                        const st = viewer.context.dkimStatus
                        const answer = st === "pass" && viewer.context.dkimTrusted ? "Yes"
                            : st === "fail" ? "No"
                            : st === "temperror" || st === "unverified" ? "Not checked"
                            : "Warning"
                        const server = viewer.serverDkimEvidence(viewer.context.authInfo)
                        return "DKIM: Does the domain's cryptographic signature on the "
                            + "message hold? " + answer + "\n\n" + viewer.context.dkimDetail
                            + (server.length ? "\n\n" + server : "")
                    }
                }
            }

            // Kept apart from both neighbours on purpose. DKIM says whether the
            // author's own signature holds; this says whether the hops that
            // carried the message left an unbroken trail — which is worth
            // exactly as much as the reader's trust in the domain named in it,
            // so the sealer is always shown rather than reduced to a tick.
            QQC2.Label {
                id: arcLabel
                // Baseline-aligned, not centred: the row mixes font sizes and
                // glyphs whose fallback fonts are taller than the text, and
                // centring made every neighbour hop when one label's height
                // changed. Text sits still on a shared baseline.
                Layout.alignment: Qt.AlignBaseline
                visible: Mail.authVerification && text.length > 0
                // Standard size like the DKIM label: first-hand verification.
                font.bold: viewer.context && viewer.context.arcStatus === "fail"
                color: {
                    if (!viewer.context)
                        return Kirigami.Theme.textColor
                    if (viewer.context.arcStatus === "fail")
                        return Kirigami.Theme.negativeTextColor
                    // Never positive-coloured: an intact chain is a claim by a
                    // third party, not verification of the sender.
                    return Kirigami.Theme.textColor
                }
                text: {
                    if (!viewer.context || viewer.context.dkimChecking)
                        return ""
                    const sealer = viewer.context.arcSealer
                    switch (viewer.context.arcStatus) {
                    case "pass":
                        // The ✓ is the answer, not an endorsement — the colour
                        // stays neutral (see above), unlike DKIM's green.
                        return "✓ ARC intact via " + sealer
                    case "sealsonly":
                        // Seals held, but the sealer's own body hash does not
                        // match our copy — nothing confirms the body we are
                        // showing, hence the ⚠ and no "intact".
                        return "⚠ ARC via " + sealer + ", body unconfirmed"
                    case "fail":
                        return "✗ ARC chain broken"
                    case "error":
                        return "ARC not checked"
                    default:
                        return "" // no chain, or never asked
                    }
                }
                HoverHandler { id: arcHover }
                HoverToolTip {
                    hover: arcHover
                    markFailures: true
                    text: {
                        if (!viewer.context || viewer.context.arcDetail.length === 0)
                            return ""
                        const st = viewer.context.arcStatus
                        const answer = st === "pass" ? "Yes"
                            : st === "fail" ? "No"
                            : st === "error" ? "Not checked"
                            : "Warning" // sealsonly: seals hold, body unconfirmed
                        return "ARC: Did the original verdict survive forwarders and "
                            + "mailing lists intact? " + answer
                            + "\n\nForwarding hops (ARC):\n" + viewer.context.arcDetail
                    }
                }
            }

            QQC2.Label {
                id: serverAuthLabel
                // Baseline-aligned, not centred: the row mixes font sizes and
                // glyphs whose fallback fonts are taller than the text, and
                // centring made every neighbour hop when one label's height
                // changed. Text sits still on a shared baseline.
                Layout.alignment: Qt.AlignBaseline
                visible: Mail.authVerification && text.length > 0
                Layout.fillWidth: true
                elide: Text.ElideRight
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                // StyledText, for the coloured glyphs condenseAuth builds —
                // the colours are the theme's own, so they follow it.
                textFormat: Text.StyledText
                text: viewer.context ? viewer.condenseAuth(viewer.context.authInfo) : ""
                HoverHandler { id: serverAuthHover }
                HoverToolTip {
                    hover: serverAuthHover
                    markFailures: true
                    // Per-method blocks: the explainer sentence with its
                    // answer, the raw evidence for that method beneath it.
                    text: viewer.context ? viewer.authLegend(viewer.context.authInfo) : ""
                }
            }
        }
    }

    Kirigami.InlineMessage {
        Layout.fillWidth: true
        Layout.leftMargin: Kirigami.Units.largeSpacing
        Layout.rightMargin: Kirigami.Units.largeSpacing
        Layout.bottomMargin: Kirigami.Units.smallSpacing
        visible: viewer.hasMessage && viewer.context.junkTextOnly && viewer.viewMode === "text"
        type: Kirigami.MessageType.Warning
        text: "Spam folder — showing plain text for safety. Click HTML above to render this message anyway."
    }

    Kirigami.Separator {
        Layout.fillWidth: true
        visible: viewer.hasMessage
    }

    // Find in message. Chromium's own find-in-page does the searching and the
    // counting; it works with JavaScript off, since it runs inside the engine
    // rather than in the (untrusted) page.
    RowLayout {
        id: findBar
        Layout.fillWidth: true
        Layout.margins: Kirigami.Units.smallSpacing
        spacing: Kirigami.Units.smallSpacing
        visible: false

        QQC2.TextField {
            id: findField
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 20
            placeholderText: "Find in message"
            // Search as you type, from the top of the document each time.
            onTextChanged: viewer.findRun(false)
            Keys.onReturnPressed: event => viewer.findRun(event.modifiers & Qt.ShiftModifier)
            Keys.onEnterPressed: event => viewer.findRun(event.modifiers & Qt.ShiftModifier)
            Keys.onEscapePressed: viewer.closeFind()
        }

        QQC2.Label {
            opacity: 0.8
            font.pointSize: Kirigami.Theme.smallFont.pointSize
            color: (findField.text.length > 0 && viewer.findMatches === 0)
                   ? Kirigami.Theme.negativeTextColor : Kirigami.Theme.textColor
            text: findField.text.length === 0 ? ""
                : viewer.findMatches === 0 ? "No matches"
                : viewer.findCurrent + " of " + viewer.findMatches
                  + (viewer.findMatches === 1 ? " match" : " matches")
        }

        QQC2.ToolButton {
            icon.name: "go-up"
            enabled: viewer.findMatches > 0
            onClicked: viewer.findRun(true)
            QQC2.ToolTip.text: "Previous match (Shift+F3)"
            QQC2.ToolTip.visible: hovered
        }
        QQC2.ToolButton {
            icon.name: "go-down"
            enabled: viewer.findMatches > 0
            onClicked: viewer.findRun(false)
            QQC2.ToolTip.text: "Next match (F3)"
            QQC2.ToolTip.visible: hovered
        }
        QQC2.ToolButton {
            id: findCase
            text: "Aa"
            checkable: true
            onToggled: viewer.findRun(false)
            QQC2.ToolTip.text: "Match case"
            QQC2.ToolTip.visible: hovered
        }
        QQC2.ToolButton {
            icon.name: "dialog-close"
            onClicked: viewer.closeFind()
            QQC2.ToolTip.text: "Close the find bar (Esc)"
            QQC2.ToolTip.visible: hovered
        }
    }

    Item {
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: viewer.hasMessage

    // Sandbox settings and console-dedupe live in the shared component —
    // the composer's quote preview is the same caged animal.
    SandboxedWebView {
        id: web
        anchors.fill: parent

        onLoadingChanged: function (loadInfo) {
            if (loadInfo.status === WebEngineView.LoadFailedStatus)
                console.warn("mailove viewer: load failed:", loadInfo.errorString, loadInfo.url)
            // A new document (another message, or the same one switched to
            // Text/Source) has no highlighting and no counts — search it again.
            if (loadInfo.status === WebEngineView.LoadSucceededStatus) {
                viewer.findMatches = 0
                viewer.findCurrent = 0
                if (viewer.findActive)
                    viewer.findRun(false)
            }
        }

        onFindTextFinished: function (result) {
            viewer.findMatches = result.numberOfMatches
            viewer.findCurrent = result.activeMatch
        }

        onNavigationRequested: function (request) {
            // Never navigate inside the viewer; open link clicks externally.
            if (request.navigationType === WebEngineNavigationRequest.LinkClickedNavigation) {
                request.reject()
                Mail.openExternalUrl(request.url)
            }
        }

        // target="_blank" links (most email links) arrive here, not as navigation.
        onNewWindowRequested: function (request) {
            Mail.openExternalUrl(request.requestedUrl)
        }
    }

    // Attachments — overlay bar pinned to the bottom. An overlay (rather than
    // a layout row) so toggling it never resizes the WebEngineView, which
    // repaints with visible glitches on resize.
    Rectangle {
        visible: viewer.context && viewer.context.attachments.length > 0
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: attachRow.implicitHeight + Kirigami.Units.smallSpacing * 2 + 1
        color: Kirigami.Theme.backgroundColor

        Kirigami.Separator {
            anchors.top: parent.top
            width: parent.width
        }
        Flickable {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.smallSpacing
            anchors.topMargin: Kirigami.Units.smallSpacing + 1
            contentWidth: attachRow.implicitWidth
            clip: true

            Row {
                id: attachRow
                spacing: Kirigami.Units.smallSpacing

                Repeater {
                    model: viewer.context ? viewer.context.attachments : []
                    delegate: QQC2.Button {
                        required property var modelData
                        required property int index
                        icon.name: "mail-attachment"
                        text: modelData.name + " (" + modelData.sizeText + ")"
                        onClicked: { // left click = open (risky types need confirmation)
                            if (viewer.context.attachmentRisky(index)) {
                                confirmOpenDialog.attachmentIndex = index
                                confirmOpenDialog.attachmentName = modelData.name
                                confirmOpenDialog.open()
                            } else {
                                viewer.context.openAttachment(index)
                            }
                        }
                        TapHandler {
                            acceptedButtons: Qt.RightButton // right click = save to ~/Downloads
                            onTapped: viewer.context.saveAttachmentToDownloads(index)
                        }
                        QQC2.ToolTip.text: "Click to open — right-click to save to Downloads"
                        QQC2.ToolTip.visible: hovered
                    }
                }
            }
        }
    }
    }

    Kirigami.PlaceholderMessage {
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: !viewer.hasMessage
        text: "Select a message"
        icon.name: "mail-message"
    }

    QQC2.Dialog {
        id: confirmOpenDialog
        property int attachmentIndex: -1
        property string attachmentName: ""
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Open executable attachment?"

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Open anyway"
                icon.name: "dialog-warning"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: viewer.context.openAttachment(attachmentIndex)

        contentItem: QQC2.Label {
            text: "\"" + confirmOpenDialog.attachmentName + "\" is a script, program "
                  + "or installer. Opening it can run code on this computer.\n\n"
                  + "Only continue if you trust the sender — and remember the "
                  + "sender address itself can be forged."
            wrapMode: Text.Wrap
        }
    }

}
