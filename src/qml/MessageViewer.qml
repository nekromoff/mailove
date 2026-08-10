// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import QtQuick.Window
import QtWebEngine
import org.kde.kirigami as Kirigami
import Mailo.Core

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
        web.url = context.bodyUrl
    }

    /// How the OpenPGP signature is stated on the badge.
    ///
    /// A name appears only when the signature is valid *and* the signing key
    /// carries the From address — signerTrusted. A valid signature from an
    /// unrelated key is exactly what a forger's own key produces, so it gets
    /// the warning wording instead of a reassuring one. And nothing here ever
    /// says "invalid": Mailo cannot prove it is checking the octets that were
    /// signed, so a mismatch is reported as unverified (doc/openpgp.md §3).
    function signatureText() {
        if (!context)
            return ""
        if (context.cryptoChecking)
            return "checking signature…"
        switch (context.signatureStatus) {
        case "valid":
            if (context.signerTrusted) {
                const who = context.signerName.length > 0 ? context.signerName
                                                          : context.signerEmail
                return "✓ signed by " + who
            }
            return "⚠ signed by another address"
        case "modified":
            // Established against octets we know are original: the signed part
            // is not the part that arrived. After a mailing list or forwarder
            // that is ordinary, so this states what happened rather than
            // accusing anyone — the same wording rule the DKIM badge follows.
            return "⚠ modified after signing"
        case "unverified":
            // We could not reproduce what was signed, so this claims nothing
            // about the message at all.
            return "signature not verified"
        case "unknownKey":
            return "signed with a key you do not have"
        case "expired":
            return "⚠ signed with an expired key"
        case "revoked":
            return "⚠ signed with a revoked key"
        case "error":
            return "signature not checked"
        default:
            return "signed"
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
        viewMode = mode
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
        let order = []      // methods in the order the server listed them
        let results = ({})  // method → its distinct results, in order
        for (let i = 1; i < fields.length; ++i) { // field 0 is the authserv-id
            const m = /^\s*(dkim|spf|dmarc)\s*=\s*([a-z]+)/i.exec(fields[i])
            if (!m)
                continue
            const method = m[1].toLowerCase()
            const result = m[2].toLowerCase()
            if (!results[method]) {
                results[method] = []
                order.push(method)
            }
            if (results[method].indexOf(result) === -1)
                results[method].push(result)
        }
        return order.map(method => {
            const list = results[method]
            // Suffix match, so softfail and hardfail are flagged too. One
            // failure among several signatures still earns the mark: the
            // reader needs to know something did not check out.
            const failed = list.some(r => /(fail|permerror)$/.test(r))
            return method + "=" + list.join(", ") + (failed ? " ❗" : "")
        }).join(" · ")
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
                text: "Forward →"
                onClicked: viewer.forwardRequested()
                QQC2.ToolTip.text: "Forward this message"
                QQC2.ToolTip.visible: hovered
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
            QQC2.ToolButton {
                text: "HTML"
                checkable: true
                checked: viewer.viewMode === "html"
                onClicked: viewer.showMode("html")
            }
            QQC2.ToolButton {
                text: "Text"
                checkable: true
                checked: viewer.viewMode === "text"
                onClicked: viewer.showMode("text")
            }
            QQC2.ToolButton {
                text: "Source"
                checkable: true
                checked: viewer.viewMode === "source"
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
                visible: Mail.authVerification && text.length > 0
                font.pointSize: Kirigami.Theme.smallFont.pointSize
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
                        return "checking signature…"
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
                            ? "⚠ Modified after signing, per ARC"
                            : "⚠ Modified after signing"
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
                    text: viewer.context ? viewer.context.dkimDetail : ""
                }
            }

            // Kept apart from both neighbours on purpose. DKIM says whether the
            // author's own signature holds; this says whether the hops that
            // carried the message left an unbroken trail — which is worth
            // exactly as much as the reader's trust in the domain named in it,
            // so the sealer is always shown rather than reduced to a tick.
            QQC2.Label {
                id: arcLabel
                visible: Mail.authVerification && text.length > 0
                font.pointSize: Kirigami.Theme.smallFont.pointSize
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
                        return "ARC intact via " + sealer
                    case "sealsonly":
                        // Seals held, but the sealer's own body hash does not
                        // match our copy. Spelled out rather than shortened:
                        // "ARC chain intact" read as *more* than the "pass"
                        // wording above it, which is the opposite of the truth
                        // — here nothing confirms the body we are showing.
                        return "ARC seals valid via " + sealer + ", body unconfirmed"
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
                    text: viewer.context && viewer.context.arcDetail.length > 0
                        ? "Forwarding hops (ARC):\n" + viewer.context.arcDetail : ""
                }
            }

            QQC2.Label {
                id: serverAuthLabel
                visible: Mail.authVerification && text.length > 0
                Layout.fillWidth: true
                elide: Text.ElideRight
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                text: viewer.context ? viewer.condenseAuth(viewer.context.authInfo) : ""
                HoverHandler { id: serverAuthHover }
                HoverToolTip {
                    hover: serverAuthHover
                    markFailures: true
                    text: viewer.context && viewer.context.authInfo.length > 0
                        ? "Reported by the receiving server:\n" + viewer.context.authInfo : ""
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

    WebEngineView {
        id: web
        anchors.fill: parent

        // Hostile-content sandbox: no scripts, no plugins, nothing local.
        // Remote requests are additionally blocked by the C++ interceptor.
        settings.javascriptEnabled: false
        settings.pluginsEnabled: false
        settings.localContentCanAccessFileUrls: false
        settings.localContentCanAccessRemoteUrls: false
        settings.localStorageEnabled: false
        settings.autoLoadImages: true
        settings.hyperlinkAuditingEnabled: false

        onLoadingChanged: function (loadInfo) {
            if (loadInfo.status === WebEngineView.LoadFailedStatus)
                console.warn("mailo viewer: load failed:", loadInfo.errorString, loadInfo.url)
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
