// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailove.Core

/// The composer. A tab page, not a window: the tab strip in Main.qml hosts it.
/// See the page contract there — title, present(), closeRequested.
Item {
    id: sheet

    /// Tab page contract (see Main.qml). The title doubles as the tab label,
    /// which is why the open*() functions set titleBase to Reply/Forward/Draft.
    property string titleBase: "Compose"
    /// Once there is a recipient the tab says who the message is going to —
    /// several open composers all reading "Compose" are indistinguishable.
    /// Only the first recipient, and its display name in preference to the
    /// address, since a tab has no room for more.
    property string title: {
        const first = toField.text.split(",")[0].trim()
        if (first === "")
            return titleBase
        const named = first.match(/^\s*"?([^"<]*[^"<\s])"?\s*</)
        return titleBase + " to: " + (named ? named[1] : first)
    }
    /// The same, plus the identity the message will be sent as. Only the
    /// window placement uses it: a title bar has room to say which account is
    /// writing, and with several composers open across accounts that is the
    /// one thing the recipient alone does not tell you. The tab strip keeps
    /// the short title — its labels are already elided at ~14 grid units.
    /// indexOf, not a plain emptiness test: with neither an address nor a
    /// login configured the fallback derives a bare "@", which is worse than
    /// saying nothing.
    readonly property string windowTitle: Mail.accountSendAddress.indexOf("@") > 0
        ? title + " (" + Mail.accountSendAddress + ")"
        : title
    signal presentRequested()
    signal closeRequested()

    /// False when the composer is a window of its own rather than a tab (the
    /// Look and feel setting). Window-wide shortcuts are gated on the tab
    /// being the visible one, which is never true outside a StackLayout.
    property bool inTab: true
    readonly property bool pageActive: !inTab || StackLayout.isCurrentItem

    // Resolved from the content layout's Window color set (chrome gray), so
    // the page fill matches the panel. bgColor override still wins.
    Rectangle {
        anchors.fill: parent
        color: sheet.panelColor
    }

    /// The uiSettings object from Main.qml (Look settings).
    property var ui: null

    // The panel/chrome follows the Window color set (chrome gray); the
    // colorSet is applied on the content ColumnLayout below (Kirigami.Theme
    // attaches to Items, not the Window). Input fields opt back into the
    // View set (white). A user bgColor override still wins.
    readonly property color panelColor: ui && ui.bgColor !== ""
        ? ui.bgColor : content.Kirigami.Theme.backgroundColor

    property list<url> attachments
    property bool focusBodyOnOpen: false
    // True from the moment Send is triggered until the send resolves. Drives
    // the Send button's "Sending…" state; cleared on failure, and the window
    // closes outright on success.
    property bool sending: false

    // --- OpenPGP -----------------------------------------------------------

    /// Sign / encrypt this message. Initialised from the account defaults when
    /// the window opens; both stay switchable per message.
    property bool pgpSign: false
    property bool pgpEncrypt: false

    /// True when encryption was switched off by a missing key rather than by
    /// the user. Only then may it switch itself back on — an explicit "off"
    /// from the user has to stay off.
    property bool pgpEncryptSuppressed: false

    /// address -> fingerprint for every recipient typed so far, "" where no
    /// usable key is available. Recomputed as the fields are edited, because it is
    /// what decides whether encryption is possible at all.
    property var pgpRecipientKeys: ({})

    readonly property bool pgpAvailable: Pgp.available && Mail.accountPgpKeyFp !== ""

    /// The bare addresses in the recipient fields, display names stripped:
    /// a key lookup for "Name <a@b.com>" has to ask about a@b.com, not about
    /// the whole string. Anything without an "@" is an address still being
    /// typed and is left out — there is no key to look up for it yet.
    function recipientList() {
        const all = (toField.text + "," + ccField.text + "," + bccField.text).split(",")
        const out = []
        for (let i = 0; i < all.length; ++i) {
            let a = all[i].trim()
            const lt = a.lastIndexOf("<")
            const gt = a.lastIndexOf(">")
            if (lt >= 0 && gt > lt)
                a = a.substring(lt + 1, gt).trim()
            if (a.indexOf("@") > 0 && out.indexOf(a) < 0)
                out.push(a)
        }
        return out
    }

    /// Recipients we hold no encryption key for.
    function missingKeys() {
        const out = []
        const list = recipientList()
        for (let i = 0; i < list.length; ++i) {
            if (!pgpRecipientKeys[list[i]])
                out.push(list[i])
        }
        return out
    }

    /// Addresses already looked up this session, so a field being typed into
    /// does not fire a lookup per keystroke — and so an address with no
    /// published key is asked about once, not forever.
    property var pgpLookedUp: ({})

    function refreshRecipientKeys() {
        if (!pgpAvailable) {
            pgpRecipientKeys = ({})
            return
        }
        pgpRecipientKeys = Pgp.encryptionKeysFor(recipientList())
        const missing = missingKeys()
        // A recipient whose key is missing must not leave encryption armed:
        // the send would be refused, which is worse than the toggle going off
        // in front of the user.
        if (pgpEncrypt && missing.length > 0) {
            pgpEncrypt = false
            // Remember that it was the missing key that turned it off, not the
            // user — so it can come back on by itself below.
            pgpEncryptSuppressed = true
        } else if (pgpEncryptSuppressed && missing.length === 0
                   && Mail.accountPgpEncryptByDefault) {
            // The recipient changed to one we do have a key for. The account
            // says encrypt by default, so honour that rather than leaving the
            // message quietly unencrypted because of a recipient who is no
            // longer on it.
            pgpEncrypt = true
            pgpEncryptSuppressed = false
        }
        if (missing.length === 0 && !pgpEncrypt)
            pgpEncryptSuppressed = false
        if (Mail.accountPgpAutoWkd)
            autoWkdTimer.restart()
    }

    /// Automatic WKD, once the typing settles. Only WKD: it asks the
    /// recipient's own domain, which mailing them tells anyway. A keyserver
    /// lookup would tell a third party who is about to be written to, so it
    /// stays a deliberate click in the key manager (doc/openpgp.md §7).
    Timer {
        id: autoWkdTimer
        interval: 1200
        onTriggered: {
            if (!sheet.pgpAvailable || !Mail.accountPgpAutoWkd)
                return
            const missing = sheet.missingKeys()
            for (let i = 0; i < missing.length; ++i) {
                const a = missing[i]
                // Only complete-looking addresses: half-typed ones would send
                // a query per keystroke to domains that do not exist.
                if (sheet.pgpLookedUp[a] || a.indexOf("@") < 1 || a.indexOf(".") < 0)
                    continue
                sheet.pgpLookedUp[a] = true
                Pgp.lookupWkd(a)
            }
        }
    }

    Connections {
        target: Pgp
        function onKeysChanged() { sheet.refreshRecipientKeys() }
    }

    // Single send entry point for the button and the Ctrl+Enter shortcut.
    function doSend() {
        if (toField.text.trim().length === 0 || sending)
            return
        // Never a silent downgrade: if encryption is on and a key is missing,
        // the user decides what happens (doc/openpgp.md §9).
        if (pgpEncrypt) {
            const missing = missingKeys()
            if (missing.length > 0) {
                missingKeyDialog.addresses = missing
                missingKeyDialog.open()
                return
            }
        }
        sending = true
        Mail.sendMail(toField.text, ccField.text, bccField.text,
                      subjectField.text, bodyEdit.text, attachments,
                      pgpSign, pgpEncrypt)
    }

    /// Set while closing deliberately (sent, draft saved, discard confirmed),
    /// so close() lets it through instead of asking again.
    property bool closingConfirmed: false

    function hasContent() {
        return toField.text.trim() !== "" || ccField.text.trim() !== ""
            || bccField.text.trim() !== "" || subjectField.text.trim() !== ""
            || bodyEdit.text.trim() !== "" || attachments.length > 0
    }

    /// The fields exactly as the composer was opened (captured in present()),
    /// so closing can tell "untouched" from "work in progress". A reply's
    /// quoted body or a resumed draft counts as untouched until the user
    /// actually edits something.
    property var openedState: null
    function captureOpenedState() {
        openedState = {
            to: toField.text,
            cc: ccField.text,
            bcc: bccField.text,
            subject: subjectField.text,
            // Read back through the editor: TextArea re-serializes rich text,
            // so comparing against this (not the HTML we assigned) is stable.
            body: bodyEdit.text,
            attachCount: attachments.length
        }
    }
    function isModified() {
        if (!openedState)
            return hasContent()
        return toField.text !== openedState.to
            || ccField.text !== openedState.cc
            || bccField.text !== openedState.bcc
            || subjectField.text !== openedState.subject
            || bodyEdit.text !== openedState.body
            || attachments.length !== openedState.attachCount
    }

    // Escape closes the tab, which routes through close() below — so an edited
    // message gets the same confirmation as the tab's close button, and an
    // untouched one just closes.
    Shortcut {
        sequence: "Esc"
        // Only the visible tab may act on a window-wide shortcut.
        enabled: sheet.pageActive
        onActivated: sheet.close()
    }

    /// Closing only asks when there is something to lose: a composer the user
    /// has not typed into (empty new message, unedited reply/forward/draft)
    /// closes silently — nothing the user wrote is being thrown away, and a
    /// resumed draft stays in the Drafts folder untouched. When it does ask,
    /// closeRequested is withheld: the tab stays until the dialog resolves.
    function close() {
        if (closingConfirmed || sending || !isModified()) {
            closeRequested()
            return
        }
        // Raise the tab rather than call present(): a question must not be
        // asked off-screen, but this is not a fresh open, so none of the
        // open-time state below may be reset.
        presentRequested()
        discardDialog.open()
    }

    function present() {
        sending = false                  // never reopen stuck in "Sending…"
        closingConfirmed = false
        // Fields are fully populated by the open*() caller at this point —
        // this snapshot is what "unchanged, close silently" compares against.
        captureOpenedState()
        presentRequested()
        if (focusBodyOnOpen) {
            bodyEdit.forceActiveFocus()
            bodyEdit.cursorPosition = 0
        } else {
            toField.forceActiveFocus()
        }
    }

    function openNew() {
        sourceDraftUid = -1
        titleBase = "Compose"
        toField.text = ""
        ccField.text = ""
        bccField.text = ""
        subjectField.text = ""
        bodyEdit.text = Mail.newMessageBody() // "" or cursor line + signature
        attachments = []
        content.ccExpanded = false
        focusBodyOnOpen = false
        // The account's defaults, then the recipient scan — which may switch
        // encryption back off if a key turns out to be missing.
        pgpSign = Mail.accountPgpSignByDefault
        pgpEncrypt = Mail.accountPgpEncryptByDefault
        pgpEncryptSuppressed = Mail.accountPgpEncryptByDefault
        refreshRecipientKeys()
        present()
    }

    /// uid of the Drafts message this composer was opened from, so the stale
    /// copy can be removed once its replacement is stored. -1 for a new message.
    property real sourceDraftUid: -1

    /// d = Mail.draftData(): {to, cc, bcc, subject, body, uid}. Nothing is
    /// quoted or prefixed — the draft is resumed exactly as it was saved.
    function openDraft(d) {
        if (!d || d.subject === undefined)
            return
        titleBase = "Draft"
        toField.text = d.to
        ccField.text = d.cc
        bccField.text = d.bcc
        subjectField.text = d.subject
        bodyEdit.text = d.body
        attachments = []
        sourceDraftUid = d.uid
        content.ccExpanded = d.cc.length > 0 || d.bcc.length > 0
        focusBodyOnOpen = true
        present()
    }

    /// r = Mail.replyData(): {to, cc, subject, body} — empty when no message.
    function openReply(r) {
        if (!r || r.to === undefined)
            return
        sourceDraftUid = -1
        titleBase = "Reply"
        toField.text = r.to
        ccField.text = r.cc
        bccField.text = ""
        subjectField.text = r.subject
        bodyEdit.text = r.body
        attachments = []
        // Reveal Cc/Bcc when a reply pre-fills Cc, so it isn't hidden.
        content.ccExpanded = r.cc.length > 0
        focusBodyOnOpen = true
        present()
    }

    /// r = Mail.forwardData(): {to, cc, subject, body} — empty when no message.
    function openForward(r) {
        if (!r || r.to === undefined)
            return
        sourceDraftUid = -1
        titleBase = "Forward"
        toField.text = r.to
        ccField.text = r.cc
        bccField.text = ""
        subjectField.text = r.subject
        bodyEdit.text = r.body
        attachments = []
        content.ccExpanded = r.cc.length > 0
        focusBodyOnOpen = false // recipient is still to be chosen
        present()
    }

    // Recipient field with autocompletion from previously used addresses.
    // Suggestions match the address token under the cursor; Up/Down pick,
    // Enter/Tab or a click insert, Esc dismisses.
    component AddressField: QQC2.TextField {
        id: addrField

        property var suggestions: []
        property bool suppressCompletion: false

        function refreshSuggestions() {
            if (suppressCompletion || !activeFocus) {
                suggestionPopup.close()
                return
            }
            const token = text.substring(0, cursorPosition).split(",").pop().trim()
            let list = token.length > 0 ? Mail.recipientSuggestions(token) : []
            const present = text.toLowerCase()
            list = list.filter(a => !present.includes(a.toLowerCase()))
            suggestions = list
            if (list.length > 0) {
                suggestionList.currentIndex = 0
                suggestionPopup.open()
            } else {
                suggestionPopup.close()
            }
        }

        function acceptSuggestion() {
            if (!suggestionPopup.visible || suggestionList.currentIndex < 0)
                return false
            const addr = suggestions[suggestionList.currentIndex]
            suppressCompletion = true
            const head = text.substring(0, cursorPosition)
            const tail = text.substring(cursorPosition)
            const cut = head.lastIndexOf(",")
            const newHead = (cut >= 0 ? head.substring(0, cut + 1) + " " : "") + addr
            text = newHead + tail
            cursorPosition = newHead.length
            suppressCompletion = false
            suggestionPopup.close()
            return true
        }

        onTextChanged: refreshSuggestions()
        onActiveFocusChanged: {
            if (!activeFocus)
                suggestionPopup.close()
        }

        Keys.onDownPressed: event => {
            if (suggestionPopup.visible)
                suggestionList.currentIndex =
                    Math.min(suggestionList.currentIndex + 1, suggestions.length - 1)
            else
                event.accepted = false
        }
        Keys.onUpPressed: event => {
            if (suggestionPopup.visible)
                suggestionList.currentIndex = Math.max(suggestionList.currentIndex - 1, 0)
            else
                event.accepted = false
        }
        Keys.onReturnPressed: event => {
            if (!acceptSuggestion())
                event.accepted = false
        }
        Keys.onTabPressed: event => {
            if (!acceptSuggestion())
                event.accepted = false
        }
        Keys.onEscapePressed: event => {
            if (suggestionPopup.visible)
                suggestionPopup.close()
            else
                event.accepted = false
        }

        QQC2.Popup {
            id: suggestionPopup
            y: addrField.height
            width: addrField.width
            padding: 0
            focus: false // keep typing in the field
            closePolicy: QQC2.Popup.CloseOnPressOutsideParent

            contentItem: ListView {
                id: suggestionList
                implicitHeight: Math.min(contentHeight, Kirigami.Units.gridUnit * 10)
                clip: true
                model: addrField.suggestions
                delegate: QQC2.ItemDelegate {
                    required property string modelData
                    required property int index
                    width: suggestionList.width
                    text: modelData
                    highlighted: suggestionList.currentIndex === index
                    onHoveredChanged: {
                        if (hovered)
                            suggestionList.currentIndex = index
                    }
                    onClicked: {
                        suggestionList.currentIndex = index
                        addrField.acceptSuggestion()
                    }
                }
            }
        }
    }

    Connections {
        target: Mail
        // No "is this composer open?" guard on any of these any more: the page
        // is created when the composer opens and destroyed when it closes, so
        // simply existing to receive the signal is the guard.
        function onMailSent() {
            // The draft this was resumed from is superseded — without this,
            // sending an edited draft leaves the old one behind.
            Mail.discardDraft(sheet.sourceDraftUid)
            sheet.closingConfirmed = true
            sheet.close()
        }
        function onDraftSaved() {
            // The superseded copy is removed by saveDraft() itself, in
            // sequence with the append — doing it from here raced the
            // refresh and briefly showed both.
            sheet.closingConfirmed = true
            sheet.close()
        }
        // Sending failed: revert the Send button, keep this tab open, and show
        // the full server error in a dismissible dialog.
        function onSendFailed(error) {
            sheet.sending = false
            sendErrorDialog.errorText = error
            sendErrorDialog.open()
        }
    }

    /// Reached only when encryption is on and a recipient has no key. Three
    /// ways out, and none of them is "send it in the clear without saying so"
    /// (doc/openpgp.md §9).
    QQC2.Dialog {
        id: missingKeyDialog
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "No key for every recipient"

        property var addresses: []
        /// Set while a lookup started from here is running, so the dialog can
        /// report what came of it instead of closing on a silence.
        property bool looking: false

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Look up the key"
                icon.name: "download"
                enabled: Pgp.available && !missingKeyDialog.looking
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.ActionRole
                onClicked: {
                    missingKeyDialog.looking = true
                    // WKD only: it asks the recipient's own domain, which
                    // mailing them tells anyway. A keyserver would tell a third
                    // party who is about to be written to, so that stays a
                    // separate, deliberate action in the key manager.
                    for (let i = 0; i < missingKeyDialog.addresses.length; ++i)
                        Pgp.lookupWkd(missingKeyDialog.addresses[i])
                }
            }
            QQC2.Button {
                text: "Send unencrypted"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.DestructiveRole
                onClicked: {
                    missingKeyDialog.close()
                    sheet.pgpEncrypt = false
                    sheet.sending = true
                    Mail.sendMail(toField.text, ccField.text, bccField.text,
                                  subjectField.text, bodyEdit.text, sheet.attachments,
                                  sheet.pgpSign, false)
                }
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
                onClicked: missingKeyDialog.close()
            }
        }

        Connections {
            target: Pgp
            enabled: missingKeyDialog.looking
            function onKeysChanged() {
                sheet.refreshRecipientKeys()
                if (sheet.missingKeys().length === 0) {
                    missingKeyDialog.looking = false
                    missingKeyDialog.close()
                    sheet.pgpEncrypt = true
                    sheet.doSend()
                }
            }
            function onLookupFinished(address, found, source) {
                if (!found)
                    missingKeyDialog.looking = false
            }
        }

        contentItem: QQC2.Label {
            width: Kirigami.Units.gridUnit * 22
            text: {
                const who = missingKeyDialog.addresses.join(", ")
                if (missingKeyDialog.looking)
                    return "Looking for a published key for " + who + "…"
                return "This message is set to be encrypted, but no OpenPGP key "
                     + "is available for " + who + ".\n\n"
                     + "Mailove will not encrypt to the others and quietly leave "
                     + who + " out, and it will not send in the clear without "
                     + "asking. Look the key up, send this one unencrypted, or "
                     + "cancel and deal with it later."
            }
            wrapMode: Text.Wrap
        }
    }

    QQC2.Dialog {
        id: discardDialog
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Discard this message?"

        // Discarding a resumed draft removes it outright — not to Trash.
        // Keeping it would mean "Discard" left the message sitting in
        // Drafts, which is the opposite of what it says. A no-op for a
        // message that was never a draft.
        function confirmDiscard() {
            Mail.discardDraft(sheet.sourceDraftUid)
            sheet.closingConfirmed = true
            discardDialog.close()
            sheet.close()
        }

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Discard"
                icon.name: "edit-delete"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.DestructiveRole
                onClicked: discardDialog.confirmDiscard()
            }
            QQC2.Button {
                text: "Save as draft"
                icon.name: "document-save"
                enabled: Mail.hasDraftsFolder
                // No closingConfirmed here: the window closes on draftSaved,
                // once the server has actually taken it. Closing first would
                // throw the message away if the APPEND failed.
                onClicked: {
                    discardDialog.close()
                    Mail.saveDraft(toField.text, ccField.text, bccField.text,
                                   subjectField.text, bodyEdit.text, sheet.attachments,
                                   sheet.sourceDraftUid, sheet.pgpSign, sheet.pgpEncrypt)
                }
            }
            QQC2.Button {
                text: "Keep editing"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }

        contentItem: QQC2.Label {
            // Deleting an existing draft is not the same act as abandoning an
            // unsaved message, so it does not get the same wording.
            text: sheet.sourceDraftUid > 0
                ? "This draft will be deleted from the Drafts folder.\n"
                  + "It does not go to Trash and cannot be recovered."
                : "This message has not been sent."
            wrapMode: Text.Wrap
        }
    }

    QQC2.Dialog {
        id: sendErrorDialog
        property string errorText: ""
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        width: Math.min(sheet.width - Kirigami.Units.gridUnit * 4,
                        Kirigami.Units.gridUnit * 30)
        title: "Message not sent"
        standardButtons: QQC2.Dialog.Close

        contentItem: QQC2.Label {
            text: sendErrorDialog.errorText
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
        }
    }

    DocumentHandler {
        id: docHandler
        document: bodyEdit.textDocument
        cursorPosition: bodyEdit.cursorPosition
        selectionStart: bodyEdit.selectionStart
        selectionEnd: bodyEdit.selectionEnd
    }

    FileDialog {
        id: attachDialog
        fileMode: FileDialog.OpenFiles
        // Use the platform (KDE/Breeze) native picker — with the
        // org.kde.desktop Controls style there is no styled QtQuick file
        // dialog, so the native one is the one that matches the app.
        onAccepted: {
            for (const f of selectedFiles)
                sheet.attachments.push(f)
        }
    }

    // Attach shortcut (configurable in Settings → Shortcuts; default Ctrl+Shift+A).
    Shortcut {
        sequence: sheet.ui ? sheet.ui.shortcutAttach : "Ctrl+Shift+A"
        // Window-wide shortcuts belong to whichever tab is on screen.
        enabled: sheet.pageActive
        onActivated: attachDialog.open()
    }

    // List shortcuts. The formatting toolbar is out of the Tab chain, so these
    // are how a list is made without the mouse; they only act while the body
    // has focus, since that is the only place a list means anything. The
    // sequences are the ones mail clients already use.
    Shortcut {
        sequence: "Ctrl+Shift+8"
        enabled: sheet.pageActive && bodyEdit.activeFocus
        onActivated: docHandler.toggleBulletList()
    }
    Shortcut {
        sequence: "Ctrl+Shift+7"
        enabled: sheet.pageActive && bodyEdit.activeFocus
        onActivated: docHandler.toggleOrderedList()
    }

    // Send shortcut (configurable; default Ctrl+Return). Also accepts the
    // numeric-keypad Enter alongside the configured sequence, and honours the
    // Send button's guard.
    Shortcut {
        sequences: sheet.ui ? [sheet.ui.shortcutSend, "Ctrl+Enter"]
                            : ["Ctrl+Return", "Ctrl+Enter"]
        enabled: sheet.pageActive
                 && toField.text.trim().length > 0 && !sheet.sending
        onActivated: sheet.doSend()
    }

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.smallSpacing

        // Chrome-gray panel; individual input fields override back to View.
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false

        AddressField {
            id: toField
            Layout.fillWidth: true
            // Which recipients we hold keys for decides whether encryption is
            // even possible, so it follows the field as it is typed.
            onTextChanged: sheet.refreshRecipientKeys()
            placeholderText: "To (comma-separated)"
            // White field on the gray panel.
            Kirigami.Theme.colorSet: Kirigami.Theme.View
            Kirigami.Theme.inherit: false
        }

        // Cc/Bcc are collapsed by default behind a single clickable row.
        property bool ccExpanded: false
        // Left inset the toggle arrow occupies — Bcc aligns to it so its field
        // starts exactly under the Cc field. Measured from the button rather
        // than from the icon size: a ToolButton is its icon *plus* padding, so
        // assuming the icon alone left Bcc short by that padding.
        readonly property real ccArrowInset:
            ccToggleButton.width + Kirigami.Units.smallSpacing

        // Row 1: collapsed → "[>] Cc + Bcc" toggle; expanded → "[⌄] <Cc field>".
        // The arrow stays put on the left in both states and toggles on click.
        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            // Focusable toggle: reachable by Tab, and Space/Enter opens or
            // collapses it (standard button-key behaviour).
            QQC2.ToolButton {
                id: ccToggleButton
                icon.name: content.ccExpanded ? "arrow-down" : "arrow-right"
                icon.width: Kirigami.Units.iconSizes.small
                icon.height: Kirigami.Units.iconSizes.small
                activeFocusOnTab: true
                onClicked: {
                    content.ccExpanded = !content.ccExpanded
                    // Opening from the keyboard: drop straight into the Cc field.
                    if (content.ccExpanded)
                        ccField.forceActiveFocus()
                }
                QQC2.ToolTip.text: content.ccExpanded ? "Hide Cc/Bcc" : "Show Cc/Bcc"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.Label {
                visible: !content.ccExpanded
                text: "Cc + Bcc"
                opacity: 0.8
                Layout.fillWidth: true
                // Clicking the label is the same as the toggle button.
                TapHandler { onTapped: content.ccExpanded = !content.ccExpanded }
            }
            AddressField {
                id: ccField
                visible: content.ccExpanded
                Layout.fillWidth: true
                placeholderText: "Cc"
                Kirigami.Theme.colorSet: Kirigami.Theme.View
                Kirigami.Theme.inherit: false
            }
        }
        AddressField {
            id: bccField
            visible: content.ccExpanded
            Layout.fillWidth: true
            // Align under the Cc field (past the arrow inset).
            Layout.leftMargin: content.ccArrowInset
            placeholderText: "Bcc"
            Kirigami.Theme.colorSet: Kirigami.Theme.View
            Kirigami.Theme.inherit: false
        }

        QQC2.TextField {
            id: subjectField
            Layout.fillWidth: true
            placeholderText: "Subject"
            Kirigami.Theme.colorSet: Kirigami.Theme.View
            Kirigami.Theme.inherit: false
        }

        // Formatting toolbar.
        //
        // Tab order through the composer is the order a message is written in:
        // recipients, subject, how it is sent (encrypt/sign), what goes with it
        // (Attach), then the message itself. The formatting buttons are the one
        // thing deliberately left out — Tab would land on five icons nobody is
        // reaching for on the way to the body — so they carry shortcuts instead
        // (Ctrl+B/I, Ctrl+Shift+8 and Ctrl+Shift+7, handled in the body below)
        // and set activeFocusOnTab explicitly rather than leaving it to the
        // style's focus policy.
        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            // Encryption and signing sit with the formatting buttons because
            // they are the same kind of thing: choices about this one message.
            QQC2.ToolButton {
                id: encryptButton
                activeFocusOnTab: true
                visible: sheet.pgpAvailable
                // A padlock, not the "mail-encrypted" envelope: next to the
                // signing envelope the two were indistinguishable at 16px.
                icon.name: "object-locked"
                checkable: true
                checked: sheet.pgpEncrypt
                // Encrypting to a recipient whose key we do not hold is not
                // possible, so the button says so rather than failing on send.
                enabled: sheet.missingKeys().length === 0
                         || sheet.recipientList().length === 0
                onClicked: {
                    sheet.pgpEncrypt = checked
                    // From here the user has said what they want; nothing
                    // switches it back on their behalf.
                    sheet.pgpEncryptSuppressed = false
                }
                QQC2.ToolTip.text: {
                    const missing = sheet.missingKeys()
                    if (missing.length > 0)
                        return "No OpenPGP key available for " + missing.join(", ")
                             + ". Look one up in Settings → Encryption → Manage keys."
                    return "Encrypt this message. The subject line is never "
                         + "encrypted — it travels in the clear."
                }
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                id: signButton
                activeFocusOnTab: true
                visible: sheet.pgpAvailable
                icon.name: "mail-signed"
                checkable: true
                checked: sheet.pgpSign
                onClicked: sheet.pgpSign = checked
                QQC2.ToolTip.text: "Sign this message with your OpenPGP key, so "
                                   + "recipients can tell it really came from you"
                QQC2.ToolTip.visible: hovered
            }
            // Key status for whoever is in the recipient fields. It lives
            // beside the toggles it explains rather than in the header block,
            // where it pushed the Subject field around as addresses were
            // typed. Elided: this is a hint, not a paragraph.
            // A key lookup is a network round trip to the recipient's domain,
            // so it needs to look like one.
            Spinner {
                running: sheet.pgpAvailable && Pgp.busy
                         && sheet.recipientList().length > 0
                Layout.alignment: Qt.AlignVCenter
            }
            QQC2.Label {
                visible: sheet.pgpAvailable && sheet.recipientList().length > 0
                Layout.maximumWidth: Kirigami.Units.gridUnit * 16
                elide: Text.ElideRight
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                opacity: 0.8
                text: {
                    const missing = sheet.missingKeys()
                    if (missing.length > 0 && Pgp.busy)
                        return "looking for a key…"
                    if (missing.length === 0)
                        return "key available for every recipient"
                    return missing.length === 1
                        ? "no key available for " + missing[0]
                        : "no key available for " + missing.length + " recipients"
                }
                QQC2.ToolTip.text: {
                    const missing = sheet.missingKeys()
                    if (missing.length === 0)
                        return "An OpenPGP key is available for every recipient, so "
                             + "this message can be encrypted."
                    return "No OpenPGP key available for " + missing.join(", ")
                         + (Mail.accountPgpAutoWkd
                            ? " — Mailove is asking their domain for one."
                            : " — encryption is unavailable for this message.")
                }
                QQC2.ToolTip.visible: hovered
                HoverHandler { id: keyStatusHover }
                property bool hovered: keyStatusHover.hovered
            }

            // Fixed height, never fillHeight: this row sits in a ColumnLayout,
            // and a separator that fills it stretches the whole toolbar down
            // the window.
            Kirigami.Separator {
                visible: sheet.pgpAvailable
                Layout.preferredHeight: Kirigami.Units.gridUnit
                Layout.alignment: Qt.AlignVCenter
            }
            QQC2.ToolButton {
                activeFocusOnTab: false
                icon.name: "format-text-bold"
                checkable: true
                checked: docHandler.bold
                onClicked: docHandler.bold = checked
                QQC2.ToolTip.text: "Bold (Ctrl+B)"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                activeFocusOnTab: false
                icon.name: "format-text-italic"
                checkable: true
                checked: docHandler.italic
                onClicked: docHandler.italic = checked
                QQC2.ToolTip.text: "Italic (Ctrl+I)"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.SpinBox {
                // A SpinBox is three focusable things in a trenchcoat: taking
                // the control itself out of the chain leaves its inner editor
                // in it, which is what still caught Tab here. NoFocus settles
                // it for the whole control, editor included.
                focusPolicy: Qt.NoFocus
                activeFocusOnTab: false
                Component.onCompleted: if (contentItem) contentItem.activeFocusOnTab = false
                from: 6
                to: 48
                value: docHandler.fontSize
                onValueModified: docHandler.fontSize = value
                QQC2.ToolTip.text: "Font size"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                activeFocusOnTab: false
                icon.name: "format-list-unordered"
                onClicked: docHandler.toggleBulletList()
                QQC2.ToolTip.text: "Bulleted list (Ctrl+Shift+8). Typing "
                                   + "\"- \" at the start of a line also starts one."
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                activeFocusOnTab: false
                icon.name: "format-list-ordered"
                onClicked: docHandler.toggleOrderedList()
                QQC2.ToolTip.text: "Numbered list (Ctrl+Shift+7). Typing "
                                   + "\"1. \" at the start of a line also starts one."
                QQC2.ToolTip.visible: hovered
            }
            Item { Layout.fillWidth: true }
            QQC2.ToolButton {
                activeFocusOnTab: true
                icon.name: "mail-attachment"
                text: "Attach"
                onClicked: attachDialog.open()
                QQC2.ToolTip.text: "Attach a file (" +
                    (sheet.ui ? sheet.ui.shortcutAttach : "Ctrl+Shift+A") + ")"
                QQC2.ToolTip.visible: hovered
            }
        }

        // Attachment chips
        Flow {
            Layout.fillWidth: true
            visible: sheet.attachments.length > 0
            spacing: Kirigami.Units.smallSpacing
            Repeater {
                model: sheet.attachments
                delegate: QQC2.Button {
                    required property url modelData
                    required property int index
                    // Tabbable on purpose: the chips sit between Attach and the
                    // body, so attaching a file and then removing it again is
                    // all keyboard work. Space or Enter on a focused chip
                    // removes that attachment.
                    activeFocusOnTab: true
                    icon.name: "edit-delete-remove"
                    text: modelData.toString().split("/").pop()
                    onClicked: {
                        const copy = sheet.attachments
                        copy.splice(index, 1)
                        sheet.attachments = copy
                    }
                    QQC2.ToolTip.text: "Remove attachment"
                    QQC2.ToolTip.visible: hovered
                }
            }
        }

        QQC2.ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            // The editing area is a white View surface on the gray panel.
            Kirigami.Theme.colorSet: Kirigami.Theme.View
            Kirigami.Theme.inherit: false
            QQC2.TextArea {
                id: bodyEdit
                textFormat: TextEdit.RichText
                wrapMode: TextEdit.Wrap
                persistentSelection: true
                // White editing surface (View set) on the gray panel, like the
                // recipient/subject fields. Let the style draw its own text and
                // background under the View set — matching the TextFields above
                // — rather than hand-painting them.
                Kirigami.Theme.colorSet: Kirigami.Theme.View
                Kirigami.Theme.inherit: false

                // Formatting is keyboard-only work here — the toolbar is out of
                // the Tab chain (see below), so every button it holds has a
                // shortcut. Bold/italic are the standard ones; the list pair
                // follows what mail clients already use (Ctrl+Shift+8 / 7).
                Keys.onPressed: event => {
                    if (event.modifiers & Qt.ControlModifier) {
                        if (event.key === Qt.Key_B) {
                            docHandler.bold = !docHandler.bold
                            event.accepted = true
                        } else if (event.key === Qt.Key_I) {
                            docHandler.italic = !docHandler.italic
                            event.accepted = true
                        } else if (event.key === Qt.Key_V
                                   && (event.modifiers & Qt.ShiftModifier)) {
                            // Paste without formatting. Accepted either way
                            // (an empty clipboard included) so the plain paste
                            // never falls through to the formatted one.
                            docHandler.pastePlainText()
                            event.accepted = true
                        }
                        // The list pair is a Shortcut below rather than a key
                        // code here: Shift+8 is not Key_8 on every layout, and
                        // QKeySequence knows that where a raw key code does not.
                        return
                    }
                    // Writing a list before there is one is how people start
                    // one; make it the real thing rather than leaving them a
                    // line that only looks like it. A dash needs the space
                    // after it — "-" alone is still a dash — while a number is
                    // committed by its own "." or ")", which is already a
                    // marker and nothing else.
                    if (event.key === Qt.Key_Space) {
                        if (docHandler.startBulletList())
                            event.accepted = true
                    } else if (event.text === "." || event.text === ")") {
                        // event.text, not a key code: ")" is Shift+0 on some
                        // layouts and its own key on others.
                        if (docHandler.startOrderedList(event.text))
                            event.accepted = true
                    } else if (event.key === Qt.Key_Return
                               || event.key === Qt.Key_Enter) {
                        // Enter on an empty item ends the list: the first Enter
                        // made the empty item, this one leaves it behind.
                        if (docHandler.leaveEmptyListItem())
                            event.accepted = true
                    } else if (event.key === Qt.Key_Tab) {
                        // In a list, Tab is a level rather than a character or
                        // a jump to the next field; outside one it stays the
                        // way out of the body.
                        if (docHandler.indentListItem())
                            event.accepted = true
                    } else if (event.key === Qt.Key_Backtab) {
                        if (docHandler.outdentListItem())
                            event.accepted = true
                    } else if (event.key === Qt.Key_Backspace) {
                        // At the start of an item there is no character to
                        // rub out, so Backspace steps back out of the level.
                        if (docHandler.outdentAtBlockStart())
                            event.accepted = true
                    }
                }
            }
        }

        // Discard on the left; a spacer pushes Send to the right, where it
        // occupies exactly half the row width (the primary action).
        RowLayout {
            id: buttonRow
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            QQC2.Button {
                id: saveDraftButton
                // Discarding now lives on the window's close button, which
                // closed without asking anyway — this slot is worth more as
                // the action that keeps the message.
                text: "Save as draft"
                icon.name: "document-save"
                enabled: Mail.hasDraftsFolder && !sheet.sending
                QQC2.ToolTip.text: Mail.hasDraftsFolder
                    ? "Store this message in the Drafts folder"
                    : "No Drafts folder on this account"
                QQC2.ToolTip.visible: hovered
                onClicked: Mail.saveDraft(toField.text, ccField.text, bccField.text,
                                          subjectField.text, bodyEdit.text, sheet.attachments,
                                          sheet.sourceDraftUid, sheet.pgpSign,
                                          sheet.pgpEncrypt)
            }
            Item { Layout.fillWidth: true } // spacer takes the remaining left space

            // Right half: the Send button, or — while sending — a spinner and
            // "Sending…" label in its place (the button is hidden, not greyed).
            Item {
                Layout.preferredWidth: (buttonRow.width - buttonRow.spacing * 2) / 2
                Layout.preferredHeight: sendButton.implicitHeight

                QQC2.Button {
                    id: sendButton
                    anchors.fill: parent
                    visible: !sheet.sending
                    text: "Send"
                    icon.name: "document-send"
                    enabled: toField.text.trim().length > 0
                    onClicked: sheet.doSend()
                    QQC2.ToolTip.text: "Send (" +
                        (sheet.ui ? sheet.ui.shortcutSend : "Ctrl+Return") + ")"
                    QQC2.ToolTip.visible: hovered
                }

                RowLayout {
                    anchors.centerIn: parent
                    visible: sheet.sending
                    spacing: Kirigami.Units.smallSpacing

                    // Plain blue arc spinner (same as the main window) — the
                    // desktop-style BusyIndicator draws a cogwheel.
                    Item {
                        id: sendSpinner
                        Layout.preferredWidth: Kirigami.Units.iconSizes.smallMedium
                        Layout.preferredHeight: Kirigami.Units.iconSizes.smallMedium

                        Canvas {
                            anchors.fill: parent
                            anchors.margins: 2
                            onPaint: {
                                const ctx = getContext("2d")
                                ctx.reset()
                                const w = width / 2
                                ctx.beginPath()
                                ctx.arc(w, height / 2, w - 1.5, 0, Math.PI * 1.5)
                                ctx.strokeStyle = Kirigami.Theme.highlightColor
                                ctx.lineWidth = 3
                                ctx.lineCap = "round"
                                ctx.stroke()
                            }
                            RotationAnimator on rotation {
                                running: sheet.sending
                                from: 0
                                to: 360
                                duration: 900
                                loops: Animation.Infinite
                            }
                        }
                    }
                    QQC2.Label { text: "Sending…" }
                }
            }
        }
    }
}
