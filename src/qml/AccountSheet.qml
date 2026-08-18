// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailove.Core

/// The settings pages. A tab page, not a window: the tab strip in Main.qml
/// hosts it. See the page contract there — title, present(), closeRequested.
Item {
    id: sheet

    /// Tab page contract (see Main.qml).
    property string title: "Settings"

    /// The activity log window, owned by Main.qml so the Ctrl+Shift+L shortcut
    /// can open it without Settings being up.
    property var logWindow: null
    signal presentRequested()
    signal closeRequested()
    function present() { presentRequested() }
    // No Cancel: everything outside the Accounts page applies live, so the
    // button only ever discarded account edits while silently keeping the
    // rest. Escape (and the tab's close button) dismisses without saving.
    function close() {
        // Leaving is a commit for the autosaved half of the form: a field left
        // focused when the tab is dismissed has still been filled in.
        savePrefs()
        closeRequested()
    }

    // Chrome-gray panel (Window color set), same treatment as the compose
    // page; the user's bgColor override wins.
    Rectangle {
        anchors.fill: parent
        color: sheet.ui && sheet.ui.bgColor !== ""
               ? sheet.ui.bgColor : content.Kirigami.Theme.backgroundColor
    }

    /// The window's persisted UI settings object (set by Main.qml).
    property var ui

    /// 0 = Accounts, 1 = General, 2 = Look and feel, 3 = Shortcuts
    property int page: 0
    // Leaving the Accounts page commits what was typed on it, the same as
    // leaving a field does.
    onPageChanged: savePrefs()

    // The tab going away — including with the window — is the last chance to
    // store a field that still had focus.
    Component.onDestruction: savePrefs()

    /// True while a shortcut-capture button is reading raw key presses — the
    /// Esc shortcut below stands down so Esc can cancel the capture instead
    /// of closing the tab.
    property bool captureActive: false

    /// Shows the settings tab (the Dialog-era entry point, kept so callers and
    /// the old open() semantics — reload the account form on every opening —
    /// stay unchanged).
    function open() {
        selectAccount(Mail.accountNames.length > 0 ? Mail.currentAccount : -1)
        present()
    }

    Shortcut {
        sequence: "Esc"
        // Only the visible tab may act on a window-wide shortcut.
        enabled: sheet.StackLayout.isCurrentItem && !sheet.captureActive
        onActivated: sheet.close()
    }

    /// Account being edited; -1 = creating a new one.
    property int editIndex: -1

    /// True when this is an imported archive: mail on disk, no server, nothing
    /// to connect to. It is a choice in the account-type list rather than a
    /// flag on the side, because everything else on this page — servers,
    /// password, how mail is composed — only means something for an account
    /// that talks to a server. Switching the type to IMAP is the
    /// deliberate upgrade path from archive to live account.
    readonly property bool localAccount: authBox.currentIndex === 4

    /// OAuth providers supply their own servers, so only the address matters.
    readonly property bool oauthAccount:
        authBox.currentIndex === 2 || authBox.currentIndex === 3

    /// True when this account speaks JMAP. The OAuth entries are Gmail and
    /// Microsoft, both IMAP here, and an archive speaks nothing at all.
    readonly property bool jmapAccount: authBox.currentIndex === 1

    /// True when the account has a plain IMAP server to configure — the rows
    /// only IMAP has (port, encryption, SMTP) hang off this.
    readonly property bool imapServerAccount: authBox.currentIndex === 0

    /// True for the two types that sign in with a server and a password, which
    /// is what the server, username and password rows are for. JMAP shares
    /// them; what it does not share is everything IMAP-shaped below them.
    readonly property bool passwordAccount:
        authBox.currentIndex === 0 || authBox.currentIndex === 1

    /// True when the secret below is an API token to be sent as a Bearer
    /// header rather than a password. Only JMAP offers the choice — IMAP has
    /// no request to hang such a header on.
    readonly property bool bearerAuth:
        jmapAccount && jmapAuthBox.currentIndex === 0

    /// The account type as *stored*: MailBackend::Credentials::authType, whose
    /// values are the on-disk format (0 password, 1 Gmail, 2 Microsoft) and
    /// bear no relation to this list's order. An archive stores 0 — imported
    /// is not an authentication method, it is the absence of one.
    readonly property int authTypeValue:
        authBox.currentIndex === 2 ? 1 : authBox.currentIndex === 3 ? 2 : 0

    /// What the account still needs before it can be saved, or "" when ready.
    /// Saving a half-filled account produced one that could never connect and
    /// had to be deleted and redone, so the button stays off until it would
    /// actually work.
    readonly property string detailsMissing: {
        if (emailField.text.trim() === "")
            return "an e-mail address"
        if (!oauthAccount && !localAccount) {
            // A JMAP server is discovered from the address when the field is
            // left blank (RFC 8620 .well-known), so it is the one server row
            // that is genuinely optional. Sending is part of the protocol, so
            // there is no SMTP server to ask for either.
            if (!jmapAccount && hostField.text.trim() === "")
                return "an IMAP server"
            if (!jmapAccount && smtpHostField.text.trim() === "")
                return "an SMTP server for sending"
            // Only for a new account: editing an existing one leaves the field
            // blank on purpose, and the saved password stays as it is.
            if (editIndex < 0 && passwordField.text === "")
                return bearerAuth ? "an API token" : "a password"
        }
        return ""
    }

    /// True once a server has been spelled out — either stored with the account
    /// or typed here. Until then the fields follow what is guessed from the
    /// address, and stop the moment the user disagrees.
    property bool hostPinned: false
    property bool smtpHostPinned: false
    /// Same idea for the login: it follows the address until the user says
    /// otherwise, because for most servers the two are the same thing.
    property bool userPinned: false

    /// The SMTP host the client falls back to when none is stored (see
    /// MailClient::loadAccount). Kept in step with that rule so the field shows
    /// what sending would actually use rather than leaving it to be guessed
    /// behind the user's back.
    // --- OpenPGP key selection -------------------------------------------
    //
    // The account stores a fingerprint and nothing else; everything shown here
    // is looked up in the keyring each time, so a key deleted or expired
    // outside mailove shows up as what it now is rather than as a stale label.

    /// Fingerprint of the key chosen for this account; "" = encryption off.
    property string pgpKeyFp: ""

    /// Secret keys that carry this account's address, as maps from
    /// PgpEngine::secretKeysFor. Reloaded when the keyring or the address
    /// changes — a key generated for the address should appear without
    /// reopening the page.
    property var pgpKeyChoices: []

    /// True while the stored fingerprint names a key that is not in the
    /// keyring (deleted elsewhere, or the account address was changed). The
    /// key still gets a row, marked as missing: silently dropping it would
    /// turn "your mail is signed" into "your mail is not" with no notice.
    readonly property bool pgpKeyMissing: {
        if (pgpKeyFp === "")
            return false
        for (let i = 0; i < pgpKeyChoices.length; ++i)
            if (pgpKeyChoices[i].fingerprint === pgpKeyFp)
                return false
        return true
    }

    function pgpShortFingerprint(fp) {
        if (!fp)
            return ""
        const tail = fp.length > 16 ? fp.slice(-16) : fp
        return tail.replace(/(.{4})/g, "$1 ").trim()
    }

    function pgpKeyLabel(k) {
        const who = (k.name && k.name !== "") ? k.name : k.email
        let label = (who && who !== "" ? who + " — " : "") + pgpShortFingerprint(k.fingerprint)
        if (k.missing)
            label += " (not in your keyring)"
        else if (k.revoked)
            label += " (revoked)"
        else if (k.expired)
            label += " (expired)"
        return label
    }

    readonly property var pgpKeyLabels: {
        const labels = ["None — do not sign or encrypt"]
        for (let i = 0; i < pgpKeyChoices.length; ++i)
            labels.push(pgpKeyLabel(pgpKeyChoices[i]))
        // Last entry, and not a key: an action. A user whose key lives in a
        // backup file rather than in GnuPG's keyring would otherwise find an
        // empty picker and no way forward from it.
        labels.push("Import a private key file…")
        return labels
    }

    /// Index of the "Import a private key file…" row — the one entry that
    /// selects nothing.
    readonly property int pgpImportIndex: pgpKeyChoices.length + 1

    readonly property int pgpKeyIndex: {
        if (pgpKeyFp === "")
            return 0
        for (let i = 0; i < pgpKeyChoices.length; ++i)
            if (pgpKeyChoices[i].fingerprint === pgpKeyFp)
                return i + 1
        return 0
    }

    readonly property var pgpSelectedKey:
        pgpKeyIndex > 0 ? pgpKeyChoices[pgpKeyIndex - 1] : null

    readonly property bool pgpKeyHintIsBad:
        pgpSelectedKey !== null && (pgpSelectedKey.missing === true
                                    || pgpSelectedKey.bad === true)

    readonly property string pgpKeyHint: {
        if (pgpKeyFp === "") {
            if (Pgp.available && pgpKeyChoices.length === 0
                && emailField.text.trim() !== "")
                return "No usable key in your keyring carries this address — "
                     + "expired and revoked keys are not offered. Generate "
                     + "one, or pick \"Import a private key file…\" above to "
                     + "point GnuPG at a key you already have — an exported "
                     + "backup, or one from another machine."
            return ""
        }
        const k = pgpSelectedKey
        if (k === null)
            return ""
        if (k.missing === true)
            return "This key is no longer in your keyring. Import it again, or "
                 + "choose another one."
        if (k.revoked === true)
            return "This key is revoked and cannot be used."
        if (k.expired === true)
            return "This key has expired. Extend it in GnuPG or choose another one."
        // An expiry that arrives unannounced means signing simply stops
        // working one morning, and correspondents' copies of the key go stale
        // at the same time. Six weeks is enough notice to extend it and let
        // the new expiry date propagate.
        if (k.expires && !isNaN(k.expires.getTime())) {
            const days = Math.floor((k.expires.getTime() - Date.now()) / 86400000)
            if (days <= 42)
                return days <= 0
                    ? "This key expires today. Extend it in GnuPG."
                    : "This key expires in " + days + (days === 1 ? " day" : " days")
                      + ". Extend it in GnuPG before it does — a key that has "
                      + "expired cannot sign, and your correspondents' copies "
                      + "need the new date."
        }
        const full = k.fingerprint.replace(/(.{4})/g, "$1 ").trim()
        // An invalid QDateTime — a key that never expires — arrives as an
        // Invalid Date, which formats as "Invalid Date" rather than failing.
        return full + (k.expires && !isNaN(k.expires.getTime())
                       ? " · expires " + Qt.formatDate(k.expires, Locale.ShortFormat)
                       : " · never expires")
    }

    /// Rebuilds the key list for the address currently in the form.
    function reloadPgpKeys() {
        if (!Pgp.available) {
            pgpKeyChoices = []
            return
        }
        const choices = Pgp.secretKeysFor(emailField.text.trim())
        // A stored key that no longer matches still belongs in the list — see
        // pgpKeyMissing.
        if (pgpKeyFp !== "") {
            let found = false
            for (let i = 0; i < choices.length; ++i)
                if (choices[i].fingerprint === pgpKeyFp)
                    found = true
            if (!found) {
                const known = Pgp.keyInfo(pgpKeyFp)
                if (known.fingerprint !== undefined) {
                    // In the keyring, just not for this address — which is the
                    // user's business, not something to overrule.
                    choices.push(known)
                } else {
                    choices.push({fingerprint: pgpKeyFp, name: "", email: "",
                                  missing: true, bad: true})
                }
            }
        }
        pgpKeyChoices = choices
    }

    Connections {
        target: Pgp
        function onKeysChanged() { sheet.reloadPgpKeys() }
    }

    function derivedSmtpHost(imapHost) {
        const h = imapHost.trim()
        return h.length > 0 ? h.replace(/^imap/, "smtp") : ""
    }

    function loadDetails() {
        loading = true
        const d = Mail.accountDetails(editIndex)
        hostPinned = (d.host ?? "") !== ""
        hostField.text = d.host ?? ""
        portField.value = d.port ?? 993
        securityBox.currentIndex = d.security ?? 0
        userField.text = d.user ?? ""
        // A saved login is a decision already made — never overwrite it with
        // the address afterwards.
        userPinned = userField.text !== ""
        displayNameField.text = d.displayName ?? ""
        organizationField.text = d.organization ?? ""
        // Accounts saved before the address was its own field kept it in the
        // login — and send off it, via MailClient::ownAddress. Show that,
        // rather than a blank the Save button then refuses to accept.
        emailField.text = (d.email ?? "") !== ""
            ? d.email
            : (userField.text.indexOf("@") >= 0 ? userField.text : "")
        passwordField.text = ""
        // Accounts saved before this field existed have no SMTP host but send
        // anyway, off the derived one — so show that instead of an empty field
        // the Save button then refuses to accept.
        smtpHostPinned = (d.smtpHost ?? "") !== ""
        smtpHostField.text = smtpHostPinned ? d.smtpHost
                                            : derivedSmtpHost(hostField.text)
        smtpPortField.value = d.smtpPort ?? 587
        smtpSecurityBox.currentIndex = d.smtpSecurity ?? 1
        // The inverse of authTypeValue/jmapAccount: an archive takes the slot
        // after the OAuth providers rather than showing as "IMAP"
        // with every server field mysteriously blank, and a JMAP account is
        // its own entry rather than a standard one with the wrong servers.
        authBox.currentIndex = (d.local ?? false)
            ? 4
            : (d.protocol ?? 0) === 1
            ? 1
            : (d.authType ?? 0) === 1 ? 2 : (d.authType ?? 0) === 2 ? 3 : 0
        // A JMAP account saved before this choice existed sent Basic, so an
        // absent key means Password — anything else would change how an
        // already-working account signs in. A brand-new account has no such
        // history and starts on the answer that is right far more often.
        jmapAuthBox.currentIndex = (d.bearerAuth ?? (editIndex < 0)) ? 0 : 1
        signatureEdit.text = d.signature ?? ""
        htmlMailBox.checked = d.htmlMail ?? true
        pgpKeyFp = d.pgpKeyFp ?? ""
        pgpSignBox.checked = d.pgpSignByDefault ?? false
        pgpEncryptBox.checked = d.pgpEncryptByDefault ?? false
        pgpAutoWkdBox.checked = d.pgpAutoWkd ?? true
        reloadPgpKeys()
        loading = false
        // The baseline every later autosave is compared against: what is on
        // screen now is what is stored.
        savedPrefs = currentPrefs()
        savedConnection = currentConnection()
        prefsSaved = false
        savedFlashTimer.stop()
    }

    /// The server and identity half of the form — everything the Save button
    /// still owns, because changing any of it re-keys the cache and the wallet
    /// entry and costs a reconnect.
    function currentConnection() {
        return {
            protocol: sheet.jmapAccount ? 1 : 0,
            host: hostField.text.trim(),
            port: portField.value,
            security: securityBox.currentIndex,
            user: userField.text.trim(),
            email: emailField.text.trim(),
            smtpHost: smtpHostField.text.trim(),
            smtpPort: smtpPortField.value,
            smtpSecurity: smtpSecurityBox.currentIndex,
            authType: sheet.authTypeValue,
            bearerAuth: sheet.bearerAuth,
            savePassword: savePasswordBox.checked,
            password: passwordField.text
        }
    }

    /// Those fields as last stored. Empty for a new account, which is why the
    /// footer asks for a Save from the first keystroke.
    property var savedConnection: ({})

    readonly property bool connectionDirty: {
        const now = currentConnection()
        for (const k in now) {
            if (savedConnection[k] !== now[k])
                return true
        }
        return false
    }

    /// Moves the form to another account (or to the new-account draft),
    /// storing whatever the current one had pending first.
    function selectAccount(index) {
        savePrefs()
        editIndex = index
        loadDetails()
    }

    // --- Autosaving the preference half of the form ----------------------
    //
    // Two halves, saved differently on purpose. Everything that only decides
    // how mail is written — the display name, organization, signature, format,
    // and the OpenPGP settings — is stored as soon as the field is done with,
    // through MailClient::saveAccountPrefs, which writes settings and stops
    // there. The server and identity fields still go through the Save button:
    // they name the cache and the wallet entry and they cost a reconnect, and
    // committing a half-typed address on the way past is not a thing to do
    // quietly.

    /// True while loadDetails() is filling the form. Every change it makes is
    /// a stored value arriving, not an edit, and saving it back would write
    /// the previous account's values into the newly selected one.
    property bool loading: false

    /// The preferences as last written, so a focus change that changed nothing
    /// writes nothing.
    property var savedPrefs: ({})

    /// The preference fields as they stand.
    function currentPrefs() {
        return {
            displayName: displayNameField.text,
            organization: organizationField.text,
            signature: signatureEdit.text,
            htmlMail: htmlMailBox.checked,
            pgpKeyFp: sheet.pgpKeyFp,
            // Without a key both are meaningless, and a stale "sign by
            // default" left behind after the key was cleared would fail on
            // every send instead of doing nothing.
            pgpSignByDefault: sheet.pgpKeyFp !== "" && pgpSignBox.checked,
            pgpEncryptByDefault: sheet.pgpKeyFp !== "" && pgpEncryptBox.checked,
            pgpAutoWkd: pgpAutoWkdBox.checked
        }
    }

    /// Stores the preference fields if any of them changed. Called when a
    /// field is finished with — focus left, box ticked — and again on the way
    /// out of the page, the account, or the tab.
    function savePrefs() {
        if (loading || editIndex < 0)
            return
        // An account that has since been removed or reordered: editIndex would
        // now point at somebody else's settings. The C++ side bounds-checks
        // too; this keeps the in-range-but-wrong-account case out of it.
        if (editIndex >= Mail.accountNames.length)
            return
        const now = currentPrefs()
        let changed = false
        for (const k in now) {
            if (savedPrefs[k] !== now[k])
                changed = true
        }
        if (!changed)
            return
        Mail.saveAccountPrefs(editIndex, now)
        savedPrefs = now
        savedFlashTimer.restart()
    }

    /// How long "Saved" stays up. Long enough to be read, short enough that it
    /// is not still claiming a save that happened a minute ago — and it takes
    /// the Save button's place while it does, so it cannot be missed.
    Timer {
        id: savedFlashTimer
        interval: 3000
        onTriggered: sheet.prefsSaved = false
        onRunningChanged: if (running) sheet.prefsSaved = true
    }
    property bool prefsSaved: false

    /// Writes a window UI setting and says so. The Look and Shortcuts pages
    /// have no Save button — every change there applies and stores itself, so
    /// the footer's "Saved" is the only confirmation there is. Setting the
    /// value through here rather than directly is what keeps that promise:
    /// a change that skipped it would land silently.
    /// The confirmation fires even when the value picked is the one already
    /// stored: picking the same color or pressing the same key is still an
    /// action taken, and a button that answers nothing reads as broken.
    function setUi(key, value) {
        if (!ui)
            return
        if (ui[key] !== value)
            ui[key] = value
        savedFlashTimer.restart()
    }

    /// Same for the application-wide settings behind the General page.
    function setMail(key, value) {
        if (Mail[key] !== value)
            Mail[key] = value
        savedFlashTimer.restart()
    }

    /// Persists the account form (the Save button). The tab stays open —
    /// saving is not leaving.
    function saveAccount() {
        // Look-page settings apply live; Save only persists account edits.
        if (page !== 0)
            return
        // Belt and braces: the button is disabled, but Enter reaches here
        // without going through it.
        if (detailsMissing !== "")
            return
        // OAuth providers get fixed, known-good server settings.
        const presets = sheet.localAccount
            ? {host: "", port: 993, security: 0,
               smtpHost: "", smtpPort: 587, smtpSecurity: 1}
            : authBox.currentIndex === 2
            ? {host: "imap.gmail.com", port: 993, security: 0,
               smtpHost: "smtp.gmail.com", smtpPort: 587, smtpSecurity: 1}
            : authBox.currentIndex === 3
            ? {host: "outlook.office365.com", port: 993, security: 0,
               smtpHost: "smtp.office365.com", smtpPort: 587, smtpSecurity: 1}
            : sheet.jmapAccount
            // JMAP discovers its own endpoints from the session object, so
            // there is nothing to store but the server itself — and blank even
            // for that means "ask the address's domain". Storing IMAP's port
            // and encryption alongside would be storing a guess nothing reads.
            ? {host: hostField.text, port: 0, security: 0,
               smtpHost: "", smtpPort: 0, smtpSecurity: 0}
            : {host: hostField.text, port: portField.value,
               security: securityBox.currentIndex, smtpHost: smtpHostField.text,
               smtpPort: smtpPortField.value, smtpSecurity: smtpSecurityBox.currentIndex}
        Mail.saveAccountDetails(editIndex, {
            protocol: sheet.jmapAccount ? 1 : 0,
            host: presets.host,
            port: presets.port,
            security: presets.security,
            // The login defaults to the address: that is what most servers
            // want, and it keeps the login non-empty, which the account key
            // (and so the wallet entry and message cache) depends on.
            user: (!oauthAccount && userField.text.trim() !== "")
                ? userField.text : emailField.text,
            email: emailField.text,
            displayName: displayNameField.text,
            organization: organizationField.text,
            password: passwordField.text,
            savePassword: savePasswordBox.checked,
            smtpHost: presets.smtpHost,
            smtpPort: presets.smtpPort,
            smtpSecurity: presets.smtpSecurity,
            authType: sheet.authTypeValue,
            bearerAuth: sheet.bearerAuth,
            local: sheet.localAccount,
            signature: signatureEdit.text,
            htmlMail: htmlMailBox.checked,
            // Only a pointer into the keyring — no key material is ever
            // written to mailove's settings.
            pgpKeyFp: sheet.pgpKeyFp,
            // Without a key both are meaningless, and a stale "sign by
            // default" left behind after the key was cleared would fail on
            // every send instead of doing nothing.
            pgpSignByDefault: sheet.pgpKeyFp !== "" && pgpSignBox.checked,
            pgpEncryptByDefault: sheet.pgpKeyFp !== "" && pgpEncryptBox.checked,
            pgpAutoWkd: pgpAutoWkdBox.checked
        })
        // A new account is now a real one, and the form is editing it — say so,
        // or its preferences would have nowhere to autosave to until the user
        // picked it out of the list again.
        if (editIndex < 0)
            editIndex = Mail.currentAccount
        // The explicit save wrote the preference half too, so both baselines
        // move with it.
        savedPrefs = currentPrefs()
        savedConnection = currentConnection()
        // Saving does not close: a tab stays until the user closes it, and
        // settings are commonly saved several times in a sitting.
    }

    QQC2.Dialog {
        id: confirmRemoveDialog
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Remove account?"

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Remove account"
                icon.name: "edit-delete"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: {
            Mail.removeAccount(sheet.editIndex)
            sheet.editIndex = Mail.accountNames.length > 0 ? Mail.currentAccount : -1
            sheet.loadDetails()
        }

        contentItem: QQC2.Label {
            text: "Remove \"" + (Mail.accountNames[sheet.editIndex] ?? "") + "\" from Mailove?\n\n"
                  + "Its settings and saved password are deleted from this computer. "
                  + "Mail on the server is not touched."
            wrapMode: Text.Wrap
        }
    }

    KeyManagerSheet {
        id: keyManagerSheet
        // Which account a new key made from in there would be for.
        ownerAddress: emailField.text.trim()
        ownerName: displayNameField.text.trim()
    }

    /// Points GnuPG at a private key that is not in its keyring yet — an
    /// exported backup, or a key moved from another machine. GnuPG asks for the
    /// file's passphrase itself if it has one; Mailove never sees the key
    /// material. From then on it is an ordinary key in the keyring, which is
    /// also the honest thing to tell the user (the label below says so).
    FileDialog {
        id: privateKeyDialog
        title: "Import a private key"
        nameFilters: ["Key files (*.asc *.gpg *.pgp *.key)", "All files (*)"]
        onAccepted: {
            sheet.pgpStatus = "Importing…"
            sheet.pgpStatusIsError = false
            Pgp.importKeyFile(selectedFile)
        }
    }

    /// Key generation, opened from the button below. Prefilled from the
    /// account being edited — this key is meant to be its identity.
    NewKeyDialog {
        id: generateKeyDialog
    }

    /// One line under the account form for whatever the last key operation
    /// did — generation and lookups finish long after the click that started
    /// them, and silence would read as nothing having happened.
    property string pgpStatus: ""
    property bool pgpStatusIsError: false

    Connections {
        target: Pgp
        function onKeyGenerated(fingerprint, error) {
            if (error !== "") {
                sheet.pgpStatus = "Key generation failed: " + error
                sheet.pgpStatusIsError = true
                return
            }
            // Neither a key nor an error: the passphrase prompt was dismissed.
            if (fingerprint === "") {
                sheet.pgpStatus = "Key generation was cancelled."
                sheet.pgpStatusIsError = false
                return
            }
            sheet.pgpStatus = "New key created."
            sheet.pgpStatusIsError = false
            // Adopt it straight away: generating a key from this page is a
            // statement about what this account should sign with.
            sheet.pgpKeyFp = fingerprint
            sheet.reloadPgpKeys()
            sheet.savePrefs()
        }
        function onErrorOccurred(text) {
            sheet.pgpStatus = text
            sheet.pgpStatusIsError = true
        }
        function onSecretKeyImported(fingerprint) {
            // Importing a private key on the account page is a statement about
            // what this account should sign with, so it is adopted straight
            // away — the same as generating one.
            sheet.pgpStatus = "Private key imported. It is now in GnuPG's keyring."
            sheet.pgpStatusIsError = false
            if (fingerprint !== "")
                sheet.pgpKeyFp = fingerprint
            sheet.reloadPgpKeys()
            sheet.savePrefs()
        }
        function onImportFinished(imported, unchanged, error) {
            if (error !== "") {
                sheet.pgpStatus = "Import failed: " + error
                sheet.pgpStatusIsError = true
            } else if (imported === 0 && unchanged === 0) {
                sheet.pgpStatus = "No key was found in that file."
                sheet.pgpStatusIsError = true
            }
            // Success is reported by onSecretKeyImported for a private key;
            // a public-only file says nothing here, because the account page
            // is not where public keys are managed.
        }
    }

    DocumentHandler {
        id: signatureDocHandler
        document: signatureEdit.textDocument
        cursorPosition: signatureEdit.cursorPosition
        selectionStart: signatureEdit.selectionStart
        selectionEnd: signatureEdit.selectionEnd
    }

    FolderDialog {
        id: thunderbirdImportDialog
        title: "Choose a folder of mbox files"
        onAccepted: {
            Mail.importThunderbird(selectedFolder)
            sheet.close()
        }
    }

    FileDialog {
        id: signatureImportDialog
        nameFilters: ["HTML files (*.html *.htm)", "All files (*)"]
        onAccepted: {
            const html = Mail.loadHtmlFile(selectedFile)
            if (html.length > 0)
                signatureEdit.text = html
        }
    }

    ColorDialog {
        id: bgColorDialog
        onAccepted: {
            sheet.setUi("bgColor", selectedColor.toString())
            bgColorField.text = sheet.ui.bgColor
        }
    }

    ColorDialog {
        id: scaleColorDialog
        property int scaleIndex: 0
        onAccepted: sheet.setUi("scaleColor" + scaleIndex, selectedColor.toString())
    }

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.smallSpacing

        // Chrome-gray panel (dialog-like); the style still draws the pages'
        // input fields with their own backgrounds.
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false

        RowLayout {
        Layout.fillWidth: true
        Layout.fillHeight: true
        spacing: Kirigami.Units.largeSpacing

        // Settings sections
        ColumnLayout {
            id: sectionList
            // Never narrower than its widest entry: a fixed 8 gridUnits cut
            // off "Look and feel". implicitWidth here is the widest delegate's
            // (icon + text + padding), so the column tracks the labels rather
            // than a guess at how long they are.
            Layout.minimumWidth: implicitWidth
            Layout.preferredWidth: Math.max(implicitWidth, Kirigami.Units.gridUnit * 8)
            Layout.alignment: Qt.AlignTop
            spacing: 0

            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "Accounts"
                icon.name: "user-identity"
                highlighted: sheet.page === 0
                onClicked: sheet.page = 0
            }
            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "General"
                icon.name: "configure"
                highlighted: sheet.page === 1
                onClicked: sheet.page = 1
            }
            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "Look and feel"
                icon.name: "preferences-desktop-theme"
                highlighted: sheet.page === 2
                onClicked: sheet.page = 2
            }
            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "Shortcuts"
                icon.name: "input-keyboard"
                highlighted: sheet.page === 3
                onClicked: sheet.page = 3
            }
            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "Advanced"
                icon.name: "configure-toolbars"
                highlighted: sheet.page === 5
                // Activating the loader here rather than binding it to
                // sheet.page keeps the page alive once opened.
                onClicked: {
                    advancedLoader.active = true
                    sheet.page = 5
                }
            }
            QQC2.ItemDelegate {
                Layout.fillWidth: true
                text: "About"
                icon.name: "help-about"
                highlighted: sheet.page === 4
                onClicked: sheet.page = 4
            }
        }

        Kirigami.Separator {
            Layout.fillHeight: true
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: sheet.page

        // --- Page 0: Accounts ---
        RowLayout {
        spacing: Kirigami.Units.largeSpacing

        // Account list
        ColumnLayout {
            Layout.preferredWidth: Kirigami.Units.gridUnit * 11
            Layout.fillHeight: true
            spacing: Kirigami.Units.smallSpacing

            QQC2.ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true

                ListView {
                    id: accountList
                    // An account being created gets a row of its own straight
                    // away, so it is visible where it will end up instead of
                    // existing only in the form. It follows the username as it
                    // is typed, and is not a real account until Save.
                    readonly property string draftName:
                        userField.text !== "" ? userField.text : "New account"
                    model: sheet.editIndex === -1
                           ? Mail.accountNames.concat([draftName])
                           : Mail.accountNames

                    delegate: QQC2.ItemDelegate {
                        required property string modelData
                        required property int index
                        readonly property bool isDraft: index >= Mail.accountNames.length
                        width: accountList.width
                        text: modelData
                        icon.name: isDraft ? "list-add" : "user-identity"
                        font.italic: isDraft
                        highlighted: isDraft ? sheet.editIndex === -1
                                             : sheet.editIndex === index
                        onClicked: {
                            if (isDraft) {
                                // Already editing it — reloading would wipe
                                // whatever has been typed so far.
                                sheet.savePrefs()
                                sheet.editIndex = -1
                                return
                            }
                            sheet.selectAccount(index)
                        }
                    }
                }
            }
            QQC2.Button {
                Layout.fillWidth: true
                icon.name: "list-add"
                text: "New account"
                highlighted: sheet.editIndex === -1
                onClicked: sheet.selectAccount(-1)
            }
            QQC2.Button {
                Layout.fillWidth: true
                icon.name: "document-import"
                text: "Import mail…"
                onClicked: thunderbirdImportDialog.open()
                // Any mbox tree, not just Thunderbird's: a file counts as mail
                // when it opens with an mbox From_ line, and the ".sbd" suffix
                // Thunderbird gives its subfolder directories is understood
                // where it appears. The profile subfolders are still named:
                // that is the one case where which folder to pick is not
                // obvious from looking at it.
                QQC2.ToolTip.text: "Import a folder of mbox files (Thunderbird, "
                                   + "Evolution, Claws, KMail, a Gmail Takeout export) "
                                   + "as a browsable archive account. Subfolders become "
                                   + "folders. For a Thunderbird profile, point it at "
                                   + "\"Mail\" or \"ImapMail\"; a single mbox file needs "
                                   + "a folder of its own."
                QQC2.ToolTip.visible: hovered
            }
            QQC2.Button {
                Layout.fillWidth: true
                icon.name: "list-remove"
                text: "Remove"
                enabled: sheet.editIndex >= 0 && Mail.accountNames.length > 0
                onClicked: confirmRemoveDialog.open()
            }
        }

        Kirigami.Separator {
            Layout.fillHeight: true
        }

        // Per-account details — scrolls inside the fixed-height dialog
        QQC2.ScrollView {
            id: detailsScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: availableWidth
            clip: true

        Kirigami.FormLayout {
            width: detailsScroll.availableWidth

            Kirigami.Separator {
                Kirigami.FormData.label: sheet.editIndex === -1
                    ? "New account" : "Account: " + (Mail.accountNames[sheet.editIndex] ?? "")
                Kirigami.FormData.isSection: true
            }
            // Account type on top — the one choice everything else on this
            // page hangs off. Which protocol an account speaks belongs here
            // rather than in a picker of its own: it decides the same things
            // the other entries do (which servers there are to configure, what
            // sending means), and asking it twice would let the two disagree.
            //
            // The order is presentation only. What is stored is an authType
            // and a protocol, mapped below, because those are the on-disk
            // format and reordering this list must never rewrite accounts.
            QQC2.ComboBox {
                id: authBox
                Kirigami.FormData.label: "Account type:"
                model: ["IMAP", "JMAP (experimental)",
                        "Gmail / Google Workspace", "Microsoft / 365",
                        "Imported account"]
            }
            // Both optional, and both about how the account presents itself,
            // so they share a row. The name gives recipients
            // "Jane Roe <jane@example.com>" instead of a bare address; the
            // organization becomes the Organization header, which is rarer
            // still — hence the lighter treatment of the second field.
            RowLayout {
                visible: !sheet.localAccount
                Kirigami.FormData.label: "Identity:"
                spacing: Kirigami.Units.smallSpacing

                QQC2.TextField {
                    id: displayNameField
                    Layout.fillWidth: true
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 12
                    placeholderText: "Full name"
                    // Stored when the field is done with, not per keystroke.
                    onActiveFocusChanged: if (!activeFocus) sheet.savePrefs()
                    onEditingFinished: sheet.savePrefs()
                }
                QQC2.TextField {
                    id: organizationField
                    Layout.fillWidth: true
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 10
                    placeholderText: "Organization (optional)"
                    // Dimmed rather than disabled: the field works, it is just
                    // the one most accounts leave empty. Only the chrome
                    // fades — text the user has typed stays full contrast.
                    opacity: activeFocus || text !== "" ? 1.0 : 0.75
                    onActiveFocusChanged: if (!activeFocus) sheet.savePrefs()
                    onEditingFinished: sheet.savePrefs()
                }
            }
            QQC2.TextField {
                id: emailField
                Kirigami.FormData.label: "E-mail address:"
                placeholderText: "user@example.com"
                // The usual shape of a provider's server names, guessed from
                // the address so the form arrives filled in. Wrong for plenty
                // of hosts, which is why both fields stay editable — a guess to
                // correct beats two blanks to research.
                onTextEdited: {
                    if (!sheet.userPinned)
                        userField.text = text
                    // Which keys count as this account's identity is a question
                    // about the address, so the picker follows it as it is typed.
                    sheet.reloadPgpKeys()
                    // An archive has no server, and guessing one for it is not
                    // a harmless guess: an imported account stays local only
                    // while its server field is empty, so filling it in here
                    // would quietly turn a finished archive into a live
                    // account pointed at a host nobody chose.
                    if (sheet.localAccount)
                        return
                    const domain = text.split("@").pop().trim()
                    if (domain.length === 0 || domain.indexOf(".") < 0)
                        return
                    // JMAP discovers its server from the address's own domain
                    // (.well-known/jmap), so a guessed "imap.<domain>" here
                    // would be a wrong answer replacing the right blank.
                    if (sheet.jmapAccount)
                        return
                    if (!sheet.hostPinned)
                        hostField.text = "imap." + domain
                    if (!sheet.smtpHostPinned)
                        smtpHostField.text = sheet.derivedSmtpHost(hostField.text)
                }
            }
            // The login is its own field because it need not be the address,
            // nor even share its domain — shared hosting hands out logins like
            // "u1234" or "mail3", and sending as that guessed address bounces.
            // OAuth providers sign in as the address, so they get no field.
            QQC2.TextField {
                id: userField
                visible: !sheet.oauthAccount
                Kirigami.FormData.label: "Username:"
                placeholderText: "Same as the e-mail address"
                // Typing here means the login is not the address after all, so
                // it stops following it.
                onTextEdited: sheet.userPinned = true
            }
            QQC2.Label {
                visible: sheet.oauthAccount
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Server settings are set up automatically. When you save, "
                      + "your browser opens to log in and authorize Mailove."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            QQC2.Label {
                visible: sheet.localAccount
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                text: "Imported (archive) account. Change type to turn it into "
                      + "a live account."
            }
            QQC2.Label {
                visible: sheet.jmapAccount
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                text: "Experimental: JMAP support is newer and less tested "
                      + "than IMAP."
            }
            QQC2.TextField {
                id: hostField
                visible: sheet.passwordAccount
                Kirigami.FormData.label: sheet.jmapAccount ? "JMAP server:" : "Server:"
                placeholderText: sheet.jmapAccount
                    ? "Discovered from your address if left blank"
                    : "imap.example.com"
                // Follow along while setting up a new account, so the SMTP row
                // is filled in by the time it is reached. onTextEdited, not
                // onTextChanged: loading an account must not overwrite what it
                // stored.
                onTextEdited: {
                    sheet.hostPinned = true
                    if (!sheet.smtpHostPinned)
                        smtpHostField.text = sheet.derivedSmtpHost(text)
                }
            }
            QQC2.SpinBox {
                id: portField
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "Port:"
                from: 1
                to: 65535
                value: 993
                editable: true
            }
            QQC2.ComboBox {
                id: securityBox
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "Security:"
                model: ["SSL/TLS", "STARTTLS", "None"]
                onActivated: portField.value = currentIndex === 0 ? 993 : 143
            }
            // JMAP servers mostly do not take a password at all: Fastmail
            // issues API tokens, and the Cyrus test server accepts a JWT and
            // nothing else. Which of the two the secret below is decides the
            // header it is sent in, and there is no way to detect it — so it
            // is asked, rather than guessed and failed on.
            QQC2.ComboBox {
                id: jmapAuthBox
                visible: sheet.jmapAccount
                Kirigami.FormData.label: "Sign in with:"
                model: ["API token (Bearer)", "Password"]
                currentIndex: 0
            }
            QQC2.TextField {
                id: passwordField
                visible: sheet.passwordAccount
                Kirigami.FormData.label: sheet.bearerAuth ? "API token:" : "Password:"
                echoMode: TextInput.Password
                placeholderText: sheet.editIndex >= 0 ? "(unchanged)" : ""
            }
            QQC2.Label {
                visible: sheet.bearerAuth
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                text: "The token is sent as an Authorization: Bearer header. "
                      + "Most JMAP servers issue one from their own settings "
                      + "page — check with your provider. Mailove cannot obtain "
                      + "one for you: its OAuth sign-in is only for Gmail and "
                      + "Microsoft, both of which it talks to over IMAP."
            }
            QQC2.CheckBox {
                id: savePasswordBox
                visible: sheet.passwordAccount
                Kirigami.FormData.label: ""
                text: sheet.bearerAuth
                    ? "Remember token (stored in KWallet / system keyring)"
                    : "Remember password (stored in KWallet / system keyring)"
                checked: true
            }

            // JMAP submits over its own API, so an account that speaks it has
            // no sending leg to configure at all.
            Kirigami.Separator {
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "Sending (SMTP)"
                Kirigami.FormData.isSection: true
            }
            QQC2.TextField {
                id: smtpHostField
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "SMTP server:"
                placeholderText: "smtp.example.com"
                // Typing here settles the question: stop mirroring the IMAP
                // server, even if it is later corrected.
                onTextEdited: sheet.smtpHostPinned = true
            }
            QQC2.SpinBox {
                id: smtpPortField
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "SMTP port:"
                from: 1
                to: 65535
                value: 587
                editable: true
            }
            QQC2.ComboBox {
                id: smtpSecurityBox
                visible: sheet.imapServerAccount
                Kirigami.FormData.label: "SMTP security:"
                model: ["SSL/TLS", "STARTTLS", "None"]
                currentIndex: 1
                onActivated: smtpPortField.value = currentIndex === 0 ? 465 : 587
            }

            Kirigami.Separator {
                visible: !sheet.localAccount
                Kirigami.FormData.label: "Composing"
                Kirigami.FormData.isSection: true
            }
            QQC2.CheckBox {
                id: htmlMailBox
                visible: !sheet.localAccount
                Kirigami.FormData.label: "Message format:"
                text: "Send HTML mail"
                checked: true
                onToggled: sheet.savePrefs()
            }
            QQC2.Label {
                visible: !sheet.localAccount
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "HTML mail carries a plain-text version alongside. "
                      + "Disable to send plain text only."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            // --- Encryption (OpenPGP) ---
            //
            // Nothing here holds key material: the only thing stored with the
            // account is a fingerprint pointing into the user's GnuPG home
            // (doc/openpgp.md §8). An imported archive gets the key manager and
            // reading, but no signing or encrypting options — it never sends.
            Kirigami.Separator {
                Kirigami.FormData.label: "Encryption"
                Kirigami.FormData.isSection: true
            }
            QQC2.Label {
                visible: !Pgp.available
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: Pgp.unavailableReason
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            RowLayout {
                visible: Pgp.available && !sheet.localAccount
                Kirigami.FormData.label: "Encryption key:"
                spacing: Kirigami.Units.smallSpacing

                QQC2.ComboBox {
                    id: pgpKeyBox
                    Layout.fillWidth: true
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 18
                    model: sheet.pgpKeyLabels
                    // Index 0 is always "None", so the model index is one ahead
                    // of the key list — keep the two in step in one place.
                    currentIndex: sheet.pgpKeyIndex
                    onActivated: {
                        if (index === sheet.pgpImportIndex) {
                            // An action, not a choice: put the selection back
                            // where it was and let the file picker decide.
                            currentIndex = Qt.binding(() => sheet.pgpKeyIndex)
                            privateKeyDialog.open()
                            return
                        }
                        sheet.pgpKeyFp =
                            index === 0 ? "" : (sheet.pgpKeyChoices[index - 1].fingerprint ?? "")
                        sheet.savePrefs()
                    }
                }
                QQC2.Button {
                    icon.name: "view-refresh"
                    display: QQC2.AbstractButton.IconOnly
                    text: "Reload keys"
                    onClicked: Pgp.refresh()
                    QQC2.ToolTip.text: "Re-read the keyring"
                    QQC2.ToolTip.visible: hovered
                }
            }
            QQC2.Label {
                visible: Pgp.available && !sheet.localAccount && text !== ""
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: sheet.pgpKeyHint
                wrapMode: Text.Wrap
                // Red and bold only when the chosen key cannot actually be
                // used, matching the DKIM badge's rule.
                font.bold: sheet.pgpKeyHintIsBad
                color: sheet.pgpKeyHintIsBad ? Kirigami.Theme.negativeTextColor
                                             : Kirigami.Theme.textColor
                opacity: sheet.pgpKeyHintIsBad ? 1.0 : 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            QQC2.CheckBox {
                id: pgpSignBox
                visible: Pgp.available && !sheet.localAccount
                enabled: sheet.pgpKeyFp !== ""
                Kirigami.FormData.label: "New message:"
                text: "Sign"
                onToggled: sheet.savePrefs()
            }
            QQC2.CheckBox {
                id: pgpEncryptBox
                visible: Pgp.available && !sheet.localAccount
                enabled: sheet.pgpKeyFp !== ""
                Kirigami.FormData.label: ""
                // Just the preference. Earlier wordings ("Encrypt when every
                // recipient has a key") put the *constraint* in the label,
                // which read as something the user was opting into — but not
                // holding a recipient's key makes encryption impossible
                // whether this is ticked or not, and at tick time there are no
                // recipients to speak of yet. The constraint belongs below.
                text: "Encrypt"
                onToggled: sheet.savePrefs()
            }
            ColumnLayout {
                visible: Pgp.available && !sheet.localAccount
                Kirigami.FormData.label: ""
                spacing: 0
                QQC2.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "Encrypting needs a public key for each recipient. "
                          + "Signing works without those."
                }
                QQC2.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "The subject line is never encrypted."
                }
            }
            QQC2.CheckBox {
                id: pgpAutoWkdBox
                visible: Pgp.available && !sheet.localAccount
                Kirigami.FormData.label: "Key discovery:"
                text: "Look up recipient keys automatically"
                onToggled: sheet.savePrefs()
                QQC2.ToolTip.text: "Asks the recipient's own domain for a published "
                                   + "key. Mailing someone already tells their "
                                   + "domain that much. Keyservers are never asked "
                                   + "without a click."
                QQC2.ToolTip.visible: hovered
            }
            RowLayout {
                visible: Pgp.available
                Kirigami.FormData.label: sheet.localAccount ? "Keys:" : ""
                spacing: Kirigami.Units.smallSpacing

                QQC2.Button {
                    icon.name: "application-pgp-keys"
                    text: "Manage keys…"
                    onClicked: {
                        keyManagerSheet.accountAddress = emailField.text.trim()
                        keyManagerSheet.open()
                    }
                }
                QQC2.Button {
                    visible: !sheet.localAccount
                    icon.name: "list-add"
                    text: "Generate a new key…"
                    enabled: emailField.text.trim() !== ""
                    onClicked: {
                        // Set rather than bound: the dialog's fields are the
                        // user's to correct once it is open.
                        generateKeyDialog.address = emailField.text.trim()
                        generateKeyDialog.displayName = displayNameField.text.trim()
                        generateKeyDialog.open()
                    }
                }
            }
            QQC2.Label {
                visible: Pgp.available && sheet.pgpStatus !== ""
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: sheet.pgpStatus
                wrapMode: Text.Wrap
                font.bold: sheet.pgpStatusIsError
                color: sheet.pgpStatusIsError ? Kirigami.Theme.negativeTextColor
                                              : Kirigami.Theme.textColor
                opacity: sheet.pgpStatusIsError ? 1.0 : 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Kirigami.Separator {
                visible: !sheet.localAccount
                Kirigami.FormData.label: "Signature"
                Kirigami.FormData.isSection: true
            }
            ColumnLayout {
                visible: !sheet.localAccount
                Kirigami.FormData.label: ""
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                // Formatting toolbar for the rich-text signature
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.smallSpacing

                    QQC2.ToolButton {
                        icon.name: "format-text-bold"
                        checkable: true
                        checked: signatureDocHandler.bold
                        onClicked: signatureDocHandler.bold = checked
                    }
                    QQC2.ToolButton {
                        icon.name: "format-text-italic"
                        checkable: true
                        checked: signatureDocHandler.italic
                        onClicked: signatureDocHandler.italic = checked
                    }
                    QQC2.SpinBox {
                        from: 6
                        to: 48
                        value: signatureDocHandler.fontSize
                        onValueModified: signatureDocHandler.fontSize = value
                        QQC2.ToolTip.text: "Font size"
                        QQC2.ToolTip.visible: hovered
                    }
                    Item { Layout.fillWidth: true }
                    QQC2.ToolButton {
                        icon.name: "document-import"
                        text: "Import HTML…"
                        onClicked: signatureImportDialog.open()
                        QQC2.ToolTip.text: "Replace the signature with the contents of an HTML file"
                        QQC2.ToolTip.visible: hovered
                    }
                }

                QQC2.ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: Kirigami.Units.gridUnit * 7
                    clip: true
                    QQC2.TextArea {
                        id: signatureEdit
                        textFormat: TextEdit.RichText
                        wrapMode: TextEdit.Wrap
                        persistentSelection: true
                        // The formatting buttons above take focus off the
                        // editor and put it back, so this saves rather more
                        // often than the text changes — savePrefs() writes
                        // only when something actually differs.
                        onActiveFocusChanged: if (!activeFocus) sheet.savePrefs()
                    }
                }
                QQC2.Label {
                    Layout.fillWidth: true
                    text: "Added automatically to every message above the "
                          + "quoted message."
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
            }
        }
        } // details ScrollView
        } // page 0

        // --- Page 1: General ---
        QQC2.ScrollView {
            id: generalScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: availableWidth
            clip: true

        Kirigami.FormLayout {
            width: generalScroll.availableWidth

            Kirigami.Separator {
                Kirigami.FormData.label: "Date format"
                Kirigami.FormData.isSection: true
            }
            QQC2.ComboBox {
                id: dateFormatBox
                Kirigami.FormData.label: "Show dates as:"
                // Display labels ↔ Qt format strings, index-matched.
                model: ["DD/MM/YYYY", "DD.MM.YYYY", "DD-MM-YYYY",
                        "MM/DD/YYYY", "YYYY-MM-DD"]
                readonly property var formats: ["dd/MM/yyyy", "dd.MM.yyyy", "dd-MM-yyyy",
                                                "MM/dd/yyyy", "yyyy-MM-dd"]
                currentIndex: Math.max(0, formats.indexOf(Mail.dateFormat))
                onActivated: sheet.setMail("dateFormat", formats[currentIndex])
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Used for message dates in the list and the reading pane."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Kirigami.Separator {
                Kirigami.FormData.label: "Mail checking and sending"
                Kirigami.FormData.isSection: true
            }
            QQC2.TextField {
                id: refreshField
                Kirigami.FormData.label: "Refresh every (minutes):"
                implicitWidth: Kirigami.Units.gridUnit * 4
                text: Mail.refreshMinutes
                validator: IntValidator { bottom: 0; top: 1440 }
                onTextEdited: {
                    if (acceptableInput)
                        sheet.setMail("refreshMinutes", parseInt(text))
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Checks for new email on this schedule. 0 to disable."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            QQC2.CheckBox {
                Kirigami.FormData.label: ""
                text: "Enable Undo send"
                checked: Mail.undoSend
                onToggled: sheet.setMail("undoSend", checked)
            }
            QQC2.Label {
                id: undoDelayHelp
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                // Re-read on every Advanced save. undoSendDelaySecs() is a
                // plain call with no change signal of its own, so without a
                // dependency on Advanced.reloaded the text would keep showing
                // whatever the delay was when this page was first built.
                property int delaySecs: Mail.undoSendDelaySecs()
                Connections {
                    target: Advanced
                    function onReloaded() {
                        undoDelayHelp.delaySecs = Mail.undoSendDelaySecs()
                    }
                }
                text: "Holds each sent message for " + undoDelayHelp.delaySecs
                      + " seconds, so you can still cancel it in the Outbox."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Kirigami.Separator {
                Kirigami.FormData.label: "Spam"
                Kirigami.FormData.isSection: true
            }
            QQC2.TextField {
                id: spamDaysField
                Kirigami.FormData.label: "Delete spam after (days):"
                implicitWidth: Kirigami.Units.gridUnit * 4
                text: Mail.spamRetentionDays
                validator: IntValidator { bottom: 0; top: 3650 }
                onTextEdited: {
                    if (acceptableInput)
                        sheet.setMail("spamRetentionDays", parseInt(text))
                }
            }
            QQC2.CheckBox {
                Kirigami.FormData.label: ""
                text: "Skip trash for spam"
                checked: Mail.spamSkipTrash
                onToggled: sheet.setMail("spamSkipTrash", checked)
            }
            ColumnLayout {
                Kirigami.FormData.label: ""
                spacing: 0
                QQC2.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "Spam received longer ago than this is removed "
                          + "automatically. 0 keeps it forever."
                }
                QQC2.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "Skip trash deletes all spam immediately without moving "
                          + "it to Trash first."
                }
            }

            Kirigami.Separator {
                Kirigami.FormData.label: "Sender authentication"
                Kirigami.FormData.isSection: true
            }
            QQC2.CheckBox {
                id: authVerifyBox
                Kirigami.FormData.label: ""
                text: "Verify DKIM, ARC, SPF and DMARC (and COMPAUTH)"
                checked: Mail.authVerification
                onToggled: sheet.setMail("authVerification", checked)
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Checks whether a message really came from the sender it claims."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Kirigami.Separator {
                Kirigami.FormData.label: "Storage"
                Kirigami.FormData.isSection: true
            }
            QQC2.TextField {
                id: maxBodyField
                Kirigami.FormData.label: "Don't cache messages over (MB):"
                implicitWidth: Kirigami.Units.gridUnit * 4
                text: Mail.maxBodyMB
                validator: IntValidator { bottom: 0; top: 1024 }
                onTextEdited: {
                    if (acceptableInput)
                        sheet.setMail("maxBodyMB", parseInt(text))
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Larger messages are not stored locally. 0 caches everything."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            RowLayout {
                Kirigami.FormData.label: "Offline cache:"
                spacing: Kirigami.Units.smallSpacing
                QQC2.Label {
                    id: cacheSizeLabel
                    // Re-read on open rather than polling: the figure only
                    // moves when a purge or a vacuum has run.
                    text: Mail.cacheSizeText()
                    // Read at the same moments as the text, so the button
                    // below agrees with the figure beside it.
                    property bool worthwhile: Mail.reclaimWorthwhile()
                }
                QQC2.BusyIndicator {
                    running: Mail.reclaiming
                    visible: running
                    implicitWidth: Kirigami.Units.gridUnit
                    implicitHeight: Kirigami.Units.gridUnit
                }
            }
            // Changes made here that the server has not been told about yet —
            // normally none, and normally for a fraction of a second. Worth
            // showing because it is the honest answer to "is everything I did
            // actually saved", which offline-first otherwise hides.
            QQC2.Label {
                Kirigami.FormData.label: ""
                visible: Mail.journalPendingCount > 0
                text: Mail.journalPendingCount === 1
                      ? "1 change waiting to reach the server"
                      : Mail.journalPendingCount + " changes waiting to reach the server"
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            QQC2.Button {
                Kirigami.FormData.label: ""
                text: cacheSizeLabel.worthwhile ? "Reclaim disk space"
                                               : "Nothing to reclaim"
                enabled: !Mail.reclaiming && cacheSizeLabel.worthwhile
                // Close Settings first: the progress dialog is modal over the
                // main window, and leaving this one open would stack two modals.
                onClicked: {
                    sheet.close()
                    Mail.reclaimDiskSpace()
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Reclaim space that is taken by deleted messages. It takes "
                      + "several minutes on a large cache and pauses syncing "
                      + "while it runs."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            Connections {
                target: Mail
                function onReclaimingChanged() {
                    if (!Mail.reclaiming) {
                        cacheSizeLabel.text = Mail.cacheSizeText()
                        cacheSizeLabel.worthwhile = Mail.reclaimWorthwhile()
                    }
                }
            }

            // Changes the server refused. Every one of them has already been
            // undone on screen, so this is the only place left that can say
            // why a message came back — the breadcrumb that announced it has
            // long scrolled away by the time anyone wonders.
            //
            // Absent entirely when there are none: an empty "Failed changes"
            // heading in Settings is a permanent suggestion that something is
            // wrong with syncing.
            Kirigami.Separator {
                Kirigami.FormData.label: "Failed changes"
                Kirigami.FormData.isSection: true
                visible: Mail.journalFailedCount > 0
            }
            ColumnLayout {
                id: failedChanges
                Kirigami.FormData.label: ""
                visible: Mail.journalFailedCount > 0
                spacing: Kirigami.Units.smallSpacing
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22

                // Rebuilt rather than bound: the rows come from a C++ call
                // that reads the cache, and re-running it on every repaint of
                // a Settings page would be a query per frame.
                property var rows: []
                function reload() { rows = Mail.failedChanges() }
                Component.onCompleted: reload()
                Connections {
                    target: Mail
                    function onJournalChanged() { failedChanges.reload() }
                }

                Repeater {
                    model: failedChanges.rows
                    delegate: ColumnLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 0
                        QQC2.Label {
                            text: modelData.what + " from " + modelData.from
                            font.bold: true
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        QQC2.Label {
                            text: modelData.which
                            wrapMode: Text.Wrap
                            opacity: 0.8
                            Layout.fillWidth: true
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                        }
                        QQC2.Label {
                            text: modelData.why + " — " + modelData.when
                            wrapMode: Text.Wrap
                            opacity: 0.8
                            Layout.fillWidth: true
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                        }
                        RowLayout {
                            spacing: Kirigami.Units.smallSpacing
                            QQC2.Button {
                                text: "Retry"
                                // Offered offline too: retrying re-makes the
                                // change locally and puts it back in the
                                // queue, which is exactly what making it
                                // offline in the first place does.
                                onClicked: Mail.retryFailedChange(modelData.id)
                            }
                            QQC2.Button {
                                text: "Discard"
                                onClicked: Mail.discardFailedChange(modelData.id)
                            }
                        }
                    }
                }
                QQC2.Button {
                    text: "Discard all"
                    visible: failedChanges.rows.length > 1
                    onClicked: Mail.discardAllFailedChanges()
                }
            }

            // Last on the page: troubleshooting, not something anyone sets on
            // the way to somewhere else.
            Kirigami.Separator {
                Kirigami.FormData.label: "Diagnostics"
                Kirigami.FormData.isSection: true
            }
            QQC2.Button {
                Kirigami.FormData.label: "Log:"
                text: "Show activity log…"
                icon.name: "view-list-text"
                // A window of its own, not a page here: it is read while
                // reproducing the problem it is about, and Settings is in
                // the way of that.
                onClicked: if (sheet.logWindow) sheet.logWindow.open()
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "The last 5000 lines Mailove logged. You can copy them "
                      + "into a bug report."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            // The label is the checkbox's own text (right column, standard
            // font), not a FormData.label in the left one — it reads as the
            // thing being switched, and the explainer sits under it like the
            // others on this page.
            ColumnLayout {
                Kirigami.FormData.label: ""
                spacing: Kirigami.Units.smallSpacing
                QQC2.CheckBox {
                    text: "Log activity in detail"
                    checked: Mail.debugLogging
                    onToggled: sheet.setMail("debugLogging", checked)
                }
                QQC2.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                    text: "Adds folder, account and sync detail to the log."
                    wrapMode: Text.Wrap
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
            }
        }
        } // general ScrollView

        // --- Page 2: Look and feel ---
        QQC2.ScrollView {
            id: lookScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: availableWidth
            clip: true

        Kirigami.FormLayout {
            width: lookScroll.availableWidth

            QQC2.ComboBox {
                Kirigami.FormData.label: "Layout:"
                model: ["Preview below", "Preview beside"]
                currentIndex: sheet.ui ? sheet.ui.messageLayout : 0
                onActivated: sheet.setUi("messageLayout", currentIndex)
            }
            ColumnLayout {
                Kirigami.FormData.label: ""
                spacing: 0
                QQC2.Label {
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "Below: email preview below the message list."
                }
                QQC2.Label {
                    opacity: 0.8
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    text: "Beside: email preview right of the message list."
                }
            }

            QQC2.ComboBox {
                Kirigami.FormData.label: "Row size:"
                model: ["Compact", "Medium", "Wide"]
                currentIndex: sheet.ui ? sheet.ui.rowDensity : 1
                onActivated: sheet.setUi("rowDensity", currentIndex)
            }

            // Only the composer is offered both ways: writing a message next
            // to the mailbox you are reading is a real need, while settings
            // and opened messages have no such pairing.
            QQC2.ComboBox {
                id: composePlacementBox
                Kirigami.FormData.label: "Compose in:"
                model: ["Tab", "Separate window"]
                currentIndex: sheet.ui && sheet.ui.composeInWindow ? 1 : 0
                onActivated: sheet.setUi("composeInWindow", currentIndex === 1)
            }

            RowLayout {
                Kirigami.FormData.label: "Background color:"
                spacing: Kirigami.Units.smallSpacing

                QQC2.TextField {
                    id: bgColorField
                    implicitWidth: Kirigami.Units.gridUnit * 7
                    text: sheet.ui ? sheet.ui.bgColor : ""
                    placeholderText: "#rrggbb"
                    // Apply live while typing — a Save-button click would
                    // close the dialog before editingFinished ever fired.
                    onTextEdited: {
                        if (text === "" || /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(text))
                            sheet.setUi("bgColor", text)
                    }
                }
                Rectangle { // swatch
                    width: Kirigami.Units.gridUnit * 1.2
                    height: width
                    radius: 3
                    color: sheet.ui && sheet.ui.bgColor !== ""
                           ? sheet.ui.bgColor : Kirigami.Theme.backgroundColor
                    border.color: Kirigami.Theme.textColor
                    border.width: 1
                }
                QQC2.Button {
                    text: "Pick…"
                    icon.name: "color-picker"
                    onClicked: {
                        bgColorDialog.selectedColor = sheet.ui.bgColor !== ""
                            ? sheet.ui.bgColor : Kirigami.Theme.backgroundColor
                        bgColorDialog.open()
                    }
                }
                QQC2.Button {
                    icon.name: "edit-clear"
                    QQC2.ToolTip.text: "Reset to theme default"
                    QQC2.ToolTip.visible: hovered
                    onClicked: {
                        sheet.setUi("bgColor", "")
                        bgColorField.text = ""
                    }
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                text: "Applies to the interface panels."
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Kirigami.Separator {
                Kirigami.FormData.label: "Mark emails"
                Kirigami.FormData.isSection: true
            }
            Repeater {
                // 0 is "no label": it takes any mark off instead of putting one
                // on, so it has a shortcut but nothing to pick a color for. It
                // leads the list because that is where it belongs when reading
                // down the rows — none, then 1 to 5.
                model: [0, 1, 2, 3, 4, 5]
                RowLayout {
                    id: scaleRow
                    required property int modelData
                    readonly property bool isNoLabel: modelData === 0
                    readonly property string keyProp: "scaleKey" + modelData
                    readonly property string colorProp: "scaleColor" + modelData
                    // "Scale" is what the settings keys call these (scaleColor1…5);
                    // there is no scale to speak of, so the UI says what they are.
                    Kirigami.FormData.label: isNoLabel ? "No label:"
                                                       : "Label " + modelData + ":"
                    spacing: Kirigami.Units.smallSpacing

                    QQC2.Button {
                        id: scaleCapture
                        property bool capturing: false
                        // Hold the window's Esc shortcut off while capturing,
                        // so Esc cancels the capture instead of closing.
                        onCapturingChanged: sheet.captureActive = capturing
                        implicitWidth: Kirigami.Units.gridUnit * 8
                        text: capturing ? "Press keys…"
                                        : (sheet.ui && sheet.ui[scaleRow.keyProp] !== ""
                                           ? sheet.ui[scaleRow.keyProp] : "None")
                        icon.name: capturing ? "input-keyboard" : ""
                        onClicked: {
                            capturing = true
                            forceActiveFocus()
                        }
                        onActiveFocusChanged: {
                            if (!activeFocus)
                                capturing = false
                        }
                        Keys.onPressed: event => {
                            if (!capturing)
                                return
                            event.accepted = true
                            if (event.key === Qt.Key_Control || event.key === Qt.Key_Shift
                                    || event.key === Qt.Key_Alt || event.key === Qt.Key_Meta)
                                return
                            if (event.key === Qt.Key_Escape) {
                                capturing = false
                                return
                            }
                            const seq = shortcutsForm.sequenceFromEvent(event)
                            if (seq !== "") {
                                sheet.setUi(scaleRow.keyProp, seq)
                                capturing = false
                            }
                        }
                    }
                    QQC2.Button {
                        icon.name: "edit-clear"
                        enabled: sheet.ui && sheet.ui[scaleRow.keyProp] !== ""
                        QQC2.ToolTip.text: "Clear shortcut"
                        QQC2.ToolTip.visible: hovered
                        onClicked: sheet.setUi(scaleRow.keyProp, "")
                    }
                    Rectangle { // swatch; hatched look when undefined
                        visible: !scaleRow.isNoLabel
                        width: Kirigami.Units.gridUnit * 1.2
                        height: width
                        radius: 3
                        // Truthiness, not !== "": a key the settings never
                        // stored reads as undefined, which passes !== "" and
                        // lands undefined on a QColor (a warning per row).
                        color: sheet.ui && sheet.ui[scaleRow.colorProp]
                               ? sheet.ui[scaleRow.colorProp] : "transparent"
                        border.color: Kirigami.Theme.textColor
                        border.width: 1
                        QQC2.Label {
                            anchors.centerIn: parent
                            visible: !sheet.ui || !sheet.ui[scaleRow.colorProp]
                            text: "?"
                            opacity: 0.8
                        }
                    }
                    QQC2.Button {
                        visible: !scaleRow.isNoLabel
                        text: "Pick…"
                        icon.name: "color-picker"
                        onClicked: {
                            scaleColorDialog.scaleIndex = scaleRow.modelData
                            scaleColorDialog.selectedColor =
                                sheet.ui[scaleRow.colorProp] !== ""
                                    ? sheet.ui[scaleRow.colorProp]
                                    : Kirigami.Theme.textColor
                            scaleColorDialog.open()
                        }
                    }
                    QQC2.Button {
                        visible: !scaleRow.isNoLabel
                        icon.name: "edit-clear"
                        enabled: sheet.ui && sheet.ui[scaleRow.colorProp] !== ""
                        QQC2.ToolTip.text: "Clear color"
                        QQC2.ToolTip.visible: hovered
                        onClicked: sheet.setUi(scaleRow.colorProp, "")
                    }
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Pressing a label shortcut marks the selected messages "
                      + "with that color (press again to clear the mark). "
                      + "No label removes all labels from any marked message. "
                      + "Defined colors appear next to the search bar as a "
                      + "quick filter."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
        }
        } // look ScrollView

        // --- Page 3: Shortcuts ---
        QQC2.ScrollView {
            id: shortcutsScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: availableWidth
            clip: true

        Kirigami.FormLayout {
            id: shortcutsForm
            width: shortcutsScroll.availableWidth

            /// Human/QKeySequence-style string for a captured key press,
            /// or "" when the pressed key cannot stand alone as a shortcut.
            function sequenceFromEvent(event) {
                let s = ""
                if (event.modifiers & Qt.ControlModifier) s += "Ctrl+"
                if (event.modifiers & Qt.AltModifier) s += "Alt+"
                if (event.modifiers & Qt.ShiftModifier) s += "Shift+"
                if (event.modifiers & Qt.MetaModifier) s += "Meta+"
                const named = {}
                named[Qt.Key_Delete] = "Del"
                named[Qt.Key_Backspace] = "Backspace"
                named[Qt.Key_Space] = "Space"
                named[Qt.Key_Insert] = "Ins"
                named[Qt.Key_Home] = "Home"
                named[Qt.Key_End] = "End"
                if (event.key in named)
                    return s + named[event.key]
                if (event.key >= Qt.Key_F1 && event.key <= Qt.Key_F12)
                    return s + "F" + (event.key - Qt.Key_F1 + 1)
                if ((event.key >= Qt.Key_A && event.key <= Qt.Key_Z)
                        || (event.key >= Qt.Key_0 && event.key <= Qt.Key_9))
                    return s + String.fromCharCode(event.key)
                return ""
            }

            Repeater {
                model: [
                    {label: "Select message:", key: "shortcutSelect", def: "Ins"},
                    {label: "Delete message:", key: "shortcutDelete", def: "Del"},
                    // Both of these flip: the key marks read when the message
                    // is unread and unread when it is read, spam when it is not
                    // and not-spam when it is. One row each, and the label says
                    // so — there is no second key to look for.
                    {label: "Mark read / unread:", key: "shortcutToggleRead", def: "M"},
                    {label: "Mark spam / not spam:", key: "shortcutJunk", def: "J"},
                    {label: "Compose:", key: "shortcutCompose", def: "C"},
                    {label: "Reply:", key: "shortcutReply", def: "R"},
                    {label: "Forward:", key: "shortcutForward", def: "F"},
                    {label: "Attach file:", key: "shortcutAttach", def: "Ctrl+Shift+A"},
                    {label: "Send message:", key: "shortcutSend", def: "Ctrl+Return"},
                    // Acts only while undo send is enabled in General — the
                    // key exists to call back a message still inside its hold.
                    {label: "Undo send message:", key: "shortcutUndoSend", def: "Ctrl+Z"},
                    {label: "Find in message:", key: "shortcutFind", def: "Ctrl+F"},
                    {label: "View source:", key: "shortcutSource", def: "Ctrl+U"},
                    {label: "Activity log:", key: "shortcutLog", def: "Ctrl+Shift+L"}
                ]
                RowLayout {
                    required property var modelData
                    Kirigami.FormData.label: modelData.label
                    spacing: Kirigami.Units.smallSpacing

                    QQC2.Button {
                        id: captureButton
                        property bool capturing: false
                        // See scaleCapture: keeps Esc for the capture.
                        onCapturingChanged: sheet.captureActive = capturing
                        implicitWidth: Kirigami.Units.gridUnit * 8
                        text: capturing ? "Press keys…"
                                        : (sheet.ui ? sheet.ui[modelData.key]
                                                    : modelData.def)
                        icon.name: capturing ? "input-keyboard" : ""
                        onClicked: {
                            capturing = true
                            forceActiveFocus()
                        }
                        onActiveFocusChanged: {
                            if (!activeFocus)
                                capturing = false
                        }
                        Keys.onPressed: event => {
                            if (!capturing)
                                return
                            event.accepted = true
                            // Wait for a real key — a held modifier is not
                            // a shortcut on its own.
                            if (event.key === Qt.Key_Control || event.key === Qt.Key_Shift
                                    || event.key === Qt.Key_Alt || event.key === Qt.Key_Meta)
                                return
                            if (event.key === Qt.Key_Escape) {
                                capturing = false
                                return
                            }
                            const seq = shortcutsForm.sequenceFromEvent(event)
                            if (seq !== "") {
                                sheet.setUi(modelData.key, seq)
                                capturing = false
                            }
                        }
                    }
                    QQC2.Button {
                        icon.name: "edit-clear"
                        QQC2.ToolTip.text: "Reset to default (" + modelData.def + ")"
                        QQC2.ToolTip.visible: hovered
                        onClicked: sheet.setUi(modelData.key, modelData.def)
                    }
                }
            }
            QQC2.Label {
                Kirigami.FormData.label: ""
                Layout.maximumWidth: Kirigami.Units.gridUnit * 22
                text: "Click a shortcut, then press the new key or combination "
                      + "(Esc cancels). Shortcuts act in the mail and folder "
                      + "lists. The label keys are under Look and feel."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

        }
        } // shortcuts ScrollView

        // --- Page 4: About ---
        QQC2.ScrollView {
            id: aboutScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: availableWidth
            clip: true

            // A FormLayout purely for its section heading, so the page title
            // is styled exactly like "Mail checking" or "Storage" rather than
            // being a Markdown heading inside the text.
            Kirigami.FormLayout {
                width: aboutScroll.availableWidth

                Kirigami.Separator {
                    // Same source as the main-bar version label: whatever the
                    // binary was built with.
                    Kirigami.FormData.label: "Mailove v" + Qt.application.version
                    Kirigami.FormData.isSection: true
                }
                QQC2.Label {
                    Kirigami.FormData.label: ""
                    Layout.fillWidth: true
                    // Compiled into the binary from ABOUT.md at build time.
                    text: Mail.aboutText
                    textFormat: Text.MarkdownText
                    wrapMode: Text.Wrap
                    onLinkActivated: link => Mail.openExternalUrl(link)
                }
            }
        } // about ScrollView

        // --- Page 5: Advanced ---
        // Built on first use, not with the rest of Settings. A StackLayout
        // constructs every page whether or not it is the current one, and this
        // page's reference list is ~70 delegates deep — eagerly building it put
        // a visible stall (340 ms on the GUI thread) in front of opening
        // Settings at all, which normally lands on Accounts. Once built it
        // stays, so an unsaved edit survives a trip to another page.
        Loader {
            id: advancedLoader
            Layout.fillWidth: true
            Layout.fillHeight: true
            active: false
            // Built off the critical path: even on its own, this page is more
            // than one frame's worth of items, and the GUI thread has 20 ms.
            asynchronous: true
            // A file rather than an inline Component: this page is compiled
            // only when it is first opened, instead of with the sheet.
            source: "AdvancedSheet.qml"
        }

        } // StackLayout
        } // content RowLayout

        // Footer: the Save button (and its "what's missing" hint) on the
        // Accounts page; on the pages that apply as you change them, the same
        // slot says so and flashes "Saved" when one of them lands. About has
        // nothing to report, and Advanced is the one page that does not apply
        // as you type — it edits a file and commits it with its own Apply
        // button, so this footer would be claiming the opposite of the truth.
        RowLayout {
            Layout.fillWidth: true
            spacing: 0
            visible: sheet.page !== 4 && sheet.page !== 5

            // What the form still needs. The other two things the footer used
            // to say live in the button now — a small grey line beside a Save
            // button is exactly what nobody reads.
            QQC2.Label {
                Layout.leftMargin: Kirigami.Units.largeSpacing
                visible: sheet.page === 0 && sheet.detailsMissing !== ""
                text: "Needs " + sheet.detailsMissing
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            Item { Layout.fillWidth: true }

            // One slot, one message. The button says what the page's state is
            // — there is something to save, or everything is saved — and an
            // autosave takes the slot over for a moment to say so itself.
            // Sized to the wider of the two so the footer never reflows on the
            // swap.
            Item {
                implicitWidth: Math.max(sheet.page === 0 ? saveButton.implicitWidth
                                                         : autoSaveNote.implicitWidth,
                                        savedFlash.implicitWidth)
                implicitHeight: Math.max(saveButton.implicitHeight, savedFlash.implicitHeight)

                // The live pages' equivalent of "All saved": there is no
                // button to press, so the slot stands there saying that is
                // deliberate until a change makes it flash.
                QQC2.Label {
                    id: autoSaveNote
                    anchors.centerIn: parent
                    text: "Changes save automatically"
                    opacity: sheet.page !== 0 && !sheet.prefsSaved ? 0.8 : 0.0
                    visible: opacity > 0
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    Behavior on opacity { NumberAnimation { duration: 300 } }
                }

                QQC2.Button {
                    id: saveButton
                    anchors.centerIn: parent
                    // The server half of the form is all this still owns; see
                    // savePrefs(). Nothing pending is a state worth stating
                    // rather than a button worth offering — reconnecting on
                    // demand is the toolbar's Reconnect button, not this.
                    text: sheet.connectionDirty ? "Save" : "All saved"
                    icon.name: sheet.connectionDirty ? "document-save" : "dialog-ok"
                    enabled: sheet.connectionDirty && sheet.detailsMissing === ""
                    highlighted: enabled
                    onClicked: sheet.saveAccount()
                    opacity: sheet.prefsSaved ? 0.0 : 1.0
                    visible: sheet.page === 0 && opacity > 0
                    Behavior on opacity { NumberAnimation { duration: 300 } }
                    QQC2.ToolTip.text: sheet.connectionDirty
                        ? "Stores the server, address and password, and reconnects. "
                          + "The name, signature and encryption settings save themselves."
                        : "Everything on this page is stored. Use Reconnect in the "
                          + "toolbar to dial the server again."
                    QQC2.ToolTip.visible: hovered
                }

                RowLayout {
                    id: savedFlash
                    anchors.centerIn: parent
                    spacing: Kirigami.Units.smallSpacing
                    opacity: sheet.prefsSaved ? 1.0 : 0.0
                    visible: opacity > 0
                    // Arrives rather than appears: a short rise into place,
                    // then a slower fade back to the button.
                    anchors.verticalCenterOffset: sheet.prefsSaved
                                                  ? 0 : Kirigami.Units.smallSpacing
                    Behavior on opacity { NumberAnimation { duration: 150 } }
                    Behavior on anchors.verticalCenterOffset {
                        NumberAnimation { duration: 150; easing.type: Easing.OutCubic }
                    }

                    Kirigami.Icon {
                        source: "dialog-ok"
                        color: Kirigami.Theme.positiveTextColor
                        implicitWidth: Kirigami.Units.iconSizes.small
                        implicitHeight: Kirigami.Units.iconSizes.small
                    }
                    QQC2.Label {
                        text: "Saved"
                        color: Kirigami.Theme.positiveTextColor
                    }
                }
            }
        }
    }

}
