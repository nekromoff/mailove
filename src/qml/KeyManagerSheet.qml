// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQuick.Window
import org.kde.kirigami as Kirigami
import Mailove.Core

/// The OpenPGP key manager: the keys GnuPG holds, and the four things a mail
/// client needs to do with them — import one, find one, hand one out, throw one
/// away. Everything else about a key (passphrases, trust signing, revocation)
/// belongs to gpg and Kleopatra, which own the warnings that go with it.
///
/// A window of its own rather than a modal sheet: keys are looked at *while*
/// reading a message or filling in an account, and the title bar's X is the
/// close button people already know.
Window {
    id: keyManager

    title: "OpenPGP keys"
    flags: Qt.Window
    color: content.Kirigami.Theme.backgroundColor

    width: Kirigami.Units.gridUnit * 42
    height: Kirigami.Units.gridUnit * 32
    minimumWidth: Kirigami.Units.gridUnit * 26
    minimumHeight: Kirigami.Units.gridUnit * 18

    /// Opens the manager, or brings it forward when it is already up. Named
    /// open() so the callers read the same as they did when this was a dialog.
    function open() {
        lookupField.text = accountAddress
        searchField.text = focusKey
        if (focusKey !== "" && keyList.count > 0)
            keyList.currentIndex = 0
        setStatus(focusKey !== "" && keyList.count === 0
                  ? "That key is not in your keyring." : "", false)
        show()
        raise()
        requestActivate()
    }

    onVisibleChanged: if (!visible) focusKey = ""

    /// The address the manager opens on — the account being edited. Only used
    /// to prefill the lookup field; the list itself always shows every key.
    property string accountAddress: ""

    /// The address a *new* key would be for: the account this manager belongs
    /// to. Separate from accountAddress, which is whoever is being looked up —
    /// opened from a message that is the sender, and generating a key for
    /// them is not a thing anyone means to do.
    property string ownerAddress: ""
    property string ownerName: ""

    /// One line under the toolbar: what the last operation did. Errors and
    /// results share it, because they answer the same question.
    property string statusText: ""
    property bool statusIsError: false

    function setStatus(text, isError) {
        statusText = text
        statusIsError = isError === true
    }

    /// A fingerprint or key ID to open on. The list filters to it and the row
    /// is selected, so a badge in the message viewer can hand the reader
    /// straight to the key it is talking about instead of a list to hunt in.
    property string focusKey: ""

    /// A fingerprint is 40 hex characters; unbroken it is unreadable and
    /// unverifiable by eye. gpg's own grouping is what people compare against.
    function groupFingerprint(fp) {
        if (!fp)
            return ""
        return fp.replace(/(.{4})/g, "$1 ").trim()
    }

    Connections {
        target: Pgp

        function onImportFinished(imported, unchanged, error) {
            if (error !== "") {
                keyManager.setStatus("Import failed: " + error, true)
            } else if (imported === 0 && unchanged === 0) {
                keyManager.setStatus("No keys were found in that data.", true)
            } else if (imported === 0) {
                keyManager.setStatus("Already in your keyring — nothing new to import.",
                                     false)
            } else {
                keyManager.setStatus(imported === 1 ? "1 key imported."
                                                    : imported + " keys imported.", false)
            }
        }
        function onSecretKeyImported(fingerprint) {
            keyManager.setStatus("A private key was imported — it is now one of "
                                 + "your own identities in GnuPG's keyring.", false)
        }
        function onKeyGenerated(fingerprint, error) {
            if (error !== "")
                keyManager.setStatus("Key generation failed: " + error, true)
            else if (fingerprint === "")
                // Neither a key nor an error: the passphrase prompt was
                // dismissed.
                keyManager.setStatus("Key generation was cancelled.", false)
            else
                keyManager.setStatus("New key created.", false)
        }
        function onLookupFinished(address, found, source) {
            if (!found)
                keyManager.setStatus("No key published for " + address
                                     + " (" + source + ").", false)
            // A key that was found is reported by the import that follows it,
            // which is the part that says whether it is now usable.
        }
        function onExportFinished(fileName, error) {
            keyManager.setStatus(error !== "" ? "Export failed: " + error
                                              : "Public key written to " + fileName,
                                 error !== "")
        }
        function onErrorOccurred(text) {
            keyManager.setStatus(text, true)
        }
        function onStatusMessage(text) {
            keyManager.setStatus(text, false)
        }
    }

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.smallSpacing

        // Chrome-gray, like the settings page it opens from; the list below
        // keeps the View color set of its own.
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false

        // No backend: say so once, plainly, and offer nothing that cannot work.
        QQC2.Label {
            visible: !Pgp.available
            Layout.fillWidth: true
            Layout.fillHeight: true
            text: Pgp.unavailableReason
            wrapMode: Text.Wrap
            verticalAlignment: Text.AlignVCenter
        }

        RowLayout {
            visible: Pgp.available
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            Kirigami.SearchField {
                id: searchField
                Layout.fillWidth: true
                placeholderText: "Filter by name, address or fingerprint"
                // Kirigami would otherwise claim Ctrl+F application-wide from
                // inside this sheet, where the viewer's find bar already has it.
                focusSequences: []
                onTextChanged: keyModel.searchText = text
            }
            QQC2.Button {
                icon.name: "document-import"
                text: "Import…"
                onClicked: importDialog.open()
                QQC2.ToolTip.text: "Import a key from a file — a correspondent's "
                                   + "public key, or one of your own private keys "
                                   + "that is not in GnuPG's keyring yet"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.Button {
                icon.name: "list-add"
                text: "New key…"
                onClicked: {
                    // Prefilled with the account this manager belongs to when
                    // it has one, and left to the user to fill in when it does
                    // not; the same dialog the settings page opens.
                    generateKeyDialog.address = keyManager.ownerAddress
                    generateKeyDialog.displayName = keyManager.ownerName
                    generateKeyDialog.open()
                }
                QQC2.ToolTip.text: "Generate a new OpenPGP key of your own"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.Button {
                icon.name: "view-refresh"
                display: QQC2.AbstractButton.IconOnly
                text: "Reload"
                enabled: !Pgp.busy
                onClicked: Pgp.refresh()
                QQC2.ToolTip.text: "Re-read the keyring"
                QQC2.ToolTip.visible: hovered
            }
        }

        // Finding someone's key. WKD first and by itself: it asks the address's
        // own domain, which mailing that address tells anyway. The keyserver is
        // a separate, deliberate click — it tells a third party who you are
        // about to write to.
        RowLayout {
            visible: Pgp.available
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            QQC2.TextField {
                id: lookupField
                Layout.fillWidth: true
                placeholderText: "Find a key for an address…"
                onAccepted: if (text.trim() !== "") Pgp.lookupWkd(text.trim())
            }
            QQC2.Button {
                icon.name: "search"
                text: "Look up"
                enabled: lookupField.text.trim() !== "" && !Pgp.busy
                onClicked: Pgp.lookupWkd(lookupField.text.trim())
                QQC2.ToolTip.text: "Ask the address's own domain for a published "
                                   + "key (Web Key Directory)"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.Button {
                text: "Also try keys.openpgp.org"
                enabled: lookupField.text.trim() !== "" && !Pgp.busy
                onClicked: Pgp.lookupKeyserver(lookupField.text.trim())
                QQC2.ToolTip.text: "Ask the keys.openpgp.org keyserver. It will "
                                   + "learn that you are looking for this address."
                QQC2.ToolTip.visible: hovered
            }
        }

        // A hint about the list, so it sits with the list rather than wedged
        // between the controls above it.
        QQC2.Label {
            visible: Pgp.available && keyList.count > 0
            Layout.fillWidth: true
            text: "Right-click a key to set trust"
            horizontalAlignment: Text.AlignRight
            elide: Text.ElideRight
            opacity: 0.7
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }

        QQC2.ScrollView {
            visible: Pgp.available
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            ListView {
                id: keyList
                // The list is a content surface, not chrome: white (or the
                // dark theme's equivalent) behind the rows rather than the
                // dialog's gray.
                Kirigami.Theme.colorSet: Kirigami.Theme.View
                Kirigami.Theme.inherit: false

                model: PgpKeyModel { id: keyModel }
                currentIndex: -1

                Kirigami.PlaceholderMessage {
                    anchors.centerIn: parent
                    width: parent.width - Kirigami.Units.gridUnit * 4
                    visible: keyList.count === 0
                    text: searchField.text.trim() !== ""
                          ? "No key matches that."
                          : "No OpenPGP keys yet"
                    explanation: searchField.text.trim() !== ""
                        ? ""
                        : "Import a correspondent's key from a file, or look one "
                          + "up by address above."
                }

                delegate: QQC2.ItemDelegate {
                    id: keyDelegate
                    required property int index
                    required property string fingerprint
                    required property string uid
                    required property string expiryText
                    required property string statusText
                    required property string algorithm
                    required property bool secret
                    required property bool bad

                    required property int ownerTrust

                    width: keyList.width
                    highlighted: keyList.currentIndex === index
                    onClicked: keyList.currentIndex = index

                    TapHandler {
                        acceptedButtons: Qt.RightButton
                        onTapped: {
                            keyList.currentIndex = keyDelegate.index
                            trustMenu.fingerprint = keyDelegate.fingerprint
                            trustMenu.uid = keyDelegate.uid
                            trustMenu.ownerTrust = keyDelegate.ownerTrust
                            trustMenu.secret = keyDelegate.secret
                            trustMenu.popup()
                        }
                    }

                    contentItem: RowLayout {
                        spacing: Kirigami.Units.largeSpacing

                        Kirigami.Icon {
                            source: keyDelegate.secret ? "user-identity" : "application-pgp-keys"
                            implicitWidth: Kirigami.Units.iconSizes.medium
                            implicitHeight: Kirigami.Units.iconSizes.medium
                            opacity: keyDelegate.bad ? 0.5 : 1.0
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Kirigami.Units.smallSpacing

                                QQC2.Label {
                                    Layout.fillWidth: true
                                    text: keyDelegate.uid
                                    elide: Text.ElideRight
                                    font.bold: keyDelegate.secret
                                }
                                // "Your key" earns the only badge here: which
                                // keys are the user's own identities is the
                                // question this list is usually open to answer.
                                QQC2.Label {
                                    visible: keyDelegate.secret
                                    text: "your key"
                                    opacity: 0.8
                                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                                }
                            }
                            QQC2.Label {
                                Layout.fillWidth: true
                                text: keyManager.groupFingerprint(keyDelegate.fingerprint)
                                elide: Text.ElideRight
                                opacity: 0.8
                                font.family: "monospace"
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                            }
                            QQC2.Label {
                                Layout.fillWidth: true
                                // Trust, expiry, algorithm — each said once.
                                // The assigned level is not repeated here: it
                                // is already what the trust word is computed
                                // from, and the right-click menu is where it
                                // is set and shown.
                                text: keyDelegate.statusText + " · " + keyDelegate.expiryText
                                      + (keyDelegate.algorithm !== ""
                                         ? " · " + keyDelegate.algorithm : "")
                                elide: Text.ElideRight
                                // Bold and red only for a key that cannot be
                                // used — the same rule the DKIM badge follows,
                                // so red keeps meaning one thing in this app.
                                font.bold: keyDelegate.bad
                                color: keyDelegate.bad
                                       ? Kirigami.Theme.negativeTextColor
                                       : Kirigami.Theme.textColor
                                opacity: keyDelegate.bad ? 1.0 : 0.8
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                            }
                        }

                        QQC2.ToolButton {
                            icon.name: "document-save-as"
                            display: QQC2.AbstractButton.IconOnly
                            text: "Export"
                            onClicked: {
                                exportDialog.fingerprint = keyDelegate.fingerprint
                                exportDialog.open()
                            }
                            QQC2.ToolTip.text: "Save this public key to a file"
                            QQC2.ToolTip.visible: hovered
                        }
                        QQC2.ToolButton {
                            icon.name: "edit-delete"
                            display: QQC2.AbstractButton.IconOnly
                            text: "Delete"
                            // Own keys are not deletable here on purpose: see
                            // PgpEngine::deletePublicKey.
                            enabled: !keyDelegate.secret
                            onClicked: {
                                confirmDeleteDialog.fingerprint = keyDelegate.fingerprint
                                confirmDeleteDialog.uid = keyDelegate.uid
                                confirmDeleteDialog.open()
                            }
                            QQC2.ToolTip.text: keyDelegate.secret
                                ? "Your own keys are deleted with GnuPG or Kleopatra"
                                : "Remove this key from your keyring"
                            QQC2.ToolTip.visible: hovered
                        }
                    }
                }
            }
        }

        RowLayout {
            visible: Pgp.available
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            Spinner {
                running: Pgp.busy
            }
            QQC2.Label {
                Layout.fillWidth: true
                text: keyManager.statusText
                wrapMode: Text.Wrap
                color: keyManager.statusIsError ? Kirigami.Theme.negativeTextColor
                                               : Kirigami.Theme.textColor
                opacity: keyManager.statusIsError ? 1.0 : 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
        }
    }

    // Popups and file dialogs live here rather than in the layout above: they
    // are not laid out, and an Item host keeps them in the window's scene
    // without a Layout claiming to manage them.
    Item {
        id: dialogHost

    /// Key generation, from the "New key…" button above — the same dialog
    /// the account page opens, so a key can be made from either place.
    NewKeyDialog {
        id: generateKeyDialog
    }

    /// Owner trust, on a right-click. This is the one trust input Mailove
    /// offers, and it is a statement about a *person*, not about bytes: gpg
    /// folds it into the validity it computes for this key and for every key
    /// its owner has signed. Everything here is reversible — "Nothing said"
    /// puts a key back exactly where it started.
    QQC2.Menu {
        id: trustMenu

        property string fingerprint: ""
        property string uid: ""
        property int ownerTrust: 0
        property bool secret: false

        function levelText(level) {
            switch (level) {
            case 5: return "Ultimate — this is my own key"
            case 4: return "Full — I have verified this key belongs to its owner"
            case 3: return "Marginal — I partly trust this key"
            case 2: return "Never — I do not trust this key"
            default: return ""
            }
        }

        /// gpg has two ways of saying nothing — Unknown (0) and Undefined (1)
        /// — and they mean the same thing to a reader. Neither is an option in
        /// this menu: "no trust set" is the state of having chosen none of
        /// them, shown by nothing being ticked.
        readonly property bool trustSet: ownerTrust > 1

        QQC2.Label {
            padding: Kirigami.Units.smallSpacing
            text: trustMenu.uid
            elide: Text.ElideRight
            width: Math.min(implicitWidth, Kirigami.Units.gridUnit * 24)
            opacity: 0.8
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.MenuSeparator {}

        Repeater {
            // Descending, so the strongest claim is furthest from the pointer
            // and takes a deliberate movement to reach.
            model: [5, 4, 3, 2]
            delegate: QQC2.MenuItem {
                required property int modelData
                text: trustMenu.levelText(modelData)
                // A tick drawn from the icon, never `checkable` + `checked`:
                // a checkable MenuItem assigns to `checked` when clicked, which
                // overwrites the binding below. This menu is shared by every
                // row, so the next key it opened on inherited the last one's
                // tick — two levels appearing set at once.
                icon.name: trustMenu.ownerTrust === modelData ? "dialog-ok" : ""
                // Ultimate means "gpg should trust everything this key signs",
                // which is only ever true of a key whose private half you hold.
                // Hidden rather than disabled for everyone else's keys: a
                // greyed-out row invites the question of how to enable it, and
                // there is no answer — it is not a choice they have.
                visible: modelData !== 5 || trustMenu.secret
                height: visible ? implicitHeight : 0
                onTriggered: Pgp.setOwnerTrust(trustMenu.fingerprint, modelData)
            }
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: "Remove trust"
            icon.name: "edit-undo"
            // The way back to "nothing said", available whenever there is
            // something to undo.
            enabled: trustMenu.trustSet
            onTriggered: Pgp.setOwnerTrust(trustMenu.fingerprint, 0)
        }
    }

    FileDialog {
        id: importDialog
        title: "Import a key"
        nameFilters: ["Key files (*.asc *.gpg *.pgp *.key)", "All files (*)"]
        onAccepted: Pgp.importKeyFile(selectedFile)
    }

    FileDialog {
        id: exportDialog
        title: "Save public key"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "asc"
        nameFilters: ["Key files (*.asc)", "All files (*)"]
        property string fingerprint: ""
        onAccepted: Pgp.exportPublicKey(fingerprint, selectedFile)
    }

    QQC2.Dialog {
        id: confirmDeleteDialog
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Delete key?"
        property string fingerprint: ""
        property string uid: ""
        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Delete key"
                icon.name: "edit-delete"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: Pgp.deletePublicKey(fingerprint)
        contentItem: QQC2.Label {
            text: "Delete " + confirmDeleteDialog.uid + " from your keyring?\n\n"
                  + "Messages already signed with it can no longer be verified. "
                  + "The key can be imported again if you still have it."
            wrapMode: Text.Wrap
        }
    }
    }
}
