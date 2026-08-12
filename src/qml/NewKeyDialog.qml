// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailove.Core

/// Key generation, shared by the account page and the key manager. gpg-agent
/// asks for the passphrase through pinentry — no passphrase is typed into
/// mailove — so all this collects is what gpg cannot infer: who the key is for
/// and how long it should last.
///
/// The result arrives on Pgp.keyGenerated(), which the two openers report in
/// their own status line; nothing is announced from here.
QQC2.Dialog {
    id: newKeyDialog

    /// Prefill. The account page knows both; the key manager opened from a
    /// message does not, so the fields stay editable either way.
    property alias address: addressField.text
    property alias displayName: nameField.text

    parent: QQC2.Overlay.overlay
    anchors.centerIn: parent
    modal: true
    title: "Generate an OpenPGP key"

    footer: QQC2.DialogButtonBox {
        QQC2.Button {
            text: "Generate"
            icon.name: "list-add"
            enabled: !Pgp.busy && addressField.text.trim() !== ""
            QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
        }
        QQC2.Button {
            text: "Cancel"
            QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
        }
    }

    onAccepted: Pgp.generateKey(nameField.text.trim(), addressField.text.trim(),
                                expiryBox.currentIndex === 0 ? 2
                                : expiryBox.currentIndex === 1 ? 3
                                : expiryBox.currentIndex === 2 ? 5 : 0)

    contentItem: ColumnLayout {
        spacing: Kirigami.Units.smallSpacing

        GridLayout {
            columns: 2
            columnSpacing: Kirigami.Units.largeSpacing
            rowSpacing: Kirigami.Units.smallSpacing

            QQC2.Label { text: "Name:" }
            QQC2.TextField {
                id: nameField
                Layout.fillWidth: true
                Layout.preferredWidth: Kirigami.Units.gridUnit * 18
                placeholderText: "Optional"
            }
            QQC2.Label { text: "E-mail:" }
            QQC2.TextField {
                id: addressField
                Layout.fillWidth: true
                Layout.preferredWidth: Kirigami.Units.gridUnit * 18
            }
            QQC2.Label { text: "Valid for:" }
            QQC2.ComboBox {
                id: expiryBox
                Layout.fillWidth: true
                // An expiry date is a dead man's switch for a key whose owner
                // loses access to it, which is why "never" is last rather than
                // the default.
                model: ["2 years", "3 years", "5 years", "Never expires"]
                currentIndex: 0
            }
        }

        QQC2.Label {
            Layout.maximumWidth: Kirigami.Units.gridUnit * 24
            Layout.fillWidth: true
            text: "GnuPG will ask you for a passphrase to protect the key. "
                  + "Mailove never sees that passphrase, and the key itself "
                  + "stays in GnuPG's own storage."
            wrapMode: Text.Wrap
            opacity: 0.8
        }
    }
}
