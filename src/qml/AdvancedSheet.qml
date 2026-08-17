// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailove.Core

// Settings' Advanced page: the knobs with no widget of their own, edited as
// the INI file they are stored in. The reference beside the editor is
// generated from the same schema the values are read through, so it cannot
// fall behind what the client actually honours.
//
// Its own file, and loaded on demand, so none of it — not the editor, not the
// reference list, not even the cost of compiling this much QML — is paid by
// anyone who never opens the page. AccountSheet is built in one turn on the
// GUI thread, and it is large enough already.
    // The knobs with no widget of their own, edited as the INI file they
    // are stored in. The reference beside the editor is generated from the
    // same schema the values are read through, so it cannot fall behind
    // what the client actually honours.
    ColumnLayout {
        id: advancedPage
        spacing: Kirigami.Units.smallSpacing

        // Everything the editor knows about the text in it. Recomputed on
        // a short delay rather than per keystroke: problems() re-parses the
        // whole file, and typing "20" should not complain about "2" first.
        property var issues: []
        property var restartKeys: []
        // Filled when this page is built — which, since the page is
        // behind a Loader the sidebar activates, is the first time anyone
        // opens Advanced. Refreshed after a save, never per keystroke: it
        // crosses into C++ and rebuilds every row.
        property var reference: []
        // Filtered, then broken into [group] sections — the same sections
        // the file is written in, so what is read here and what is typed
        // there line up. Headers are rows with header: true; a plain JS
        // array model has no roles for ListView.section to work from.
        readonly property var filteredReference: {
            const q = advancedFilter.text.toLowerCase()
            const rows = q === ""
                ? reference
                : reference.filter(r => r.key.toLowerCase().indexOf(q) >= 0
                                     || r.doc.toLowerCase().indexOf(q) >= 0)
            const out = []
            let group = ""
            for (let i = 0; i < rows.length; ++i) {
                if (rows[i].group !== group) {
                    group = rows[i].group
                    // The heading carries the section's own explainer, for the
                    // same reason each key does: "psl" and "dkim" name nothing
                    // to a reader who does not already know what they are.
                    out.push({ "header": true, "group": group,
                               "groupTitle": rows[i].groupTitle,
                               "groupDoc": rows[i].groupDoc })
                }
                out.push(rows[i])
            }
            return out
        }
        property bool dirty: false
        property string saveError: ""
        // Keys applied on this visit whose new value the running client cannot
        // pick up. restartKeys only describes *unsaved* edits, so it empties
        // itself the moment Apply lands — which is exactly when the reader
        // needs telling. Accumulated instead, and only cleared by the restart
        // it asks for.
        property var appliedRestartKeys: []
        readonly property bool fatal: {
            for (let i = 0; i < issues.length; ++i)
                if (issues[i].fatal)
                    return true
            return false
        }

        function recheck() {
            issues = Advanced.problems(advancedEditor.text)
            restartKeys = Advanced.restartKeys(advancedEditor.text)
        }

        // A [group] heading, styled like the section headings on the
        // other Settings pages.
        Component {
            id: advancedGroupHeading
            ColumnLayout {
                id: groupHeading
                // The row this was loaded for. Read through the Loader,
                // which is this item's parent — and guarded, because a
                // binding here can run before the Loader has a parent to
                // offer. Every text below tolerates a null entry for the
                // same reason: an undefined in a string binding is a
                // warning per row, and there are 70 of them.
                readonly property var entry: parent ? parent.entry : null
                width: parent ? parent.width : 0
                spacing: Kirigami.Units.smallSpacing
                Item {
                    implicitHeight: Kirigami.Units.smallSpacing
                }
                Kirigami.Heading {
                    level: 4
                    text: groupHeading.entry ? groupHeading.entry.groupTitle : ""
                }
                QQC2.Label {
                    Layout.fillWidth: true
                    text: groupHeading.entry ? groupHeading.entry.groupDoc : ""
                    wrapMode: Text.Wrap
                    opacity: 0.8
                }
                QQC2.Label {
                    text: groupHeading.entry ? "[" + groupHeading.entry.group + "]" : ""
                    font.family: "monospace"
                    opacity: 0.6
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
                Kirigami.Separator {
                    Layout.fillWidth: true
                }
            }
        }

        // One key: what it does, then what it is called and what it
        // defaults to.
        Component {
            id: advancedKeyRow
            QQC2.ItemDelegate {
                id: keyRow
                readonly property var entry: parent ? parent.entry : null
                width: parent ? parent.width : 0
                enabled: entry !== null
                // Set keys are the answer to "what have I changed?" — the
                // file itself only shows what was typed, not what it
                // overrides.
                highlighted: entry !== null && entry.set === true
                // Adds the key at its default under the section it belongs
                // to, reusing that section if the file already has one.
                onClicked: {
                    if (!entry)
                        return
                    advancedEditor.text = Advanced.withKey(advancedEditor.text, entry.key)
                    advancedPage.recheck()
                }
                contentItem: ColumnLayout {
                    spacing: 0
                    // What the setting does comes first and at full size:
                    // it is the line anyone scanning the list is actually
                    // reading. The key and the default are lookups once
                    // that line has landed.
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: keyRow.entry ? keyRow.entry.doc : ""
                        wrapMode: Text.Wrap
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.smallSpacing
                        QQC2.Label {
                            Layout.fillWidth: true
                            text: keyRow.entry ? keyRow.entry.name : ""
                            font.family: "monospace"
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                            opacity: 0.8
                            elide: Text.ElideRight
                        }
                        QQC2.Label {
                            visible: keyRow.entry !== null && keyRow.entry.set === true
                            text: "set"
                            color: Kirigami.Theme.positiveTextColor
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                        }
                    }
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: !keyRow.entry ? ""
                              : "default " + keyRow.entry.def
                                + (keyRow.entry.range !== ""
                                   ? ", " + keyRow.entry.range : "")
                                + (keyRow.entry.restart ? ", needs restart" : "")
                        opacity: 0.6
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                    }
                }
            }
        }

        Timer {
            id: advancedCheckTimer
            interval: 300
            onTriggered: advancedPage.recheck()
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing
            Kirigami.Heading {
                level: 4
                text: "Advanced settings"
            }
            Item { Layout.fillWidth: true }
            QQC2.Label {
                text: Advanced.filePath
                opacity: 0.7
                elide: Text.ElideMiddle
                Layout.maximumWidth: Kirigami.Units.gridUnit * 20
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Kirigami.Units.largeSpacing

            // The editor.
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: Kirigami.Units.smallSpacing

                QQC2.ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true

                    QQC2.TextArea {
                        id: advancedEditor
                        text: Advanced.text
                        // A config file is read by column as much as by
                        // line: keys line up only in a fixed pitch.
                        font.family: "monospace"
                        wrapMode: TextEdit.NoWrap
                        selectByMouse: true
                        placeholderText: "Empty — every setting is at its default.\n"
                                         + "Use \u201cInsert all defaults\u201d to see them all, "
                                         + "commented out."
                        onTextChanged: {
                            advancedPage.dirty = (text !== Advanced.text)
                            advancedPage.saveError = ""
                            advancedCheckTimer.restart()
                        }
                    }
                }

                // Problems, worst first. Errors block the save; warnings
                // are things the client corrected and carried on with.
                Repeater {
                    model: advancedPage.issues
                    QQC2.Label {
                        required property var modelData
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        color: modelData.fatal ? Kirigami.Theme.negativeTextColor
                                               : Kirigami.Theme.neutralTextColor
                        text: (modelData.line > 0 ? "line " + modelData.line + ": " : "")
                              + modelData.text
                    }
                }
                QQC2.Label {
                    Layout.fillWidth: true
                    visible: advancedPage.saveError !== ""
                    text: advancedPage.saveError
                    color: Kirigami.Theme.negativeTextColor
                    wrapMode: Text.Wrap
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.smallSpacing
                    QQC2.Button {
                        text: "Insert all defaults"
                        icon.name: "edit-table-insert-row-below"
                        // Commented out, so inserting changes nothing by
                        // itself — it is the documentation, in place.
                        onClicked: {
                            advancedEditor.text = Advanced.defaultTemplate()
                                + (advancedEditor.text.length > 0
                                   ? "\n" + advancedEditor.text : "")
                            advancedPage.recheck()
                        }
                    }
                    QQC2.Button {
                        text: "Revert"
                        icon.name: "edit-undo"
                        enabled: advancedPage.dirty
                        onClicked: {
                            advancedEditor.text = Advanced.text
                            advancedPage.recheck()
                        }
                    }
                    Item { Layout.fillWidth: true }
                    // The one that commits, on the side the eye ends on.
                    QQC2.Button {
                        text: "Apply"
                        icon.name: "document-save"
                        enabled: advancedPage.dirty && !advancedPage.fatal
                        highlighted: enabled
                        onClicked: {
                            // Asked before the save, because saving is what
                            // makes the answer empty: afterwards the file and
                            // the values in force agree, restart key or not.
                            const needRestart = advancedPage.restartKeys
                            const error = Advanced.save(advancedEditor.text)
                            advancedPage.saveError = error
                            if (error === "") {
                                const kept = advancedPage.appliedRestartKeys.slice()
                                for (let i = 0; i < needRestart.length; ++i) {
                                    if (kept.indexOf(needRestart[i]) === -1)
                                        kept.push(needRestart[i])
                                }
                                advancedPage.appliedRestartKeys = kept
                                // Back from what was saved, not from what was
                                // typed: a secret typed into the editor is in
                                // the wallet now and the saved text carries
                                // only its placeholder, which is what the
                                // editor has to show.
                                advancedEditor.text = Advanced.text
                                advancedPage.dirty = false
                                advancedPage.recheck()
                            }
                        }
                    }
                }

                // Under the button that caused it. Two states, and the applied
                // one wins: before Apply this is a warning about what the edit
                // will cost, after it a standing reminder that the file and
                // the running client disagree until it is restarted.
                RowLayout {
                    id: restartNotice
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.smallSpacing
                    visible: advancedPage.appliedRestartKeys.length > 0
                             || advancedPage.restartKeys.length > 0

                    // Pushes the notice under Apply, which is the button it
                    // is about — and lets it grow leftwards when the list of
                    // keys is long enough to wrap.
                    Item { Layout.fillWidth: true }

                    Kirigami.Icon {
                        source: advancedPage.appliedRestartKeys.length > 0
                                ? "system-reboot" : "documentinfo"
                        Layout.preferredWidth: Kirigami.Units.iconSizes.small
                        Layout.preferredHeight: Kirigami.Units.iconSizes.small
                        Layout.alignment: Qt.AlignTop
                    }
                    QQC2.Label {
                        Layout.maximumWidth: restartNotice.width
                                             - Kirigami.Units.iconSizes.small
                                             - Kirigami.Units.smallSpacing * 2
                        text: advancedPage.appliedRestartKeys.length > 0
                              ? "Saved. Restart Mailove for these to take effect: "
                                + advancedPage.appliedRestartKeys.join(", ")
                              : "Takes effect only after a restart: "
                                + advancedPage.restartKeys.join(", ")
                        wrapMode: Text.Wrap
                        horizontalAlignment: Text.AlignRight
                        opacity: 0.8
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                    }
                }
            }

            // The reference: every key, its default and what it does.
            ColumnLayout {
                Layout.preferredWidth: Kirigami.Units.gridUnit * 20
                Layout.fillHeight: true
                spacing: Kirigami.Units.smallSpacing

                Kirigami.SearchField {
                    id: advancedFilter
                    Layout.fillWidth: true
                    placeholderText: "Search settings"
                }

                QQC2.ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true

                    ListView {
                        id: advancedReference
                        // The filter narrows the model itself. Hiding
                        // delegates instead leaves their slots (and the
                        // spacing between them) in the list, which pushes
                        // the one match far below the top of an apparently
                        // empty pane.
                        model: advancedPage.filteredReference
                        spacing: Kirigami.Units.smallSpacing
                        // Rows are uniform enough to recycle, and filtering
                        // rebuilds the model on every keystroke.
                        reuseItems: true
                        // Every rebuild starts at the first key, not wherever
                        // the previous list happened to be scrolled to: the
                        // model is replaced wholesale on every keystroke, and
                        // a kept contentY lands somewhere arbitrary in the new
                        // one — which is what made the list look like it was
                        // opening from its middle.
                        onModelChanged: positionViewAtBeginning()
                        // One sub-tree per row, chosen by kind. Building
                        // both and hiding one costs twice the items on
                        // every row, and the hidden half still evaluates
                        // its bindings — a heading has no doc or default,
                        // so those bindings ran on undefined.
                        delegate: Loader {
                            required property var modelData
                            // What the loaded component reads through its
                            // parent; a Component cannot see the id of the
                            // delegate instance that loads it.
                            readonly property var entry: modelData
                            width: advancedReference.width
                            // A guess until the sub-tree is up, not 0: at zero
                            // height the view thinks every row fits and builds
                            // the whole schema at once, then re-lays it out as
                            // the real heights arrive — the list visibly
                            // settling outwards while it does. The guess only
                            // has to be the right order of magnitude.
                            height: item ? item.implicitHeight
                                         : Kirigami.Units.gridUnit * 3
                            sourceComponent: modelData.header === true
                                ? advancedGroupHeading : advancedKeyRow
                        }
                    }
                }
            }
        }

        Component.onCompleted: {
            reference = Advanced.reference()
            recheck()
        }
        Connections {
            target: Advanced
            // A save re-reads the file; the reference's "set" marks and the
            // editor both follow it rather than keeping a stale copy.
            function onReloaded() {
                advancedPage.reference = Advanced.reference()
                advancedPage.recheck()
            }
        }
    } // Advanced page
