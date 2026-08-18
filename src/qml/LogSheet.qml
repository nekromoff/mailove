// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQuick.Window
import org.kde.kirigami as Kirigami
import Mailove.Core

/// What the client has been saying, for someone who never sees a terminal.
///
/// A window rather than a page inside Settings, and for the same reason the
/// key manager is one: a log is read *while* reproducing the problem it is
/// about. Settings is modal to the thing you are trying to make go wrong.
///
/// The model is the last 5000 lines the client logged, filtered by severity;
/// the same lines are in the file named at the bottom, which is what outlives
/// a crash. See diagnosticslog.h for why there is only ever one file and why
/// it never needs clearing out.
Window {
    id: logSheet

    title: "Activity log"
    flags: Qt.Window
    color: content.Kirigami.Theme.backgroundColor

    width: Kirigami.Units.gridUnit * 54
    height: Kirigami.Units.gridUnit * 32
    minimumWidth: Kirigami.Units.gridUnit * 30
    minimumHeight: Kirigami.Units.gridUnit * 16

    /// Opens the log, or brings it forward when it is already up. Named
    /// open() to read like the other sheets at their call sites.
    function open() {
        logSheet.show()
        logSheet.raise()
        logSheet.requestActivate()
        lines.positionViewAtEnd()
    }

    /// The mouse selection, as row indices into what the filter is showing.
    /// Whole lines rather than characters: a log is read by the line, the
    /// interesting part of one is usually its tail (the error, not the
    /// timestamp), and character selection over a list of 5000 rows means
    /// laying every one of them out at once. Drag to extend, shift-click to
    /// extend, Ctrl+A for all, Ctrl+C or Copy to take them. Clicking the one
    /// selected line again, or Esc, lets go.
    property int selectionAnchor: -1
    property int selectionHead: -1
    readonly property int selectionFirst: selectionAnchor < 0
                                          ? -1 : Math.min(selectionAnchor, selectionHead)
    readonly property int selectionLast: selectionAnchor < 0
                                         ? -1 : Math.max(selectionAnchor, selectionHead)
    readonly property int selectionCount: selectionAnchor < 0
                                          ? 0 : selectionLast - selectionFirst + 1

    function clearSelection() {
        selectionAnchor = -1
        selectionHead = -1
    }

    /// Whether new lines scroll into view. Set by where the list is: a reader
    /// who has scrolled up is reading something, and yanking them back to the
    /// end every 200 ms is how a log viewer becomes unusable during a storm.
    /// Auto-tail is off while something is selected: new lines scrolling the
    /// view out from under a selection the reader is about to copy is the
    /// same annoyance as the jump-to-end, one step later.
    readonly property bool following: lines.atYEnd && selectionAnchor < 0

    Shortcut {
        sequences: [StandardKey.Copy]
        onActivated: Diagnostics.copyRange(logSheet.selectionFirst,
                                           logSheet.selectionLast,
                                           Diagnostics.redact)
    }
    Shortcut {
        sequences: [StandardKey.SelectAll]
        onActivated: {
            logSheet.selectionAnchor = 0
            logSheet.selectionHead = lines.count - 1
        }
    }
    Shortcut {
        sequence: "Esc"
        onActivated: logSheet.clearSelection()
    }

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.smallSpacing

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            QQC2.Label { text: "Show:" }
            QQC2.ComboBox {
                id: severityBox
                // Indexes line up with DiagnosticsLog's 0..4 severities, with
                // the two nobody filters on (Info, Fatal) left out of the
                // list rather than given a row that reads the same as its
                // neighbour.
                model: ["Everything", "Activity and problems", "Problems only",
                        "Errors only"]
                property var severities: [0, 1, 2, 3]
                currentIndex: 1
                onActivated: Diagnostics.minimumSeverity = severities[currentIndex]
                Component.onCompleted: Diagnostics.minimumSeverity = severities[currentIndex]
            }

            QQC2.Label {
                text: Diagnostics.totalLines > 0
                      ? lines.count + " of " + Diagnostics.totalLines + " lines"
                      : "Nothing logged yet"
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Item { Layout.fillWidth: true }

            QQC2.CheckBox {
                id: redactBox
                text: "Mask addresses"
                // The model masks what it hands out, so the list below shows
                // exactly what Copy and Save will produce. On by default: the
                // reason anyone opens this window is to send what is in it to
                // someone else.
                checked: Diagnostics.redact
                onToggled: Diagnostics.redact = checked
                QQC2.ToolTip.visible: hovered
                QQC2.ToolTip.delay: Math.round(Kirigami.Units.toolTipDelay / 2)
                QQC2.ToolTip.text: "Anonymize all email addresses and your "
                                   + "home directory path. Double check for "
                                   + "any private leftover data before you "
                                   + "send the logs."
            }
        }

        QQC2.ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            ListView {
                id: lines
                model: Diagnostics
                // Rows are one line each and there are thousands of them.
                reuseItems: true
                // Only when already at the end — see following, above.
                onCountChanged: if (logSheet.following) positionViewAtEnd()
                // A filter change renumbers every row, so a selection made
                // against the old numbering would highlight arbitrary lines.
                onModelChanged: logSheet.clearSelection()

                delegate: Rectangle {
                    id: row
                    required property int index
                    required property string line
                    required property int severity
                    width: lines.width
                    height: rowText.implicitHeight
                    readonly property bool selected:
                        logSheet.selectionAnchor >= 0
                        && index >= logSheet.selectionFirst
                        && index <= logSheet.selectionLast
                    color: selected ? Kirigami.Theme.highlightColor : "transparent"

                    QQC2.Label {
                        id: rowText
                        width: parent.width
                        text: row.line
                        // A log is columns of timestamps: proportional type
                        // turns them into a ragged left edge nothing lines
                        // up in.
                        font.family: "monospace"
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        wrapMode: Text.Wrap
                        color: row.selected ? Kirigami.Theme.highlightedTextColor
                             : row.severity >= 3 ? Kirigami.Theme.negativeTextColor
                             : row.severity === 2 ? Kirigami.Theme.neutralTextColor
                             : Kirigami.Theme.textColor
                        // Debug lines are the bulk when the trace is on, and
                        // they are context for the warnings rather than the
                        // point.
                        opacity: row.severity === 0 && !row.selected ? 0.7 : 1.0
                    }
                }

                // One handler over the whole view rather than one per
                // delegate: a drag that starts on row 4 and ends on row 40
                // never enters most of the rows it covers, because recycled
                // delegates come and go under the cursor.
                MouseArea {
                    anchors.fill: parent
                    acceptedButtons: Qt.LeftButton
                    // Leave the wheel to the view, or the log cannot be
                    // scrolled at all.
                    onPressed: mouse => {
                        const at = lines.indexAt(mouse.x, mouse.y + lines.contentY)
                        if (at < 0) {
                            logSheet.clearSelection()
                            return
                        }
                        if (mouse.modifiers & Qt.ShiftModifier
                                && logSheet.selectionAnchor >= 0) {
                            logSheet.selectionHead = at
                        } else if (logSheet.selectionCount === 1
                                   && at === logSheet.selectionFirst) {
                            // Clicking the one selected line again lets go of
                            // it. Without this a selection could only be
                            // dropped with Esc or by finding empty space below
                            // the last row — and with a full list there is
                            // none, so the Copy button was stuck offering one
                            // line and there was no way back to copying all.
                            logSheet.clearSelection()
                        } else {
                            logSheet.selectionAnchor = at
                            logSheet.selectionHead = at
                        }
                    }
                    onPositionChanged: mouse => {
                        if (!pressed || logSheet.selectionAnchor < 0)
                            return
                        const at = lines.indexAt(mouse.x,
                                                 Math.max(0, mouse.y) + lines.contentY)
                        if (at >= 0)
                            logSheet.selectionHead = at
                    }
                }
            }
        }

        // What the file is, and anything wrong with it. Both are things a bug
        // report needs and neither is worth a line of chrome when it is fine.
        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing
            visible: Diagnostics.lastError !== "" || Diagnostics.droppedLines > 0

            Kirigami.Icon {
                source: "dialog-warning"
                Layout.preferredWidth: Kirigami.Units.iconSizes.small
                Layout.preferredHeight: Kirigami.Units.iconSizes.small
            }
            QQC2.Label {
                Layout.fillWidth: true
                text: Diagnostics.lastError !== ""
                      ? Diagnostics.lastError
                      : Diagnostics.droppedLines + " lines were dropped before "
                        + "they could be written — the file has a gap."
                wrapMode: Text.Wrap
                opacity: 0.8
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            QQC2.Label {
                Layout.fillWidth: true
                text: Diagnostics.filePath
                elide: Text.ElideMiddle
                opacity: 0.6
                font.family: "monospace"
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }
            QQC2.Button {
                text: "Clear"
                icon.name: "edit-clear-history"
                // Emptying both halves is the point: it is what someone does
                // just before reproducing a bug, so the file holds that and
                // nothing else.
                onClicked: Diagnostics.clear()
            }
            QQC2.Button {
                text: "Save as…"
                icon.name: "document-save-as"
                onClicked: saveDialog.open()
            }
            QQC2.Button {
                // Says which it will do, because both are reasonable and the
                // difference is the whole log versus four lines of it.
                text: logSheet.selectionCount > 0
                      ? "Copy " + logSheet.selectionCount + " selected"
                      : "Copy all"
                icon.name: "edit-copy"
                highlighted: true
                onClicked: Diagnostics.copyRange(logSheet.selectionFirst,
                                                 logSheet.selectionLast,
                                                 Diagnostics.redact)
            }
        }

        QQC2.Label {
            id: saveStatus
            property string saveError: ""
            Layout.fillWidth: true
            visible: saveError !== ""
            text: saveError
            wrapMode: Text.Wrap
            color: Kirigami.Theme.negativeTextColor
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
    }

    FileDialog {
        id: saveDialog
        title: "Save the log"
        fileMode: FileDialog.SaveFile
        // No preselected name: FileDialog only accepts one that already
        // exists, and the only such file is the live log itself — which is
        // the one file Save must not offer to overwrite.
        defaultSuffix: "log"
        nameFilters: ["Log files (*.log *.txt)", "All files (*)"]
        onAccepted: saveStatus.saveError = Diagnostics.saveTo(selectedFile,
                                                              Diagnostics.redact)
    }
}
