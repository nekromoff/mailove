// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

import QtCore
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Mailo.Core

Kirigami.ApplicationWindow {
    id: root
    title: "Mailo"
    width: windowSettings.width
    height: windowSettings.height

    // Last window geometry; restored at startup, captured on close.
    // x/y are best effort: Wayland compositors place windows themselves and
    // ignore programmatic positions. -1 = never saved, let the WM place it.
    Settings {
        id: windowSettings
        category: "window"
        property int width: 1200
        property int height: 760
        property int x: -1
        property int y: -1
        property bool maximized: false
    }
    onClosing: close => {
        // VACUUM cannot be interrupted and the destructor has to join its
        // thread — quitting mid-rebuild would look like a hang, so refuse.
        if (Mail.reclaiming) {
            close.accepted = false
            return
        }
        windowSettings.maximized = root.visibility === Window.Maximized
        // Keep the last windowed geometry — maximized dimensions would make
        // un-maximizing on the next run a no-op.
        if (root.visibility === Window.Windowed) {
            windowSettings.width = root.width
            windowSettings.height = root.height
            windowSettings.x = root.x
            windowSettings.y = root.y
        }
        // Closing the mail window means quitting — it is the only window
        // there is now that compose, settings and opened messages are tabs.
        Qt.quit()
    }

    // Same category as the C++ trace, so QT_LOGGING_RULES='mailo.trace.debug=true'
    // (or the Settings toggle) turns both on together.
    LoggingCategory {
        id: traceLog
        name: "mailo.trace"
        defaultLogLevel: LoggingCategory.Fatal
    }

    // Persisted UI state (column order, sorting, collapsed account nodes)
    Settings {
        id: uiSettings
        category: "ui"
        property string columnOrder: "[]"
        property int sortColumn: 0
        property bool sortDescending: true
        property string collapsedAccounts: "[]"
        property int rowDensity: 1     // 0 compact, 1 medium, 2 wide
        property string bgColor: ""    // "" = theme default
        // Compose is the one view offered both ways; everything else is a tab.
        property bool composeInWindow: false
        // Definable shortcuts (Look settings); QKeySequence strings.
        property string shortcutDelete: "Del"
        property string shortcutJunk: "J"
        property string shortcutNotSpam: "Shift+J"
        property string shortcutCompose: "C"
        property string shortcutReply: "R"
        property string shortcutForward: "F"
        property string shortcutSelect: "Ins"
        // Compose-window shortcuts (full QKeySequence strings with modifiers).
        property string shortcutAttach: "Ctrl+Shift+A"
        property string shortcutSend: "Ctrl+Return"
        // Message-viewer shortcuts (reading pane and detached message window).
        property string shortcutFind: "Ctrl+F"
        property string shortcutSource: "Ctrl+U"
        // Color scale 1–5: shortcut + color per slot, both "" = undefined.
        // A slot with a shortcut but no color clears the mark instead.
        // Slot 0 is "no label" — it has no color to define, it only takes the
        // mark off, and it is the one that comes with a key bound out of the box.
        property string scaleKey0: "0"
        property string scaleKey1: ""
        property string scaleKey2: ""
        property string scaleKey3: ""
        property string scaleKey4: ""
        property string scaleKey5: ""
        property string scaleColor1: ""
        property string scaleColor2: ""
        property string scaleColor3: ""
        property string scaleColor4: ""
        property string scaleColor5: ""
    }

    // Active color quick filter (0 = off), mirrored to Mail.filterByColor().
    property int colorFilter: 0
    function scaleColorOf(i) {
        return uiSettings["scaleColor" + i]
    }

    // Mail-list row height from the density setting
    readonly property real listRowHeight:
        Kirigami.Units.gridUnit * [1.15, 1.4, 1.9][uiSettings.rowDensity]
    readonly property color panelColor: uiSettings.bgColor !== ""
        ? uiSettings.bgColor : Kirigami.Theme.backgroundColor

    // True while a text field has focus. Single-letter shortcuts must not fire
    // mid-word in the search box or a rename field — the old list-only wiring
    // got that for free, window-wide Shortcut objects have to ask.
    // Detected by properties only text editors carry: WebEngineView, buttons
    // and list views have none of them, so the reading pane still gets
    // shortcuts.
    readonly property bool textFieldFocused: {
        const item = root.activeFocusItem
        return !!item && item.hasOwnProperty("cursorPosition")
                      && item.hasOwnProperty("selectionStart")
    }
    // Also off while Settings is open: its shortcut-capture buttons read raw
    // key presses, and a window-wide Shortcut would run the very action being
    // rebound.
    /// Set when a click in Drafts starts a fetch, so the message opens in the
    /// composer once it arrives rather than in the reader.
    property bool draftEditPending: false

    // Mail shortcuts belong to the mail tab. On any other tab they are not
    // merely irrelevant — Settings' shortcut-capture buttons read raw key
    // presses, and a window-wide Shortcut would run the very action being
    // rebound.
    readonly property bool shortcutsLive:
        !textFieldFocused && tabStack.currentIndex === 0

    // The message Reply and Forward should act on: the reading pane while the
    // mail tab is up front, otherwise the message the open tab is showing.
    // Without this, opening a message in its own tab silently disabled the very
    // shortcuts that message is for.
    readonly property var activeMessageContext: {
        if (tabStack.currentIndex === 0)
            return Mail.readingContext
        const page = root.tabPages[tabStack.currentIndex]
        return page && page.isMessageTab === true ? page.context : null
    }
    // Reply/Forward/Compose work on a message tab too. Delete, Spam, Select and
    // the colour keys deliberately do not: they act on the list selection,
    // which a message tab has no say over.
    readonly property bool messageShortcutsLive:
        !textFieldFocused && (tabStack.currentIndex === 0
                              || root.activeMessageContext !== null)

    // Window-wide rather than per-view: these used to be handled only by the
    // folder and message lists' Keys.onPressed, so pressing Compose while the
    // reading pane (or anything else) had focus did nothing at all.
    // Ctrl+W closes the current tab, as everywhere else with tabs. Routed
    // through the page so the composer still gets to ask about unsaved work,
    // and a no-op on the mail tab — that one is the window itself.
    Shortcut {
        sequence: "Ctrl+W"
        enabled: tabStack.currentIndex > 0
        onActivated: {
            const page = root.tabPages[tabStack.currentIndex]
            if (page)
                page.close()
        }
    }
    Shortcut {
        sequence: uiSettings.shortcutCompose
        enabled: sequence !== "" && root.messageShortcutsLive && Mail.hasAccount
        onActivated: composeSheet().openNew()
    }
    Shortcut {
        sequence: uiSettings.shortcutReply
        enabled: sequence !== "" && root.messageShortcutsLive
                 && root.activeMessageContext && root.activeMessageContext.hasMessage
        onActivated: composeSheet().openReply(root.activeMessageContext.replyData(false))
    }
    Shortcut {
        sequence: uiSettings.shortcutForward
        enabled: sequence !== "" && root.messageShortcutsLive
                 && root.activeMessageContext && root.activeMessageContext.hasMessage
        onActivated: composeSheet().openForward(root.activeMessageContext.forwardData())
    }
    Shortcut {
        sequence: uiSettings.shortcutDelete
        enabled: sequence !== "" && root.shortcutsLive
        onActivated: messageList.requestDelete()
    }
    Shortcut {
        sequence: uiSettings.shortcutJunk
        enabled: sequence !== "" && root.shortcutsLive
        onActivated: messageList.requestJunk()
    }
    Shortcut {
        sequence: uiSettings.shortcutNotSpam
        enabled: sequence !== "" && root.shortcutsLive
        onActivated: messageList.requestNotSpam()
    }
    Shortcut {
        sequence: uiSettings.shortcutSelect
        enabled: sequence !== "" && root.shortcutsLive
        onActivated: messageList.toggleSelectAndAdvance()
    }
    // Instantiator, not Repeater: Shortcut is not an Item and has nothing to
    // lay out.
    Instantiator {
        // 0 is "no label" — see uiSettings.scaleKey0.
        model: 6
        delegate: Shortcut {
            required property int index
            readonly property int slot: index
            sequence: uiSettings["scaleKey" + slot]
            enabled: sequence !== "" && root.shortcutsLive
            // Slot 0, and any slot left without a color, pass 0 — which clears
            // the mark rather than toggling one on.
            onActivated: Mail.markMessageColor(
                messageList.selectedIndexes(),
                slot > 0 && root.scaleColorOf(slot) !== "" ? slot : 0)
        }
    }

    Component.onCompleted: {
        // Position before maximizing, so un-maximizing lands where it was.
        if (windowSettings.x >= 0) {
            root.x = windowSettings.x
            root.y = windowSettings.y
        }
        if (windowSettings.maximized)
            root.showMaximized()
        // A local archive account counts: it never connects (connectAccount
        // is a no-op for it), but it must not trigger the first-run sheet.
        if (Mail.hasAccount || Mail.accountIsLocal) {
            Mail.connectAccount()
            // Keyboard-ready from the start: the list has focus, and
            // autoSelect() makes the newest message current once it loads.
            messageList.forceActiveFocus()
        } else {
            accountSheet().open()
        }
    }

    Connections {
        target: Mail
        // Errors are folded into the status breadcrumb (Mail.setStatus), not
        // shown as passive popups — the status line already carries them, kept
        // short. No onErrorOccurred handler on purpose.
        // The reading pane itself renders from Mail.readingContext; this
        // handler only routes drafts into the composer.
        function onMessageLoaded(subject, from, to, cc, date, bodyUrl, authInfo) {
            if (root.draftEditPending) {
                root.draftEditPending = false
                composeSheet().openDraft(Mail.draftData())
            }
        }
        // A double-clicked message is ready: show it in its own window.
        function onMessageWindowReady(context) {
            root.openMessageWindow(context)
        }
        // A Thunderbird import ended while the user may have been working
        // elsewhere — the one-line outcome is worth a popup either way.
        function onImportFinished(ok, message) {
            root.showPassiveNotification(message, "long")
        }
        // Once the server refresh lands, (re)load the selected message —
        // the startup auto-select may have fired while still offline.
        function onFolderRefreshed() {
            if (messageList.currentIndex >= 0 && !viewer.hasMessage)
                fetchDebounce.restart()
            else
                messageList.autoSelect()
        }
    }

    // --- Tabs -------------------------------------------------------------
    //
    // Compose, Settings and opened messages used to be top-level windows;
    // they are tab pages now. A page is a plain Item with:
    //
    //   property string title    the tab label, live (a compose page retitles
    //                            itself Reply/Forward/Draft)
    //   signal presentRequested  "bring me to the front"
    //   signal closeRequested    "I agree to being closed" — a page may
    //                            withhold this while it asks the user first,
    //                            which is how the composer's discard prompt
    //                            still gets to veto
    //   function releaseResources()   optional, called before destruction
    //
    // tabPages[i] is the page in tab i, and mirrors tabStack's child order —
    // pages are created into tabStack (appended) and reparented out before
    // destruction, so the two never drift. Index 0 is the mail view and is
    // never closed.
    property var tabPages: []

    /// Registers a freshly created page and switches to it.
    function addTab(page) {
        page.presentRequested.connect(function() { root.showTab(page) })
        page.closeRequested.connect(function() { root.closeTab(page) })
        const list = tabPages.slice()
        list.push(page)
        tabPages = list
        sizeTabs()
        showTab(page)
    }

    /// Sizes every page to the host. StackLayout does this itself for the page
    /// it is showing, but only on its own layout pass — a page created and
    /// switched to in the same turn missed it and laid out at its implicit
    /// size. Driving the geometry from here instead of binding to it in each
    /// page keeps it correct even after StackLayout assigns width/height
    /// directly (which would have overwritten such a binding for good).
    function sizeTabs() {
        for (let i = 0; i < tabPages.length; ++i) {
            tabPages[i].width = tabStack.width
            tabPages[i].height = tabStack.height
        }
    }
    /// The open tab showing message \a key, or null. Tab 0 is the mail view
    /// and has no context, so it never matches.
    function tabForMessage(key) {
        if (!key)
            return null
        for (let i = 1; i < tabPages.length; ++i) {
            const p = tabPages[i]
            if (p.context && p.context.sourceKey === key)
                return p
        }
        return null
    }
    function showTab(page) {
        const i = tabPages.indexOf(page)
        if (i >= 0)
            tabStack.currentIndex = i
    }
    function closeTab(page) {
        const i = tabPages.indexOf(page)
        if (i <= 0) // the mail tab has no close
            return
        const wasCurrent = tabStack.currentIndex === i
        const list = tabPages.slice()
        list.splice(i, 1)
        tabPages = list
        if (wasCurrent) {
            // Fall back to the tab on the left. Landing on whatever slid into
            // the freed index instead means closing a tab drops you onto a tab
            // you were never looking at — and closing the last one would leave
            // currentIndex past the end, showing nothing at all.
            tabStack.currentIndex = i - 1
        } else if (tabStack.currentIndex > i) {
            // A tab closed to the left of the current one shifts it down;
            // without this the view would jump to its neighbour.
            tabStack.currentIndex = tabStack.currentIndex - 1
        }
        // Drop the singleton handles before destroying, or the next open
        // would hand back a dead object.
        if (page === composeWindow)
            composeWindow = null
        if (page === accountDialog)
            accountDialog = null
        if (page.releaseResources)
            page.releaseResources()
        // destroy() is deferred, so unparent first: a page still counted among
        // tabStack's children would put every later tab off by one.
        page.parent = null
        page.destroy()
    }

    // One tab per double-clicked message; each owns its context and releases
    // it on close.
    Component {
        id: messageWindowComponent
        MessageWindow {}
    }
    function openMessageWindow(context) {
        // One tab per message: opening the same mail again raises the tab that
        // already has it rather than stacking a second, identical one. The
        // freshly detached context is then surplus, and holds a scheme-handler
        // slot and a parsed message until it is released.
        const existing = tabForMessage(context.sourceKey)
        if (existing) {
            context.release()
            showTab(existing)
            return
        }
        const w = messageWindowComponent.createObject(tabStack, {
            context: context,
            ui: uiSettings
        })
        w.replyRequested.connect(replyAll =>
            composeSheet().openReply(context.replyData(replyAll)))
        w.forwardRequested.connect(() =>
            composeSheet().openForward(context.forwardData()))
        addTab(w)
    }

    // Both of these are built on first use, not at startup. Between them they
    // were the whole cost of the QML load — AccountSheet instantiates all five
    // settings pages (a StackLayout builds every child regardless of
    // currentIndex) and ComposeSheet a full editor window, for UI the user may
    // never open in a session.
    // A vacuum holds an exclusive lock on the whole cache for minutes, so the
    // mailbox genuinely is unavailable while it runs — every folder switch or
    // fetch would block on the lock. Rather than let the app look hung, say so
    // and take input away. No buttons: it cannot be cancelled or dismissed.
    QQC2.Dialog {
        id: reclaimDialog
        modal: true
        closePolicy: QQC2.Popup.NoAutoClose
        anchors.centerIn: parent
        parent: root.contentItem
        title: "Reclaiming disk space"
        visible: Mail.reclaiming
        ColumnLayout {
            spacing: Kirigami.Units.largeSpacing
            QQC2.Label {
                Layout.maximumWidth: Kirigami.Units.gridUnit * 20
                wrapMode: Text.Wrap
                text: "Rebuilding the mail cache to return free space to the disk.\n\n"
                      + "Your mail is unavailable until this finishes, and it "
                      + "cannot be interrupted. This usually takes a few minutes."
            }
            QQC2.ProgressBar {
                Layout.fillWidth: true
                indeterminate: true
            }
        }
    }

    // Built on first use rather than at startup. Between them these were
    // essentially the whole cost of the QML load: AccountSheet builds all five
    // settings pages (a StackLayout instantiates every child regardless of
    // currentIndex) and ComposeSheet a full editor — for UI that many sessions
    // never open. Both are one-at-a-time, so a handle is kept: reopening while
    // the tab is already up must reuse it, not stack a second one.
    property var accountDialog: null
    Component {
        id: accountComponent
        AccountSheet { ui: uiSettings }
    }
    function accountSheet() {
        if (!accountDialog) {
            accountDialog = accountComponent.createObject(tabStack)
            addTab(accountDialog)
        }
        return accountDialog
    }

    // The composer is either a tab page or a window of its own, per the Look
    // and feel setting. Both expose the same open*()/present()/close() and a
    // title, so nothing downstream of composeSheet() has to know which it got.
    // The choice is read at creation: flipping the setting while a composer is
    // open leaves that one where it is and applies to the next.
    property var composeWindow: null
    Component {
        id: composeComponent
        ComposeSheet { ui: uiSettings }
    }
    Component {
        id: composeWindowComponent
        ComposeWindow { ui: uiSettings }
    }
    function composeSheet() {
        if (!composeWindow) {
            if (uiSettings.composeInWindow) {
                composeWindow = composeWindowComponent.createObject(root)
                composeWindow.finished.connect(function() {
                    root.composeWindow = null
                })
            } else {
                composeWindow = composeComponent.createObject(tabStack)
                addTab(composeWindow)
            }
        }
        return composeWindow
    }

    // Unread-count pill, shared by the live tree and the
    // cached trees. Sits at the right edge of a row;
    // absent entirely at zero, so a quiet folder carries
    // no furniture.
    component UnreadPill: Rectangle {
        /// Unread in the folder itself.
        required property int count
        /// Unread folded away in subfolders this row is standing in for,
        /// because it is collapsed. Drawn as an outline rather than a solid,
        /// so a borrowed number never reads as the folder's own mail.
        property int hiddenCount: 0
        /// The inbox. Its pill is blue wherever it is, selected or not — it is
        /// the folder worth finding at a glance. Every other folder is neutral
        /// grey.
        property bool primary: false
        /// This row is selected, so its background is already the solid
        /// highlight bar. The pill inverts to light on it: blue on blue, or
        /// grey on blue, would be lost.
        property bool onHighlight: false

        readonly property int total: count + hiddenCount
        readonly property bool ownMail: count > 0

        // Grey at 0.65 rather than paler: the solid form carries background-
        // coloured text, and anything lighter drops it below 4.5:1.
        readonly property color accent: onHighlight
                                        ? Kirigami.Theme.highlightedTextColor
                                        : (primary ? Kirigami.Theme.highlightColor
                                                   : Qt.alpha(Kirigami.Theme.textColor, 0.65))

        visible: total > 0
        implicitWidth: Math.max(height,
                                pillText.implicitWidth
                                + Kirigami.Units.smallSpacing * 2)
        implicitHeight: Math.round(Kirigami.Units.gridUnit * 0.95)
        radius: height / 2
        color: ownMail ? accent : "transparent"
        border.width: ownMail ? 0 : 1
        border.color: accent

        QQC2.Label {
            id: pillText
            anchors.centerIn: parent
            // Four digits is where a folder stops being
            // countable and starts being "a lot".
            text: parent.total > 999 ? "999+" : parent.total
            // Solid pill: the text sits on the pill, so it takes that fill's
            // contrasting partner. Outline pill: the text sits on the row, so
            // it takes the row's own foreground — never the accent, since
            // highlight blue as text is ~2.4:1 and fails AA.
            color: parent.ownMail
                   ? (parent.onHighlight
                      ? Kirigami.Theme.highlightColor
                      : (parent.primary ? Kirigami.Theme.highlightedTextColor
                                        : Kirigami.Theme.backgroundColor))
                   : (parent.onHighlight ? Kirigami.Theme.highlightedTextColor
                                         : Kirigami.Theme.textColor)
            font.pointSize: Kirigami.Theme.smallFont.pointSize
            font.bold: true
        }
    }

    // What is currently being dragged, and the pill that follows the cursor.
    // One shared instance — only one drag can be in flight at a time. It lives
    // in the overlay so it draws above both panes and can be positioned in
    // scene coordinates from any delegate, wherever the drag started.
    Item {
        id: dragPayload
        parent: QQC2.Overlay.overlay
        z: 9999
        visible: false
        width: dragPill.width
        height: dragPill.height

        property string kind: ""    // "messages" | "folder" | "account" | ""
        property var rows: []       // message rows, for kind "messages"
        property string mailBox: "" // dragged folder, for kind "folder"
        property int accountIndex: -1 // dragged account, for kind "account"
        property string label: ""

        Drag.active: false
        Drag.source: dragPayload
        // The pill sits just off the cursor (see moveTo), so the drop point
        // is its top-left corner — i.e. the cursor itself.
        Drag.hotSpot: Qt.point(0, 0)

        /// Records what a press would drag, without starting a drag yet.
        function prepare(dragKind, dragRows, box, text) {
            kind = dragKind
            rows = dragRows
            mailBox = box
            label = text
        }
        /// Places the pill at \a scenePos (overlay coordinates).
        function moveTo(scenePos) {
            x = scenePos.x + Kirigami.Units.smallSpacing
            y = scenePos.y + Kirigami.Units.smallSpacing
        }
        function begin() {
            visible = true
            Drag.active = true
        }
        function finish() {
            if (Drag.active)
                Drag.drop()
            Drag.active = false
            visible = false
            kind = ""
            rows = []
            mailBox = ""
            accountIndex = -1
        }

        Rectangle {
            id: dragPill
            width: pillLabel.implicitWidth + Kirigami.Units.largeSpacing * 2
            height: pillLabel.implicitHeight + Kirigami.Units.smallSpacing * 2
            radius: Kirigami.Units.smallSpacing
            color: Kirigami.Theme.highlightColor
            border.width: 1
            border.color: Kirigami.Theme.textColor
            opacity: 0.9

            QQC2.Label {
                id: pillLabel
                anchors.centerIn: parent
                text: dragPayload.label
                color: Kirigami.Theme.highlightedTextColor
            }
        }
    }

    // Right-click menu of a message row. Acts on `rows`, captured when the
    // menu opens, so a selection change behind it cannot redirect the command.
    QQC2.Menu {
        id: messageMenu
        property var rows: []
        // Not "count": QQC2.Menu already has a FINAL property of that name
        // (its item count), and shadowing it fails the whole component load.
        readonly property int rowCount: rows ? rows.length : 0

        QQC2.MenuItem {
            text: "Mark unread"
            icon.name: "mail-mark-unread"
            onTriggered: Mail.markMessagesUnread(messageMenu.rows)
        }
        QQC2.MenuSeparator {}
        // These go through the list's own handlers rather than calling Mail
        // directly, so the menu and the keyboard shortcuts cannot drift apart —
        // and so Delete still asks first when the folder is the trash.
        QQC2.MenuItem {
            text: "Mark as spam"
            icon.name: "mail-mark-junk"
            onTriggered: messageList.requestJunk()
        }
        QQC2.MenuItem {
            text: "Not spam"
            icon.name: "mail-mark-notjunk"
            onTriggered: messageList.requestNotSpam()
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: messageMenu.rowCount > 1
                  ? "Delete " + messageMenu.rowCount + " messages" : "Delete"
            icon.name: "edit-delete"
            onTriggered: messageList.requestDelete()
        }
    }

    // Right-click menu of a folder in the sidebar.
    QQC2.Menu {
        id: folderMenu
        property string mailBox: ""
        property string name: ""
        // Recomputed rather than bound: folderRenameBlockedReason() is a plain
        // invokable with no change signal, so a live binding would keep
        // whatever it first saw.
        property string renameBlocked: ""
        // Same reason: folderHasUnread() is a plain invokable, and the count it
        // answers from is refreshed by a background recount.
        property bool hasUnread: false
        function refreshRenameBlocked() {
            renameBlocked = Mail.folderRenameBlockedReason(mailBox)
            hasUnread = Mail.folderHasUnread(mailBox)
        }
        onAboutToShow: refreshRenameBlocked()

        // Right-clicking a folder in another account switches to it, and the
        // menu opens before that connection is up — so the first answer is
        // "needs a connection". Waiting for the connection before showing the
        // menu would make every right-click feel slow; instead the menu opens
        // at once and this swaps the note for the real command the moment the
        // account is ready, while it is still on screen.
        Connections {
            target: Mail
            enabled: folderMenu.opened
            function onConnectedChanged() { folderMenu.refreshRenameBlocked() }
        }

        // First, and the only entry that acts on the mail rather than on the
        // folder itself — it is what a right-click on a folder with a pill is
        // usually after. Recomputed on open for the same reason renameBlocked
        // is: folderHasUnread() has no change signal of its own.
        QQC2.MenuItem {
            text: "Mark all read"
            icon.name: "mail-mark-read"
            enabled: folderMenu.hasUnread
            onTriggered: Mail.markFolderRead(folderMenu.mailBox)
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            visible: folderMenu.renameBlocked === ""
            height: visible ? implicitHeight : 0
            text: "Rename folder…"
            icon.name: "edit-rename"
            onTriggered: {
                renameFolderDialog.mailBox = folderMenu.mailBox
                renameFolderDialog.open()
            }
        }
        // The protocol reason this folder keeps its name, in place of the
        // command — an entry that is merely greyed out says "not now", and
        // this is a "not ever".
        QQC2.MenuItem {
            visible: folderMenu.renameBlocked !== ""
            height: visible ? implicitHeight : 0
            enabled: false
            icon.name: "documentinfo"
            text: folderMenu.renameBlocked
        }
        QQC2.MenuSeparator {}
        QQC2.MenuItem {
            text: "Move to top level"
            icon.name: "go-up"
            enabled: Mail.canMoveFolder(folderMenu.mailBox, "")
            onTriggered: Mail.moveFolder(folderMenu.mailBox, "")
        }
        QQC2.MenuItem {
            text: Mail.folderDeleteIsPermanent(folderMenu.mailBox)
                  ? "Delete folder…" : "Move folder to trash…"
            icon.name: "edit-delete"
            enabled: !Mail.folderProtected(folderMenu.mailBox)
            onTriggered: {
                confirmFolderDelete.mailBox = folderMenu.mailBox
                confirmFolderDelete.name = folderMenu.name
                confirmFolderDelete.permanent =
                    Mail.folderDeleteIsPermanent(folderMenu.mailBox)
                confirmFolderDelete.open()
            }
        }
    }

    QQC2.Dialog {
        id: renameFolderDialog
        property string mailBox: ""

        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Rename folder"

        // Prefilled with the name the sidebar shows, which for a folder inside
        // a parent is its last step only — the rest of the path is not the
        // user's to retype, and changing it here would be a move, not a rename.
        onOpened: {
            renameFolderField.text = Mail.folderDisplayLeaf(mailBox)
            renameFolderField.selectAll()
            renameFolderField.forceActiveFocus()
        }

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Rename"
                icon.name: "edit-rename"
                enabled: renameFolderField.text.trim() !== ""
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: Mail.renameFolder(renameFolderDialog.mailBox,
                                      renameFolderField.text)

        contentItem: QQC2.TextField {
            id: renameFolderField
            implicitWidth: Kirigami.Units.gridUnit * 20
            onAccepted: renameFolderDialog.accept()
        }
    }

    QQC2.Dialog {
        id: confirmFolderDelete
        property string mailBox: ""
        property string name: ""
        property bool permanent: false

        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: permanent ? "Delete folder permanently?" : "Move folder to trash?"

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: confirmFolderDelete.permanent ? "Delete permanently" : "Move to trash"
                icon.name: "edit-delete"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: Mail.deleteFolder(confirmFolderDelete.mailBox)

        // Wrapped in an Item because Text sizes itself to its content: a
        // paragraph of explanation would otherwise make the dialog as wide as
        // the sentence. The Item is what carries the width cap.
        contentItem: Item {
            implicitWidth: Kirigami.Units.gridUnit * 22
            implicitHeight: folderDeleteText.implicitHeight

            QQC2.Label {
                id: folderDeleteText
                anchors.fill: parent
                text: confirmFolderDelete.permanent
                      ? "“" + confirmFolderDelete.name + "” and everything in it "
                        + "(including any subfolders) are removed from the server "
                        + "permanently — this cannot be undone."
                      : "“" + confirmFolderDelete.name + "” and its subfolders "
                        + "are moved into the trash, with all the messages they hold. "
                        + "Deleting it again from there removes it for good."
                wrapMode: Text.Wrap
            }
        }
    }

    QQC2.Dialog {
        id: confirmPermanentDelete
        property var rows: []
        parent: QQC2.Overlay.overlay
        anchors.centerIn: parent
        modal: true
        title: "Delete permanently?"

        footer: QQC2.DialogButtonBox {
            QQC2.Button {
                text: "Delete permanently"
                icon.name: "edit-delete"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.AcceptRole
            }
            QQC2.Button {
                text: "Cancel"
                QQC2.DialogButtonBox.buttonRole: QQC2.DialogButtonBox.RejectRole
            }
        }
        onAccepted: {
            Mail.deleteMessages(rows)
            messageList.clearSelection()
        }

        contentItem: QQC2.Label {
            text: confirmPermanentDelete.rows.length === 1
                  ? "This message is in the trash. Deleting it here removes it "
                    + "from the server permanently — this cannot be undone."
                  : confirmPermanentDelete.rows.length + " messages are in the trash. "
                    + "Deleting them here removes them from the server permanently "
                    + "— this cannot be undone."
            wrapMode: Text.Wrap
        }
    }

    pageStack.initialPage: Kirigami.Page {
        padding: 0
        background: Rectangle {
            color: root.panelColor
        }
        titleDelegate: RowLayout {
            Layout.fillWidth: true
            Kirigami.Heading {
                text: "Mailo"
                level: 2
            }
            // Version straight from QCoreApplication (main.cpp sets it from
            // MAILO_VERSION), so it can never drift from the built binary.
            QQC2.Label {
                text: "v" + Qt.application.version
                opacity: 0.7
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                Layout.alignment: Qt.AlignBaseline
            }
            // Plain arc spinner — the desktop-style BusyIndicator draws a
            // cogwheel, which reads as "settings" rather than "loading".
            Item {
                id: busySpinner
                visible: Mail.busy
                implicitWidth: Kirigami.Units.iconSizes.smallMedium
                implicitHeight: Kirigami.Units.iconSizes.smallMedium

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
                        running: busySpinner.visible
                        from: 0
                        to: 360
                        duration: 900
                        loops: Animation.Infinite
                    }
                }
            }
            QQC2.Label {
                id: statusLabel
                Layout.fillWidth: true
                // With no account there is no activity to report, so the
                // status line would otherwise sit empty on every run until
                // one is set up. Bold because it is the only prompt on screen.
                text: Mail.hasAccount || Mail.accountIsLocal
                    ? Mail.statusText
                    // Named after the button's own tooltip rather than
                    // described by shape — the icon is theme-supplied and is
                    // not a gear.
                    : "Welcome to Mailo! Add an account to get started — Settings, top right."
                font.bold: !Mail.hasAccount && !Mail.accountIsLocal
                elide: Text.ElideRight
                opacity: 0.8
                // The label elides, so the older crumbs may be off-screen —
                // right-click copies the full breadcrumb trail, and hovering
                // shows it in a tooltip.
                QQC2.ToolTip.text: Mail.statusText
                QQC2.ToolTip.visible: statusHover.hovered && Mail.statusText.length > 0
                HoverHandler { id: statusHover }
                TapHandler {
                    acceptedButtons: Qt.RightButton
                    onTapped: {
                        if (Mail.statusText.length === 0)
                            return
                        Mail.copyToClipboard(Mail.statusText)
                        root.showPassiveNotification("Status copied", "short")
                    }
                }
            }
            QQC2.ToolButton {
                icon.name: "mail-message-new"
                enabled: Mail.hasAccount
                onClicked: composeSheet().openNew()
                QQC2.ToolTip.text: "Compose"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                icon.name: "view-refresh"
                enabled: Mail.hasAccount && !Mail.busy
                onClicked: Mail.connectAccount()
                QQC2.ToolTip.text: "Reconnect and refresh"
                QQC2.ToolTip.visible: hovered
            }
            QQC2.ToolButton {
                icon.name: "settings-configure"
                onClicked: accountSheet().open()
                QQC2.ToolTip.text: "Settings"
                QQC2.ToolTip.visible: hovered
            }
        }

        // Everything below the top row lives in a tab: the mail view is tab 0
        // and is always there, and Compose, Settings and opened messages join
        // it as they are created. With nothing else open there is only the
        // mail tab, and the strip stays out of the way.
        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            QQC2.TabBar {
                id: tabBar
                Layout.fillWidth: true
                visible: root.tabPages.length > 1
                // A hidden TabBar still reports its implicit height to the
                // layout, which would leave a strip-sized gap above the mail
                // view when there is nothing to show.
                Layout.preferredHeight: visible ? implicitHeight : 0

                // TabBar sets its own currentIndex when a tab is clicked, so
                // the two indices are mirrored rather than bound — a binding
                // here would be overwritten by the first click. Assigning an
                // unchanged int emits nothing, so this settles immediately.
                onCurrentIndexChanged: tabStack.currentIndex = currentIndex
                Connections {
                    target: tabStack
                    function onCurrentIndexChanged() {
                        tabBar.currentIndex = tabStack.currentIndex
                    }
                }

                Repeater {
                    model: root.tabPages
                    delegate: QQC2.TabButton {
                        id: tabButton
                        required property var modelData
                        required property int index

                        // The mail tab is the app itself — it has no close.
                        readonly property bool closable: index > 0

                        // Breathing room at the ends: the label ran straight
                        // into the tab edge (and into the close button)
                        // without it.
                        leftPadding: Kirigami.Units.largeSpacing
                        rightPadding: Kirigami.Units.largeSpacing

                        // Every tab is always on screen: the strip never
                        // scrolls, it divides itself up. Tabs take an even
                        // share of the bar, capped so that two open tabs are
                        // not two half-screen slabs, and with no floor — a
                        // floor is what forces scrolling, and a title that has
                        // elided away is still easier to reach than one that
                        // has scrolled off. Floored to whole pixels: a
                        // fraction over, repeated per tab, is enough to push
                        // the last one out and start the strip scrolling.
                        implicitWidth: Math.floor(
                            Math.min(Kirigami.Units.gridUnit * 14,
                                     tabBar.availableWidth
                                         / Math.max(1, root.tabPages.length)))

                        onClicked: tabStack.currentIndex = tabButton.index
                        // Middle-click closes, as everywhere else with tabs.
                        TapHandler {
                            acceptedButtons: Qt.MiddleButton
                            onTapped: {
                                if (tabButton.closable)
                                    tabButton.modelData.close()
                            }
                        }

                        contentItem: RowLayout {
                            spacing: Kirigami.Units.smallSpacing
                            QQC2.Label {
                                Layout.fillWidth: true
                                // Live: a compose tab retitles itself Reply or
                                // Draft, a message tab carries its subject.
                                text: tabButton.modelData.title
                                elide: Text.ElideRight
                                horizontalAlignment: Text.AlignHCenter
                                color: Kirigami.Theme.textColor
                            }
                            QQC2.ToolButton {
                                visible: tabButton.closable
                                icon.name: "window-close"
                                // Routed through the page, not straight to
                                // closeTab: the composer answers a close by
                                // asking about unsaved work first.
                                onClicked: tabButton.modelData.close()
                                implicitWidth: Kirigami.Units.iconSizes.small
                                              + Kirigami.Units.smallSpacing
                                implicitHeight: implicitWidth
                                icon.width: Kirigami.Units.iconSizes.small
                                icon.height: Kirigami.Units.iconSizes.small
                            }
                        }
                    }
                }
            }

            StackLayout {
                id: tabStack
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: 0

                onWidthChanged: root.sizeTabs()
                onHeightChanged: root.sizeTabs()

                // Tab 0: the mail view. Registered in tabPages at startup so
                // page indices and tab indices line up from the first tab on.
                Item {
                    id: mailTab
                    property string title: "Mail"
                    Component.onCompleted: root.tabPages = [mailTab]

                    QQC2.SplitView {
                        anchors.fill: parent
                        orientation: Qt.Horizontal

                        // Folder pane — one scrolling column. Every account can be open
                        // at the same time; the next account continues right after the
                        // previous account's folders (nothing is pinned to the bottom).
                        // Only the connected account's list is live; the others show
                        // their cached folder tree, and clicking a folder there switches
                        // the connection over and opens it.
                        ColumnLayout {
                            id: folderPane
                            QQC2.SplitView.preferredWidth: 220
                            QQC2.SplitView.minimumWidth: 140
                            spacing: 0

                            property Item folderListView: null

                            // Special-role folder icons, matched on the folder's own name
                            // (Trash, INBOX/Spam, Junk E-mail, Deleted Items, …).
                            function folderIcon(mailBox) {
                                if (mailBox.toUpperCase() === "INBOX")
                                    return "mail-folder-inbox"
                                const leaf = mailBox.split(/[/.]/).pop().toLowerCase()
                                if (leaf.includes("trash") || leaf.includes("deleted"))
                                    return "user-trash"
                                if (leaf.includes("spam") || leaf.includes("junk"))
                                    return "mail-mark-junk"
                                if (leaf.includes("sent"))
                                    return "mail-folder-sent"
                                if (leaf.includes("outbox"))
                                    return "mail-folder-outbox"
                                if (leaf.includes("draft"))
                                    return "document-edit"
                                return "folder-mail"
                            }

                            // The inbox, however the account spells it: a bare
                            // INBOX, or the last step of an archive path
                            // ("mail.example.com/Inbox").
                            function isInbox(mailBox) {
                                if (mailBox.toUpperCase() === "INBOX")
                                    return true
                                return mailBox.split(/[/.]/).pop().toLowerCase() === "inbox"
                            }

                            function isCollapsed(name) {
                                return JSON.parse(uiSettings.collapsedAccounts).indexOf(name) >= 0
                            }
                            function setCollapsed(name, collapsed) {
                                const a = JSON.parse(uiSettings.collapsedAccounts)
                                const i = a.indexOf(name)
                                if (collapsed && i < 0)
                                    a.push(name)
                                else if (!collapsed && i >= 0)
                                    a.splice(i, 1)
                                uiSettings.collapsedAccounts = JSON.stringify(a)
                            }

                            QQC2.Label {
                                visible: Mail.accountNames.length === 0
                                Layout.fillWidth: true
                                Layout.margins: Kirigami.Units.smallSpacing
                                Layout.leftMargin: Kirigami.Units.largeSpacing
                                text: "No account"
                                font.bold: true
                                elide: Text.ElideRight
                            }

                            QQC2.ScrollView {
                                id: folderScroll
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                contentWidth: availableWidth
                                clip: true

                                ColumnLayout {
                                    width: folderScroll.availableWidth
                                    spacing: 0

                                    Repeater {
                                        model: Mail.accountNames

                                        delegate: ColumnLayout {
                                            id: accountSection
                                            required property string modelData
                                            required property int index

                                            readonly property bool isCurrent: index === Mail.currentAccount
                                            readonly property bool open: !folderPane.isCollapsed(modelData)

                                            Layout.fillWidth: true
                                            spacing: 0

                                            // Divides this account from the previous one's
                                            // folder list — above the name, not under it.
                                            Kirigami.Separator {
                                                visible: accountSection.index > 0
                                                Layout.fillWidth: true
                                            }
                                            QQC2.ItemDelegate {
                                                Layout.fillWidth: true
                                                implicitHeight: root.listRowHeight + 2
                                                topPadding: 1
                                                bottomPadding: 1
                                                contentItem: RowLayout {
                                                    spacing: Kirigami.Units.smallSpacing
                                                    Kirigami.Icon {
                                                        source: accountSection.open ? "arrow-down" : "arrow-right"
                                                        Layout.preferredWidth: Kirigami.Units.iconSizes.small
                                                        Layout.preferredHeight: Kirigami.Units.iconSizes.small
                                                        opacity: 0.6
                                                    }
                                                    // Highlight-blue dot marks the active
                                                    // account. The cue is carried by this
                                                    // graphical accent (3:1 bar), not by
                                                    // the text color — the theme highlight
                                                    // blue as text is only ~2.4:1 and fails
                                                    // AA, so the name keeps full-contrast
                                                    // textColor (bold does the rest).
                                                    Rectangle {
                                                        visible: accountSection.isCurrent
                                                        Layout.preferredWidth: Kirigami.Units.smallSpacing * 1.5
                                                        Layout.preferredHeight: Layout.preferredWidth
                                                        radius: width / 2
                                                        color: Kirigami.Theme.highlightColor
                                                    }
                                                    QQC2.Label {
                                                        Layout.fillWidth: true
                                                        text: accountSection.modelData
                                                        font.bold: true
                                                            color: Kirigami.Theme.textColor
                                                        elide: Text.ElideRight
                                                    }
                                                }
                                                // Dragging an account name reorders the
                                                // pane. A long threshold because the same
                                                // press collapses the account — reordering
                                                // should take deliberate movement, not a
                                                // twitch during a click.
                                                MouseArea {
                                                    id: accountMouse
                                                    anchors.fill: parent
                                                    drag.threshold: Kirigami.Units.gridUnit
                                                    // A lone account has nowhere to go.
                                                    drag.target: Mail.accountNames.length > 1
                                                                 ? dragPayload : null

                                                    onPressed: mouse => {
                                                        dragPayload.prepare("account", [], "",
                                                                            accountSection.modelData)
                                                        dragPayload.accountIndex = accountSection.index
                                                        dragPayload.moveTo(accountSection.mapToItem(
                                                            QQC2.Overlay.overlay, mouse.x, mouse.y))
                                                    }
                                                    drag.onActiveChanged: {
                                                        if (accountMouse.drag.active)
                                                            dragPayload.begin()
                                                        else
                                                            dragPayload.finish()
                                                    }
                                                    // Only a press that stayed put reaches
                                                    // here — a completed drag does not — so
                                                    // collapsing on click is safe.
                                                    onClicked: folderPane.setCollapsed(
                                                        accountSection.modelData, accountSection.open)
                                                }

                                                // Two kinds of drop land on an account
                                                // name: a folder being moved out to the top
                                                // level (the one reparenting target that is
                                                // not a row in the tree), and another
                                                // account being dropped into this slot.
                                                DropArea {
                                                    id: accountDrop
                                                    anchors.fill: parent

                                                    readonly property bool acceptsFolder:
                                                        accountSection.isCurrent
                                                        && dragPayload.kind === "folder"
                                                        && Mail.canMoveFolder(dragPayload.mailBox, "")
                                                    readonly property bool acceptsAccount:
                                                        dragPayload.kind === "account"
                                                        && dragPayload.accountIndex >= 0
                                                        && dragPayload.accountIndex !== accountSection.index
                                                    readonly property bool acceptable:
                                                        acceptsFolder || acceptsAccount

                                                    onEntered: drag => drag.accepted = acceptable
                                                    onDropped: drop => {
                                                        if (!acceptable) {
                                                            drop.accepted = false
                                                            return
                                                        }
                                                        if (acceptsAccount)
                                                            Mail.moveAccount(dragPayload.accountIndex,
                                                                             accountSection.index)
                                                        else
                                                            Mail.moveFolder(dragPayload.mailBox, "")
                                                    }
                                                }
                                                Rectangle {
                                                    anchors.fill: parent
                                                    visible: accountDrop.containsDrag
                                                             && accountDrop.acceptsFolder
                                                    color: Qt.alpha(Kirigami.Theme.highlightColor, 0.25)
                                                    border.width: 2
                                                    border.color: Kirigami.Theme.highlightColor
                                                    radius: Kirigami.Units.smallSpacing
                                                }
                                                // A reorder lands *between* accounts, so it
                                                // gets an insertion line rather than the
                                                // filled box a reparenting drop uses —
                                                // above this row or below it, depending on
                                                // which way the account is travelling.
                                                Rectangle {
                                                    visible: accountDrop.containsDrag
                                                             && accountDrop.acceptsAccount
                                                    anchors.left: parent.left
                                                    anchors.right: parent.right
                                                    anchors.top: dragPayload.accountIndex
                                                                 > accountSection.index
                                                                 ? parent.top : undefined
                                                    anchors.bottom: dragPayload.accountIndex
                                                                    > accountSection.index
                                                                    ? undefined : parent.bottom
                                                    height: 2
                                                    color: Kirigami.Theme.highlightColor
                                                }
                                            }

                                            // Live folder list of the connected account
                                            ListView {
                                                id: folderList
                                                visible: accountSection.open && accountSection.isCurrent
                                                Layout.fillWidth: true
                                                Layout.preferredHeight: visible ? contentHeight : 0
                                                interactive: false
                                                model: accountSection.isCurrent ? Mail.folderModel : null
                                                keyNavigationEnabled: true
                                                activeFocusOnTab: accountSection.isCurrent
                                                Keys.onPressed: event => {
                                                    // Arrow keys are the one case where
                                                    // moving the selection should open the
                                                    // folder. Arming the debounce from the
                                                    // key press (rather than from
                                                    // currentIndex changing) means only a
                                                    // real keystroke can ever open one.
                                                    if (event.key === Qt.Key_Up || event.key === Qt.Key_Down
                                                            || event.key === Qt.Key_PageUp
                                                            || event.key === Qt.Key_PageDown
                                                            || event.key === Qt.Key_Home
                                                            || event.key === Qt.Key_End)
                                                        folderOpenDebounce.restart()
                                                    // Mail shortcuts are window-wide
                                                    // Shortcut objects now; handling them
                                                    // here too would fire them twice.
                                                }

                                                property bool live: accountSection.isCurrent
                                                onLiveChanged: {
                                                    if (live)
                                                        folderPane.folderListView = folderList
                                                }
                                                Component.onCompleted: {
                                                    if (live)
                                                        folderPane.folderListView = folderList
                                                }

                                                // True while currentIndex is being moved to
                                                // match the folder that is already open, so
                                                // the debounce below does not treat that as
                                                // the user asking to open something.
                                                property bool syncingIndex: false

                                                // The model is rebuilt on every account
                                                // switch and folder refresh, which snaps
                                                // currentIndex back to row 0. Left alone
                                                // that fired openCurrent() for INBOX and
                                                // overrode the folder the user had just
                                                // clicked — including the one an account
                                                // switch was still in the middle of opening.
                                                function syncToOpenFolder() {
                                                    if (!live)
                                                        return
                                                    const open = Mail.selectedFolder
                                                    // count === 0 means the model is mid-
                                                    // rebuild; setting an index now would
                                                    // just be undone by the repopulation.
                                                    if (!open || count === 0)
                                                        return
                                                    // Ask the model, not the view: a folder
                                                    // scrolled out of sight has no delegate,
                                                    // so itemAtIndex() returns null for it
                                                    // and the row would never be found.
                                                    const row = Mail.folderModel.rowForMailBox(open)
                                                    if (row < 0 || row === currentIndex)
                                                        return
                                                    syncingIndex = true
                                                    currentIndex = row
                                                    syncingIndex = false
                                                }
                                                Connections {
                                                    target: Mail
                                                    function onSelectedFolderChanged() {
                                                        folderList.syncToOpenFolder()
                                                    }
                                                }
                                                onCountChanged: {
                                                    console.debug(traceLog, "[qml] count -> " + count
                                                                  + " idx=" + currentIndex
                                                                  + " open=" + Mail.selectedFolder)
                                                    // A repopulated model is never the user
                                                    // asking for a folder — cancel any
                                                    // auto-open the reset index just armed.
                                                    folderOpenDebounce.stop()
                                                    rebuildSettle.restart()
                                                    syncToOpenFolder()
                                                }

                                                /// \a takeFocus moves the keyboard to the
                                                /// message list, so it can be navigated
                                                /// straight away. Deliberately not the
                                                /// default: the arrow-key debounce also
                                                /// calls this, and pulling focus out of
                                                /// the folder tree mid-walk would end the
                                                /// walk after one row.
                                                function openCurrent(takeFocus) {
                                                    // Model-backed, for the same reason as
                                                    // syncToOpenFolder above.
                                                    const mailBox = Mail.folderModel.mailBoxAt(currentIndex)
                                                    console.debug(traceLog, "[qml] openCurrent idx="
                                                                  + currentIndex + " mailBox=" + mailBox
                                                                  + " open=" + Mail.selectedFolder)
                                                    if (mailBox && mailBox !== Mail.selectedFolder
                                                            && Mail.folderModel.selectableAt(currentIndex)) {
                                                        messageList.currentIndex = -1
                                                        messageList.openedUid = -1
                                                        messageList.clearSelection()
                                                        Mail.openFolder(mailBox)
                                                        if (takeFocus)
                                                            messageList.forceActiveFocus()
                                                    }
                                                }
                                                Keys.onReturnPressed: openCurrent(true)
                                                Keys.onEnterPressed: openCurrent(true)
                                                Keys.onRightPressed: messageList.forceActiveFocus()

                                                // Key navigation opens the highlighted
                                                // folder by itself — debounced so holding
                                                // an arrow key doesn't open every folder
                                                // it passes over.
                                                Timer {
                                                    id: folderOpenDebounce
                                                    interval: 300
                                                    onTriggered: folderList.openCurrent()
                                                }
                                                // Deliberately NOT hooked to open a folder.
                                                // currentIndex moves for reasons that are
                                                // not the user: a model reset snaps it to
                                                // 0 or -1, and ListView also re-adjusts it
                                                // asynchronously while laying out, i.e.
                                                // after any "I am syncing" flag has been
                                                // cleared. Auto-opening from here made the
                                                // selection walk the list opening folders
                                                // as it went. Only real input opens now:
                                                // a click on the delegate, Return/Enter, or
                                                // arrow-key navigation (armed in
                                                // Keys.onPressed below).
                                                onCurrentIndexChanged: {
                                                    console.debug(traceLog, "[qml] currentIndex -> "
                                                                  + currentIndex + " syncing=" + syncingIndex
                                                                  + " open=" + Mail.selectedFolder
                                                                  + " count=" + count)
                                                    // While a rebuild settles, ListView
                                                    // snaps the cursor to row 0 (INBOX) and
                                                    // to -1 before landing. Nothing opens
                                                    // from here any more, so putting it
                                                    // straight back is safe — and stops
                                                    // INBOX drawing as the current item for
                                                    // a frame. Outside that window the
                                                    // cursor is the user's to move.
                                                    if (!syncingIndex && rebuildSettle.running)
                                                        syncToOpenFolder()
                                                }

                                                // Runs for a moment after any model change;
                                                // see onCurrentIndexChanged above.
                                                Timer {
                                                    id: rebuildSettle
                                                    interval: 600
                                                }

                                                delegate: QQC2.ItemDelegate {
                                                    id: folderDelegate
                                                    required property string name
                                                    required property string mailBox
                                                    required property int level
                                                    required property bool selectable
                                                    required property bool hasChildren
                                                    required property bool expanded
                                                    required property int unread
                                                    required property int hiddenUnread
                                                    required property int index

                                                    width: folderList.width
                                                    implicitHeight: root.listRowHeight + 2
                                                    topPadding: 1
                                                    bottomPadding: 1
                                                    enabled: selectable || hasChildren

                                                    // The style's own selection bar stops short
                                                    // of the row's right edge, which left the
                                                    // pill sitting outside it. This spans the
                                                    // whole delegate, so the pill is on the bar
                                                    // rather than past it — the same explicit
                                                    // background the message rows already use.
                                                    background: Rectangle {
                                                        color: folderDelegate.highlighted
                                                               ? Kirigami.Theme.highlightColor
                                                               : folderDelegate.hovered
                                                                 ? Qt.alpha(Kirigami.Theme.highlightColor, 0.2)
                                                                 : "transparent"
                                                    }
                                                    // One gridUnit deeper than the account
                                                    // header: the account is the parent,
                                                    // its folders nest visibly under it.
                                                    leftPadding: Kirigami.Units.largeSpacing + Kirigami.Units.gridUnit * 1.5
                                                                 + level * Kirigami.Units.gridUnit
                                                    rightPadding: Kirigami.Units.smallSpacing

                                                    // Icon, name and pill as the row's own content, not an
                                                    // overlay anchored over it. Anchoring the pill to the
                                                    // delegate's right edge kept dropping it outside the
                                                    // selection bar; laid out here it is inside the row by
                                                    // construction, and the name elides against it instead of
                                                    // needing its width reserved by hand.
                                                    contentItem: RowLayout {
                                                        spacing: Kirigami.Units.smallSpacing

                                                        Kirigami.Icon {
                                                            source: folderPane.folderIcon(folderDelegate.mailBox)
                                                            Layout.preferredWidth: Kirigami.Units.iconSizes.small
                                                            Layout.preferredHeight: Kirigami.Units.iconSizes.small
                                                            color: folderDelegate.highlighted
                                                                   ? Kirigami.Theme.highlightedTextColor
                                                                   : Qt.alpha(Kirigami.Theme.textColor, 0.55)
                                                        }
                                                        QQC2.Label {
                                                            Layout.fillWidth: true
                                                            text: folderDelegate.name
                                                            elide: Text.ElideRight
                                                            color: folderDelegate.highlighted
                                                                   ? Kirigami.Theme.highlightedTextColor
                                                                   : Kirigami.Theme.textColor
                                                        }
                                                        UnreadPill {
                                                            id: folderUnread
                                                            count: folderDelegate.unread
                                                            hiddenCount: folderDelegate.hiddenUnread
                                                            primary: folderPane.isInbox(folderDelegate.mailBox)
                                                        onHighlight: folderDelegate.highlighted
                                                            Layout.preferredWidth: implicitWidth
                                                            Layout.preferredHeight: implicitHeight
                                                        }
                                                    }
                                                    // Follows the folder that is actually
                                                    // open, not the view's cursor. During a
                                                    // model rebuild currentIndex churns
                                                    // through 0 (INBOX) and -1 before
                                                    // settling, which made INBOX flash as
                                                    // selected on every account switch.
                                                    highlighted: folderDelegate.mailBox === Mail.selectedFolder

                                                    // Opening the folder — reached from the
                                                    // click handler below rather than from
                                                    // ItemDelegate.onClicked, because the
                                                    // drag source takes the press.
                                                    function activate() {
                                                        if (!selectable) { // container-only folder: toggle instead
                                                            Mail.folderModel.toggleExpanded(index)
                                                            return
                                                        }
                                                        // Clicking a folder works its
                                                        // subtree like the arrow does:
                                                        // reveal it, and fold it away again
                                                        // on a second click. "Second" means
                                                        // this folder is already the open
                                                        // one — clicking a different
                                                        // expanded parent to read its mail
                                                        // should not collapse it. Children
                                                        // sort below this row, so index
                                                        // stays valid either way.
                                                        if (hasChildren && expanded
                                                                && Mail.selectedFolder === mailBox) {
                                                            Mail.folderModel.toggleExpanded(index)
                                                            return // already open; nothing to re-fetch
                                                        }
                                                        Mail.folderModel.expandRow(index)
                                                        folderList.currentIndex = index
                                                        folderList.forceActiveFocus()
                                                        // A click opens right away — drop
                                                        // the key-navigation debounce the
                                                        // currentIndex change just armed.
                                                        folderOpenDebounce.stop()
                                                        messageList.currentIndex = -1
                                                        messageList.openedUid = -1
                                                        messageList.clearSelection()
                                                        Mail.openFolder(mailBox)
                                                        // The list the user is now looking
                                                        // at is the one the keyboard should
                                                        // be on.
                                                        messageList.forceActiveFocus()
                                                    }

                                                    // Drop target: messages land in this
                                                    // folder, another folder is reparented
                                                    // under it. What a drop would mean is
                                                    // asked of the backend, so a row only
                                                    // lights up when the drop would work.
                                                    DropArea {
                                                        id: folderDrop
                                                        anchors.fill: parent

                                                        readonly property bool acceptable:
                                                            dragPayload.kind === "messages"
                                                            ? (folderDelegate.selectable
                                                               && folderDelegate.mailBox !== Mail.selectedFolder)
                                                            : dragPayload.kind === "folder"
                                                              && Mail.canMoveFolder(dragPayload.mailBox,
                                                                                    folderDelegate.mailBox)

                                                        onEntered: drag => drag.accepted = acceptable
                                                        onDropped: drop => {
                                                            if (!acceptable) {
                                                                drop.accepted = false
                                                                return
                                                            }
                                                            if (dragPayload.kind === "messages") {
                                                                Mail.moveMessagesTo(dragPayload.rows,
                                                                                    folderDelegate.mailBox)
                                                                messageList.clearSelection()
                                                            } else {
                                                                Mail.moveFolder(dragPayload.mailBox,
                                                                                folderDelegate.mailBox)
                                                            }
                                                        }
                                                    }

                                                    // Outline marking the row a drop would
                                                    // land in. Deliberately an outline plus
                                                    // a light fill rather than a color
                                                    // change: it has to read on top of the
                                                    // selection highlight as well.
                                                    Rectangle {
                                                        anchors.fill: parent
                                                        visible: folderDrop.containsDrag && folderDrop.acceptable
                                                        color: Qt.alpha(Kirigami.Theme.highlightColor, 0.25)
                                                        border.width: 2
                                                        border.color: Kirigami.Theme.highlightColor
                                                        radius: Kirigami.Units.smallSpacing
                                                    }

                                                    // Clicks and the folder drag both come
                                                    // from here: ItemDelegate.onClicked
                                                    // never fires once this takes the press.
                                                    MouseArea {
                                                        id: folderMouse
                                                        anchors.fill: parent
                                                        acceptedButtons: Qt.LeftButton | Qt.RightButton
                                                        // Dragging a folder moves a whole
                                                        // mailbox — an easy accident with
                                                        // the default few pixels.
                                                        drag.threshold: Kirigami.Units.gridUnit
                                                        // Every row can be picked up. Gating
                                                        // this on folderProtected() left rows
                                                        // undraggable for good: it is a plain
                                                        // invokable with no change signal, and
                                                        // the binding kept the value it got
                                                        // while the delegate was still being
                                                        // built — mailBox empty, which
                                                        // folderProtected() answers true to.
                                                        // What a folder may do is decided by
                                                        // the drop targets instead: they ask
                                                        // canMoveFolder() per hovered row, so a
                                                        // protected folder finds nothing that
                                                        // lights up.
                                                        drag.target: dragPayload

                                                        onPressed: mouse => {
                                                            if (mouse.button !== Qt.LeftButton)
                                                                return
                                                            dragPayload.prepare("folder", [],
                                                                                folderDelegate.mailBox,
                                                                                folderDelegate.name)
                                                            dragPayload.moveTo(folderDelegate.mapToItem(
                                                                QQC2.Overlay.overlay, mouse.x, mouse.y))
                                                        }
                                                        drag.onActiveChanged: {
                                                            if (folderMouse.drag.active)
                                                                dragPayload.begin()
                                                            else
                                                                dragPayload.finish()
                                                        }
                                                        onClicked: mouse => {
                                                            if (mouse.button === Qt.RightButton) {
                                                                folderMenu.mailBox = folderDelegate.mailBox
                                                                folderMenu.name = folderDelegate.name
                                                                folderMenu.popup()
                                                                return
                                                            }
                                                            folderDelegate.activate()
                                                        }
                                                    }

                                                    Kirigami.Icon {
                                                        visible: folderDelegate.hasChildren
                                                        x: Kirigami.Units.smallSpacing + Kirigami.Units.gridUnit / 2
                                                           + folderDelegate.level * Kirigami.Units.gridUnit
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        source: folderDelegate.expanded ? "arrow-down" : "arrow-right"
                                                        width: Kirigami.Units.iconSizes.small
                                                        height: width
                                                        opacity: 0.6

                                                        MouseArea {
                                                            anchors.fill: parent
                                                            anchors.margins: -Kirigami.Units.smallSpacing
                                                            onClicked: Mail.folderModel.toggleExpanded(folderDelegate.index)
                                                        }
                                                    }
                                                }
                                            }

                                            // Cached folder tree of an account that is
                                            // open in the panel but not connected.
                                            ColumnLayout {
                                                visible: accountSection.open && !accountSection.isCurrent
                                                Layout.fillWidth: true
                                                spacing: 0

                                                Repeater {
                                                    // Depends on currentAccount (connection
                                                    // moved) and cachedFolderRevision
                                                    // (collapse toggled) so the list refreshes.
                                                    model: accountSection.isCurrent
                                                           ? []
                                                           : (Mail.currentAccount,
                                                              Mail.cachedFolderRevision,
                                                              Mail.cachedFolderList(accountSection.index))

                                                    delegate: QQC2.ItemDelegate {
                                                        id: cachedFolderDelegate
                                                        required property var modelData

                                                        Layout.fillWidth: true
                                                        implicitHeight: root.listRowHeight + 2
                                                        topPadding: 1
                                                        bottomPadding: 1
                                                        // Same account-under-parent indent as
                                                        // the connected tree above.
                                                        leftPadding: Kirigami.Units.largeSpacing + Kirigami.Units.gridUnit * 1.5
                                                                     + modelData.level * Kirigami.Units.gridUnit
                                                        rightPadding: Kirigami.Units.smallSpacing

                                                        // Laid out as row content, same as the connected tree.
                                                        contentItem: RowLayout {
                                                            spacing: Kirigami.Units.smallSpacing

                                                            Kirigami.Icon {
                                                                source: folderPane.folderIcon(cachedFolderDelegate.modelData.mailBox)
                                                                Layout.preferredWidth: Kirigami.Units.iconSizes.small
                                                                Layout.preferredHeight: Kirigami.Units.iconSizes.small
                                                                color: Qt.alpha(Kirigami.Theme.textColor, 0.55)
                                                            }
                                                            QQC2.Label {
                                                                Layout.fillWidth: true
                                                                text: cachedFolderDelegate.modelData.name
                                                                elide: Text.ElideRight
                                                                color: Kirigami.Theme.textColor
                                                            }
                                                            UnreadPill {
                                                                count: cachedFolderDelegate.modelData.unread || 0
                                                                hiddenCount: cachedFolderDelegate.modelData.hiddenUnread || 0
                                                                primary: folderPane.isInbox(cachedFolderDelegate.modelData.mailBox)
                                                                // Nothing in a cached tree is the open folder — that
                                                                // account is not the connected one.
                                                                onHighlight: false
                                                                Layout.preferredWidth: implicitWidth
                                                                Layout.preferredHeight: implicitHeight
                                                            }
                                                        }
                                                        onClicked: {
                                                            messageList.currentIndex = -1
                                                            messageList.openedUid = -1
                                                            messageList.clearSelection()
                                                            // Focus BEFORE the switch: switching
                                                            // repopulates this Repeater and takes
                                                            // this delegate with it (see the
                                                            // right-click handler below), so a
                                                            // line after the call runs in a dead
                                                            // context where no id resolves —
                                                            // "messageList is not defined".
                                                            messageList.forceActiveFocus()
                                                            Mail.openFolderInAccount(accountSection.index,
                                                                                     modelData.mailBox)
                                                        }

                                                        // Right-click on another account's tree.
                                                        // Every folder command runs against the
                                                        // connected account, so none of them can
                                                        // act here — but a menu that simply never
                                                        // appears reads as a broken click, so it
                                                        // opens and says what is missing.
                                                        MouseArea {
                                                            anchors.fill: parent
                                                            acceptedButtons: Qt.RightButton
                                                            onClicked: {
                                                                // Read the row before switching:
                                                                // the switch repopulates this
                                                                // Repeater and takes the delegate
                                                                // with it.
                                                                const box = cachedFolderDelegate.modelData.mailBox
                                                                const nm = cachedFolderDelegate.modelData.name
                                                                // Every folder command acts on the
                                                                // open folder of the open account,
                                                                // so open this one — the folder
                                                                // that was right-clicked, not the
                                                                // account's inbox, which is what
                                                                // switchAccount() lands on and
                                                                // what left the menu acting on
                                                                // INBOX. Same call the left-click
                                                                // above makes, and the list is
                                                                // reset the same way.
                                                                messageList.currentIndex = -1
                                                                messageList.openedUid = -1
                                                                messageList.clearSelection()
                                                                Mail.openFolderInAccount(
                                                                    accountSection.index, box)
                                                                folderMenu.mailBox = box
                                                                folderMenu.name = nm
                                                                folderMenu.popup()
                                                            }
                                                        }

                                                        // Same expand/collapse arrow as the
                                                        // connected account's tree.
                                                        Kirigami.Icon {
                                                            visible: cachedFolderDelegate.modelData.hasChildren
                                                            x: Kirigami.Units.smallSpacing + Kirigami.Units.gridUnit / 2
                                                               + cachedFolderDelegate.modelData.level * Kirigami.Units.gridUnit
                                                            anchors.verticalCenter: parent.verticalCenter
                                                            source: cachedFolderDelegate.modelData.expanded
                                                                    ? "arrow-down" : "arrow-right"
                                                            width: Kirigami.Units.iconSizes.small
                                                            height: width
                                                            opacity: 0.6

                                                            MouseArea {
                                                                anchors.fill: parent
                                                                anchors.margins: -Kirigami.Units.smallSpacing
                                                                onClicked: Mail.toggleCachedCollapsed(
                                                                               accountSection.index,
                                                                               cachedFolderDelegate.modelData.mailBox)
                                                            }
                                                        }
                                                    }
                                                }

                                                QQC2.Label {
                                                    visible: parent.visible
                                                             && Mail.cachedFolderList(accountSection.index).length === 0
                                                    Layout.fillWidth: true
                                                    leftPadding: Kirigami.Units.largeSpacing + Kirigami.Units.gridUnit * 1.5
                                                    text: "Not synced yet"
                                                    opacity: 0.8
                                                    elide: Text.ElideRight
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Right side: message list on top, viewer below
                        QQC2.SplitView {
                            id: rightSplit
                            QQC2.SplitView.fillWidth: true
                            QQC2.SplitView.minimumWidth: 300
                            orientation: Qt.Vertical

                            // Wider, hover-highlighted grab area for the list/viewer divider
                            handle: Rectangle {
                                implicitHeight: 6
                                color: QQC2.SplitHandle.hovered || QQC2.SplitHandle.pressed
                                       ? Kirigami.Theme.highlightColor : "transparent"
                                opacity: QQC2.SplitHandle.pressed ? 0.6 : 0.3
                                Kirigami.Separator {
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: parent.width
                                }
                            }

                        // Message list pane
                        ColumnLayout {
                            id: messagePane
                            QQC2.SplitView.preferredHeight: rightSplit.height / 2
                            QQC2.SplitView.minimumHeight: 160
                            spacing: 0

                            // Column layout shared by the header row and every message row.
                            // Order is user-adjustable by dragging headers; weight 0 marks
                            // the fixed-width attachment icon column.
                            property ListModel columns: ListModel {
                                ListElement { colId: "attach"; title: ""; sortCol: 3; weight: 0 }
                                ListElement { colId: "subject"; title: "Subject"; sortCol: 2; weight: 4 }
                                ListElement { colId: "from"; title: "From"; sortCol: 1; weight: 3 }
                                ListElement { colId: "date"; title: "Date"; sortCol: 0; weight: 2 }
                            }
                            property real fixedColumnWidth: Kirigami.Units.gridUnit * 2

                            function saveColumnOrder() {
                                const ids = []
                                for (let i = 0; i < columns.count; i++)
                                    ids.push(columns.get(i).colId)
                                uiSettings.columnOrder = JSON.stringify(ids)
                            }
                            Component.onCompleted: {
                                // Restore the saved column order (ignore unknown/missing ids)
                                const saved = JSON.parse(uiSettings.columnOrder)
                                let target = 0
                                for (const colId of saved) {
                                    for (let i = target; i < columns.count; i++) {
                                        if (columns.get(i).colId === colId) {
                                            if (i !== target)
                                                columns.move(i, target, 1)
                                            target++
                                            break
                                        }
                                    }
                                }
                            }
                            function columnWidth(weight, totalWidth) {
                                if (weight === 0)
                                    return fixedColumnWidth
                                let flexTotal = 0
                                let fixedTotal = 0
                                for (let i = 0; i < columns.count; i++) {
                                    const w = columns.get(i).weight
                                    if (w === 0)
                                        fixedTotal += fixedColumnWidth
                                    else
                                        flexTotal += w
                                }
                                return Math.max(0, (totalWidth - fixedTotal) * weight / flexTotal)
                            }

                            // Search row
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.margins: Kirigami.Units.smallSpacing
                                spacing: Kirigami.Units.smallSpacing

                                Kirigami.SearchField {
                                    id: searchField
                                    Layout.fillWidth: true
                                    placeholderText: "Search… (/pattern/ = regex on loaded)"
                                    // Kirigami claims Ctrl+F (StandardKey.Find) here by
                                    // default, which collided with the viewer's find bar —
                                    // two shortcuts on one sequence and Qt activates
                                    // neither. Ctrl+F searches inside the open message;
                                    // Ctrl+Shift+F searches the mailbox.
                                    focusSequences: ["Ctrl+Shift+F"]
                                    function startSearch() {
                                        // Search results read from the top. Left alone, the
                                        // remapping that keeps the cursor on its message
                                        // makes the view chase it around while results
                                        // reconcile — park the cursor and stay at the top.
                                        messageList.currentIndex = -1
                                        messageList.positionViewAtBeginning()
                                        Mail.searchMessages(searchField.text, searchFieldBox.currentIndex)
                                    }
                                    // Not on every keystroke: half a beat after typing
                                    // pauses. Enter still searches immediately (accepted
                                    // fires regardless of autoAccept).
                                    autoAccept: false
                                    onAccepted: {
                                        searchDebounce.stop()
                                        startSearch()
                                    }
                                    onTextChanged: {
                                        if (text.length === 0) {
                                            searchDebounce.stop()
                                            Mail.clearSearch()
                                        } else {
                                            searchDebounce.restart()
                                        }
                                    }
                                    Timer {
                                        id: searchDebounce
                                        interval: 200
                                        onTriggered: searchField.startSearch()
                                    }
                                    Keys.onEscapePressed: {
                                        text = ""
                                        messageList.forceActiveFocus()
                                    }
                                }
                                QQC2.ComboBox {
                                    id: searchFieldBox
                                    // From+Subject first and default: searching bodies too
                                    // ("Everything" — body, cc, all headers) is the slower,
                                    // noisier search, so it is the one you opt into.
                                    model: ["From + Subject", "Everything"]
                                    implicitWidth: Kirigami.Units.gridUnit * 8
                                    // Changing the scope IS a new query when there is text
                                    // to search — no reason to make the user press Enter
                                    // to get what they just asked for.
                                    onActivated: {
                                        if (searchField.text.length > 0)
                                            searchField.startSearch()
                                    }
                                }

                                // Quick filter by color mark — one square per defined
                                // scale color; click filters, click again clears.
                                Repeater {
                                    model: [1, 2, 3, 4, 5]
                                    Rectangle {
                                        required property int modelData
                                        readonly property string scaleColor:
                                            root.scaleColorOf(modelData)
                                        visible: scaleColor !== ""
                                        width: Kirigami.Units.gridUnit * 1.1
                                        height: width
                                        radius: 3
                                        color: scaleColor !== "" ? scaleColor : "transparent"
                                        border.width: root.colorFilter === modelData ? 2 : 1
                                        border.color: root.colorFilter === modelData
                                                      ? Kirigami.Theme.highlightColor
                                                      : Qt.alpha(Kirigami.Theme.textColor, 0.55)
                                        // Deliberately a MouseArea, not a Button: filtering
                                        // must never steal keyboard focus from the search
                                        // field or the message list.
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: {
                                                root.colorFilter = root.colorFilter === parent.modelData
                                                    ? 0 : parent.modelData
                                                Mail.filterByColor(root.colorFilter)
                                            }
                                        }
                                        QQC2.ToolTip.text: root.colorFilter === modelData
                                            ? "Clear color filter"
                                            : "Show only messages marked with this color"
                                        QQC2.ToolTip.visible: squareHover.hovered
                                        HoverHandler { id: squareHover }
                                    }
                                }
                            }

                            // Column headers: click to sort, drag onto another header to
                            // reorder the columns.
                            Item {
                                id: columnHeader
                                Layout.fillWidth: true
                                implicitHeight: Kirigami.Units.gridUnit * 1.6

                                // model order: 0 date, 1 from, 2 subject, 3 attachment
                                property int sortColumn: uiSettings.sortColumn
                                property bool sortDescending: uiSettings.sortDescending

                                function toggle(col) {
                                    if (sortColumn === col)
                                        sortDescending = !sortDescending
                                    else {
                                        sortColumn = col
                                        // dates newest-first, attachments-first by default
                                        sortDescending = (col === 0 || col === 3)
                                    }
                                    uiSettings.sortColumn = sortColumn
                                    uiSettings.sortDescending = sortDescending
                                    // Re-sorting is a new ordering to read, and it reads
                                    // from the top. onLayoutChanged otherwise follows the
                                    // opened message to wherever the new order put it and
                                    // scrolls the view there, so tell it not to this once.
                                    messageList.sortJumpsToTop = true
                                    Mail.messageModel.sortBy(sortColumn, sortDescending)
                                    // The list only holds the newest page of the
                                    // folder, so re-ordering it alone shows the
                                    // head of that page, not of the folder —
                                    // oldest-first began at the oldest message
                                    // loaded so far rather than the oldest there
                                    // is. This switches paging onto the new sort:
                                    // the folder's real first page replaces the
                                    // list, and scrolling down walks the cache
                                    // in the sort's own order from there.
                                    Mail.seedSortOrder(sortColumn, sortDescending)
                                }
                                Component.onCompleted: {
                                    if (sortColumn !== 0 || !sortDescending) {
                                        Mail.messageModel.sortBy(sortColumn, sortDescending)
                                        Mail.seedSortOrder(sortColumn, sortDescending)
                                    }
                                }

                                Row {
                                    anchors.fill: parent
                                    Repeater {
                                        model: messagePane.columns
                                        delegate: Item {
                                            id: headerCell
                                            required property string colId
                                            required property string title
                                            required property int sortCol
                                            required property real weight
                                            required property int index

                                            width: messagePane.columnWidth(weight, columnHeader.width)
                                            height: columnHeader.height
                                            z: headerMouse.drag.active ? 10 : 0

                                            DropArea {
                                                anchors.fill: parent
                                                onDropped: drop => {
                                                    const from = drop.source.headerIndex
                                                    if (from !== headerCell.index) {
                                                        messagePane.columns.move(from, headerCell.index, 1)
                                                        messagePane.saveColumnOrder()
                                                    }
                                                }
                                            }

                                            Rectangle {
                                                id: headerContent
                                                property int headerIndex: headerCell.index
                                                width: headerCell.width
                                                height: headerCell.height
                                                color: headerMouse.drag.active
                                                       ? Kirigami.Theme.alternateBackgroundColor
                                                       : "transparent"
                                                opacity: headerMouse.drag.active ? 0.8 : 1

                                                Drag.active: headerMouse.drag.active
                                                Drag.source: headerContent
                                                Drag.hotSpot: Qt.point(width / 2, height / 2)

                                                Kirigami.Icon {
                                                    visible: headerCell.colId === "attach"
                                                    anchors.centerIn: parent
                                                    source: "mail-attachment"
                                                    width: Kirigami.Units.iconSizes.small
                                                    height: width
                                                    opacity: 0.7
                                                }
                                                // Title and sort arrow travel together:
                                                // parked on the column's right edge the
                                                // arrow sat far from the word it qualifies,
                                                // often with empty space between them, and
                                                // read as unrelated decoration.
                                                Row {
                                                    id: headerLabelRow
                                                    visible: headerCell.colId !== "attach"
                                                    anchors.left: parent.left
                                                    anchors.right: parent.right
                                                    anchors.verticalCenter: parent.verticalCenter
                                                    anchors.leftMargin: Kirigami.Units.smallSpacing
                                                    anchors.rightMargin: Kirigami.Units.smallSpacing
                                                    spacing: Kirigami.Units.smallSpacing / 2

                                                    QQC2.Label {
                                                        width: Math.min(implicitWidth,
                                                                        headerLabelRow.width - sortArrow.width
                                                                        - headerLabelRow.spacing)
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        text: headerCell.title
                                                        elide: Text.ElideRight
                                                        font.bold: columnHeader.sortColumn === headerCell.sortCol
                                                    }
                                                    Kirigami.Icon {
                                                        id: sortArrow
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        // Symbolic, and masked to the theme's
                                                        // text color: the plain arrow-down icon
                                                        // is fixed dark artwork that does not
                                                        // recolor, so on a dark header it was
                                                        // drawn in a color nobody could see.
                                                        source: columnHeader.sortDescending ? "arrow-down-symbolic"
                                                                                            : "arrow-up-symbolic"
                                                        isMask: true
                                                        color: Kirigami.Theme.textColor
                                                        visible: headerCell.sortCol >= 0
                                                                 && columnHeader.sortColumn === headerCell.sortCol
                                                        width: Kirigami.Units.iconSizes.small
                                                        height: width
                                                        opacity: 0.9
                                                    }
                                                }

                                                MouseArea {
                                                    id: headerMouse
                                                    anchors.fill: parent
                                                    drag.target: headerContent
                                                    drag.axis: Drag.XAxis
                                                    onClicked: {
                                                        if (headerCell.sortCol >= 0)
                                                            columnHeader.toggle(headerCell.sortCol)
                                                    }
                                                    onReleased: {
                                                        headerContent.Drag.drop()
                                                        headerContent.x = 0
                                                        headerContent.y = 0
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            Kirigami.Separator {
                                Layout.fillWidth: true
                            }

                            QQC2.ScrollView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true

                                ListView {
                                    id: messageList
                                    model: Mail.messageModel
                                    currentIndex: -1
                                    keyNavigationEnabled: true
                                    activeFocusOnTab: true

                                    // Recycle delegates instead of destroying and
                                    // re-creating them as rows scroll by. A row here
                                    // is an ItemDelegate, a MouseArea and a Repeater
                                    // of per-column cells — a held PageDown built and
                                    // tore down ~14 of those per keypress, and the
                                    // JS garbage that leaves behind is collected in
                                    // pauses that grow with the heap: the longer the
                                    // scroll, the longer the freezes (a measured
                                    // 0.4 s → 2.1 s staircase over one minute of
                                    // paging). Pooled rows are just re-filled with
                                    // the next row's data, so scrolling stops paying
                                    // that tax. The delegate holds no per-row state
                                    // outside its model properties, which is what
                                    // makes it safe to reuse.
                                    reuseItems: true

                                    // Snap to the current row instead of gliding to it.
                                    // ListView scrolls itself to follow the cursor, and
                                    // by default that scroll is *animated* at 400 px/s —
                                    // a PageDown of some 900 px takes over two seconds,
                                    // and a held key keeps restarting the animation, so
                                    // the view crawls along behind the cursor animating
                                    // every frame while never catching up. That is the
                                    // whole "paging slows the app down": the work is the
                                    // animation, not the paging.
                                    highlightMoveDuration: 0
                                    highlightMoveVelocity: -1

                                    // The message the cursor is on, tracked by uid so it
                                    // survives a model reset renumbering the rows. Uids are
                                    // only unique within a folder, so every folder change
                                    // clears this alongside currentIndex. "real", not
                                    // "int": IMAP uids run past 2^31.
                                    property real openedUid: -1

                                    // Set for the one layout change a header click causes:
                                    // that re-sort must land at the top, every other one
                                    // keeps following the opened message.
                                    property bool sortJumpsToTop: false

                                    // Multi-selection (ctrl+click toggles, shift+click ranges)
                                    property var selectedSet: ({})
                                    property int selectionRev: 0
                                    property int selectionAnchor: -1

                                    function isSelected(i) {
                                        void selectionRev
                                        return selectedSet[i] === true
                                    }
                                    function clearSelection() {
                                        selectedSet = {}
                                        selectionAnchor = -1
                                        selectionRev++
                                    }
                                    // A plain cursor move: no explicit multi-selection —
                                    // the row is implicitly selected by being current
                                    // (highlight and selectedIndexes() both cover that).
                                    // Keeping the set empty lets the select shortcut
                                    // toggle the current row ON with its first press.
                                    function selectSingle(i) {
                                        selectedSet = {}
                                        selectionAnchor = i
                                        selectionRev++
                                    }
                                    function toggleSelect(i) {
                                        if (selectedSet[i])
                                            delete selectedSet[i]
                                        else
                                            selectedSet[i] = true
                                        selectionAnchor = i
                                        selectionRev++
                                    }
                                    // Toggle-select the current row and step down one —
                                    // repeated presses select a run (file-manager style).
                                    // The advance must not collapse the selection like a
                                    // normal cursor move does.
                                    property bool preserveSelection: false
                                    function toggleSelectAndAdvance() {
                                        if (currentIndex < 0)
                                            return
                                        toggleSelect(currentIndex)
                                        if (currentIndex < count - 1) {
                                            preserveSelection = true
                                            currentIndex++
                                            preserveSelection = false
                                        }
                                    }
                                    function selectRange(a, b) {
                                        const s = {}
                                        for (let i = Math.min(a, b); i <= Math.max(a, b); i++)
                                            s[i] = true
                                        selectedSet = s
                                        selectionRev++
                                    }
                                    function selectedIndexes() {
                                        const out = []
                                        for (const k in selectedSet) {
                                            if (selectedSet[k])
                                                out.push(parseInt(k))
                                        }
                                        if (out.length === 0 && currentIndex >= 0)
                                            out.push(currentIndex)
                                        return out
                                    }
                                    function requestDelete() {
                                        const rows = selectedIndexes()
                                        console.debug(traceLog, "mailo: requestDelete rows",
                                                      JSON.stringify(rows),
                                                      "permanent", Mail.deleteIsPermanent())
                                        if (rows.length === 0)
                                            return
                                        // Spam counts as permanent too when
                                        // Skip Trash is on — the prompt has to
                                        // say what will actually happen.
                                        if (Mail.deleteIsPermanent()) {
                                            confirmPermanentDelete.rows = rows
                                            confirmPermanentDelete.open()
                                        } else {
                                            Mail.deleteMessages(rows)
                                            clearSelection()
                                        }
                                    }
                                    function requestJunk() {
                                        const rows = selectedIndexes()
                                        if (rows.length === 0)
                                            return
                                        Mail.markAsJunk(rows)
                                        clearSelection()
                                    }
                                    function requestNotSpam() {
                                        const rows = selectedIndexes()
                                        if (rows.length === 0)
                                            return
                                        Mail.markAsNotSpam(rows)
                                        clearSelection()
                                    }

                                    // Row indexes shift on re-sort/search — selections
                                    // would silently point at the wrong messages.
                                    Connections {
                                        target: Mail.messageModel
                                        function onModelReset() {
                                            messageList.clearSelection()
                                            // The rows under the cursor are different ones
                                            // now (search/filter/sort) — currentIndex often
                                            // keeps its old number, so no change signal
                                            // fires and the preview would show the previous
                                            // message.
                                            if (messageList.count <= 0) {
                                                // openedUid deliberately survives: opening a
                                                // folder clears the model and *then* fills
                                                // it, so every refresh passes through an
                                                // empty model. Forgetting the user's pick
                                                // here made the restore below a no-op — the
                                                // first reset wiped it, the second snapped
                                                // to row 0. A real folder change clears it
                                                // explicitly at the click instead.
                                                messageList.currentIndex = -1
                                                console.debug(traceLog,
                                                              "mailo: msg reset: empty, keeping uid",
                                                              messageList.openedUid)
                                                return
                                            }
                                            // A message the user opened is followed by uid,
                                            // not by row number. An account switch resets
                                            // this model again when the folder refresh
                                            // lands, and snapping to row 0 unconditionally
                                            // threw away a message clicked in between —
                                            // the click registered, then the reset moved
                                            // the cursor back to the top.
                                            const row = messageList.openedUid >= 0
                                                ? Mail.messageModel.rowForUid(messageList.openedUid) : -1
                                            messageList.currentIndex = row >= 0 ? row : 0
                                            // Set explicitly: assigning the same number
                                            // fires no change signal, which would leave a
                                            // uid here that is no longer under the cursor.
                                            // Only when the restore actually failed — if
                                            // the message was found, the cursor is already
                                            // on it and its uid is the one to keep.
                                            if (row < 0) {
                                                messageList.openedUid =
                                                    Mail.messageModel.uidAt(messageList.currentIndex)
                                            }
                                            console.debug(traceLog,
                                                          "mailo: msg reset: count", messageList.count,
                                                          "wanted uid", messageList.openedUid,
                                                          "-> row", row,
                                                          "current", messageList.currentIndex)
                                            // Only when the cursor landed on a *different*
                                            // message than the viewer is showing. A
                                            // successful restore means the same mail is
                                            // still under the cursor, and re-fetching it
                                            // re-parsed the MIME and reloaded the web view
                                            // on every refresh — three times per message
                                            // during a reconnect, all on the GUI thread.
                                            if (row < 0)
                                                fetchDebounce.restart()
                                        }
                                        // Re-sorting keeps the same rows and only renumbers
                                        // them, so it reports a layout change instead of a
                                        // reset — that is what lets the view keep its
                                        // delegates. selectedSet, selectionAnchor and
                                        // currentIndex are row numbers all the same, so
                                        // they still have to be re-derived, exactly as
                                        // onModelReset does above.
                                        function onLayoutChanged() {
                                            messageList.clearSelection()
                                            if (messageList.count <= 0) {
                                                messageList.currentIndex = -1
                                                return
                                            }
                                            // The user just picked a different order and is
                                            // about to read it from the start; chasing
                                            // their previously opened message would drop
                                            // them somewhere in the middle of it.
                                            if (messageList.sortJumpsToTop) {
                                                messageList.sortJumpsToTop = false
                                                messageList.currentIndex = -1
                                                Qt.callLater(() => messageList.positionViewAtBeginning())
                                                return
                                            }
                                            const row = messageList.openedUid >= 0
                                                ? Mail.messageModel.rowForUid(messageList.openedUid) : -1
                                            messageList.currentIndex = row >= 0 ? row : 0
                                            if (row < 0) {
                                                messageList.openedUid =
                                                    Mail.messageModel.uidAt(messageList.currentIndex)
                                                fetchDebounce.restart()
                                            }
                                            // Follow the cursor to its new row. Keeping the
                                            // old scroll offset would leave the view
                                            // showing unrelated messages — and if it was
                                            // sitting at the bottom it stays at the bottom,
                                            // where atYEnd below keeps asking for another
                                            // page, which lands somewhere else in the new
                                            // order and leaves it at the bottom again: the
                                            // list scrolls on by itself. Deferred, because
                                            // the view has not finished relaying out the
                                            // rows while this signal is still being
                                            // delivered.
                                            Qt.callLater(() => {
                                                if (messageList.currentIndex >= 0)
                                                    messageList.positionViewAtIndex(
                                                        messageList.currentIndex, ListView.Center)
                                            })
                                            console.debug(traceLog,
                                                          "mailo: msg re-sorted: count",
                                                          messageList.count,
                                                          "uid", messageList.openedUid,
                                                          "-> row", messageList.currentIndex)
                                        }
                                        // Incremental inserts (appendHeaders: search local
                                        // merge, load-more) shift every row at/after the
                                        // insertion point. selectedSet, selectionAnchor and
                                        // currentIndex are stored as row numbers, so without
                                        // remapping the highlight sticks to whatever message
                                        // now sits at the old index — leaving the real row
                                        // unhighlighted and a stale highlight behind.
                                        function onRowsInserted(parent, first, last) {
                                            const shift = last - first + 1
                                            const remap = k => (k >= first ? k + shift : k)
                                            const next = {}
                                            for (const key in messageList.selectedSet) {
                                                if (messageList.selectedSet[key])
                                                    next[remap(parseInt(key))] = true
                                            }
                                            messageList.selectedSet = next
                                            if (messageList.selectionAnchor >= 0)
                                                messageList.selectionAnchor = remap(messageList.selectionAnchor)
                                            if (messageList.currentIndex >= first)
                                                messageList.currentIndex = remap(messageList.currentIndex)
                                            messageList.selectionRev++
                                            // Results reconcile in place while a search
                                            // runs, and an insert above the viewport
                                            // re-anchors the view on the rows it was
                                            // showing — which reads as the list scrolling
                                            // by itself. Until the user picks a row, the
                                            // top of the results is the place to be.
                                            if (Mail.searching && messageList.currentIndex < 0)
                                                Qt.callLater(() => messageList.positionViewAtBeginning())
                                        }
                                        function onRowsRemoved(parent, first, last) {
                                            const shift = last - first + 1
                                            const remap = k => (k > last ? k - shift : k)
                                            const next = {}
                                            for (const key in messageList.selectedSet) {
                                                const k = parseInt(key)
                                                if (messageList.selectedSet[key] && (k < first || k > last))
                                                    next[remap(k)] = true
                                            }
                                            messageList.selectedSet = next
                                            const a = messageList.selectionAnchor
                                            messageList.selectionAnchor =
                                                (a >= first && a <= last) ? -1
                                                : (a > last ? a - shift : a)
                                            messageList.selectionRev++
                                            // Same top-pinning as onRowsInserted: pruning
                                            // stale rows at search completion must not
                                            // leave the view parked mid-list.
                                            if (Mail.searching && messageList.currentIndex < 0)
                                                Qt.callLater(() => messageList.positionViewAtBeginning())

                                            // Keep the preview in sync with what now sits
                                            // under the cursor. If the current row itself
                                            // was removed, currentIndex often keeps its old
                                            // number and points at a *different* message,
                                            // yet no onCurrentIndexChanged fires — so the
                                            // preview would keep showing the deleted mail.
                                            // Re-anchor and re-fetch explicitly.
                                            const cur = messageList.currentIndex
                                            if (cur >= first && cur <= last) {
                                                // The current row was deleted: land on the
                                                // row that took its place (clamped to end).
                                                const target = Math.min(first, messageList.count - 1)
                                                if (target < 0) {
                                                    messageList.currentIndex = -1
                                                    viewer.clear()
                                                } else if (messageList.currentIndex === target) {
                                                    // Same number, new message → force a fetch.
                                                    Mail.fetchMessage(target)
                                                } else {
                                                    messageList.currentIndex = target
                                                }
                                            } else if (cur > last) {
                                                // Rows above the cursor went away; its number
                                                // shifts but the message is the same — just
                                                // keep the highlight in the right place.
                                                messageList.currentIndex = cur - shift
                                            }
                                        }
                                    }

                                    // Fetch older messages when scrolled (or key-navigated)
                                    // to the end — but not on every arrival. A held
                                    // PageDown lands on the end, loads a page, lands on
                                    // the new end, loads another: at key-repeat rate that
                                    // is thousands of rows a second being queried and
                                    // inserted, which is what made holding the key drag
                                    // the whole app down. Waiting for the key to settle
                                    // costs nothing perceptible on a real scroll.
                                    Timer {
                                        id: loadMoreDebounce
                                        interval: 120
                                        onTriggered: {
                                            if (messageList.atYEnd && messageList.count > 0)
                                                Mail.loadMoreMessages()
                                        }
                                    }
                                    onAtYEndChanged: {
                                        if (atYEnd && count > 0)
                                            loadMoreDebounce.restart()
                                    }

                                    // Prefetch ahead of the scroll: start loading
                                    // the next page while the end is still well
                                    // away, so a held PageDown reaches rows that
                                    // already arrived instead of pausing at the
                                    // boundary for the debounce and the fetch.
                                    // Twelve screens ≈ 300 rows: enough runway
                                    // that even a sender-sorted page (about half
                                    // a second on a worker) lands before a held
                                    // key eats through it. Each page pushes the
                                    // boundary further out than the zone is
                                    // deep, so this cannot cascade; the C++ side
                                    // drops repeats while a page is in flight.
                                    onContentYChanged: {
                                        if (count > 0
                                                && contentHeight - (contentY + height) < height * 12)
                                            Mail.loadMoreMessages()
                                    }

                                    // Debounce so holding an arrow key doesn't fetch every row.
                                    Timer {
                                        id: fetchDebounce
                                        interval: 150
                                        onTriggered: {
                                            if (messageList.currentIndex >= 0)
                                                Mail.fetchMessage(messageList.currentIndex)
                                        }
                                    }
                                    onCurrentIndexChanged: {
                                        if (currentIndex >= 0) {
                                            // Keep the cursor on screen. ListView scrolls
                                            // to follow it on its own, but a held arrow
                                            // key outruns that on a long list and the
                                            // selected row ends up off the edge with the
                                            // view left behind. Contain only scrolls when
                                            // the row is not already fully visible, so
                                            // ordinary moves within the page cost nothing
                                            // and the view does not jump.
                                            positionViewAtIndex(currentIndex, ListView.Contain)
                                            // Moving the cursor (keyboard or click) always
                                            // collapses any multi-selection to that row —
                                            // otherwise the clicked row stays highlighted
                                            // while the arrow keys move a second one.
                                            // Exception: the select-and-advance shortcut
                                            // moves the cursor without dropping the set.
                                            if (!preserveSelection)
                                                selectSingle(currentIndex)
                                            // Record the pick now, not when the debounced
                                            // fetch fires: a reset landing inside those
                                            // 150 ms is exactly the case this exists for.
                                            // Only when the row names a real message —
                                            // emptying the model drives the cursor to 0
                                            // with nothing behind it, and recording that
                                            // -1 threw away the uid this is meant to keep.
                                            const uid = Mail.messageModel.uidAt(currentIndex)
                                            if (uid >= 0)
                                                openedUid = uid
                                            // Trace, not info: this fires on every cursor
                                            // move, so at key-repeat rate an unconditional
                                            // log is string formatting and terminal I/O
                                            // dozens of times a second, in the middle of
                                            // the thing being complained about.
                                            console.debug(traceLog, "[qml] msg cursor -> "
                                                          + currentIndex + " uid " + uid
                                                          + " kept " + openedUid)
                                            fetchDebounce.restart()
                                        }
                                    }
                                    // Auto-select (and show) the newest message when a
                                    // folder's list appears. The cached list can already
                                    // be populated before this view exists (constructor
                                    // preload), so check at creation too — onCountChanged
                                    // alone never fires in that case.
                                    function autoSelect() {
                                        if (count > 0 && currentIndex < 0)
                                            currentIndex = 0
                                    }
                                    onCountChanged: autoSelect()
                                    Component.onCompleted: autoSelect()
                                    Keys.onLeftPressed: {
                                        if (folderPane.folderListView)
                                            folderPane.folderListView.forceActiveFocus()
                                    }

                                    // Enter opens the message in its own tab — the
                                    // keyboard equivalent of the double-click, since
                                    // moving the cursor already shows it in the reading
                                    // pane and Enter would otherwise do nothing.
                                    function openCurrentMessage() {
                                        if (currentIndex >= 0)
                                            Mail.openMessageInWindow(currentIndex)
                                    }
                                    Keys.onReturnPressed: openCurrentMessage()
                                    Keys.onEnterPressed: openCurrentMessage()

                                    // Page and Home/End navigation. ListView's own key
                                    // handling covers Up/Down and nothing else, so a
                                    // folder of any size could only be walked a row at a
                                    // time. Setting currentIndex is all these do — the
                                    // existing cursor handler picks it up from there and
                                    // loads the message, exactly as for an arrow key.
                                    Keys.onPressed: event => {
                                        if (count === 0)
                                            return
                                        // A page is what is on screen, less one row kept
                                        // as overlap so the jump has a line of context
                                        // rather than landing among strangers.
                                        const rowH = currentItem && currentItem.height > 0
                                            ? currentItem.height : root.listRowHeight
                                        const page = Math.max(
                                            1, Math.floor(height / Math.max(1, rowH)) - 1)
                                        // From -1 (nothing picked yet) a page down should
                                        // land a page from the top, not a page from row -1.
                                        const from = Math.max(0, currentIndex)
                                        let target = -1
                                        switch (event.key) {
                                        case Qt.Key_PageDown:
                                            target = Math.min(count - 1, from + page)
                                            break
                                        case Qt.Key_PageUp:
                                            target = Math.max(0, from - page)
                                            break
                                        case Qt.Key_Home:
                                            target = 0
                                            break
                                        case Qt.Key_End:
                                            // Pull in the rest of the folder first: the
                                            // list only holds what has been scrolled to,
                                            // so without this End reached the oldest
                                            // message paged in so far rather than the
                                            // oldest there is. For an imported archive
                                            // the cache is the whole account, so this is
                                            // the real end; for a server account still
                                            // backfilling, it is as far back as the cache
                                            // goes.
                                            Mail.loadAllCachedMessages()
                                            target = count - 1
                                            break
                                        default:
                                            return // not ours — leave it to the ListView
                                        }
                                        event.accepted = true
                                        // onCurrentIndexChanged scrolls the cursor into
                                        // view — for every kind of move, not just these
                                        // keys — so there is nothing to do here.
                                        currentIndex = target
                                    }

                                    // Hover prefetch: dwell on a row for a beat and its
                                    // body is quietly cached before you even click.
                                    Timer {
                                        id: hoverPrefetch
                                        interval: 300
                                        property int row: -1
                                        onTriggered: {
                                            if (row >= 0)
                                                Mail.prefetchMessage(row)
                                        }
                                    }

                                    delegate: QQC2.ItemDelegate {
                                        id: msgDelegate
                                        required property string subject
                                        required property string from
                                        required property string date
                                        required property bool seen
                                        required property bool suspicious
                                        required property bool hasAttachment
                                        required property bool calendarAttachment
                                        /// PgpMime::StoredKind: 0 none, 1 encrypted, 2 signed,
                                        /// 3 both. 1 and 3 both draw the lock — what matters at
                                        /// list level is that it is encrypted.
                                        required property int crypto
                                        required property string authInfo
                                        /// Local spam heuristics said so (spamheuristics.h).
                                        /// Shares the "!" marker with `suspicious`: both mean
                                        /// "not what it appears to be", and one glyph to learn
                                        /// beats two that need telling apart.
                                        required property bool spam
                                        required property string spamDetail
                                        required property int colorLabel
                                        required property int index

                                        // The message's color-scale mark (empty if none).
                                        // Shown as a row background tint rather than as the
                                        // text color, so text keeps full theme contrast and
                                        // an arbitrary user color never becomes unreadable.
                                        readonly property string markColor:
                                            colorLabel > 0 ? root.scaleColorOf(colorLabel) : ""

                                        width: messageList.width
                                        // Row height comes from the density setting alone;
                                        // fixed slim padding keeps the density steps even.
                                        topPadding: 1
                                        bottomPadding: 1
                                        highlighted: messageList.currentIndex === index
                                                     || messageList.isSelected(index)

                                        // Row background: selection highlight, then hover,
                                        // then the color-scale mark as a light tint. The
                                        // mark shows as a tint only when the row is NOT
                                        // selected ("moved away"); a selected marked row
                                        // shows the mark on its TEXT instead (see below).
                                        background: Rectangle {
                                            color: msgDelegate.highlighted
                                                    ? Kirigami.Theme.highlightColor
                                                    : msgDelegate.hovered
                                                      ? Qt.alpha(Kirigami.Theme.highlightColor, 0.2)
                                                      : msgDelegate.markColor !== ""
                                                        ? Qt.alpha(msgDelegate.markColor, 0.22)
                                                        : "transparent"
                                        }

                                        onHoveredChanged: {
                                            if (hovered) {
                                                hoverPrefetch.row = index
                                                hoverPrefetch.restart()
                                            }
                                        }

                                        MouseArea {
                                            id: msgMouse
                                            anchors.fill: parent
                                            acceptedButtons: Qt.LeftButton | Qt.RightButton
                                            // Past this the press becomes a drag and the
                                            // list stops scrolling under it; short enough
                                            // to feel immediate, long enough that a click
                                            // with a shaky hand is still a click.
                                            drag.threshold: Kirigami.Units.gridUnit
                                            drag.target: dragPayload

                                            onPressed: mouse => {
                                                // A drag carries the selection when the
                                                // pressed row is part of it, and just that
                                                // row otherwise — the selection itself is
                                                // only changed on release (onClicked), so
                                                // dragging never silently reselects.
                                                const rows = messageList.isSelected(msgDelegate.index)
                                                           ? messageList.selectedIndexes()
                                                           : [msgDelegate.index]
                                                dragPayload.prepare(
                                                    "messages", rows, "",
                                                    rows.length === 1 ? msgDelegate.subject
                                                                      : rows.length + " messages")
                                                dragPayload.moveTo(msgDelegate.mapToItem(
                                                    QQC2.Overlay.overlay, mouse.x, mouse.y))
                                            }
                                            drag.onActiveChanged: {
                                                if (msgMouse.drag.active)
                                                    dragPayload.begin()
                                                else
                                                    dragPayload.finish()
                                            }
                                            onClicked: mouse => {
                                                messageList.forceActiveFocus()
                                                if (mouse.button === Qt.RightButton) {
                                                    // Right-click acts on the selection when
                                                    // the row is part of it, and on that row
                                                    // alone otherwise — the same rule the
                                                    // drag uses. It never opens the message:
                                                    // asking what to do with mail is not
                                                    // reading it.
                                                    if (!messageList.isSelected(msgDelegate.index)) {
                                                        messageList.selectSingle(msgDelegate.index)
                                                        messageList.currentIndex = msgDelegate.index
                                                    }
                                                    messageMenu.rows = messageList.selectedIndexes()
                                                    messageMenu.popup()
                                                    return
                                                }
                                                console.debug(traceLog,
                                                              "mailo: click row", msgDelegate.index,
                                                              "modifiers", mouse.modifiers,
                                                              "anchor", messageList.selectionAnchor)
                                                if (mouse.modifiers & Qt.ControlModifier) {
                                                    messageList.toggleSelect(msgDelegate.index)
                                                    return
                                                }
                                                if (mouse.modifiers & Qt.ShiftModifier) {
                                                    const anchor = messageList.selectionAnchor >= 0
                                                        ? messageList.selectionAnchor
                                                        : (messageList.currentIndex >= 0
                                                           ? messageList.currentIndex : msgDelegate.index)
                                                    console.debug(traceLog, "mailo: shift range",
                                                                  anchor, "->", msgDelegate.index)
                                                    messageList.selectRange(anchor, msgDelegate.index)
                                                    return
                                                }
                                                messageList.selectSingle(msgDelegate.index)
                                                messageList.currentIndex = msgDelegate.index
                                                // Clicks are deliberate — skip the key-repeat debounce.
                                                fetchDebounce.stop()
                                                // A draft is resumed, not read. Armed only
                                                // by a real click, so arrow-keying through
                                                // Drafts does not open a composer per row.
                                                root.draftEditPending = Mail.viewingDrafts
                                                Mail.fetchMessage(msgDelegate.index)
                                            }
                                            // Double-click: the message in its own window.
                                            // The first click of the pair has already
                                            // selected and fetched it, so this usually
                                            // detaches instantly from the reading pane.
                                            // Drafts open in the composer instead (the
                                            // single-click path above), never in a window.
                                            onDoubleClicked: mouse => {
                                                if (mouse.modifiers & (Qt.ControlModifier | Qt.ShiftModifier))
                                                    return
                                                if (Mail.viewingDrafts)
                                                    return
                                                Mail.openMessageInWindow(msgDelegate.index)
                                            }
                                        }

                                        contentItem: Row {
                                            Repeater {
                                                model: messagePane.columns
                                                delegate: Item {
                                                    id: rowCell
                                                    required property string colId
                                                    required property real weight

                                                    width: messagePane.columnWidth(weight, columnHeader.width)
                                                    height: root.listRowHeight

                                                    // Attachment and encryption share one column:
                                                    // both are one-glyph facts about the message,
                                                    // and a message can carry both at once. Driven
                                                    // by the stored crypto column, so the list pays
                                                    // no extra query for the lock.
                                                    Row {
                                                        visible: rowCell.colId === "attach"
                                                        anchors.centerIn: parent
                                                        spacing: 2

                                                        Kirigami.Icon { // encrypted / signed marker
                                                            visible: msgDelegate.crypto > 0
                                                            source: msgDelegate.crypto === 2
                                                                    ? "mail-signed" : "mail-encrypted"
                                                            width: Kirigami.Units.iconSizes.small
                                                            height: width
                                                            opacity: 0.7
                                                        }
                                                        Kirigami.Icon { // paperclip / calendar-invite
                                                            visible: msgDelegate.hasAttachment
                                                            source: msgDelegate.calendarAttachment
                                                                    ? "view-calendar" : "mail-attachment"
                                                            width: Kirigami.Units.iconSizes.small
                                                            height: width
                                                            opacity: 0.7
                                                        }
                                                    }
                                                    QQC2.Label { // sender-authentication / spam marker
                                                        id: authMark
                                                        // One glyph for both, because to a reader
                                                        // they say the same thing. The tooltip is
                                                        // where they differ: authentication quotes
                                                        // the server, spam lists the rules that
                                                        // fired, so "Why?" always has an answer.
                                                        readonly property bool authFailed:
                                                            msgDelegate.suspicious && Mail.authVerification
                                                        visible: rowCell.colId === "subject"
                                                                 && (authFailed || msgDelegate.spam)
                                                        anchors.left: parent.left
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        text: "!"
                                                        color: Kirigami.Theme.negativeTextColor
                                                        font.bold: true
                                                        QQC2.ToolTip.text:
                                                            authMark.authFailed
                                                            ? "Sender authentication failed:\n" + msgDelegate.authInfo
                                                            : "Looks like spam:\n" + msgDelegate.spamDetail
                                                        QQC2.ToolTip.visible: authHover.hovered
                                                        HoverHandler { id: authHover }
                                                    }
                                                    QQC2.Label {
                                                        visible: rowCell.colId !== "attach"
                                                        anchors.left: parent.left
                                                        anchors.right: parent.right
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        anchors.leftMargin: authMark.visible
                                                            ? authMark.width + Kirigami.Units.smallSpacing * 2
                                                            : Kirigami.Units.smallSpacing
                                                        anchors.rightMargin: Kirigami.Units.smallSpacing
                                                        text: rowCell.colId === "subject" ? msgDelegate.subject
                                                            : rowCell.colId === "from" ? msgDelegate.from
                                                            : rowCell.colId === "date" ? msgDelegate.date : ""
                                                        elide: Text.ElideRight
                                                        font.bold: rowCell.colId === "subject" && !msgDelegate.seen
                                                        // Secondary columns are dimmed to ≥7:1 (AAA) on
                                                        // normal rows, but shown at full opacity when the
                                                        // row is highlighted — the theme's selection color
                                                        // is already low-contrast, so dimming there would
                                                        // push it further below AA.
                                                        opacity: (rowCell.colId === "subject"
                                                                  || msgDelegate.highlighted) ? 1 : 0.8
                                                        // A marked, selected row shows the
                                                        // mark as its TEXT color (the tint
                                                        // background is suppressed under
                                                        // selection). When not selected the
                                                        // mark lives in the background tint,
                                                        // so text uses the normal theme color.
                                                        color: (msgDelegate.highlighted && msgDelegate.markColor !== "")
                                                               ? msgDelegate.markColor
                                                               : msgDelegate.highlighted
                                                                 ? Kirigami.Theme.highlightedTextColor
                                                                 : Kirigami.Theme.textColor
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    Kirigami.PlaceholderMessage {
                                        anchors.centerIn: parent
                                        width: parent.width - Kirigami.Units.gridUnit * 4
                                        // Not while a search runs: an empty list then means
                                        // "no results yet", which the spinner below says.
                                        visible: messageList.count === 0 && !Mail.searching
                                        text: Mail.connected ? "No messages" : "Not connected"
                                        icon.name: "mail-folder-inbox"
                                    }

                                    // Search progress lives here in the list, not in the
                                    // status breadcrumb. LoadingPlaceholder, not the
                                    // style's BusyIndicator — Breeze draws that as a cog.
                                    Kirigami.LoadingPlaceholder {
                                        anchors.centerIn: parent
                                        width: parent.width - Kirigami.Units.gridUnit * 4
                                        visible: Mail.searching && messageList.count === 0
                                        text: "Searching…"
                                    }

                                    // Results are already showing and more are coming: say
                                    // so over them instead of replacing them.
                                    QQC2.Label {
                                        anchors.horizontalCenter: parent.horizontalCenter
                                        anchors.bottom: parent.bottom
                                        anchors.bottomMargin: Kirigami.Units.largeSpacing
                                        visible: Mail.searching && messageList.count > 0
                                        padding: Kirigami.Units.smallSpacing
                                        text: "Searching — " + Mail.searchFound + " found"
                                        background: Kirigami.ShadowedRectangle {
                                            radius: Kirigami.Units.cornerRadius
                                            color: Kirigami.Theme.backgroundColor
                                            border.width: 1
                                            border.color: Kirigami.ColorUtils.linearInterpolation(
                                                Kirigami.Theme.backgroundColor,
                                                Kirigami.Theme.textColor, 0.2)
                                        }
                                    }
                                }
                            }
                        }

                        // Viewer pane — bottom half of the right side
                        MessageViewer {
                            id: viewer
                            context: Mail.readingContext
                            ui: uiSettings
                            // Only while the mail tab is up front: a message
                            // tab has its own viewer, and both answering Find
                            // or View source makes the shortcut ambiguous.
                            shortcutsActive: tabStack.currentIndex === 0
                            QQC2.SplitView.fillHeight: true
                            QQC2.SplitView.minimumHeight: 160
                            onReplyRequested: replyAll => composeSheet().openReply(Mail.replyData(replyAll))
                            onForwardRequested: composeSheet().openForward(Mail.forwardData())
                        }
                        }
                    }
                }
            }
        }
    }
}
