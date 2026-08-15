// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <QApplication>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QStyleHints>
#include <QIcon>
#include <QTimer>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QtWebEngineQuick/qtwebenginequickglobal.h>

#include "documenthandler.h"
#include "mailclient.h"
#include "messagecontext.h"
#include "pgpengine.h"
#include "pgpkeymodel.h"
#include "viewersecurity.h"

#include <QLoggingCategory>

#include <cstdio>

Q_DECLARE_LOGGING_CATEGORY(logTrace)

/// Drops Qt warnings that say nothing about mailove. Two come out of
/// QTextDocument while it parses a sender's HTML for the plain-text preview
/// and the search index:
///
///   QFont::setPixelSize: Pixel size <= 0        — "font-size:0", the standard
///                                                 way to hide preheader text
///   QTextHtmlParser: Unknown color name '#abc ' — a colour with a stray space,
///                                                 which Qt does not trim
///
/// Neither is actionable, both fire per message, and their volume is chosen by
/// the sender — a single message can bury the log in them, which is enough to
/// make real diagnostics unreadable.
///
/// The third is Kirigami's: ToolBarPageHeader.qml binds
/// `root.pageRow?.separatorVisible && …` to a bool, and with no PageRow (mailove
/// does not use one) the ?. yields undefined and the assignment warns —
/// upstream's bug, one line per header built. Anything else is passed through
/// untouched.
static QtMessageHandler g_previousHandler = nullptr;

static void filterMailHtmlNoise(QtMsgType type, const QMessageLogContext &context,
                                const QString &message)
{
    if (message.startsWith(QLatin1String("QFont::setPixelSize: Pixel size <= 0"))
        || message.startsWith(QLatin1String("QTextHtmlParser::applyAttributes: "
                                            "Unknown color name")))
        return;
    if (message.contains(QLatin1String("ToolBarPageHeader.qml"))
        && message.contains(QLatin1String("Unable to assign [undefined] to bool")))
        return;
    if (g_previousHandler)
        g_previousHandler(type, context, message);
    else
        fprintf(stderr, "%s\n", qPrintable(qFormatLogMessage(type, context, message)));
}

int main(int argc, char *argv[])
{
    g_previousHandler = qInstallMessageHandler(filterMailHtmlNoise);
    // Quiet from the first instruction: the PSL cache and other startup work
    // log before MailClient reads the debug-logging setting and re-applies
    // the rules that match it. QT_LOGGING_RULES in the environment still
    // overrides both.
    MailClient::applyLogFilterRules(false);

    ViewerSchemeHandler::registerScheme();
    QtWebEngineQuick::initialize();

    // QApplication, not QGuiApplication, purely for the file pickers. KDE's
    // native ones are widget-based, so without QtWidgets in the process the
    // platform theme cannot offer them and Qt Quick's own pickers open
    // instead — no Places sidebar, and colors of their own rather than the
    // desktop's. Nothing else here uses a widget.
    QApplication app(argc, argv);
    QGuiApplication::setOrganizationName(QStringLiteral("mailove"));
    QGuiApplication::setApplicationName(QStringLiteral("mailove"));
    QGuiApplication::setApplicationVersion(QStringLiteral(MAILOVE_VERSION));
    // Wayland matches a window to its .desktop entry (and hence its icon) by
    // app_id, which Qt takes from the desktop file name — it must be the
    // desktop entry's basename, not the application name. X11 uses the window
    // icon instead, so set both.
    QGuiApplication::setDesktopFileName(QStringLiteral("org.mailove.Mailove"));
    // Press-and-hold reveals secondary actions (the Forward button's
    // "as attachment"); the platform default of 800ms reads as "nothing is
    // happening". Snappier, still long past any click.
    QGuiApplication::styleHints()->setMousePressAndHoldInterval(450);

    // The UI asks for named icons (mail-attachment, arrow-down, …), which only
    // resolve once an icon theme is set. A KDE session sets one; anything else
    // — a bare Wayland/X11 session, or the AppImage, which bundles Breeze but
    // has no session to announce it — leaves it unset and every icon renders
    // as an empty square. Only overridden when nothing usable is configured,
    // so a user's own theme still wins.
    QIcon::setFallbackThemeName(QStringLiteral("breeze"));
    if (QIcon::themeName().isEmpty()
        || !QIcon::hasThemeIcon(QStringLiteral("mail-message-new"))) {
        QIcon::setThemeName(QStringLiteral("breeze"));
    }
    QGuiApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("org.mailove.Mailove")));

    // GUI-thread stall detector: a 100 ms heartbeat whose late firing is the
    // definition of a frozen UI. Everything instrumented so far (cache
    // queries, model appends) reports fast while scrolling still hitches, so
    // this pins down when the event loop itself stops turning and for how
    // long — anything above half a second is loud, smaller gaps go to the
    // trace. Purely an observer: one timer, no per-event cost.
    {
        auto *beat = new QTimer(&app);
        auto *last = new QElapsedTimer;
        last->start();
        QObject::connect(beat, &QTimer::timeout, &app, [last] {
            const qint64 gap = last->restart();
            if (gap > 500)
                qWarning("mailove: GUI thread stalled ~%lld ms", gap - 100);
            else if (gap > 220)
                qCDebug(logTrace, "GUI heartbeat late: %lld ms", gap - 100);
        });
        beat->start(100);
    }

    if (qEnvironmentVariableIsEmpty("QT_QUICK_CONTROLS_STYLE"))
        QQuickStyle::setStyle(QStringLiteral("org.kde.desktop"));
    // What anything org.kde.desktop does not implement falls back to. It does
    // not implement the file/folder/color pickers, and off a KDE session (no
    // platform theme to supply the native ones) Qt Quick's are what opens.
    // Left to itself that fallback is the Basic style, whose colors are
    // hardcoded rather than taken from the palette: a pale blue selection
    // under white text, roughly 1.6:1, and identical in a dark theme. Fusion
    // follows the system palette instead.
    QQuickStyle::setFallbackStyle(QStringLiteral("Fusion"));

    ViewerSchemeHandler *viewerHandler = ViewerSchemeHandler::install();

    MailClient client;
    client.setViewerHandler(viewerHandler);

    // Constructed before the QML engine so PgpEngine::instance() is already
    // there when QML creates its first PgpKeyModel. Cheap when gpg is absent:
    // it works out that it is, and every operation then reports why.
    PgpEngine pgp;
    client.setPgpEngine(&pgp);

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Mail", &client);
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Pgp", &pgp);
    qmlRegisterType<DocumentHandler>("Mailove.Core", 1, 0, "DocumentHandler");
    // Created per view: the key manager and each key picker filter differently
    // over the one keyring snapshot PgpEngine holds.
    qmlRegisterType<PgpKeyModel>("Mailove.Core", 1, 0, "PgpKeyModel");
    // Created only by MailClient (reading pane + detached message windows).
    qmlRegisterUncreatableType<MessageContext>(
        "Mailove.Core", 1, 0, "MessageContext",
        QStringLiteral("MessageContext instances come from Mail"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
                     &app, [] { QCoreApplication::exit(1); },
                     Qt::QueuedConnection);
    engine.loadFromModule("Mailove", "Main");

    const int rc = app.exec();
    // Bracket the teardown: if the window disappears but the process does not,
    // this says whether the event loop even returned before the destructors ran.
    qCDebug(logTrace, "shutdown: event loop returned %d", rc);
    return rc;
}
