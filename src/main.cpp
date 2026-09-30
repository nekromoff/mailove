// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <QApplication>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QStyleHints>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QIcon>
#include <QTimer>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QtWebEngineQuick/qtwebenginequickglobal.h>
#include <qt6keychain/keychain.h>

#include "advancedconfig.h"
#include "avatarprovider.h"
#include "diagnosticslog.h"
#include "settingsbackup.h"
#include "uisettings.h"
#include "updatecheck.h"
#include "documenthandler.h"
#include "mailclient.h"
#include "messagecontext.h"
#include "pgpengine.h"
#include "pgpkeymodel.h"
#include "viewersecurity.h"

#include <QLoggingCategory>

#include <atomic>
#include <chrono>
#include <thread>
#ifdef Q_OS_LINUX
#include <csignal>
#include <execinfo.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstdlib>

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
    // Everything that survives the filter above is kept, whether or not
    // anyone is watching a terminal — running mailove from a launcher is the
    // normal case, and "reproduce it with logging on" is not something a
    // crash lets you do. See diagnosticslog.h: this only copies a string.
    DiagnosticsLog::instance().append(type, context, message);
    // The terminal's share. With detailed logging off it gets what it always
    // got — critical and worse — while the lines above it go to the log in
    // Settings, which is the half a GUI-only user can actually read.
    if (MailClient::consoleQuiet() && type != QtCriticalMsg && type != QtFatalMsg)
        return;
    if (g_previousHandler)
        g_previousHandler(type, context, message);
    else
        fprintf(stderr, "%s\n", qPrintable(qFormatLogMessage(type, context, message)));
}

namespace
{
qint64 steadyMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

/// Last heartbeat, in steadyMs(); 0 until the first one. Written by the GUI
/// thread, read by the watchdog.
std::atomic<qint64> g_lastBeatMs{0};
/// How many backtraces the watchdog took during the stall now ending —
/// consumed by the heartbeat that ends it, which logs them.
std::atomic<int> g_stallSamples{0};
#ifdef Q_OS_LINUX
std::atomic<bool> g_stallStop{false};
/// The samples themselves: raw return addresses, filled by the signal
/// handler and read back by the heartbeat once the GUI thread is running
/// again. Two slots, one per sample the watchdog takes.
constexpr int kStallFrames = 96;
void *g_stallFrames[2][kStallFrames];
std::atomic<int> g_stallFrameCount[2]{0, 0};
std::atomic<int> g_stallSlot{0};

/// Runs on the GUI thread, in the middle of whatever is blocking it. Only
/// async-signal-safe work: backtrace() into a static buffer. Resolving the
/// symbols allocates, so that waits for the heartbeat.
void stallSampleHandler(int)
{
    const int slot = g_stallSlot.load(std::memory_order_relaxed);
    if (slot < 0 || slot > 1)
        return;
    const int n = backtrace(g_stallFrames[slot], kStallFrames);
    g_stallFrameCount[slot].store(n, std::memory_order_release);
}

/// Appends the samples taken during the stall that just ended to the log,
/// right under its "stalled" line. Addresses into this binary: resolve with
/// addr2line -e mailove against the same build.
void logStallSamples(int samples)
{
    for (int slot = 0; slot < samples && slot < 2; ++slot) {
        const int n = g_stallFrameCount[slot].load(std::memory_order_acquire);
        if (n <= 0)
            continue;
        char **symbols = backtrace_symbols(g_stallFrames[slot], n);
        qCWarning(logTrace, "stall sample %d (%s):", slot + 1,
                  slot == 0 ? "at ~2 s" : "at ~6 s");
        // The top frames are the signal machinery and this handler; the
        // caller's code starts a few frames down. Logged whole anyway —
        // which frames are noise is easier to tell than to guess here.
        for (int i = 0; i < n; ++i)
            qCWarning(logTrace, "  #%02d %s", i, symbols ? symbols[i] : "?");
        free(symbols);
        g_stallFrameCount[slot].store(0, std::memory_order_relaxed);
    }
}
#endif

void startStallSampler(QCoreApplication *app)
{
#ifdef Q_OS_LINUX
    struct sigaction action {};
    action.sa_handler = stallSampleHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR2, &action, nullptr) != 0)
        return;
    const pthread_t gui = pthread_self();
    auto *watchdog = new std::thread([gui] {
        int taken = 0;
        while (!g_stallStop.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            const qint64 last = g_lastBeatMs.load(std::memory_order_relaxed);
            if (last == 0)
                continue;
            const qint64 silent = steadyMs() - last;
            // One sample at two seconds, one more at six: the first says
            // where it sits, the second whether it is still there.
            const int due = silent > 6000 ? 2 : silent > 2000 ? 1 : 0;
            if (due > taken) {
                g_stallSlot.store(taken, std::memory_order_relaxed);
                pthread_kill(gui, SIGUSR2);
                ++taken;
                g_stallSamples.store(taken, std::memory_order_relaxed);
            } else if (silent < 2000) {
                taken = 0;
            }
        }
    });
    QObject::connect(app, &QCoreApplication::aboutToQuit, app, [watchdog] {
        g_stallStop.store(true, std::memory_order_relaxed);
        watchdog->join();
        delete watchdog;
    });
#else
    Q_UNUSED(app);
#endif
}
} // namespace

int main(int argc, char *argv[])
{
    g_previousHandler = qInstallMessageHandler(filterMailHtmlNoise);
    // Quiet from the first instruction: the PSL cache and other startup work
    // log before MailClient reads the debug-logging setting and re-applies
    // the rules that match it. QT_LOGGING_RULES in the environment still
    // overrides both.
    MailClient::applyLogFilterRules(false);

    // --force-version=X makes the update check compare against X instead of
    // this build's version, so the "update available" marker can be exercised
    // without cutting a release. Scanned by hand rather than through
    // QCommandLineParser: Qt has already taken its own arguments by now, and a
    // parser here would start rejecting everything it did not recognise.
    for (int i = 1; i < argc; ++i) {
        const QLatin1StringView arg(argv[i]);
        if (arg.startsWith(QLatin1StringView("--force-version=")))
            UpdateCheck::setRunningVersion(QString::fromLocal8Bit(argv[i]).section(u'=', 1));
    }

    // The message preview turns black — and stays black for the rest of the
    // session — as soon as a drag passes over the application: QtWebEngine's
    // GPU compositor loses the view's texture when the drag takes the context
    // and nothing brings it back. Not a Wayland fault; xcb does it too.
    //
    // Only the compositing comes off the GPU. Rasterization stays on it: the
    // full --disable-gpu cures this as well, but gives up more than the bug
    // costs, and this narrower flag was enough to survive a drag.
    //
    // Appended rather than assigned, so flags set in the environment still
    // reach Chromium; skipped entirely when they already say --disable-gpu
    // (in either form), which also keeps this from stacking up on itself.
    const QByteArray chromiumFlags = qgetenv("QTWEBENGINE_CHROMIUM_FLAGS");
    if (!chromiumFlags.contains("--disable-gpu")) {
        const QByteArray flag("--disable-gpu-compositing");
        qputenv("QTWEBENGINE_CHROMIUM_FLAGS",
                chromiumFlags.isEmpty() ? flag : chromiumFlags + " " + flag);
    }

    ViewerSchemeHandler::registerScheme();
    QtWebEngineQuick::initialize();

    // QApplication, not QGuiApplication, purely for the file pickers. KDE's
    // native ones are widget-based, so without QtWidgets in the process the
    // platform theme cannot offer them and Qt Quick's own pickers open
    // instead — no Places sidebar, and colors of their own rather than the
    // desktop's. Nothing else here uses a widget.
    QApplication app(argc, argv);
    // The mirror on disk. Here and not earlier only because the writer thread
    // and the drain timer both need an event dispatcher on this thread, which
    // is what QApplication brings; everything logged before this point is
    // already buffered and lands in the first batch.
    DiagnosticsLog::instance().start();
    QGuiApplication::setOrganizationName(QStringLiteral("mailove"));
    QGuiApplication::setApplicationName(QStringLiteral("mailove"));
    QGuiApplication::setApplicationVersion(QStringLiteral(MAILOVE_VERSION));
    // Wayland matches a window to its .desktop entry (and hence its icon) by
    // app_id, which Qt takes from the desktop file name — it must be the
    // desktop entry's basename, not the application name. X11 uses the window
    // icon instead, so set both.
    //
    // The AppImage has no entry on the host under that name: either none at
    // all (run straight from Downloads) or the one AppImageLauncher/appimaged
    // wrote, which is prefixed — appimagekit_<hash>-org.mailove.Mailove. Take
    // whichever is there, so the icon matches; with none, leave the name
    // unset rather than announce an id the host cannot resolve, which Qt
    // reports on every launch as "Failed to register with host portal … App
    // info not found".
    QString desktopId = QStringLiteral("org.mailove.Mailove");
    if (!qEnvironmentVariableIsEmpty("APPIMAGE")) {
        const QString self = qEnvironmentVariable("APPDIR");
        QString found;
        const QStringList dirs =
            QStandardPaths::standardLocations(QStandardPaths::ApplicationsLocation);
        for (const QString &dir : dirs) {
            // Not the copy inside the mounted image: XDG_DATA_DIRS leads
            // with it (see the AppRun hook), and the portal never sees it.
            if (!self.isEmpty() && dir.startsWith(self))
                continue;
            const QStringList hits = QDir(dir).entryList(
                {QStringLiteral("*org.mailove.Mailove.desktop")}, QDir::Files);
            if (!hits.isEmpty()) {
                found = QFileInfo(hits.first()).completeBaseName();
                break;
            }
        }
        desktopId = found;
    }
    if (!desktopId.isEmpty())
        QGuiApplication::setDesktopFileName(desktopId);

    // Where the spare copy of the settings is taken from at exit. Nothing is
    // read from the backup here or anywhere else — see settingsbackup.h.
    const QString settingsPath =
        QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
        + QStringLiteral("/mailove/mailove.conf");
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
    //
    // Plus, on Linux, a sampler: a watchdog thread that sees the heartbeat
    // go quiet for two seconds signals the GUI thread, whose handler writes
    // its own backtrace to a file next to the log. A stall's duration says
    // that something blocked; only a stack from inside the stall says what.
    // Frames are addresses into this binary (resolve with addr2line against
    // the same build), which is what backtrace_symbols_fd can give from a
    // signal handler without allocating.
    {
        auto *beat = new QTimer(&app);
        auto *last = new QElapsedTimer;
        last->start();
        QObject::connect(beat, &QTimer::timeout, &app, [last] {
            const qint64 gap = last->restart();
            g_lastBeatMs.store(steadyMs(), std::memory_order_relaxed);
            const int samples = g_stallSamples.exchange(0, std::memory_order_relaxed);
            if (gap > 500) {
                qCWarning(logTrace, "GUI thread stalled ~%lld ms", gap - 100);
#ifdef Q_OS_LINUX
                logStallSamples(samples);
#else
                Q_UNUSED(samples);
#endif
            } else if (gap > 220) {
                qCDebug(logTrace, "GUI heartbeat late: %lld ms", gap - 100);
            }
        });
        beat->start(100);
        startStallSampler(&app);
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

    // Startup phases, so a slow launch says which one it was rather than only
    // that the GUI thread stalled. Cheap: four timestamps, all behind the
    // trace category.
    QElapsedTimer boot;
    boot.start();

    // Where a secret typed into advanced.conf goes. AdvancedConfig itself
    // knows nothing about wallets — it links into the test binaries, which
    // have none — so the one wallet write it needs is handed to it here, and
    // the sweep below moves anything a hand-edited file is already holding
    // before the first read of that file can see it.
    AdvancedConfig::setSecretSink([](const QString &walletKey, const QString &value) {
        if (value.isEmpty()) {
            auto *del = new QKeychain::DeletePasswordJob(QStringLiteral("mailove"), qApp);
            del->setKey(walletKey);
            del->start();
            return;
        }
        auto *write = new QKeychain::WritePasswordJob(QStringLiteral("mailove"), qApp);
        write->setKey(walletKey);
        write->setTextData(value);
        write->start();
    });
    AdvancedConfig::instance().sweepSecrets();
    qCDebug(logTrace, "boot: advanced settings %lld ms", boot.restart());

    ViewerSchemeHandler *viewerHandler = ViewerSchemeHandler::install();
    qCDebug(logTrace, "boot: viewer scheme handler %lld ms", boot.restart());

    MailClient client;
    qCDebug(logTrace, "boot: MailClient %lld ms", boot.restart());
    client.setViewerHandler(viewerHandler);

    // Constructed before the QML engine so PgpEngine::instance() is already
    // there when QML creates its first PgpKeyModel. Cheap when gpg is absent:
    // it works out that it is, and every operation then reports why.
    PgpEngine pgp;
    qCDebug(logTrace, "boot: PgpEngine %lld ms", boot.restart());
    client.setPgpEngine(&pgp);

    int rc = 0;
    {
    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Mail", &client);
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Pgp", &pgp);
    // The advanced settings editor. A singleton instance rather than a type:
    // the values it edits are read from every corner of the client, and there
    // is exactly one file behind them.
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Advanced", &AdvancedConfig::instance());
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "UiSettings", &UiSettings::instance());
    // Whether a newer release exists. Its own singleton rather than three more
    // properties on Mail: nothing about it touches mail, and it answers long
    // after everything else has settled.
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Updates", &UpdateCheck::instance());
    // A machine that was offline 30 seconds in still gets an answer once it has
    // a network; the daily interval keeps reconnects from meaning re-checks.
    QObject::connect(&client, &MailClient::connectedChanged, &UpdateCheck::instance(),
                     &UpdateCheck::maybeCheck);
    UpdateCheck::instance().start();
    // The log viewer's model, and the three things it can do with the text.
    qmlRegisterSingletonInstance("Mailove.Core", 1, 0, "Diagnostics",
                                 &DiagnosticsLog::instance());
    // Sender pictures. Registered only when they are switched on, so with the
    // default off there is not even a provider for an image://gravatar URL to
    // reach — and no fetcher thread standing by for one.
    if (AdvancedConfig::b("avatars/enabled"))
        engine.addImageProvider(QStringLiteral("gravatar"), new AvatarProvider);
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
    qCDebug(logTrace, "boot: QML registration %lld ms", boot.restart());
    engine.loadFromModule("Mailove", "Main");
    qCDebug(logTrace, "boot: Main.qml %lld ms", boot.restart());

    rc = app.exec();
    // Bracket the teardown: if the window disappears but the process does not,
    // this says whether the event loop even returned before the destructors ran.
    qCDebug(logTrace, "shutdown: event loop returned %d", rc);
    } // the QML engine dies here, and with it the last flush of QML Settings

    // Now the file is final, so the spare copy is of the settings as they were
    // actually left, not as they were found.
    SettingsBackup::write(settingsPath);

    // Last, so the shutdown trail above is on disk like every other line: the
    // half of a hang report that says whether the event loop returned at all.
    DiagnosticsLog::instance().stop();
    return rc;
}
