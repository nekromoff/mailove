// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// Offscreen end-to-end check of the message-viewer pipeline:
// registers the mailove: scheme, serves HTML through ViewerSchemeHandler,
// loads it in a WebEngineView with production settings, and verifies the
// document title arrives. Exit 0 = viewer pipeline works.
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickItem>
#include <QTimer>
#include <QtWebEngineQuick/qtwebenginequickglobal.h>

#include "../src/viewersecurity.h"

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");

    // Save all images: what the context menu lists from a served body.
    {
        const QByteArray csp = "<meta http-equiv=\"Content-Security-Policy\" content=\"img-src mailove: data:; \">";
        const QByteArray cspRemote = "<meta http-equiv=\"Content-Security-Policy\" content=\"img-src mailove: data: https: http:; \">";
        const QByteArray body =
            "<p><img src=\"mailove:cid/7/image001.png@01D\" width=\"300\">"
            "<IMG alt=x SRC='data:image/png;base64,iVBORw0KGgo='>"
            "<img src=\"mailove:cid/7/image001.png@01D\">"          // duplicate
            "<img src=\"https://t.example/p.gif?a=1&amp;b=2\" width=1 height=1>" // pixel
            "<img src=\"https://cdn.example/photo.jpg?x=1&amp;y=2\">"
            "<img src=\"cid:never-rewritten\"></p>";
        const QStringList blocked = ViewerSchemeHandler::imagesInHtml(csp + body);
        const QStringList allowed = ViewerSchemeHandler::imagesInHtml(cspRemote + body);
        const QStringList wantBlocked = {QStringLiteral("mailove:cid/7/image001.png@01D"),
                                         QStringLiteral("data:image/png;base64,iVBORw0KGgo=")};
        const QStringList wantAllowed =
            wantBlocked + QStringList{QStringLiteral("https://cdn.example/photo.jpg?x=1&y=2")};
        if (blocked != wantBlocked || allowed != wantAllowed) {
            fprintf(stderr, "FAIL: imagesInHtml\n  blocked: %s\n  allowed: %s\n",
                    qPrintable(blocked.join(QLatin1String(" | "))),
                    qPrintable(allowed.join(QLatin1String(" | "))));
            return 1;
        }
        fprintf(stderr, "PASS: imagesInHtml lists shown images, skips pixels and blocked remotes\n");
    }
    ViewerSchemeHandler::registerScheme();
    QtWebEngineQuick::initialize();
    QGuiApplication app(argc, argv);

    ViewerSchemeHandler *handler = ViewerSchemeHandler::install();
    const quint64 context = handler->allocateContext();
    const QString url = handler->setMessageHtml(
        context,
        QByteArrayLiteral("<meta charset=\"utf-8\"><html><head><title>MAILOVE_OK</title></head>"
                          "<body><p>hello été</p></body></html>"));

    QQmlApplicationEngine engine;
    engine.loadData(QByteArrayLiteral(
        "import QtQuick\n"
        "import QtWebEngine\n"
        "Window { visible: true; width: 640; height: 480\n"
        "  WebEngineView { id: web; objectName: \"web\"; anchors.fill: parent\n"
        "    settings.javascriptEnabled: false\n"
        "    settings.localContentCanAccessFileUrls: false\n"
        "    settings.localContentCanAccessRemoteUrls: false\n"
        "  }\n"
        "}\n"));
    if (engine.rootObjects().isEmpty()) {
        qCritical("FAIL: QML did not load");
        return 2;
    }
    QObject *web = engine.rootObjects().first()->findChild<QObject *>("web");
    web->setProperty("url", url);

    QTimer poll;
    int elapsed = 0;
    QObject::connect(&poll, &QTimer::timeout, [&] {
        elapsed += 200;
        const QString title = web->property("title").toString();
        if (title == QLatin1String("MAILOVE_OK")) {
            qInfo("PASS: mailove: scheme served and rendered (title=%s)", qPrintable(title));
            QCoreApplication::exit(0);
        } else if (elapsed >= 10000) {
            qCritical("FAIL: timeout, title=\"%s\" url=%s loading=%d",
                      qPrintable(title),
                      qPrintable(web->property("url").toUrl().toString()),
                      web->property("loading").toBool());
            QCoreApplication::exit(1);
        }
    });
    poll.start(200);
    return app.exec();
}
