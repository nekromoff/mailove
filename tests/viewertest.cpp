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
