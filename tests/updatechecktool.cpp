// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// Runs one real update check and says what it concluded, with the update log
// category turned on. The GUI can only ever show the answer or not show it;
// this prints every step in between, which is what you want when the marker
// does not appear and you need to know whether the request went out, what came
// back, and how it compared.
//
//   updatechecktool [forced-version]
//
// Point XDG_CONFIG_HOME somewhere disposable before running it: the check
// reads and writes update/lastCheck and update/latestSeen in mailove.conf, and
// a run here should not be able to move what the real app sees.

#include <QCoreApplication>
#include <QLoggingCategory>
#include <QStandardPaths>
#include <QTimer>

#include <cstdio>

#include "../src/advancedconfig.h"
#include "../src/updatecheck.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));
    QLoggingCategory::setFilterRules(QStringLiteral("mailove.update.debug=true\n"
                                                    "mailove.update.info=true"));

    fprintf(stderr, "config: %s\n",
            qPrintable(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)));

    if (argc > 1) {
        UpdateCheck::setRunningVersion(QString::fromLocal8Bit(argv[1]));
        fprintf(stderr, "forced running version: %s\n",
                qPrintable(UpdateCheck::runningVersion()));
    }
    fprintf(stderr, "checkEnabled=%d url=%s interval=%dh\n",
            AdvancedConfig::b("update/checkEnabled"),
            qPrintable(AdvancedConfig::s("update/checkUrl")),
            AdvancedConfig::i("update/checkIntervalHours"));
    fprintf(stderr, "comparing against: %s\n", qPrintable(UpdateCheck::runningVersion()));
    // Before any request: what the constructor restored from the last completed
    // check. This is what puts the marker on screen at launch.
    fprintf(stderr, "cached at construction: available=%d latest=%s\n",
            UpdateCheck::instance().available(),
            qPrintable(UpdateCheck::instance().latestVersion()));

    QObject::connect(&UpdateCheck::instance(), &UpdateCheck::changed, &app, [] {
        fprintf(stderr, "\nRESULT available=%d latest=%s url=%s\n",
                UpdateCheck::instance().available(),
                qPrintable(UpdateCheck::instance().latestVersion()),
                qPrintable(UpdateCheck::instance().releaseUrl()));
        QCoreApplication::exit(0);
    });

    UpdateCheck::instance().checkNow();

    QTimer::singleShot(15000, &app, [] {
        fprintf(stderr, "\nRESULT no change signal within 15s; available=%d\n",
                UpdateCheck::instance().available());
        QCoreApplication::exit(1);
    });
    return app.exec();
}

