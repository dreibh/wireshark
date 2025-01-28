/* stratoshark_application.cpp
 *
 * Stratoshark - System call and event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_application.h"

StratosharkApplication *ssApp;

StratosharkApplication::StratosharkApplication(int &argc, char **argv) :
    MainApplication(argc, argv)
{
    ssApp = this;
    Q_INIT_RESOURCE(ssicon);
    setApplicationName("Stratoshark");
    setDesktopFileName(QStringLiteral("org.wireshark.Stratoshark"));
}

StratosharkApplication::~StratosharkApplication()
{
    ssApp = NULL;
}

void StratosharkApplication::initializeIcons()
{
    // Do this as late as possible in order to allow time for
    // MimeDatabaseInitThread to do its work.
    QList<int> icon_sizes = QList<int>() << 16 << 24 << 32 << 48 << 64 << 128 << 256 << 512 << 1024;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QStringLiteral(":/ssicon/ssicon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QStringLiteral(":/ssicon/ssiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }
}
