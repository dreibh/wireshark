/* lua_debugger_settings.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Persistent UI settings for the Lua debugger (lua_debugger.json).
 */

#ifndef LUA_DEBUGGER_SETTINGS_H
#define LUA_DEBUGGER_SETTINGS_H

#include <QJsonArray>
#include <QVariantMap>

/**
 * @brief In-memory Lua debugger UI settings backed by lua_debugger.json
 *        (global personal config, not per-profile).
 */
class LuaDebuggerSettingsStore
{
  public:
    void loadFromFile();
    void saveToFile() const;

    QVariantMap &map() { return map_; }
    const QVariantMap &map() const { return map_; }

    /** QVariantMap values for JSON arrays are typically QVariantList of QVariantMap. */
    static QJsonArray jsonArrayAt(const QVariantMap &map, const char *key);

  private:
    QVariantMap map_;
};

#endif
