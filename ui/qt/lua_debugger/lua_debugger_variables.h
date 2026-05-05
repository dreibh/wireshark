/* lua_debugger_variables.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Variables panel: Locals / Upvalues / Globals tree, lazy expansion.
 */

#ifndef LUA_DEBUGGER_VARIABLES_H
#define LUA_DEBUGGER_VARIABLES_H

#include <QHash>
#include <QObject>
#include <QString>

#include "lua_debugger_utils.h"

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItem;
class QStandardItemModel;
class QTreeView;

/** @brief Column indices for the Variables tree model. */
namespace VariablesColumn
{
constexpr int Name = 0;
constexpr int Value = 1;
constexpr int Type = 2;
constexpr int Count = 3;
} // namespace VariablesColumn

/**
 * @brief Variables panel: column sizing, expansion persistence, lazy child
 *        fill on expand, context menu, and selection helpers.
 */
class LuaDebuggerVariablesController : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerVariablesController(LuaDebuggerDialog *host);

    void attach(QTreeView *tree, QStandardItemModel *model);

    void configureColumns() const;

    /** @brief Re-expand Locals/Globals/Upvalues after a variables refresh. */
    void restoreExpansionState() const;

    /** @brief Clear the model, re-fetch Locals/Globals/Upvalues from the engine,
     *  and re-apply persisted expansion. */
    void rebuildFromEngine();

    /** @brief Append children of @p path under @p parent (or as new top-level
     *  rows when @p parent is null). Used by @ref rebuildFromEngine for the
     *  initial Locals/Globals/Upvalues fetch and by @ref onExpanded for
     *  lazy descent into nested tables. Reaches back to the dialog for
     *  change-highlight baselines and the active stack frame. */
    void fetchAndAppend(QStandardItem *parent, const QString &path);

    QStandardItem *findItemByPath(const QString &path) const;

    QHash<QString, LuaDbgTreeSectionExpansionState> &expansionMap() { return expansion_; }

    const QHash<QString, LuaDbgTreeSectionExpansionState> &expansionMap() const { return expansion_; }

  public slots:
    void showContextMenu(const QPoint &pos);
    void onExpanded(const QModelIndex &index);
    void onCollapsed(const QModelIndex &index);

  private:
    LuaDebuggerDialog *host_ = nullptr;
    QTreeView *tree_ = nullptr;
    QStandardItemModel *model_ = nullptr;
    QHash<QString, LuaDbgTreeSectionExpansionState> expansion_;
};

#endif
