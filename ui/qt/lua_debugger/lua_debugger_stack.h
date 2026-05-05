/* lua_debugger_stack.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Call-stack panel: column layout, model build, frame selection.
 */

#ifndef LUA_DEBUGGER_STACK_H
#define LUA_DEBUGGER_STACK_H

#include <QObject>

#include "lua_debugger_utils.h"

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItemModel;
class QTreeView;

/** @brief Column indices for the Stack Trace tree model. */
namespace StackColumn
{
constexpr int Function = 0;
constexpr int Location = 1;
constexpr int Count = 2;
} // namespace StackColumn

/**
 * @brief Stack trace panel: column layout, rebuild from the engine, selection
 *        → variables frame, open-source gestures, and context menu.
 */
class LuaDebuggerStackController : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerStackController(LuaDebuggerDialog *host);

    void attach(QTreeView *tree, QStandardItemModel *model);

    void configureColumns() const;

    /** @brief Rebuild rows from @c wslua_debugger_get_stack. */
    void updateFromEngine();

    /** @brief Stack frame index whose locals/upvalues currently drive the
     *  Variables and Watch panels (0 = topmost / paused frame). Owned here
     *  because every panel that needs it is downstream of stack selection. */
    int selectionLevel() const { return selectionLevel_; }

    /** @brief Update the active stack frame index. Does not refresh anything;
     *  callers are expected to follow up with the appropriate variable/watch
     *  refresh. */
    void setSelectionLevel(int level) { selectionLevel_ = level; }

  public slots:
    void onCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    void onItemDoubleClicked(const QModelIndex &index);
    void showContextMenu(const QPoint &pos);

  private:
    LuaDebuggerDialog *host_ = nullptr;
    QTreeView *tree_ = nullptr;
    QStandardItemModel *model_ = nullptr;
    int selectionLevel_ = 0;
};

#endif
