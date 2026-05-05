/* lua_debugger_files.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Files panel: scan plugin/script directories, navigate the tree.
 */

#ifndef LUA_DEBUGGER_FILES_H
#define LUA_DEBUGGER_FILES_H

#include <QIcon>
#include <QObject>
#include <QPair>
#include <QString>
#include <QVector>

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItem;
class QStandardItemModel;
class QTreeView;

/**
 * @brief Files panel: plugin/script indexing, hierarchical entries, open /
 *        reveal / copy gestures, and tree chrome.
 */
class LuaDebuggerFilesController : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerFilesController(LuaDebuggerDialog *host);

    void attach(QTreeView *tree, QStandardItemModel *model);

    /** @brief Decorations, scrollbar, and header sizing (after widgets exist). */
    void configureTreeChrome() const;

    void refreshAvailableScripts();

    void scanScriptDirectory(const QString &dir_path);

    /** @return True if a new leaf row was created. */
    bool ensureEntry(const QString &file_path);

    /** @brief Sort column 0 (after discrete inserts from callbacks). */
    void sortModel();

  public slots:
    void onItemDoubleClicked(const QModelIndex &index);
    void showContextMenu(const QPoint &pos);

  private:
    QStandardItem *findChildItemByPath(QStandardItem *parent, const QString &path) const;
    bool appendPathComponents(const QString &absolute_path, QVector<QPair<QString, QString>> &components) const;

    LuaDebuggerDialog *host_ = nullptr;
    QTreeView *tree_ = nullptr;
    QStandardItemModel *model_ = nullptr;

    /** @brief Stock icons used to decorate folder / leaf rows. Loaded
     *  in @ref attach so they're ready before the first ensureEntry. */
    QIcon folderIcon_;
    QIcon fileIcon_;
};

#endif
