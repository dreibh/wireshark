/* lua_debugger_evaluate.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Evaluate panel: run Lua expressions while paused.
 */

#ifndef LUA_DEBUGGER_EVALUATE_H
#define LUA_DEBUGGER_EVALUATE_H

#include <QObject>
#include <QStringList>

class LuaDebuggerDialog;
class QPlainTextEdit;
class QPushButton;

/**
 * @brief Evaluate panel: enable/disable by pause state, run expressions,
 *        clear I/O, and append batched logpoint lines to the output.
 */
class LuaDebuggerEvalController : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerEvalController(LuaDebuggerDialog *host);

    void attach(QPlainTextEdit *input, QPlainTextEdit *output, QPushButton *evalBtn, QPushButton *clearBtn);

    void updatePanelState() const;

    /** @brief Append lines (e.g. logpoint drain) and scroll to the end. */
    void appendOutputLines(const QStringList &lines);

  public slots:
    void onEvaluate();
    void onEvalClear();

  private:
    LuaDebuggerDialog *host_ = nullptr;
    QPlainTextEdit *input_ = nullptr;
    QPlainTextEdit *output_ = nullptr;
    QPushButton *evalBtn_ = nullptr;
    QPushButton *clearBtn_ = nullptr;
};

#endif
