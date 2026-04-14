/* lua_debugger_code_view.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_CODE_VIEW_H
#define LUA_DEBUGGER_CODE_VIEW_H

#include <QFont>
#include <QObject>
#include <QPlainTextEdit>
#include <QtGlobal>

class QSyntaxHighlighter;

/**
 * @brief Read-only code editor supporting gutter breakpoints and highlighting.
 */
class LuaDebuggerCodeView : public QPlainTextEdit
{
    Q_OBJECT

  public:
    /**
     * @brief Create the code view and configure the line number gutter.
     * @param parent Optional parent widget for ownership.
     */
    LuaDebuggerCodeView(QWidget *parent = nullptr);

    /**
     * @brief Paint the custom gutter that hosts line numbers and breakpoints.
     * @param event Exposes the area to repaint.
     */
    void lineNumberAreaPaintEvent(QPaintEvent *event);
    /**
     * @brief Compute the width required for the gutter, including icons.
     * @return Width in device-independent pixels.
     */
    qint32 lineNumberAreaWidth();

    void setFilename(const QString &f) { filename = f; }
    QString getFilename() const { return filename; }
    /**
     * @brief Highlight and scroll to the requested line.
     * @param line Line number to select (1-based).
     */
    void setCurrentLine(qint32 line);
    /** @brief Remove any current-line highlight from the view. */
    void clearCurrentLineHighlight();
    /** @brief Apply a monospace font to both editor text and gutter. */
    void setEditorFont(const QFont &font);
    /** @brief Refresh breakpoint markers in the gutter area. */
    void updateBreakpointMarkers();
    /** @brief Re-apply theme colors from the current preference. */
    void applyTheme();

  signals:
    /** @brief Emitted when a breakpoint icon is clicked within the gutter. */
    void breakpointToggled(const QString &filename, qint32 line);

  protected:
    /** @brief Update margins whenever Qt reports a size change. */
    void resizeEvent(QResizeEvent *event) override;

  private slots:
    /** @brief Update margins to accommodate new block digits. */
    void updateLineNumberAreaWidth(int newBlockCount);
    /** @brief Recompute the highlight for the active line. */
    void highlightCurrentLine();
    /** @brief Repaint the gutter when Qt issues update requests. */
    void updateLineNumberArea(const QRect &rect, int dy);

  private:
    QWidget *lineNumberArea;
    qint32 currentLine;
    QSyntaxHighlighter *syntaxHighlighter;

    friend class LineNumberArea;
    QString filename;
    /** @brief Apply a VS Code inspired dark palette to the editor. */
    void applyEditorPalette();
};

class LineNumberArea : public QWidget
{
  public:
    /**
     * @brief Construct the helper widget bound to a specific code view.
     * @param editor Owning code editor responsible for painting content.
     */
    LineNumberArea(LuaDebuggerCodeView *editor)
        : QWidget(editor), codeEditor(editor)
    {
    }

    /** @brief Size the gutter according to the editor's width requirements. */
    QSize sizeHint() const override
    {
        return QSize(codeEditor->lineNumberAreaWidth(), 0);
    }

  protected:
    /** @brief Delegate painting back to the code view. */
    void paintEvent(QPaintEvent *event) override
    {
        codeEditor->lineNumberAreaPaintEvent(event);
    }

    /** @brief Toggle breakpoints when the gutter is clicked. */
    void mousePressEvent(QMouseEvent *event) override;

  private:
    LuaDebuggerCodeView *codeEditor;
};

#endif // LUA_DEBUGGER_CODE_VIEW_H
