/* lua_debugger_code_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lua_debugger_code_view.h"
#include "lua_debugger_dialog.h"

#include <algorithm>

#include <QColor>
#include <QContextMenuEvent>
#include <QEvent>
#include <QFontDatabase>
#include <QKeyEvent>
#include <QMetaObject>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextCharFormat>

#include "epan/wslua/wslua_debugger.h"
#include "main_application.h"
#include "utils/color_utils.h"

namespace
{

constexpr qint32 kStringStateBase =
    0x1000; // Unique positive range for long strings
constexpr qint32 kCommentStateBase =
    0x2000; // Distinct positive range for block comments

/**
 * @brief Theme color definitions for syntax highlighting.
 */
struct ThemeColors
{
    QColor stringColor;
    QColor keywordColor;
    QColor numberColor;
    QColor builtInColor;
    QColor functionCallColor;
    QColor commentColor;
};

/**
 * @brief Get theme colors based on the current preference.
 * @param isDark true for dark theme, false for light theme.
 * @return ThemeColors structure with appropriate colors.
 */
static ThemeColors getThemeColors(bool isDark)
{
    ThemeColors colors;
    if (isDark)
    {
        // VS Code Dark+ inspired colors
        colors.stringColor = QColor("#CE9178");
        colors.keywordColor = QColor("#569CD6");
        colors.numberColor = QColor("#B5CEA8");
        colors.builtInColor = QColor("#4FC1FF");
        colors.functionCallColor = QColor("#DCDCAA");
        colors.commentColor = QColor("#6A9955");
    }
    else
    {
        // VS Code Light+ inspired colors
        colors.stringColor = QColor("#A31515");
        colors.keywordColor = QColor("#0000FF");
        colors.numberColor = QColor("#098658");
        colors.builtInColor = QColor("#267F99");
        colors.functionCallColor = QColor("#795E26");
        colors.commentColor = QColor("#008000");
    }
    return colors;
}

/**
 * @brief Resolve the effective theme based on the preference setting.
 *
 * When the debugger theme preference is set to AUTO, this function
 * uses ColorUtils::themeIsDark() to detect Wireshark's current theme.
 * Otherwise, it returns the explicit preference choice.
 *
 * @return true for dark theme, false for light theme.
 */
static bool resolveIsDarkTheme()
{
    const int32_t themePref = LuaDebuggerDialog::currentTheme();
    if (themePref == WSLUA_DEBUGGER_THEME_AUTO)
    {
        return ColorUtils::themeIsDark();
    }
    return (themePref == WSLUA_DEBUGGER_THEME_DARK);
}

struct HighlightingRule
{
    QRegularExpression pattern;
    QTextCharFormat format;
};

/**
 * @brief Syntax highlighter tuned for Lua keywords, strings, and comments.
 */
class LuaSyntaxHighlighter : public QSyntaxHighlighter
{
  public:
    /** @brief Build the rule set and bind to the owning document. */
    explicit LuaSyntaxHighlighter(QTextDocument *parent = nullptr);

    /** @brief Update colors based on theme preference. */
    void setTheme(bool isDark);

  protected:
    /** @brief Apply highlighting to a single text block. */
    void highlightBlock(const QString &text) override;

  private:
    QVector<HighlightingRule> highlightingRules;
    QTextCharFormat stringFormat;
    QTextCharFormat commentFormat;
    QRegularExpression singleLineCommentPattern;

    /** @brief Highlight multi-line strings or comments, preserving parser
     * state. */
    bool highlightLongBlock(const QString &text, bool isComment,
                            bool continuingPrevious, qint32 eqCountFromState,
                            qint32 &nextStateEqCount);
    /** @brief Locate the beginning of a Lua long bracket token. */
    qint32 findLongBlockStart(const QString &text, qint32 from, bool isComment,
                              qint32 &eqCount, qint32 &tokenLength) const;
    /** @brief Locate the closing delimiter for a Lua long bracket token. */
    qint32 findLongBlockEnd(const QString &text, qint32 from,
                            qint32 eqCount) const;

    void buildRules(const ThemeColors &colors);
};

LuaSyntaxHighlighter::LuaSyntaxHighlighter(QTextDocument *parent)
    : QSyntaxHighlighter(parent)
{
    singleLineCommentPattern =
        QRegularExpression(QStringLiteral(R"(--(?!\[).*)"));
    const bool isDark = resolveIsDarkTheme();
    buildRules(getThemeColors(isDark));
}

void LuaSyntaxHighlighter::setTheme(bool isDark)
{
    buildRules(getThemeColors(isDark));
    rehighlight();
}

void LuaSyntaxHighlighter::buildRules(const ThemeColors &colors)
{
    highlightingRules.clear();

    stringFormat.setForeground(colors.stringColor);
    highlightingRules.append(
        {QRegularExpression(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"")),
         stringFormat});
    highlightingRules.append(
        {QRegularExpression(QStringLiteral("'(?:\\\\.|[^'\\\\])*'")),
         stringFormat});

    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(colors.keywordColor);
    keywordFormat.setFontWeight(QFont::Bold);
    const QStringList keywords = {
        QStringLiteral("and"),      QStringLiteral("break"),
        QStringLiteral("do"),       QStringLiteral("else"),
        QStringLiteral("elseif"),   QStringLiteral("end"),
        QStringLiteral("false"),    QStringLiteral("for"),
        QStringLiteral("function"), QStringLiteral("goto"),
        QStringLiteral("if"),       QStringLiteral("in"),
        QStringLiteral("local"),    QStringLiteral("nil"),
        QStringLiteral("not"),      QStringLiteral("or"),
        QStringLiteral("repeat"),   QStringLiteral("return"),
        QStringLiteral("then"),     QStringLiteral("true"),
        QStringLiteral("until"),    QStringLiteral("while")};
    for (const QString &keyword : keywords)
    {
        HighlightingRule rule;
        rule.pattern =
            QRegularExpression(QStringLiteral("\\b%1\\b").arg(keyword));
        rule.format = keywordFormat;
        highlightingRules.append(rule);
    }

    QTextCharFormat numberFormat;
    numberFormat.setForeground(colors.numberColor);
    highlightingRules.append(
        {QRegularExpression(QStringLiteral("\\b0[xX][0-9a-fA-F]+\\b")),
         numberFormat});
    highlightingRules.append(
        {QRegularExpression(QStringLiteral("\\b\\d+(?:\\.\\d+)?\\b")),
         numberFormat});

    QTextCharFormat builtInFormat;
    builtInFormat.setForeground(colors.builtInColor);
    highlightingRules.append(
        {QRegularExpression(QStringLiteral("\\bself\\b")), builtInFormat});

    QTextCharFormat functionCallFormat;
    functionCallFormat.setForeground(colors.functionCallColor);
    HighlightingRule functionCallRule;
    functionCallRule.pattern = QRegularExpression(
        QStringLiteral("\\b(?!function\\b)([A-Za-z_]\\w*)\\s*(?=\\()"));
    functionCallRule.format = functionCallFormat;
    highlightingRules.append(functionCallRule);

    commentFormat.setForeground(colors.commentColor);
}

void LuaSyntaxHighlighter::highlightBlock(const QString &text)
{
    for (const HighlightingRule &rule : highlightingRules)
    {
        QRegularExpressionMatchIterator iterator =
            rule.pattern.globalMatch(text);
        while (iterator.hasNext())
        {
            const QRegularExpressionMatch match = iterator.next();
            setFormat(static_cast<int>(match.capturedStart()),
                      static_cast<int>(match.capturedLength()), rule.format);
        }
    }

    QRegularExpressionMatchIterator commentMatches =
        singleLineCommentPattern.globalMatch(text);
    while (commentMatches.hasNext())
    {
        const QRegularExpressionMatch match = commentMatches.next();
        setFormat(static_cast<int>(match.capturedStart()),
                  static_cast<int>(match.capturedLength()), commentFormat);
    }

    const qint32 previousState = previousBlockState();
    const bool continuingString = (previousState >= kStringStateBase) &&
                                  (previousState < kCommentStateBase);
    const bool continuingComment = previousState >= kCommentStateBase;
    const qint32 stringEqCount =
        continuingString ? (previousState - kStringStateBase) : 0;
    const qint32 commentEqCount =
        continuingComment ? (previousState - kCommentStateBase) : 0;

    qint32 nextStringEqCount = 0;
    const bool stringStillOpen = highlightLongBlock(
        text, false, continuingString, stringEqCount, nextStringEqCount);

    qint32 nextCommentEqCount = 0;
    const bool commentStillOpen = highlightLongBlock(
        text, true, continuingComment, commentEqCount, nextCommentEqCount);

    if (commentStillOpen)
    {
        setCurrentBlockState(kCommentStateBase + nextCommentEqCount);
    }
    else if (stringStillOpen)
    {
        setCurrentBlockState(kStringStateBase + nextStringEqCount);
    }
    else
    {
        setCurrentBlockState(0);
    }
}

bool LuaSyntaxHighlighter::highlightLongBlock(const QString &text,
                                              bool isComment,
                                              bool continuingPrevious,
                                              qint32 eqCountFromState,
                                              qint32 &nextStateEqCount)
{
    QTextCharFormat format = isComment ? commentFormat : stringFormat;
    qint32 eqCount = eqCountFromState;
    qint32 tokenLength = 0;
    bool continuing = continuingPrevious;
    qint32 startIndex = continuing ? 0
                                   : findLongBlockStart(text, 0, isComment,
                                                        eqCount, tokenLength);

    while (startIndex >= 0)
    {
        const qint32 searchFrom = continuing ? 0 : startIndex + tokenLength;
        const qint32 endIndex = findLongBlockEnd(text, searchFrom, eqCount);
        if (endIndex == -1)
        {
            setFormat(startIndex, static_cast<int>(text.length()) - startIndex,
                      format);
            nextStateEqCount = eqCount;
            return true;
        }

        setFormat(startIndex, endIndex - startIndex + 1, format);
        continuing = false;
        startIndex = findLongBlockStart(text, endIndex + 1, isComment, eqCount,
                                        tokenLength);
    }

    nextStateEqCount = 0;
    return false;
}

qint32 LuaSyntaxHighlighter::findLongBlockStart(const QString &text,
                                                qint32 from, bool isComment,
                                                qint32 &eqCount,
                                                qint32 &tokenLength) const
{
    const qint32 len = static_cast<qint32>(text.length());
    for (qint32 i = from; i < len; ++i)
    {
        if (isComment)
        {
            if (i + 3 >= len)
            {
                break;
            }
            if (text[i] == '-' && text[i + 1] == '-' && text[i + 2] == '[')
            {
                qint32 j = i + 3;
                qint32 equals = 0;
                while (j < len && text[j] == '=')
                {
                    ++equals;
                    ++j;
                }
                if (j < len && text[j] == '[')
                {
                    eqCount = equals;
                    tokenLength = (j - i) + 1;
                    return i;
                }
            }
        }
        else
        {
            if (text[i] == '[')
            {
                if (i >= 2 && text[i - 2] == '-' && text[i - 1] == '-')
                {
                    continue; // Part of comment start, skip
                }
                qint32 j = i + 1;
                qint32 equals = 0;
                while (j < len && text[j] == '=')
                {
                    ++equals;
                    ++j;
                }
                if (j < len && text[j] == '[')
                {
                    eqCount = equals;
                    tokenLength = (j - i) + 1;
                    return i;
                }
            }
        }
    }
    return -1;
}

qint32 LuaSyntaxHighlighter::findLongBlockEnd(const QString &text, qint32 from,
                                              qint32 eqCount) const
{
    const qint32 len = static_cast<qint32>(text.length());
    for (qint32 i = from; i < len; ++i)
    {
        if (text[i] == ']')
        {
            qint32 j = i + 1;
            qint32 equals = 0;
            while (j < len && text[j] == '=')
            {
                ++equals;
                ++j;
            }
            if (equals == eqCount && j < len && text[j] == ']')
            {
                return j;
            }
        }
    }
    return -1;
}

} // unnamed namespace

LuaDebuggerCodeView::LuaDebuggerCodeView(QWidget *parent)
    : QPlainTextEdit(parent), lineNumberArea(new LineNumberArea(this)),
      syntaxHighlighter(nullptr)
{
    /* Gutter tooltip surfaces both click affordances; the Shift+click
     * behavior is otherwise non-discoverable. */
    lineNumberArea->setToolTip(
        tr("Click: add or remove breakpoint\n"
           "Shift+click: on an empty line, add a disabled breakpoint;\n"
           "on an existing breakpoint, toggle its active state"));
    syntaxHighlighter = new LuaSyntaxHighlighter(document());

    connect(this, &LuaDebuggerCodeView::blockCountChanged, this,
            &LuaDebuggerCodeView::updateLineNumberAreaWidth);
    connect(this, &LuaDebuggerCodeView::updateRequest, this,
            &LuaDebuggerCodeView::updateLineNumberArea);
    connect(this, &LuaDebuggerCodeView::cursorPositionChanged, this,
            &LuaDebuggerCodeView::rebuildLineHighlights);

    /* QAbstractScrollArea delivers key events to the viewport; Esc never
     * reaches QDialog::keyPressEvent. Forward to LuaDebuggerDialog::handleEscapeKey(). */
    viewport()->installEventFilter(this);

    setReadOnly(false);
    setLineWrapMode(QPlainTextEdit::NoWrap);

    QFont initialFont;
    if (mainApp && mainApp->isInitialized())
    {
        initialFont = mainApp->monospaceFont();
    }
    setEditorFont(initialFont);
    applyEditorPalette();
    rebuildLineHighlights();
}

qint32 LuaDebuggerCodeView::lineNumberAreaWidth()
{
    qint32 digits = 1;
    qint32 maxBlockCount = qMax(1, blockCount());
    while (maxBlockCount >= 10)
    {
        maxBlockCount /= 10;
        ++digits;
    }

    const qint32 space =
        3 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
    return space + 20; // Extra space for breakpoint icon
}

void LuaDebuggerCodeView::updateLineNumberAreaWidth(int /* newBlockCount */)
{
    setViewportMargins(static_cast<int>(lineNumberAreaWidth()), 0, 0, 0);
}

void LuaDebuggerCodeView::updateLineNumberArea(const QRect &rect, int dy)
{
    if (dy)
        lineNumberArea->scroll(0, dy);
    else
        lineNumberArea->update(0, rect.y(), lineNumberArea->width(),
                               rect.height());

    if (rect.contains(viewport()->rect()))
        updateLineNumberAreaWidth(0);
}

void LuaDebuggerCodeView::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);

    QRect cr = contentsRect();
    lineNumberArea->setGeometry(QRect(cr.left(), cr.top(),
                                      static_cast<int>(lineNumberAreaWidth()),
                                      cr.height()));
}

bool LuaDebuggerCodeView::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == viewport() && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_Escape && ke->modifiers() == Qt::NoModifier)
        {
            if (LuaDebuggerDialog *dlg = LuaDebuggerDialog::instance())
            {
                QMetaObject::invokeMethod(dlg, "handleEscapeKey",
                                          Qt::QueuedConnection);
                return true;
            }
        }
    }
    return QPlainTextEdit::eventFilter(watched, event);
}

void LuaDebuggerCodeView::rebuildLineHighlights()
{
    QList<QTextEdit::ExtraSelection> extraSelections;

    /* Debugger paused line — amber bar; theme-specific (independent of caret). */
    if (pausedExecutionLine_ > 0)
    {
        QTextBlock pauseBlock = document()->findBlockByNumber(
            static_cast<int>(pausedExecutionLine_ - 1));
        if (pauseBlock.isValid())
        {
            QTextCursor pauseCursor(pauseBlock);
            pauseCursor.movePosition(QTextCursor::StartOfBlock);
            QTextEdit::ExtraSelection pauseSel;
            QColor dbgColor;
            if (resolveIsDarkTheme())
            {
                /* Dark: translucent deep gold (reads well on #1E1E1E). */
                dbgColor = QColor(QStringLiteral("#806F00"));
                dbgColor.setAlpha(120);
            }
            else
            {
                /* Light: pale warm amber; distinct from selection #ADD6FF. */
                dbgColor = QColor(QStringLiteral("#FEF3C7"));
            }
            pauseSel.format.setBackground(dbgColor);
            pauseSel.format.setProperty(QTextFormat::FullWidthSelection, true);
            pauseSel.cursor = pauseCursor;
            pauseSel.cursor.clearSelection();
            extraSelections.append(pauseSel);
        }
    }

    /* Caret line — subtle; skip if same line as debugger (do not replace pause look). */
    QTextBlock caretBlock = textCursor().block();
    if (caretBlock.isValid())
    {
        const int caretLine = caretBlock.blockNumber() + 1;
        const bool sameAsPause =
            (pausedExecutionLine_ > 0) && (caretLine == pausedExecutionLine_);

        if (!sameAsPause)
        {
            /* Match the line-number gutter background (see applyEditorPalette). */
            const QColor lineColor =
                lineNumberArea->palette().color(QPalette::Base);

            QTextCursor caretLineCursor(caretBlock);
            caretLineCursor.movePosition(QTextCursor::StartOfBlock);
            QTextEdit::ExtraSelection caretSel;
            caretSel.format.setBackground(lineColor);
            caretSel.format.setProperty(QTextFormat::FullWidthSelection, true);
            caretSel.cursor = caretLineCursor;
            caretSel.cursor.clearSelection();
            extraSelections.append(caretSel);
        }
    }

    setExtraSelections(extraSelections);
}

void LuaDebuggerCodeView::setCurrentLine(qint32 line)
{
    /* The gutter repaints on cursor movement via the updateRequest
     * signal, but the early-return branches below do not move the
     * cursor, and we need the paused-line yellow arrow (and the
     * accompanying dimmed breakpoint circle, if any) to appear /
     * disappear whenever pausedExecutionLine_ changes. Request a
     * line-number-area repaint explicitly in every branch. */
    if (line <= 0)
    {
        pausedExecutionLine_ = -1;
        rebuildLineHighlights();
        lineNumberArea->update();
        return;
    }

    QTextBlock block =
        document()->findBlockByNumber(static_cast<int>(line - 1));
    if (!block.isValid())
    {
        pausedExecutionLine_ = -1;
        rebuildLineHighlights();
        lineNumberArea->update();
        return;
    }

    pausedExecutionLine_ = line;
    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);
    setTextCursor(cursor);
    rebuildLineHighlights();
    lineNumberArea->update();
}

void LuaDebuggerCodeView::moveCaretToLineStart(qint32 line)
{
    if (line <= 0)
    {
        return;
    }

    QTextBlock block =
        document()->findBlockByNumber(static_cast<int>(line - 1));
    if (!block.isValid())
    {
        return;
    }

    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);
    setTextCursor(cursor);
}

void LuaDebuggerCodeView::clearCurrentLineHighlight()
{
    pausedExecutionLine_ = -1;
    rebuildLineHighlights();
    /* Force the gutter to repaint so the paused-line yellow arrow
     * is cleared and any dimmed breakpoint circle returns to full
     * brightness on resume, even when no cursor movement triggers
     * updateRequest. */
    lineNumberArea->update();
}

void LuaDebuggerCodeView::setEditorFont(const QFont &font)
{
    QFont resolvedFont = font;
    if (resolvedFont.family().isEmpty())
    {
        resolvedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
    resolvedFont.setStyleHint(QFont::TypeWriter, QFont::PreferDefault);
    QPlainTextEdit::setFont(resolvedFont);
    lineNumberArea->setFont(resolvedFont);
    updateLineNumberAreaWidth(0);
    lineNumberArea->update();
    viewport()->update();
}

void LuaDebuggerCodeView::updateBreakpointMarkers()
{
    lineNumberArea->update();
}

void LuaDebuggerCodeView::applyTheme()
{
    const bool isDark = resolveIsDarkTheme();
    applyEditorPalette();
    if (syntaxHighlighter)
    {
        static_cast<LuaSyntaxHighlighter *>(syntaxHighlighter)
            ->setTheme(isDark);
    }
    lineNumberArea->update();
    viewport()->update();
    rebuildLineHighlights();
}

void LuaDebuggerCodeView::applyEditorPalette()
{
    const bool isDark = resolveIsDarkTheme();
    QPalette pal = palette();
    QPalette gutterPal = lineNumberArea->palette();

    QColor baseColor;
    QColor gutterColor;

    if (isDark)
    {
        // VS Code Dark+ inspired palette
        baseColor = QColor("#1E1E1E");
        gutterColor = QColor("#252526");
        pal.setColor(QPalette::Base, baseColor);
        pal.setColor(QPalette::Text, QColor("#D4D4D4"));
        pal.setColor(QPalette::Highlight, QColor("#264F78"));
        pal.setColor(QPalette::HighlightedText, QColor("#FFFFFF"));
        // Gutter palette
        gutterPal.setColor(QPalette::Window, gutterColor);
        gutterPal.setColor(QPalette::Base, gutterColor);
        gutterPal.setColor(QPalette::WindowText, QColor("#858585"));
    }
    else
    {
        // VS Code Light+ inspired palette
        baseColor = QColor("#FFFFFF");
        gutterColor = QColor("#F3F3F3");
        pal.setColor(QPalette::Base, baseColor);
        pal.setColor(QPalette::Text, QColor("#000000"));
        pal.setColor(QPalette::Highlight, QColor("#ADD6FF"));
        pal.setColor(QPalette::HighlightedText, QColor("#000000"));
        // Gutter palette
        gutterPal.setColor(QPalette::Window, gutterColor);
        gutterPal.setColor(QPalette::Base, gutterColor);
        gutterPal.setColor(QPalette::WindowText, QColor("#237893"));
    }

    // Set palette on main widget to fix the gap between gutter and viewport
    pal.setColor(QPalette::Window, baseColor);
    setPalette(pal);
    setAutoFillBackground(true);

    viewport()->setPalette(pal);
    viewport()->setAutoFillBackground(true);

    lineNumberArea->setPalette(gutterPal);
    lineNumberArea->setAutoFillBackground(true);
    lineNumberArea->update();
}

void LuaDebuggerCodeView::lineNumberAreaPaintEvent(QPaintEvent *event)
{
    const bool isDark = resolveIsDarkTheme();
    QPainter painter(lineNumberArea);
    painter.setRenderHint(QPainter::Antialiasing, true);
    QColor gutterColor;
    QColor textColor;

    if (isDark)
    {
        gutterColor = QColor("#252526");
        textColor = QColor("#858585");
    }
    else
    {
        gutterColor = QColor("#F3F3F3");
        textColor = QColor("#237893");
    }

    painter.fillRect(event->rect(), gutterColor);

    /* Canonicalize the filename once for all visible lines. */
    char *canonical = nullptr;
    if (!filename.isEmpty())
    {
        canonical =
            wslua_debugger_canonical_path(filename.toUtf8().constData());
    }

    QTextBlock block = firstVisibleBlock();
    qint32 blockNumber = block.blockNumber();
    qint32 top = static_cast<qint32>(
        blockBoundingGeometry(block).translated(contentOffset()).top());
    qint32 bottom =
        top + static_cast<qint32>(blockBoundingRect(block).height());

    while (block.isValid() && top <= event->rect().bottom())
    {
        if (block.isVisible() && bottom >= event->rect().top())
        {
            QString number = QString::number(blockNumber + 1);
            painter.setPen(textColor);
            painter.drawText(0, top, lineNumberArea->width() - 20,
                             fontMetrics().height(), Qt::AlignRight, number);

            const qint32 lineNo = static_cast<qint32>(blockNumber + 1);
            const bool pausedHere = (pausedExecutionLine_ == lineNo);

            /* Breakpoint circle. On the paused line the red (enabled)
             * circle is drawn dimmed (reduced alpha) so the overlaid
             * yellow right-pointing triangle is visually dominant while
             * the breakpoint itself stays recognizable underneath.
             * Gray (disabled) circles are not dimmed — the yellow
             * arrow is the only indicator that is never dimmed. */
            if (canonical)
            {
                bool hasExtras = false;
                const int32_t state =
                    wslua_debugger_get_breakpoint_state_canonical_ex(
                        canonical, lineNo, &hasExtras);
                if (state != -1)
                {
                    /* Match the toolbar state-indicator palette used
                     * in updateEnabledCheckboxIcon(): red #DC3545 for
                     * enabled breakpoints, gray #808080 for disabled
                     * ones. The yellow paused-arrow triangle below
                     * uses the same palette's #FFC107. */
                    QColor circleColor = (state == 1)
                                             ? QColor("#DC3545")
                                             : QColor("#808080");
                    painter.setBrush(circleColor);
                    /* 1px darker rim matches the Enable-checkbox state
                     * indicator in the toolbar
                     * (updateEnabledCheckboxIcon()); alpha is
                     * preserved by QColor::darker(), so the dimmed
                     * paused-red variant also gets a proportionally
                     * dimmed rim. */
                    painter.setPen(QPen(circleColor.darker(140), 1));
                    const qint32 radius = fontMetrics().height() / 2 - 2;
                    const qint32 cx = lineNumberArea->width() - 15;
                    const qint32 cy = top + 2;
                    painter.drawEllipse(cx, cy, radius * 2, radius * 2);

                    /* Conditional / hit-count / logpoint indicator: a
                     * white core inside the breakpoint dot. Mirrors the
                     * Breakpoints-list italic Location text and tooltip
                     * so users can see at a glance which lines have
                     * extras attached to them without hovering. The
                     * core is drawn with alpha matched to the outer
                     * dot so the dimmed paused-line variant still reads
                     * correctly. */
                    if (hasExtras)
                    {
                        QColor coreColor(Qt::white);
                        coreColor.setAlpha(circleColor.alpha());
                        painter.setBrush(coreColor);
                        painter.setPen(Qt::NoPen);
                        /* Half-radius core, centred. Reads well at the
                         * 12–14 px sizes typical for editor fonts;
                         * scales naturally with the line height. */
                        const qint32 coreRadius =
                            std::max(2, radius / 2);
                        const qint32 coreX = cx + radius - coreRadius;
                        const qint32 coreY = cy + radius - coreRadius;
                        painter.drawEllipse(coreX, coreY, coreRadius * 2,
                                            coreRadius * 2);
                    }
                }
            }

            /* Yellow right-pointing triangle marks the line the
             * debugger is paused at. Drawn after (and therefore on
             * top of) the breakpoint circle, which is dimmed on this
             * line so the triangle dominates while the breakpoint is
             * still visible. */
            if (pausedHere)
            {
                const qint32 radius = fontMetrics().height() / 2 - 2;
                const qint32 diameter = radius * 2;
                const qreal x = lineNumberArea->width() - 15;
                const qreal y = top + 2;
                QPolygonF triangle;
                triangle << QPointF(x, y)
                         << QPointF(x, y + diameter)
                         << QPointF(x + diameter, y + diameter / 2.0);
                const QColor triangleColor("#FFC107");
                painter.setBrush(triangleColor);
                /* Same 1px darker rim as the toolbar state indicator
                 * (see updateEnabledCheckboxIcon()). */
                painter.setPen(QPen(triangleColor.darker(140), 1));
                painter.drawPolygon(triangle);
            }
        }

        block = block.next();
        top = bottom;
        bottom = top + static_cast<qint32>(blockBoundingRect(block).height());
        ++blockNumber;
    }

    g_free(canonical);
}

qint32 LineNumberArea::lineAtY(qint32 yPx) const
{
    QTextBlock block = codeEditor->firstVisibleBlock();
    qint32 top = static_cast<qint32>(
        codeEditor->blockBoundingGeometry(block)
            .translated(codeEditor->contentOffset())
            .top());
    qint32 bottom =
        top +
        static_cast<qint32>(codeEditor->blockBoundingRect(block).height());
    qint32 blockNumber = block.blockNumber();
    while (block.isValid())
    {
        if (yPx >= top && yPx <= bottom)
        {
            return blockNumber + 1;
        }
        block = block.next();
        top = bottom;
        bottom = top + static_cast<qint32>(
                           codeEditor->blockBoundingRect(block).height());
        ++blockNumber;
    }
    return -1;
}

void LineNumberArea::mousePressEvent(QMouseEvent *event)
{
    /* Only the primary button drives add / remove / toggle here. The
     * secondary button (right-click on Win/Linux, Ctrl-click or
     * two-finger trackpad tap on macOS) is handled by
     * @ref contextMenuEvent, which always pops the
     * Edit / Disable / Remove menu so that gesture is never confused
     * with the toggle path. */
    if (event->button() != Qt::LeftButton)
    {
        return;
    }

    const QPoint click_pos = event->pos();
    if (click_pos.x() <= width() - 20)
    {
        return;
    }

    const qint32 lineNo = lineAtY(click_pos.y());
    if (lineNo < 1)
    {
        return;
    }

    const bool toggleActive =
        (event->modifiers() & Qt::ShiftModifier) != 0;

    /* Plain left-click on a "rich" breakpoint (one carrying a
     * condition, a hit-count target, or a log message) opens the
     * Edit / Disable / Remove popup instead of removing it: those
     * extras are easy to lose to a misclick, so the destructive
     * action requires an explicit Remove choice from the menu. Plain
     * breakpoints and clicks on bare lines keep the original
     * add-or-remove-on-click flow. Shift+click keeps the existing
     * modifier semantics (toggle active / pre-arm disabled). */
    bool richBp = false;
    if (!toggleActive && !codeEditor->filename.isEmpty())
    {
        char *canonical = wslua_debugger_canonical_path(
            codeEditor->filename.toUtf8().constData());
        if (canonical)
        {
            bool hasExtras = false;
            const int32_t state =
                wslua_debugger_get_breakpoint_state_canonical_ex(
                    canonical, lineNo, &hasExtras);
            g_free(canonical);
            if (state != -1 && hasExtras)
            {
                richBp = true;
            }
        }
    }

    if (richBp)
    {
        QPoint globalPos =
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            event->globalPosition().toPoint();
#else
            event->globalPos();
#endif
        emit codeEditor->breakpointGutterMenuRequested(
            codeEditor->filename, lineNo, globalPos);
    }
    else
    {
        emit codeEditor->breakpointToggled(codeEditor->filename, lineNo,
                                            toggleActive);
        codeEditor->viewport()->update();
        update();
    }
}

void LineNumberArea::contextMenuEvent(QContextMenuEvent *event)
{
    /* Secondary-click contract on the gutter: always pop the
     * Edit / Disable / Remove menu when the gesture lands on an
     * existing breakpoint, regardless of whether it carries extras.
     * This is the canonical "second click" affordance — works on
     * Windows / Linux right-click, macOS Ctrl-click and the macOS
     * two-finger trackpad tap, all of which Qt funnels through
     * QContextMenuEvent. Bare lines have nothing to act on; we let
     * the event through so the parent editor (or its viewport) can
     * decide what to do (currently nothing in that area). */
    const QPoint pos = event->pos();
    if (pos.x() <= width() - 20 || codeEditor->filename.isEmpty())
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    const qint32 lineNo = lineAtY(pos.y());
    if (lineNo < 1)
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    char *canonical = wslua_debugger_canonical_path(
        codeEditor->filename.toUtf8().constData());
    if (!canonical)
    {
        QWidget::contextMenuEvent(event);
        return;
    }
    const int32_t state = wslua_debugger_get_breakpoint_state_canonical_ex(
        canonical, lineNo, /*has_extras=*/nullptr);
    g_free(canonical);
    if (state == -1)
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    emit codeEditor->breakpointGutterMenuRequested(
        codeEditor->filename, lineNo, event->globalPos());
    event->accept();
}
