/* lua_debugger_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lua_debugger_dialog.h"
#include "accordion_frame.h"
#include <QApplication>
#include "lua_debugger_code_view.h"
#include "lua_debugger_find_frame.h"
#include "lua_debugger_goto_line_frame.h"
#include "main_application.h"
#include "main_window.h"
#include "ui_lua_debugger_dialog.h"
#include "utils/stock_icon.h"
#include "widgets/collapsible_section.h"

#include <QAction>
#include <QCheckBox>
#include <QChildEvent>
#include <QClipboard>
#include <QCloseEvent>
#include <QEvent>
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QKeyCombination>
#endif
#include <QKeyEvent>
#include <QColor>
#include <QComboBox>
#include <QDir>
#include <QAbstractItemView>
#include <QDirIterator>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonParseError>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QMouseEvent>
#include <QMetaObject>
#include <QPainter>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointer>
#include <QSet>
#include <QStandardPaths>
#include <QStyle>
#include <QTextDocument>
#include <QSplitter>
#include <QTimer>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QAbstractItemModel>
#include <QModelIndex>
#include <QTreeWidgetItem>
#include <QTextStream>
#include <QVBoxLayout>
#include <QToolButton>
#include <QHBoxLayout>
#include <algorithm>

#include <glib.h>

#include "ui/recent.h"
#include "app/application_flavor.h"
#include "wsutil/filesystem.h"
#include <epan/prefs.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/utils/qt_ui_utils.h>

#define LUA_DEBUGGER_SETTINGS_FILE "lua_debugger.json"

namespace
{
/** Global personal config path — debugger settings are not profile-specific. */
QString
luaDebuggerSettingsFilePath()
{
    char *p = get_persconffile_path(
        LUA_DEBUGGER_SETTINGS_FILE, false,
        application_configuration_environment_prefix());
    return gchar_free_to_qstring(p);
}
} // namespace

extern "C" void wslua_debugger_ui_callback(const char *file_path, int64_t line)
{
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instance();
    if (dialog)
    {
        dialog->handlePause(file_path, line);
    }
}

LuaDebuggerDialog *LuaDebuggerDialog::_instance = nullptr;
int32_t LuaDebuggerDialog::currentTheme_ = WSLUA_DEBUGGER_THEME_AUTO;

int32_t LuaDebuggerDialog::currentTheme() {
    return currentTheme_;
}

namespace
{
// ============================================================================
// Settings Keys (for JSON persistence)
// ============================================================================
namespace SettingsKeys
{
constexpr const char *Theme = "theme";
constexpr const char *MainSplitter = "mainSplitterState";
constexpr const char *LeftSplitter = "leftSplitterState";
constexpr const char *SectionVariables = "sectionVariables";
constexpr const char *SectionStack = "sectionStack";
constexpr const char *SectionFiles = "sectionFiles";
constexpr const char *SectionBreakpoints = "sectionBreakpoints";
constexpr const char *SectionEval = "sectionEval";
constexpr const char *SectionSettings = "sectionSettings";
constexpr const char *SectionWatch = "sectionWatch";
constexpr const char *Breakpoints = "breakpoints";
constexpr const char *Watches = "watches";
} // namespace SettingsKeys

/** QVariantMap values for JSON arrays are typically QVariantList of QVariantMap. */
static QJsonArray
jsonArrayFromSettingsMap(const QVariantMap &map, const char *key)
{
    const QVariant v = map.value(QString::fromUtf8(key));
    if (!v.isValid())
    {
        return QJsonArray();
    }
    return QJsonValue::fromVariant(v).toArray();
}

// ============================================================================
// Tree Widget User Roles
// ============================================================================
constexpr qint32 FileTreePathRole = static_cast<qint32>(Qt::UserRole);
constexpr qint32 FileTreeIsDirectoryRole = static_cast<qint32>(Qt::UserRole + 1);
constexpr qint32 BreakpointFileRole = static_cast<qint32>(Qt::UserRole + 2);
constexpr qint32 BreakpointLineRole = static_cast<qint32>(Qt::UserRole + 3);
constexpr qint32 StackItemFileRole = static_cast<qint32>(Qt::UserRole + 4);
constexpr qint32 StackItemLineRole = static_cast<qint32>(Qt::UserRole + 5);
constexpr qint32 StackItemNavigableRole = static_cast<qint32>(Qt::UserRole + 6);
constexpr qint32 StackItemLevelRole = static_cast<qint32>(Qt::UserRole + 7);
constexpr qint32 VariablePathRole = static_cast<qint32>(Qt::UserRole + 8);
constexpr qint32 VariableTypeRole = static_cast<qint32>(Qt::UserRole + 9);
constexpr qint32 VariableCanExpandRole = static_cast<qint32>(Qt::UserRole + 10);
constexpr qint32 WatchSpecRole = static_cast<qint32>(Qt::UserRole + 11);
constexpr qint32 WatchSubpathRole = static_cast<qint32>(Qt::UserRole + 13);
constexpr qint32 WatchLastValueRole = static_cast<qint32>(Qt::UserRole + 14);
constexpr qint32 WatchPendingNewRole = static_cast<qint32>(Qt::UserRole + 15);
/*
 * Expansion state for watch roots and Variables sections is tracked in
 * LuaDebuggerDialog::watchExpansion_ and variablesExpansion_ (runtime-only
 * QHashes). The dialog members are the single source of truth and survive
 * child-item destruction during pause / resume / step.
 */
/** Per-root map path/subpath key → last raw value string (child bold-on-change). */
constexpr qint32 WatchChildSnapRole =
    static_cast<qint32>(Qt::UserRole + 20);

constexpr qsizetype WATCH_TOOLTIP_MAX_CHARS = 4096;
constexpr int WATCH_EXPR_MAX_CHARS = 65536;

/** @brief Registers the UI callback with the Lua debugger core at load time. */
class LuaDebuggerUiCallbackRegistrar
{
  public:
    LuaDebuggerUiCallbackRegistrar()
    {
        wslua_debugger_register_ui_callback(wslua_debugger_ui_callback);
    }

    ~LuaDebuggerUiCallbackRegistrar()
    {
        wslua_debugger_register_ui_callback(NULL);
    }
};

static LuaDebuggerUiCallbackRegistrar g_luaDebuggerUiCallbackRegistrar;

/** @brief Build a key sequence from a key event for matching QAction shortcuts. */
static QKeySequence luaSeqFromKeyEvent(const QKeyEvent *ke)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return QKeySequence(QKeyCombination(ke->modifiers(), static_cast<Qt::Key>(ke->key())));
#else
    return QKeySequence(ke->key() | ke->modifiers());
#endif
}

/**
 * @brief True if @a pressed is one of the debugger shortcuts that overlap the
 * main window (Find, Save, Go to line, Reload Lua plugins).
 */
static bool matchesLuaDebuggerShortcutKeys(Ui::LuaDebuggerDialog *ui,
                                           const QKeySequence &pressed)
{
    return (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) == QKeySequence::ExactMatch);
}

/**
 * @brief Run debugger toolbar actions that share shortcuts with the main window.
 *
 * When a capture file is open, Wireshark enables Find Packet (Ctrl+F) and
 * Go to Packet (Ctrl+G). QEvent::ShortcutOverride is handled separately: we only
 * accept() there so Qt does not activate the main-window QAction; triggering
 * happens on KeyPress only. Doing both would call showAccordionFrame(..., true)
 * twice and toggle the bar closed immediately after opening.
 *
 * @return True if @a pressed matches one of these shortcuts (handled or not).
 */
static bool triggerLuaDebuggerShortcuts(Ui::LuaDebuggerDialog *ui,
                                        const QKeySequence &pressed)
{
    if (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionFind->isEnabled())
        {
            ui->actionFind->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionSaveFile->isEnabled())
        {
            ui->actionSaveFile->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionGoToLine->isEnabled())
        {
            ui->actionGoToLine->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) ==
        QKeySequence::ExactMatch)
    {
        if (ui->actionReloadLuaPlugins->isEnabled())
        {
            ui->actionReloadLuaPlugins->trigger();
        }
        return true;
    }
    return false;
}

static QTreeWidgetItem *watchRootItem(QTreeWidgetItem *item)
{
    while (item && item->parent())
    {
        item = item->parent();
    }
    return item;
}

/** Top-level Variables section key (`Locals` / `Globals` / `Upvalues`). */
static QString variableSectionRootKeyFromItem(const QTreeWidgetItem *item)
{
    if (!item)
    {
        return QString();
    }
    const QTreeWidgetItem *walk = item;
    while (walk->parent())
    {
        walk = walk->parent();
    }
    return walk->data(0, VariablePathRole).toString();
}

static bool watchSpecUsesPathResolution(const QString &spec)
{
    const QByteArray ba = spec.toUtf8();
    return wslua_debugger_watch_spec_uses_path_resolution(ba.constData());
}

/** Child variable path under @a parentPath (Variables tree and path-based Watch rows). */
static QString variableTreeChildPath(const QString &parentPath,
                                     const QString &nameText)
{
    if (parentPath.isEmpty())
    {
        return nameText;
    }
    if (nameText.startsWith(QLatin1Char('[')))
    {
        return parentPath + nameText;
    }
    return parentPath + QLatin1Char('.') + nameText;
}

/** Globals subtree is sorted by name; Locals/Upvalues keep engine order. */
static bool variableChildrenShouldSortByName(const QString &parentPath)
{
    return !parentPath.isEmpty() &&
           parentPath.startsWith(QLatin1String("Globals"));
}

/**
 * Shared fields extracted from a `wslua_variable_t` for populating either the
 * Variables tree or a Watch child row. Kept here so both call sites agree on
 * how engine data maps to UI strings.
 */
struct VariableRowFields
{
    QString name;
    QString value;
    QString type;
    bool canExpand = false;
    QString childPath;
};

static VariableRowFields readVariableRowFields(const wslua_variable_t &v,
                                               const QString &parentPath)
{
    VariableRowFields f;
    f.name = QString::fromUtf8(v.name ? v.name : "");
    f.value = QString::fromUtf8(v.value ? v.value : "");
    f.type = QString::fromUtf8(v.type ? v.type : "");
    f.canExpand = v.can_expand ? true : false;
    f.childPath = variableTreeChildPath(parentPath, f.name);
    return f;
}

/**
 * Install the expansion indicator on @a item and (optionally) a dummy child
 * placeholder so that onItemExpanded can lazily populate children. Watch rows
 * use `enabledOnlyPlaceholder=true` so the placeholder never becomes selectable.
 */
static void applyVariableExpansionIndicator(QTreeWidgetItem *item,
                                            bool canExpand,
                                            bool enabledOnlyPlaceholder)
{
    if (canExpand)
    {
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        QTreeWidgetItem *const ph = new QTreeWidgetItem(item);
        if (enabledOnlyPlaceholder)
        {
            ph->setFlags(Qt::ItemIsEnabled);
        }
    }
    else
    {
        item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
    }
}

/** Full Variables path for path-style watches (e.g. Locals.foo for "foo"). */
static QString watchVariablePathForSpec(const QString &spec)
{
    char *p =
        wslua_debugger_watch_variable_path_for_spec(spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

/**
 * Variables-tree path for UI (matches locals / upvalues / globals resolution for
 * the first path segment when paused; otherwise same as watchVariablePathForSpec).
 */
static QString watchResolvedVariablePathForTooltip(const QString &spec)
{
    if (spec.trimmed().isEmpty())
    {
        return QString();
    }
    char *p = wslua_debugger_watch_resolved_variable_path_for_spec(
        spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

/** Sets VariablePathRole on a watch root from spec (resolved section when paused). */
static void watchRootSetVariablePathRoleFromSpec(QTreeWidgetItem *row,
                                                 const QString &spec)
{
    if (!row)
    {
        return;
    }
    const QString t = spec.trimmed();
    if (t.isEmpty())
    {
        row->setData(0, VariablePathRole, QVariant());
        return;
    }
    const QString vpRes = watchResolvedVariablePathForTooltip(t);
    if (!vpRes.isEmpty())
    {
        row->setData(0, VariablePathRole, vpRes);
        return;
    }
    const QString vp = watchVariablePathForSpec(t);
    if (!vp.isEmpty())
    {
        row->setData(0, VariablePathRole, vp);
    }
    else
    {
        row->setData(0, VariablePathRole, QVariant());
    }
}

/** Locals / Upvalues / Globals line for watch tooltips (full variable-tree path). */
static QString watchPathOriginSuffix(const QTreeWidgetItem *item,
                                     const QString &spec)
{
    /* Prefer resolver output (matches lookup order for unqualified names). */
    QString vp;
    if (!spec.trimmed().isEmpty())
    {
        vp = watchResolvedVariablePathForTooltip(spec);
    }
    if (vp.isEmpty() && item)
    {
        vp = item->data(0, VariablePathRole).toString();
    }
    if (vp.startsWith(QLatin1String("Locals.")) ||
        vp == QLatin1String("Locals"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Locals"));
    }
    if (vp.startsWith(QLatin1String("Upvalues.")) ||
        vp == QLatin1String("Upvalues"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Upvalues"));
    }
    if (vp.startsWith(QLatin1String("Globals.")) ||
        vp == QLatin1String("Globals"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Globals"));
    }
    return QString();
}

static QString capWatchTooltipText(const QString &s)
{
    if (s.size() <= WATCH_TOOLTIP_MAX_CHARS)
    {
        return s;
    }
    return s.left(WATCH_TOOLTIP_MAX_CHARS) +
           LuaDebuggerDialog::tr("\n… (truncated)");
}

/** Parent path key for Locals.a.b / a[1].x style watch paths (expression subpaths or variable paths). */
static QString watchPathParentKey(const QString &path)
{
    if (path.isEmpty())
    {
        return QString();
    }
    if (path.endsWith(QLatin1Char(']')))
    {
        int depth = 0;
        for (int i = static_cast<int>(path.size()) - 1; i >= 0; --i)
        {
            const QChar c = path.at(i);
            if (c == QLatin1Char(']'))
            {
                depth++;
            }
            else if (c == QLatin1Char('['))
            {
                depth--;
                if (depth == 0)
                {
                    return path.left(i);
                }
            }
        }
        return QString();
    }
    const qsizetype dot = path.lastIndexOf(QLatin1Char('.'));
    if (dot > 0)
    {
        return path.left(dot);
    }
    return QString();
}

static void applyWatchChildRowPresentation(QTreeWidgetItem *item,
                                           const QString &stableKey,
                                           const QString &rawVal,
                                           const QString &typeText)
{
    QTreeWidgetItem *root = watchRootItem(item);
    if (!root)
    {
        return;
    }
    QVariantMap snaps = root->data(0, WatchChildSnapRole).toMap();
    const QString prev = snaps.value(stableKey).toString();
    item->setText(1, rawVal);
    QString tooltipSuffix =
        typeText.isEmpty()
            ? QString()
            : LuaDebuggerDialog::tr("Type: %1").arg(typeText);
    item->setToolTip(
        0,
        capWatchTooltipText(
            tooltipSuffix.isEmpty()
                ? item->text(0)
                : QStringLiteral("%1\n%2").arg(item->text(0), tooltipSuffix)));
    item->setToolTip(
        1,
        capWatchTooltipText(
            tooltipSuffix.isEmpty()
                ? rawVal
                : QStringLiteral("%1\n%2").arg(rawVal, tooltipSuffix)));
    QFont f1 = item->font(1);
    f1.setBold(!prev.isEmpty() && prev != rawVal);
    item->setFont(1, f1);
    snaps[stableKey] = rawVal;
    root->setData(0, WatchChildSnapRole, snaps);
}

static int watchSubpathBoundaryCount(const QString &subpath)
{
    QString p = subpath;
    if (p.startsWith(QLatin1Char('.')))
    {
        p = p.mid(1);
    }
    int n = 0;
    for (QChar ch : p)
    {
        if (ch == QLatin1Char('.') || ch == QLatin1Char('['))
        {
            n++;
        }
    }
    return n;
}

static QTreeWidgetItem *findWatchItemBySubpathOrPathKey(QTreeWidgetItem *subtree,
                                                        const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QTreeWidgetItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QTreeWidgetItem *it = queue.takeFirst();
        const QString sp = it->data(0, WatchSubpathRole).toString();
        const QString vp = it->data(0, VariablePathRole).toString();
        if ((!sp.isEmpty() && sp == key) || (!vp.isEmpty() && vp == key))
        {
            return it;
        }
        for (int i = 0; i < it->childCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

/** Variables tree: match @a key against VariablePathRole only. */
static QTreeWidgetItem *findVariableTreeItemByPathKey(QTreeWidgetItem *subtree,
                                                      const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QTreeWidgetItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QTreeWidgetItem *it = queue.takeFirst();
        if (it->data(0, VariablePathRole).toString() == key)
        {
            return it;
        }
        for (int i = 0; i < it->childCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

using TreePathKeyFinder = QTreeWidgetItem *(*)(QTreeWidgetItem *,
                                                const QString &);

/**
 * Re-expand @a subtree's descendants whose path key matches one of @a pathKeys.
 * Ancestors are expanded first so that Qt's lazy expand handlers populate each
 * level before we descend.
 *
 * Shared by Watch (`findWatchItemBySubpathOrPathKey`, `onWatchItemExpanded`)
 * and Variables (`findVariableTreeItemByPathKey`, `onVariableItemExpanded`).
 *
 * Keys are processed shallow-first (by path-boundary count). The per-key
 * ancestor chain handles deep-only keys whose intermediate ancestors are not
 * in @a pathKeys; missing items are skipped (structural gaps between pauses).
 */
static void reexpandTreeDescendantsByPathKeys(QTreeWidgetItem *subtree,
                                             QStringList pathKeys,
                                             TreePathKeyFinder findByKey)
{
    if (!subtree || pathKeys.isEmpty() || !findByKey)
    {
        return;
    }
    std::sort(pathKeys.begin(), pathKeys.end(),
              [](const QString &a, const QString &b)
              {
                  const int ca = watchSubpathBoundaryCount(a);
                  const int cb = watchSubpathBoundaryCount(b);
                  if (ca != cb)
                  {
                      return ca < cb;
                  }
                  return a < b;
              });
    for (const QString &pathKey : pathKeys)
    {
        QStringList chain;
        for (QString cur = pathKey; !cur.isEmpty();
             cur = watchPathParentKey(cur))
        {
            chain.prepend(cur);
        }
        for (const QString &k : chain)
        {
            QTreeWidgetItem *n = findByKey(subtree, k);
            if (!n)
            {
                continue;
            }
            if (!n->isExpanded())
            {
                n->setExpanded(true);
            }
        }
    }
}

static void reexpandWatchDescendantsByPathKeys(QTreeWidgetItem *subtree,
                                               QStringList pathKeys)
{
    reexpandTreeDescendantsByPathKeys(subtree, std::move(pathKeys),
                                       findWatchItemBySubpathOrPathKey);
}

static void clearWatchFilterErrorChrome(QTreeWidgetItem *item, QTreeWidget *tree)
{
    const QPalette &pal = tree->palette();
    item->setForeground(0, pal.brush(QPalette::Text));
    item->setForeground(1, pal.brush(QPalette::Text));
    item->setBackground(0, QBrush());
    item->setBackground(1, QBrush());
}

static void applyWatchFilterErrorChrome(QTreeWidgetItem *item, QTreeWidget *tree)
{
    Q_UNUSED(tree);
    QColor fg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_fg);
    QColor bg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_bg);
    item->setForeground(0, fg);
    item->setForeground(1, fg);
    item->setBackground(0, bg);
    item->setBackground(1, bg);
}

/* Initialize a freshly-created top-level watch row from a canonical spec.
 * The on-disk "watches" array is a flat list of spec strings (see
 * storeWatchList / rebuildWatchTreeFromSettings). */
static void setupWatchRootItemFromSpec(QTreeWidgetItem *row,
                                       const QString &spec)
{
    row->setFlags(row->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                  Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    row->setText(0, spec);
    row->setData(0, WatchSpecRole, spec);
    row->setData(0, WatchSubpathRole, QString());
    row->setData(0, WatchPendingNewRole, QVariant(false));
    watchRootSetVariablePathRoleFromSpec(row, spec);
    row->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    QTreeWidgetItem *const ph = new QTreeWidgetItem(row);
    ph->setFlags(Qt::ItemIsEnabled);
}

/**
 * @brief Watch tree that only allows top-level reordering via drag-and-drop.
 *
 * The dialog's settings map (`settings_`) is refreshed from the tree only at
 * close time via `storeDialogSettings()` / `saveSettingsFile()`, so a drop
 * event has no persistence work to do beyond letting QTreeWidget finish the
 * internal move.
 */
class WatchTreeWidget : public QTreeWidget
{
  public:
    explicit WatchTreeWidget(LuaDebuggerDialog *dlg, QWidget *parent = nullptr)
        : QTreeWidget(parent)
    {
        Q_UNUSED(dlg);
    }

  protected:
    void dragMoveEvent(QDragMoveEvent *event) override
    {
        QTreeWidget::dragMoveEvent(event);
        if (!event->isAccepted())
        {
            return;
        }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const QPoint pos = event->position().toPoint();
#else
        const QPoint pos = event->pos();
#endif
        const QModelIndex idx = indexAt(pos);
        if (idx.isValid() && idx.parent().isValid())
        {
            event->ignore();
            return;
        }
        /* OnItem on a top-level row nests the dragged row as a child — only allow
         * AboveItem / BelowItem reorder between roots. */
        if (idx.isValid() && !idx.parent().isValid() &&
            dropIndicatorPosition() == QAbstractItemView::OnItem)
        {
            event->ignore();
            return;
        }
    }

    void dropEvent(QDropEvent *event) override
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const QPoint pos = event->position().toPoint();
#else
        const QPoint pos = event->pos();
#endif
        const QModelIndex idx = indexAt(pos);
        if (idx.isValid() && idx.parent().isValid())
        {
            event->ignore();
            return;
        }
        if (idx.isValid() && !idx.parent().isValid() &&
            dropIndicatorPosition() == QAbstractItemView::OnItem)
        {
            event->ignore();
            return;
        }
        QTreeWidget::dropEvent(event);
    }
};

/** Elide long values in the Value column (plan: Qt::ElideMiddle). */
class WatchValueColumnDelegate : public QStyledItemDelegate
{
  public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);
        const QString full = index.data(Qt::DisplayRole).toString();
        const int avail = qMax(opt.rect.width() - 8, 1);
        opt.text = opt.fontMetrics.elidedText(full, Qt::ElideMiddle, avail);
        const QWidget *w = opt.widget;
        QStyle *style = w ? w->style() : QApplication::style();
        style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, w);
    }

    /* The Value column is read-only: block the default item editor so
     * double-click / F2 cannot open a line edit here. The item's
     * Qt::ItemIsEditable flag is kept because column 0 (the Watch spec)
     * remains editable through WatchRootDelegate. */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override
    {
        Q_UNUSED(parent);
        Q_UNUSED(option);
        Q_UNUSED(index);
        return nullptr;
    }
};

#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
// QTreeWidget::itemFromIndex() is protected in Qt5 but public in Qt6. Use a
// friend-style helper subclass to access it portably.
class TreeWidgetItemFromIndex : public QTreeWidget
{
  public:
    using QTreeWidget::itemFromIndex;
};

static inline QTreeWidgetItem *
itemFromIndexHelper(const QTreeWidget *tree, const QModelIndex &index)
{
    return static_cast<const TreeWidgetItemFromIndex *>(tree)->itemFromIndex(
        index);
}
#endif

class WatchRootDelegate : public QStyledItemDelegate
{
  public:
    WatchRootDelegate(QTreeWidget *tree, LuaDebuggerDialog *dialog,
                      QObject *parent = nullptr)
        : QStyledItemDelegate(parent), tree_(tree), dialog_(dialog)
    {
    }

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

  private:
    QTreeWidget *tree_;
    LuaDebuggerDialog *dialog_;
};

QWidget *
WatchRootDelegate::createEditor(QWidget *parent,
                                const QStyleOptionViewItem &option,
                                const QModelIndex &index) const
{
    Q_UNUSED(option);
    if (!tree_ || !index.isValid() || index.column() != 0)
    {
        return nullptr;
    }
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QTreeWidgetItem *it = tree_->itemFromIndex(index);
#else
    QTreeWidgetItem *it = itemFromIndexHelper(tree_, index);
#endif
    if (!it || it->parent() != nullptr)
    {
        return nullptr;
    }
    return new QLineEdit(parent);
}

void WatchRootDelegate::setEditorData(QWidget *editor,
                                      const QModelIndex &index) const
{
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !tree_)
    {
        return;
    }
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QTreeWidgetItem *it = tree_->itemFromIndex(index);
#else
    QTreeWidgetItem *it = itemFromIndexHelper(tree_, index);
#endif
    if (!it)
    {
        return;
    }
    QString s = it->data(0, WatchSpecRole).toString();
    if (s.isEmpty())
    {
        s = it->text(0);
    }
    le->setText(s);
}

void WatchRootDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                     const QModelIndex &index) const
{
    Q_UNUSED(model);
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !dialog_ || !tree_)
    {
        return;
    }
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QTreeWidgetItem *it = tree_->itemFromIndex(index);
#else
    QTreeWidgetItem *it = itemFromIndexHelper(tree_, index);
#endif
    if (!it)
    {
        return;
    }
    dialog_->commitWatchRootSpec(it, le->text());
}

} // namespace

LuaDebuggerDialog::LuaDebuggerDialog(QWidget *parent)
    : GeometryStateDialog(parent), ui(new Ui::LuaDebuggerDialog),
      eventLoop(nullptr), enabledCheckBox(nullptr), breakpointTabsPrimed(false),
      debuggerPaused(false), reloadDeferred(false), variablesSection(nullptr),
      watchSection(nullptr), stackSection(nullptr), breakpointsSection(nullptr),
      filesSection(nullptr), evalSection(nullptr), settingsSection(nullptr),
      variablesTree(nullptr), watchTree(nullptr), stackTree(nullptr),
      fileTree(nullptr), breakpointsTree(nullptr),
      evalInputEdit(nullptr), evalOutputEdit(nullptr), evalButton(nullptr),
      evalClearButton(nullptr), themeComboBox(nullptr)
{
    _instance = this;
    setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);
    loadGeometry();

    lastOpenDirectory =
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (lastOpenDirectory.isEmpty())
    {
        lastOpenDirectory = QDir::homePath();
    }

    // Create collapsible sections with their content widgets
    createCollapsibleSections();

    fileTree->setRootIsDecorated(true);
    fileTree->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    fileTree->header()->setStretchLastSection(true);
    fileTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    // Compact toolbar styling with consistent icons
    ui->toolBar->setIconSize(QSize(18, 18));
    ui->toolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    ui->toolBar->setStyleSheet(QStringLiteral(
        "QToolBar {"
        "  background-color: palette(window);"
        "  border: none;"
        "  spacing: 4px;"
        "  padding: 2px 4px;"
        "}"));
    ui->actionOpenFile->setIcon(StockIcon("document-open"));
    ui->actionSaveFile->setIcon(
        style()->standardIcon(QStyle::SP_DialogSaveButton));
    ui->actionContinue->setIcon(StockIcon("x-lua-debug-continue"));
    ui->actionStepOver->setIcon(StockIcon("x-lua-debug-step-over"));
    ui->actionStepIn->setIcon(StockIcon("x-lua-debug-step-in"));
    ui->actionStepOut->setIcon(StockIcon("x-lua-debug-step-out"));
    ui->actionReloadLuaPlugins->setIcon(StockIcon("view-refresh"));
    ui->actionClearBreakpoints->setIcon(StockIcon("edit-clear"));
    {
        QIcon addWatchIcon = QIcon::fromTheme(QStringLiteral("system-search"));
        if (addWatchIcon.isNull())
        {
            addWatchIcon = QIcon::fromTheme(QStringLiteral("list-add"));
        }
        if (addWatchIcon.isNull())
        {
            addWatchIcon = style()->standardIcon(
                QStyle::SP_FileDialogDetailedView);
        }
        ui->actionAddWatch->setIcon(addWatchIcon);
    }
    ui->actionFind->setIcon(StockIcon("edit-find"));
    ui->actionOpenFile->setToolTip(tr("Open Lua Script"));
    ui->actionSaveFile->setToolTip(tr("Save (%1)").arg(
        QKeySequence(QKeySequence::Save)
            .toString(QKeySequence::NativeText)));
    ui->actionContinue->setToolTip(tr("Continue execution (F5)"));
    ui->actionStepOver->setToolTip(tr("Step over (F10)"));
    ui->actionStepIn->setToolTip(tr("Step into (F11)"));
    ui->actionStepOut->setToolTip(tr("Step out (Shift+F11)"));
    ui->actionReloadLuaPlugins->setToolTip(
        tr("Reload Lua Plugins (Ctrl+Shift+L)"));
    ui->actionClearBreakpoints->setToolTip(tr("Remove all breakpoints"));
    ui->actionAddWatch->setToolTip(tr("%1 (%2)")
                                       .arg(ui->actionAddWatch->toolTip(),
                                            ui->actionAddWatch->shortcut()
                                                .toString(QKeySequence::NativeText)));
    ui->actionAddWatch->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionFind->setToolTip(tr("Find in script (%1)")
                                   .arg(QKeySequence(QKeySequence::Find)
                                            .toString(QKeySequence::NativeText)));
    ui->actionGoToLine->setToolTip(tr("Go to line (%1)")
                                       .arg(QKeySequence(Qt::CTRL | Qt::Key_G)
                                                .toString(QKeySequence::NativeText)));
    ui->actionContinue->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepOver->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepIn->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepOut->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionReloadLuaPlugins->setShortcut(
        QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_L));
    ui->actionReloadLuaPlugins->setShortcutContext(
        Qt::WidgetWithChildrenShortcut);
    ui->actionSaveFile->setShortcut(QKeySequence::Save);
    ui->actionSaveFile->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionFind->setShortcut(QKeySequence::Find);
    ui->actionFind->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionGoToLine->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
    ui->actionGoToLine->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    folderIcon = StockIcon("folder");
    fileIcon = StockIcon("text-x-generic");

    // Toolbar controls - Checkbox for enable/disable
    // Order: Checkbox | Separator | Continue | Step Over/In/Out | Separator |
    // Open | Reload | Clear
    QAction *firstAction = ui->toolBar->actions().isEmpty()
                               ? nullptr
                               : ui->toolBar->actions().first();

    // Enable/Disable checkbox with colored icon
    enabledCheckBox = new QCheckBox(ui->toolBar);
    enabledCheckBox->setChecked(wslua_debugger_is_enabled());
    ui->toolBar->insertWidget(firstAction, enabledCheckBox);

    connect(enabledCheckBox, &QCheckBox::toggled, this,
            &LuaDebuggerDialog::onDebuggerToggled);
    connect(ui->actionContinue, &QAction::triggered, this,
            &LuaDebuggerDialog::onContinue);
    connect(ui->actionStepOver, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepOver);
    connect(ui->actionStepIn, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepIn);
    connect(ui->actionStepOut, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepOut);
    connect(ui->actionClearBreakpoints, &QAction::triggered, this,
            &LuaDebuggerDialog::onClearBreakpoints);
    connect(ui->actionAddWatch, &QAction::triggered, this, [this]()
            { insertNewWatchRow(QString(), true); });
    connect(ui->actionOpenFile, &QAction::triggered, this,
            &LuaDebuggerDialog::onOpenFile);
    connect(ui->actionSaveFile, &QAction::triggered, this,
            &LuaDebuggerDialog::onSaveFile);
    connect(ui->actionFind, &QAction::triggered, this,
            &LuaDebuggerDialog::onEditorFind);
    connect(ui->actionGoToLine, &QAction::triggered, this,
            &LuaDebuggerDialog::onEditorGoToLine);
    connect(ui->actionReloadLuaPlugins, &QAction::triggered, this,
            &LuaDebuggerDialog::onReloadLuaPlugins);
    addAction(ui->actionContinue);
    addAction(ui->actionStepOver);
    addAction(ui->actionStepIn);
    addAction(ui->actionStepOut);
    addAction(ui->actionReloadLuaPlugins);
    addAction(ui->actionAddWatch);
    addAction(ui->actionSaveFile);
    addAction(ui->actionFind);
    addAction(ui->actionGoToLine);

    ui->luaDebuggerFindFrame->hide();
    ui->luaDebuggerGoToLineFrame->hide();

    // Tab Widget
    connect(ui->codeTabWidget, &QTabWidget::tabCloseRequested, this,
            &LuaDebuggerDialog::onCodeTabCloseRequested);
    connect(ui->codeTabWidget, &QTabWidget::currentChanged, this,
            [this](int)
            {
                updateSaveActionState();
                updateLuaEditorAuxFrames();
            });

    // Breakpoints
    connect(breakpointsTree, &QTreeWidget::itemChanged, this,
            &LuaDebuggerDialog::onBreakpointItemChanged);
    connect(breakpointsTree, &QTreeWidget::itemClicked, this,
            &LuaDebuggerDialog::onBreakpointItemClicked);
    connect(breakpointsTree, &QTreeWidget::itemDoubleClicked, this,
            &LuaDebuggerDialog::onBreakpointItemDoubleClicked);

    QHeaderView *breakpointHeader = breakpointsTree->header();
    breakpointHeader->setStretchLastSection(false);
    breakpointHeader->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(2, QHeaderView::Stretch);
    breakpointHeader->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    breakpointsTree->headerItem()->setText(2, tr("Location"));
    breakpointsTree->setColumnHidden(1, true);

    // Variables
    connect(variablesTree, &QTreeWidget::itemExpanded, this,
            &LuaDebuggerDialog::onVariableItemExpanded);
    connect(variablesTree, &QTreeWidget::itemCollapsed, this,
            &LuaDebuggerDialog::onVariableItemCollapsed);
    variablesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(variablesTree, &QTreeWidget::customContextMenuRequested, this,
            &LuaDebuggerDialog::onVariablesContextMenuRequested);

    /* onWatchItemExpanded updates watchExpansion_ (the runtime expansion
     * map) and performs lazy child fill; onWatchItemCollapsed mirrors the
     * update on collapse. No storeWatchList() call is needed on expand /
     * collapse because expansion state is intentionally not persisted to
     * lua_debugger.json. */
    connect(watchTree, &QTreeWidget::itemExpanded, this,
            &LuaDebuggerDialog::onWatchItemExpanded);
    connect(watchTree, &QTreeWidget::itemCollapsed, this,
            &LuaDebuggerDialog::onWatchItemCollapsed);
    watchTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(watchTree, &QTreeWidget::customContextMenuRequested, this,
            &LuaDebuggerDialog::onWatchContextMenuRequested);
    watchTree->setItemDelegateForColumn(
        0, new WatchRootDelegate(watchTree, this, watchTree));
    watchTree->setItemDelegateForColumn(
        1, new WatchValueColumnDelegate(watchTree));
    watchTree->viewport()->installEventFilter(this);

    connect(watchTree, &QTreeWidget::currentItemChanged, this,
            &LuaDebuggerDialog::onWatchCurrentItemChanged);
    connect(variablesTree, &QTreeWidget::currentItemChanged, this,
            &LuaDebuggerDialog::onVariablesCurrentItemChanged);

    // Files
    connect(fileTree, &QTreeWidget::itemDoubleClicked,
            [this](QTreeWidgetItem *item, int column)
            {
                Q_UNUSED(column);
                if (!item || item->data(0, FileTreeIsDirectoryRole).toBool())
                {
                    return;
                }
                const QString path = item->data(0, FileTreePathRole).toString();
                if (!path.isEmpty())
                {
                    loadFile(path);
                }
            });

    connect(stackTree, &QTreeWidget::itemDoubleClicked, this,
            &LuaDebuggerDialog::onStackItemDoubleClicked);
    connect(stackTree, &QTreeWidget::currentItemChanged, this,
            &LuaDebuggerDialog::onStackCurrentItemChanged);

    // Evaluate panel
    connect(evalButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvaluate);
    connect(evalClearButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvalClear);

    configureVariablesTreeColumns();
    configureWatchTreeColumns();
    configureStackTreeColumns();
    applyMonospaceFonts();

    /*
     * Register our reload callback with the debugger core.
     * This callback is invoked by wslua_reload_plugins() BEFORE
     * Lua scripts are reloaded, allowing us to refresh our cached
     * script content from disk.
     */
    wslua_debugger_register_reload_callback(
        LuaDebuggerDialog::onLuaReloadCallback);

    /*
     * Register a callback to be notified AFTER Lua plugins are reloaded.
     * This allows us to refresh the file tree with newly loaded scripts.
     */
    wslua_debugger_register_post_reload_callback(
        LuaDebuggerDialog::onLuaPostReloadCallback);

    /*
     * Register a callback to be notified when a Lua script is loaded.
     * This allows us to add the script to the file tree immediately.
     */
    wslua_debugger_register_script_loaded_callback(
        LuaDebuggerDialog::onScriptLoadedCallback);

    if (mainApp)
    {
        connect(mainApp, &MainApplication::zoomMonospaceFont, this,
                &LuaDebuggerDialog::onMonospaceFontUpdated, Qt::UniqueConnection);
        connect(mainApp, &MainApplication::appInitialized, this,
                &LuaDebuggerDialog::onMainAppInitialized, Qt::UniqueConnection);
        connect(mainApp, &MainApplication::preferencesChanged, this,
                &LuaDebuggerDialog::onPreferencesChanged, Qt::UniqueConnection);
        /*
         * Connect to colorsChanged signal to update code view themes when
         * Wireshark's color scheme changes. This is important when the debugger
         * theme preference is set to "Auto (follow color scheme)".
         */
        connect(mainApp, &MainApplication::colorsChanged, this,
                &LuaDebuggerDialog::onColorsChanged, Qt::UniqueConnection);
        if (mainApp->isInitialized())
        {
            onMainAppInitialized();
        }
    }

    refreshAvailableScripts();
    syncDebuggerToggleWithCore();
    updateWidgets();

    /*
     * Apply all settings from JSON file (theme, font, sections, splitters,
     * breakpoints). This is done after all widgets are created.
     */
    applyDialogSettings();
    updateBreakpoints();
    updateSaveActionState();
    updateLuaEditorAuxFrames();

    installDescendantShortcutFilters();
}

LuaDebuggerDialog::~LuaDebuggerDialog()
{
    /*
     * Persist JSON only from closeEvent(); if the dialog is destroyed without
     * a normal close (rare), flush once here.
     */
    if (!luaDebuggerJsonSaved_)
    {
        storeDialogSettings();
        saveSettingsFile();
    }

    /*
     * Unregister our reload callbacks when the dialog is destroyed.
     */
    wslua_debugger_register_reload_callback(NULL);
    wslua_debugger_register_post_reload_callback(NULL);
    wslua_debugger_register_script_loaded_callback(NULL);

    delete ui;
    _instance = nullptr;
}

void LuaDebuggerDialog::createCollapsibleSections()
{
    QSplitter *splitter = ui->leftSplitter;

    // --- Variables Section ---
    variablesSection = new CollapsibleSection(tr("Variables"), this);
    variablesSection->setToolTip(
        tr("<p><b>Locals</b><br/>"
           "Parameters and local variables for the selected stack frame.</p>"
           "<p><b>Upvalues</b><br/>"
           "Outer variables that this function actually uses from surrounding code. "
           "Anything the function does not reference does not appear here.</p>"
           "<p><b>Globals</b><br/>"
           "Names from the global environment table.</p>"));
    variablesTree = new QTreeWidget();
    variablesTree->setColumnCount(3);
    variablesTree->setHeaderLabels({tr("Name"), tr("Value"), tr("Type")});
    variablesTree->setUniformRowHeights(true);
    variablesTree->setWordWrap(false);
    variablesSection->setContentWidget(variablesTree);
    variablesSection->setExpanded(true);
    splitter->addWidget(variablesSection);

    /*
     * Watch panel: two columns; formats, expansion persistence, depth cap
     * WSLUA_WATCH_MAX_PATH_SEGMENTS, drag reorder, error styling, muted em dash
     * when no live value.
     */
    // --- Watch Section ---
    watchSection = new CollapsibleSection(tr("Watch"), this);
    watchSection->setToolTip(
        tr("<p>Each row is a <b>Variables-tree path</b>, not a Lua "
           "expression. Accepted forms:</p>"
           "<ul>"
           "<li>Section-qualified: <code>Locals.<i>name</i></code>, "
           "<code>Upvalues.<i>name</i></code>, "
           "<code>Globals.<i>name</i></code>.</li>"
           "<li>Section root alone: <code>Locals</code>, "
           "<code>Upvalues</code>, <code>Globals</code> "
           "(<code>_G</code> is an alias for <code>Globals</code>).</li>"
           "<li>Unqualified name: resolved in "
           "<b>Locals &rarr; Upvalues &rarr; Globals</b> order; the row "
           "tooltip shows which section matched.</li>"
           "</ul>"
           "<p>After the first segment, chain <code>.field</code> or "
           "bracket keys &mdash; integer "
           "(<code>[1]</code>, <code>[-1]</code>, <code>[0x1F]</code>), "
           "boolean (<code>[true]</code>), or short-literal string "
           "(<code>[\"key\"]</code>, <code>['k']</code>). Depth is capped "
           "at 32 segments. Use the <b>Evaluate</b> panel below for "
           "arbitrary Lua expressions.</p>"
           "<p>Values are only read while the debugger is "
           "<b>paused</b>; otherwise the Value column shows a muted "
           "em dash. Child values that changed since the previous pause "
           "are shown in <b>bold</b>.</p>"
           "<p>Double-click or press <b>F2</b> to edit a row; "
           "<b>Delete</b> removes it; drag rows to reorder.</p>"));
    watchTree = new WatchTreeWidget(this);
    watchTree->setColumnCount(2);
    watchTree->setHeaderLabels({tr("Watch"), tr("Value")});
    watchTree->setRootIsDecorated(true);
    watchTree->setDragDropMode(QAbstractItemView::InternalMove);
    watchTree->setDefaultDropAction(Qt::MoveAction);
    watchTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    watchTree->setUniformRowHeights(true);
    watchTree->setWordWrap(false);
    {
        auto *watchWrap = new QWidget();
        auto *watchOuter = new QVBoxLayout(watchWrap);
        watchOuter->setContentsMargins(0, 0, 0, 0);
        watchOuter->setSpacing(4);
        watchOuter->addWidget(watchTree, 1);
        watchSection->setContentWidget(watchWrap);
    }
    watchSection->setExpanded(true);
    splitter->addWidget(watchSection);

    // --- Stack Trace Section ---
    stackSection = new CollapsibleSection(tr("Stack Trace"), this);
    stackTree = new QTreeWidget();
    stackTree->setColumnCount(2);
    stackTree->setHeaderLabels({tr("Function"), tr("Location")});
    stackTree->setRootIsDecorated(true);
    stackTree->setToolTip(
        tr("Select a row to inspect locals and upvalues for that frame. "
           "Double-click a Lua frame to open its source location."));
    stackSection->setContentWidget(stackTree);
    stackSection->setExpanded(true);
    splitter->addWidget(stackSection);

    // --- Breakpoints Section ---
    breakpointsSection = new CollapsibleSection(tr("Breakpoints"), this);
    breakpointsTree = new QTreeWidget();
    breakpointsTree->setColumnCount(4);
    breakpointsTree->setHeaderLabels(
        {tr("Active"), tr("Line"), tr("File"), QString()});
    breakpointsTree->setRootIsDecorated(false);
    breakpointsSection->setContentWidget(breakpointsTree);
    breakpointsSection->setExpanded(true);
    splitter->addWidget(breakpointsSection);

    // --- Files Section ---
    filesSection = new CollapsibleSection(tr("Files"), this);
    fileTree = new QTreeWidget();
    fileTree->setColumnCount(1);
    fileTree->setHeaderLabels({tr("Files")});
    fileTree->setRootIsDecorated(false);
    filesSection->setContentWidget(fileTree);
    filesSection->setExpanded(true);
    splitter->addWidget(filesSection);

    // --- Evaluate Section ---
    evalSection = new CollapsibleSection(tr("Evaluate"), this);
    QWidget *evalWidget = new QWidget();
    QVBoxLayout *evalMainLayout = new QVBoxLayout(evalWidget);
    evalMainLayout->setContentsMargins(0, 0, 0, 0);
    evalMainLayout->setSpacing(4);

    QSplitter *evalSplitter = new QSplitter(Qt::Vertical);
    evalInputEdit = new QPlainTextEdit();
    evalInputEdit->setPlaceholderText(
        tr("Enter Lua expression (prefix with = to return value)"));
    evalInputEdit->setToolTip(
        tr("<b>Lua Expression Evaluation</b><br><br>"
           "Code is executed using <code>lua_pcall()</code> in a protected "
           "environment. "
           "Runtime errors are caught and displayed in the output.<br><br>"
           "<b>Prefix with <code>=</code></b> to return a value (e.g., "
           "<code>=my_var</code>).<br><br>"
           "<b>What works:</b><ul>"
           "<li>Read/modify global variables (<code>_G.x = 42</code>)</li>"
           "<li>Modify table contents (<code>my_table.field = 99</code>)</li>"
           "<li>Call functions and inspect return values</li>"
           "</ul>"
           "<b>Limitations:</b><ul>"
           "<li>Local variables cannot be modified directly (use "
           "<code>debug.setlocal()</code>)</li>"
           "<li>Long-running expressions are automatically aborted</li>"
           "<li><b>Warning:</b> Changes to globals persist and can affect "
           "ongoing dissection</li>"
           "</ul>"));
    evalOutputEdit = new QPlainTextEdit();
    evalOutputEdit->setReadOnly(true);
    evalOutputEdit->setPlaceholderText(tr("Output"));
    evalSplitter->addWidget(evalInputEdit);
    evalSplitter->addWidget(evalOutputEdit);
    evalMainLayout->addWidget(evalSplitter, 1);

    QHBoxLayout *evalButtonLayout = new QHBoxLayout();
    evalButton = new QPushButton(tr("Evaluate"));
    evalButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return));
    evalButton->setToolTip(tr("Execute the Lua code (Ctrl+Return)"));
    evalClearButton = new QPushButton(tr("Clear"));
    evalClearButton->setToolTip(tr("Clear input and output"));
    evalButtonLayout->addWidget(evalButton);
    evalButtonLayout->addWidget(evalClearButton);
    evalButtonLayout->addStretch();
    evalMainLayout->addLayout(evalButtonLayout);

    evalSection->setContentWidget(evalWidget);
    evalSection->setExpanded(false);
    splitter->addWidget(evalSection);

    // --- Settings Section ---
    settingsSection = new CollapsibleSection(tr("Settings"), this);
    QWidget *settingsWidget = new QWidget();
    QFormLayout *settingsLayout = new QFormLayout(settingsWidget);
    settingsLayout->setContentsMargins(4, 4, 4, 4);
    settingsLayout->setSpacing(6);

    themeComboBox = new QComboBox();
    themeComboBox->addItem(tr("Auto (follow color scheme)"),
                           WSLUA_DEBUGGER_THEME_AUTO);
    themeComboBox->addItem(tr("Dark"), WSLUA_DEBUGGER_THEME_DARK);
    themeComboBox->addItem(tr("Light"), WSLUA_DEBUGGER_THEME_LIGHT);
    themeComboBox->setToolTip(tr("Color theme for the code editor"));
    // Theme will be set by applyDialogSettings() later
    settingsLayout->addRow(tr("Code View Theme:"), themeComboBox);

    connect(themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LuaDebuggerDialog::onThemeChanged);

    settingsSection->setContentWidget(settingsWidget);
    settingsSection->setExpanded(false);
    splitter->addWidget(settingsSection);

    // Set initial sizes - expanded sections get more space
    QList<int> sizes;
    int headerH = variablesSection->headerHeight();
    sizes << 120 << 70 << 100 << headerH << 80 << headerH
          << headerH; // Variables, Watch, Stack, Files(collapsed), Breakpoints,
                      // Eval(collapsed), Settings(collapsed)
    splitter->setSizes(sizes);
}

LuaDebuggerDialog *LuaDebuggerDialog::instance(QWidget *parent)
{
    if (!_instance)
    {
        QWidget *resolved_parent = parent;
        if (!resolved_parent && mainApp && mainApp->isInitialized())
        {
            resolved_parent = mainApp->mainWindow();
        }
        new LuaDebuggerDialog(resolved_parent);
    }
    return _instance;
}

void LuaDebuggerDialog::handlePause(const char *file_path, int64_t line)
{
    // Prevent deletion while in event loop
    setAttribute(Qt::WA_DeleteOnClose, false);

    // Bring to front
    show();
    raise();
    activateWindow();

    QString normalizedPath = normalizedFilePath(QString::fromUtf8(file_path));
    ensureFileTreeEntry(normalizedPath);
    LuaDebuggerCodeView *view = loadFile(normalizedPath);
    if (view)
    {
        view->setCurrentLine(static_cast<qint32>(line));
    }

    debuggerPaused = true;
    updateWidgets();

    stackSelectionLevel = 0;
    updateStack();
    variablesTree->clear();
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshWatchDisplay();

    /*
     * If an event loop is already running (e.g. we were called from a step
     * action which triggered an immediate re-pause), reuse it instead of nesting.
     * The outer loop.exec() is still on the stack and will return when we
     * eventually quit it via Continue or close.
     */
    if (eventLoop)
    {
        return;
    }

    QEventLoop loop;
    eventLoop = &loop;

    /*
     * If the parent window is destroyed while we're paused (e.g. the
     * application is shutting down), quit the event loop so the Lua
     * call stack can unwind cleanly.
     */
    QPointer<QWidget> parentGuard(parentWidget());
    QMetaObject::Connection parentConn;
    if (parentGuard) {
        parentConn = connect(parentGuard, &QObject::destroyed, &loop,
                             &QEventLoop::quit);
    }

    // Enter event loop - blocks until Continue or dialog close
    loop.exec();

    if (parentConn) {
        disconnect(parentConn);
    }

    // Restore delete-on-close behavior and clear event loop pointer
    eventLoop = nullptr;
    setAttribute(Qt::WA_DeleteOnClose, true);

    /*
     * If a Lua plugin reload was requested while we were paused,
     * schedule it now that the Lua/C call stack has fully unwound.
     * We must NOT schedule it from inside the event loop (via
     * QTimer::singleShot) because the timer can fire before the
     * loop exits, running cf_close/wslua_reload_plugins while
     * cf_read is still on the C call stack.
     */
    if (reloadDeferred) {
        reloadDeferred = false;
        if (mainApp) {
            mainApp->reloadLuaPluginsDelayed();
        }
    }
}

void LuaDebuggerDialog::onContinue()
{
    resumeDebuggerAndExitLoop();
    updateWidgets();
}

void LuaDebuggerDialog::runDebuggerStep(void (*step_fn)(void))
{
    if (!debuggerPaused)
    {
        return;
    }

    debuggerPaused = false;
    clearPausedStateUi();

    /*
     * The step function resumes the VM and may synchronously hit handlePause()
     * again. handlePause() detects that eventLoop is already set and reuses
     * it instead of nesting a new one — so the stack does NOT grow with each
     * step.
     */
    step_fn();

    /*
     * If handlePause() was NOT called (e.g. step landed in C code
     * and the hook didn't fire), we need to quit the event loop so
     * the original handlePause() caller can return.
     */
    if (!debuggerPaused && eventLoop)
    {
        eventLoop->quit();
    }

    updateWidgets();
}

void LuaDebuggerDialog::onStepOver()
{
    runDebuggerStep(wslua_debugger_step_over);
}

void LuaDebuggerDialog::onStepIn()
{
    runDebuggerStep(wslua_debugger_step_in);
}

void LuaDebuggerDialog::onStepOut()
{
    runDebuggerStep(wslua_debugger_step_out);
}

void LuaDebuggerDialog::onDebuggerToggled(bool checked)
{
    if (!checked && debuggerPaused)
    {
        onContinue();
    }
    wslua_debugger_set_enabled(checked);
    if (!checked)
    {
        debuggerPaused = false;
        clearPausedStateUi();
    }
    updateWidgets();
}

void LuaDebuggerDialog::reject()
{
    /* Base QDialog::reject() calls done(Rejected), which hides() without
     * delivering QCloseEvent, so our closeEvent() unsaved-scripts check does
     * not run (e.g. Esc). Synchronous close() from keyPressEvent → reject()
     * can fail to finish closing; queue close() so closeEvent() runs on the
     * next event-loop turn (same path as the window close control). */
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::closeEvent(QCloseEvent *event)
{
    if (!ensureUnsavedChangesHandled(tr("Lua Debugger")))
    {
        event->ignore();
        return;
    }

    storeDialogSettings();
    saveSettingsFile();
    luaDebuggerJsonSaved_ = true;

    /* Disable the debugger so breakpoints won't fire and reopen the
     * dialog after it has been closed. */
    wslua_debugger_set_enabled(false);
    resumeDebuggerAndExitLoop();

    /*
     * Do not call QDialog::closeEvent (GeometryStateDialog inherits it):
     * QDialog::closeEvent invokes reject(); our reject() queues close()
     * asynchronously, so the dialog stays visible and Qt then ignores the
     * close event (see qdialog.cpp: if (that && isVisible()) e->ignore()).
     * QWidget::closeEvent only accepts the event so the window can close.
     */
    QWidget::closeEvent(event);
}

void LuaDebuggerDialog::handleEscapeKey()
{
    QWidget *const modal = QApplication::activeModalWidget();
    if (modal && modal != this)
    {
        return;
    }
    if (ui->luaDebuggerFindFrame->isVisible())
    {
        ui->luaDebuggerFindFrame->animatedHide();
        return;
    }
    if (ui->luaDebuggerGoToLineFrame->isVisible())
    {
        ui->luaDebuggerGoToLineFrame->animatedHide();
        return;
    }
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::installDescendantShortcutFilters()
{
    installEventFilter(this);
    for (QWidget *w : findChildren<QWidget *>())
    {
        w->installEventFilter(this);
    }
}

void LuaDebuggerDialog::childEvent(QChildEvent *event)
{
    if (event->added())
    {
        if (auto *w = qobject_cast<QWidget *>(event->child()))
        {
            w->installEventFilter(this);
            for (QWidget *d : w->findChildren<QWidget *>())
            {
                d->installEventFilter(this);
            }
        }
    }
    QDialog::childEvent(event);
}

bool LuaDebuggerDialog::eventFilter(QObject *obj, QEvent *event)
{
    QWidget *const receiver = qobject_cast<QWidget *>(obj);
    const bool inDebuggerUi =
        receiver && isVisible() && isAncestorOf(receiver);

    if (watchTree && obj == watchTree->viewport() &&
        event->type() == QEvent::MouseButtonDblClick)
    {
        auto *me = static_cast<QMouseEvent *>(event);
        if (me->button() == Qt::LeftButton && !watchTree->itemAt(me->pos()))
        {
            insertNewWatchRow(QString(), true);
            return true;
        }
    }

    if (inDebuggerUi && event->type() == QEvent::ShortcutOverride)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        const QKeySequence pressed = luaSeqFromKeyEvent(ke);
        if (matchesLuaDebuggerShortcutKeys(ui, pressed))
        {
            ke->accept();
            return false;
        }
    }

    if (inDebuggerUi && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (watchTree && (obj == watchTree || obj == watchTree->viewport()))
        {
            if (watchTree->hasFocus() ||
                (watchTree->viewport() && watchTree->viewport()->hasFocus()))
            {
                QTreeWidgetItem *cur = watchTree->currentItem();
                if (cur && cur->parent() == nullptr)
                {
                    if ((ke->key() == Qt::Key_Delete ||
                         ke->key() == Qt::Key_Backspace) &&
                        ke->modifiers() == Qt::NoModifier)
                    {
                        QList<QTreeWidgetItem *> del;
                        for (QTreeWidgetItem *it : watchTree->selectedItems())
                        {
                            if (it && it->parent() == nullptr)
                            {
                                del.append(it);
                            }
                        }
                        if (del.isEmpty())
                        {
                            del.append(cur);
                        }
                        deleteWatchRows(del);
                        return true;
                    }
                    if (ke->key() == Qt::Key_F2 &&
                        ke->modifiers() == Qt::NoModifier)
                    {
                        watchTree->editItem(cur, 0);
                        return true;
                    }
                }
            }
        }
        /*
         * Esc must be handled here: QPlainTextEdit accepts Key_Escape without
         * propagating to QDialog::keyPressEvent, so reject() never runs.
         * Dismiss inline find/go bars first; then queue close() so closeEvent()
         * runs (unsaved-scripts prompt). Skip if a different modal dialog owns
         * the event (e.g. nested prompt).
         */
        if (ke->key() == Qt::Key_Escape && ke->modifiers() == Qt::NoModifier)
        {
            QWidget *const modal = QApplication::activeModalWidget();
            if (modal && modal != this)
            {
                return QDialog::eventFilter(obj, event);
            }
            handleEscapeKey();
            return true;
        }
        const QKeySequence pressed = luaSeqFromKeyEvent(ke);
        if (triggerLuaDebuggerShortcuts(ui, pressed))
        {
            return true;
        }
    }
    return QDialog::eventFilter(obj, event);
}

void LuaDebuggerDialog::onClearBreakpoints()
{
    // Confirmation dialog
    const unsigned count = wslua_debugger_get_breakpoint_count();
    if (count == 0)
    {
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Clear All Breakpoints"),
        tr("Are you sure you want to remove %Ln breakpoint(s)?", "", count),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }

    wslua_debugger_clear_breakpoints();
    updateBreakpoints();
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
            view->updateBreakpointMarkers();
    }
}

void LuaDebuggerDialog::updateBreakpoints()
{
    breakpointsTree->clear();
    unsigned count = wslua_debugger_get_breakpoint_count();
    bool hasActiveBreakpoint = false;
    const bool collectInitialFiles = !breakpointTabsPrimed;
    QVector<QString> initialBreakpointFiles;
    QSet<QString> seenInitialFiles;
    for (unsigned i = 0; i < count; i++)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
        {
            QString normalizedPath =
                normalizedFilePath(QString::fromUtf8(file_path));
            QTreeWidgetItem *item = new QTreeWidgetItem(breakpointsTree);

            /* Check if file exists */
            QFileInfo fileInfo(normalizedPath);
            bool fileExists = fileInfo.exists() && fileInfo.isFile();

            item->setCheckState(0, active ? Qt::Checked : Qt::Unchecked);
            item->setData(0, BreakpointFileRole, normalizedPath);
            item->setData(0, BreakpointLineRole, static_cast<qlonglong>(line));
            item->setToolTip(0, tr("Enable or disable this breakpoint"));
            item->setText(1, QString::number(line));
            const QString fileDisplayName = fileInfo.fileName();
            QString locationText =
                QStringLiteral("%1:%2")
                    .arg(fileDisplayName.isEmpty() ? normalizedPath
                                                    : fileDisplayName)
                    .arg(line);
            item->setText(2, locationText);
            item->setTextAlignment(2, Qt::AlignLeft | Qt::AlignVCenter);

            if (!fileExists)
            {
                /* Mark stale breakpoints with warning icon and gray text */
                item->setIcon(2, QIcon::fromTheme("dialog-warning"));
                item->setToolTip(2,
                                 tr("File not found: %1").arg(normalizedPath));
                item->setForeground(0, QBrush(Qt::gray));
                item->setForeground(1, QBrush(Qt::gray));
                item->setForeground(2, QBrush(Qt::gray));
                /* Disable the checkbox for stale breakpoints */
                item->setFlags(item->flags() & ~Qt::ItemIsUserCheckable);
                item->setCheckState(0, Qt::Unchecked);
            }
            else
            {
                item->setToolTip(
                    2, tr("%1\nLine %2").arg(normalizedPath).arg(line));
            }

            item->setIcon(3, QIcon::fromTheme("edit-delete"));
            item->setToolTip(3, tr("Remove this breakpoint"));
            if (active && fileExists)
            {
                hasActiveBreakpoint = true;
            }

            /* Only add to file tree if file exists */
            if (fileExists)
            {
                ensureFileTreeEntry(normalizedPath);
            }

            /* Only open existing files initially */
            if (collectInitialFiles && fileExists &&
                !seenInitialFiles.contains(normalizedPath))
            {
                initialBreakpointFiles.append(normalizedPath);
                seenInitialFiles.insert(normalizedPath);
            }
        }
    }

    if (hasActiveBreakpoint)
    {
        ensureDebuggerEnabledForActiveBreakpoints();
    }
    syncDebuggerToggleWithCore();

    if (collectInitialFiles)
    {
        breakpointTabsPrimed = true;
        openInitialBreakpointFiles(initialBreakpointFiles);
    }
}

void LuaDebuggerDialog::updateStack()
{
    if (!stackTree)
    {
        return;
    }

    const bool signalsWereBlocked = stackTree->blockSignals(true);
    stackTree->clear();

    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);
    QTreeWidgetItem *itemToSelect = nullptr;
    if (stack && frameCount > 0)
    {
        const int maxLevel = static_cast<int>(frameCount) - 1;
        stackSelectionLevel = qBound(0, stackSelectionLevel, maxLevel);
        wslua_debugger_set_variable_stack_level(
            static_cast<int32_t>(stackSelectionLevel));

        for (int32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex)
        {
            QTreeWidgetItem *item = new QTreeWidgetItem(stackTree);
            item->setData(0, StackItemLevelRole,
                            static_cast<qlonglong>(frameIndex));
            const char *rawSource = stack[frameIndex].source;
            const bool isLuaFrame = rawSource && rawSource[0] == '@';
            const QString functionName = QString::fromUtf8(
                stack[frameIndex].name ? stack[frameIndex].name : "?");
            QString locationText;
            QString resolvedPath;
            if (isLuaFrame)
            {
                const QString filePath = QString::fromUtf8(rawSource + 1);
                resolvedPath = normalizedFilePath(filePath);
                if (resolvedPath.isEmpty())
                {
                    resolvedPath = filePath;
                }
                const QString fileDisplayName =
                    QFileInfo(resolvedPath).fileName();
                locationText = QStringLiteral("%1:%2")
                                   .arg(fileDisplayName.isEmpty() ? resolvedPath
                                                                 : fileDisplayName)
                                   .arg(stack[frameIndex].line);
                item->setToolTip(
                    1, QStringLiteral("%1:%2")
                           .arg(resolvedPath)
                           .arg(stack[frameIndex].line));
            }
            else
            {
                locationText = QString::fromUtf8(rawSource ? rawSource : "[C]");
            }

            item->setText(0, functionName);
            item->setText(1, locationText);

            if (isLuaFrame)
            {
                item->setData(0, StackItemNavigableRole, true);
                item->setData(0, StackItemFileRole, resolvedPath);
                item->setData(0, StackItemLineRole,
                              static_cast<qlonglong>(stack[frameIndex].line));
            }
            else
            {
                item->setData(0, StackItemNavigableRole, false);
                QColor disabledColor =
                    palette().color(QPalette::Disabled, QPalette::Text);
                item->setForeground(0, disabledColor);
                item->setForeground(1, disabledColor);
            }

            if (frameIndex == stackSelectionLevel)
            {
                itemToSelect = item;
            }
        }
        wslua_debugger_free_stack(stack, frameCount);
    }
    else
    {
        stackSelectionLevel = 0;
        wslua_debugger_set_variable_stack_level(0);
    }

    if (itemToSelect)
    {
        stackTree->setCurrentItem(itemToSelect);
    }
    stackTree->blockSignals(signalsWereBlocked);
}

void LuaDebuggerDialog::refreshVariablesForCurrentStackFrame()
{
    if (!variablesTree || !debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }
    variablesTree->clear();
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onStackCurrentItemChanged(QTreeWidgetItem *current,
                                                  QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (!stackTree || !current || !debuggerPaused ||
        !wslua_debugger_is_paused())
    {
        return;
    }

    const int level = static_cast<int>(current->data(0, StackItemLevelRole).toLongLong());
    if (level < 0 || level == stackSelectionLevel)
    {
        return;
    }

    stackSelectionLevel = level;
    wslua_debugger_set_variable_stack_level(static_cast<int32_t>(level));
    refreshVariablesForCurrentStackFrame();
    syncVariablesTreeToCurrentWatch();
}

// NOLINTNEXTLINE(misc-no-recursion)
void LuaDebuggerDialog::updateVariables(QTreeWidgetItem *parent,
                                        const QString &path)
{
    int32_t variableCount = 0;
    wslua_variable_t *variables = wslua_debugger_get_variables(
        path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    if (variables)
    {
        for (int32_t variableIndex = 0; variableIndex < variableCount;
             ++variableIndex)
        {
            QTreeWidgetItem *item;
            if (parent)
            {
                item = new QTreeWidgetItem(parent);
            }
            else
            {
                item = new QTreeWidgetItem(variablesTree);
            }

            const VariableRowFields f =
                readVariableRowFields(variables[variableIndex], path);

            item->setText(0, f.name);
            item->setText(1, f.value);

            const QString tooltipSuffix =
                f.type.isEmpty() ? QString() : tr("Type: %1").arg(f.type);
            item->setToolTip(
                0, tooltipSuffix.isEmpty()
                       ? f.name
                       : QStringLiteral("%1\n%2").arg(f.name, tooltipSuffix));
            item->setToolTip(1, tooltipSuffix.isEmpty()
                                    ? f.value
                                    : QStringLiteral("%1\n%2").arg(
                                          f.value, tooltipSuffix));
            item->setData(0, VariableTypeRole, f.type);
            item->setData(0, VariableCanExpandRole, f.canExpand);
            item->setData(0, VariablePathRole, f.childPath);

            applyVariableExpansionIndicator(item, f.canExpand,
                                            /*enabledOnlyPlaceholder=*/false);
        }
        // Sort Globals alphabetically; preserve declaration order for
        // Locals and Upvalues since that is more natural for debugging.
        if (variableChildrenShouldSortByName(path))
        {
            if (parent)
            {
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else
            {
                variablesTree->sortItems(0, Qt::AscendingOrder);
            }
        }

        wslua_debugger_free_variables(variables, variableCount);
    }
}

void LuaDebuggerDialog::onVariableItemExpanded(QTreeWidgetItem *item)
{
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        recordTreeSectionRootExpansion(variablesExpansion_, section, true);
    }
    else
    {
        const QString key = item->data(0, VariablePathRole).toString();
        recordTreeSectionSubpathExpansion(variablesExpansion_, section, key,
                                          true);
    }

    if (item->childCount() == 1 && item->child(0)->text(0).isEmpty())
    {
        // Remove dummy
        delete item->takeChild(0);

        QString path = item->data(0, VariablePathRole).toString();
        updateVariables(item, path);
    }
}

void LuaDebuggerDialog::onVariableItemCollapsed(QTreeWidgetItem *item)
{
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        recordTreeSectionRootExpansion(variablesExpansion_, section, false);
    }
    else
    {
        const QString key = item->data(0, VariablePathRole).toString();
        recordTreeSectionSubpathExpansion(variablesExpansion_, section, key,
                                          false);
    }
}

LuaDebuggerCodeView *LuaDebuggerDialog::loadFile(const QString &file_path)
{
    QString normalizedPath = normalizedFilePath(file_path);
    if (normalizedPath.isEmpty())
    {
        normalizedPath = file_path;
    }

    /* Check if file exists before creating a tab */
    QFileInfo fileInfo(normalizedPath);
    if (!fileInfo.exists() || !fileInfo.isFile())
    {
        /* File doesn't exist - don't create a tab */
        return nullptr;
    }

    // Check if already open
    const qint32 existingTabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < existingTabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->getFilename() == normalizedPath)
        {
            ui->codeTabWidget->setCurrentIndex(static_cast<int>(tabIndex));
            return view;
        }
    }

    // Create new tab
    LuaDebuggerCodeView *codeView = new LuaDebuggerCodeView(ui->codeTabWidget);
    codeView->setEditorFont(effectiveMonospaceFont(true));
    codeView->setFilename(normalizedPath);

    QFile file(normalizedPath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        codeView->setPlainText(file.readAll());
    }
    else
    {
        /* This should not happen since we checked exists() above,
         * but handle it gracefully just in case */
        delete codeView;
        return nullptr;
    }

    ensureFileTreeEntry(normalizedPath);

    // Connect signals
    codeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(codeView, &QWidget::customContextMenuRequested, this,
            &LuaDebuggerDialog::onCodeViewContextMenu);

    connect(
        codeView, &LuaDebuggerCodeView::breakpointToggled,
        [this](const QString &file_path, qint32 line)
        {
            const int32_t state = wslua_debugger_get_breakpoint_state(
                file_path.toUtf8().constData(), line);
            if (state == -1)
            {
                wslua_debugger_add_breakpoint(file_path.toUtf8().constData(),
                                              line);
                ensureDebuggerEnabledForActiveBreakpoints();
            }
            else
            {
                wslua_debugger_remove_breakpoint(file_path.toUtf8().constData(),
                                                 line);
                syncDebuggerToggleWithCore();
            }
            updateBreakpoints();
            // Update all views as breakpoint might affect them (unlikely but
            // safe)
            const qint32 tabCount =
                static_cast<qint32>(ui->codeTabWidget->count());
            for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
            {
                LuaDebuggerCodeView *tabView =
                    qobject_cast<LuaDebuggerCodeView *>(
                        ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
                if (tabView)
                    tabView->updateBreakpointMarkers();
            }
        });

    connect(codeView->document(), &QTextDocument::modificationChanged, this,
            [this, codeView]()
            {
                updateTabTextForCodeView(codeView);
                updateWindowModifiedState();
                if (ui->codeTabWidget->currentWidget() == codeView)
                {
                    updateSaveActionState();
                }
            });

    ui->codeTabWidget->addTab(codeView, QFileInfo(normalizedPath).fileName());
    updateTabTextForCodeView(codeView);
    ui->codeTabWidget->setCurrentWidget(codeView);
    ui->codeTabWidget->show();
    updateSaveActionState();
    updateWindowModifiedState();
    updateLuaEditorAuxFrames();
    return codeView;
}

LuaDebuggerCodeView *LuaDebuggerDialog::currentCodeView() const
{
    return qobject_cast<LuaDebuggerCodeView *>(
        ui->codeTabWidget->currentWidget());
}

qint32 LuaDebuggerDialog::unsavedOpenScriptTabCount() const
{
    qint32 count = 0;
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            ++count;
        }
    }
    return count;
}

bool LuaDebuggerDialog::hasUnsavedChanges() const
{
    return unsavedOpenScriptTabCount() > 0;
}

bool LuaDebuggerDialog::ensureUnsavedChangesHandled(const QString &title)
{
    if (!hasUnsavedChanges())
    {
        return true;
    }

    const qint32 unsavedCount = unsavedOpenScriptTabCount();
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, title,
        tr("There are unsaved changes in %Ln open file(s).", "", unsavedCount),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,
        QMessageBox::Save);

    if (reply == QMessageBox::Cancel)
    {
        return false;
    }
    if (reply == QMessageBox::Save)
    {
        return saveAllModified();
    }
    clearAllDocumentModified();
    return true;
}

void LuaDebuggerDialog::clearAllDocumentModified()
{
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->document()->setModified(false);
        }
    }
}

bool LuaDebuggerDialog::saveCodeView(LuaDebuggerCodeView *view)
{
    if (!view)
    {
        return false;
    }
    const QString path = view->getFilename();
    if (path.isEmpty())
    {
        return false;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(
            this, tr("Save Lua Script"),
            tr("Could not write to %1:\n%2").arg(path, file.errorString()));
        return false;
    }
    QTextStream out(&file);
    out << view->toPlainText();
    file.close();
    view->document()->setModified(false);
    return true;
}

bool LuaDebuggerDialog::saveAllModified()
{
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            if (!saveCodeView(view))
            {
                return false;
            }
        }
    }
    return true;
}

void LuaDebuggerDialog::updateTabTextForCodeView(LuaDebuggerCodeView *view)
{
    if (!view)
    {
        return;
    }
    const int tabIndex = ui->codeTabWidget->indexOf(view);
    if (tabIndex < 0)
    {
        return;
    }
    QString label = QFileInfo(view->getFilename()).fileName();
    if (view->document()->isModified())
    {
        label += QStringLiteral(" *");
    }
    ui->codeTabWidget->setTabText(tabIndex, label);
}

void LuaDebuggerDialog::updateSaveActionState()
{
    LuaDebuggerCodeView *view = currentCodeView();
    ui->actionSaveFile->setEnabled(view && view->document()->isModified());
}

void LuaDebuggerDialog::updateWindowModifiedState()
{
    setWindowModified(hasUnsavedChanges());
}

void LuaDebuggerDialog::showAccordionFrame(AccordionFrame *show_frame,
                                           bool toggle)
{
    QList<AccordionFrame *> frame_list =
        QList<AccordionFrame *>() << ui->luaDebuggerFindFrame
                                  << ui->luaDebuggerGoToLineFrame;
    frame_list.removeAll(show_frame);
    for (AccordionFrame *af : frame_list)
    {
        if (af)
        {
            af->animatedHide();
        }
    }
    if (!show_frame)
    {
        return;
    }
    if (toggle && show_frame->isVisible())
    {
        show_frame->animatedHide();
        return;
    }
    LuaDebuggerGoToLineFrame *const goto_frame =
        qobject_cast<LuaDebuggerGoToLineFrame *>(show_frame);
    if (goto_frame)
    {
        goto_frame->syncLineFieldFromEditor();
    }
    show_frame->animatedShow();
    if (LuaDebuggerFindFrame *const find_frame =
            qobject_cast<LuaDebuggerFindFrame *>(show_frame))
    {
        find_frame->scheduleFindFieldFocus();
    }
    else if (goto_frame)
    {
        goto_frame->scheduleLineFieldFocus();
    }
}

void LuaDebuggerDialog::updateLuaEditorAuxFrames()
{
    QPlainTextEdit *ed = currentCodeView();
    ui->luaDebuggerFindFrame->setTargetEditor(ed);
    ui->luaDebuggerGoToLineFrame->setTargetEditor(ed);
}

void LuaDebuggerDialog::onEditorFind()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerFindFrame, true);
}

void LuaDebuggerDialog::onEditorGoToLine()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerGoToLineFrame, true);
}

void LuaDebuggerDialog::onSaveFile()
{
    LuaDebuggerCodeView *view = currentCodeView();
    if (!view || !view->document()->isModified())
    {
        return;
    }
    saveCodeView(view);
    updateSaveActionState();
}

void LuaDebuggerDialog::onCodeTabCloseRequested(int idx)
{
    QWidget *widget = ui->codeTabWidget->widget(idx);
    LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(widget);
    if (view && view->document()->isModified())
    {
        const QMessageBox::StandardButton reply = QMessageBox::question(
            this, tr("Lua Debugger"),
            tr("Save changes to %1 before closing?")
                .arg(QFileInfo(view->getFilename()).fileName()),
            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,
            QMessageBox::Save);
        if (reply == QMessageBox::Cancel)
        {
            return;
        }
        if (reply == QMessageBox::Save)
        {
            if (!saveCodeView(view))
            {
                return;
            }
        }
        else
        {
            view->document()->setModified(false);
        }
    }

    ui->codeTabWidget->removeTab(idx);
    delete widget;
    updateSaveActionState();
    updateWindowModifiedState();
}

void LuaDebuggerDialog::onBreakpointItemChanged(QTreeWidgetItem *item,
                                                int column)
{
    if (column == 0)
    {
        const QString file = item->data(0, BreakpointFileRole).toString();
        const int64_t lineNumber =
            item->data(0, BreakpointLineRole).toLongLong();
        const bool active = item->checkState(0) == Qt::Checked;
        wslua_debugger_set_breakpoint_active(file.toUtf8().constData(),
                                             lineNumber, active);
        if (active)
        {
            ensureDebuggerEnabledForActiveBreakpoints();
        }
        else
        {
            syncDebuggerToggleWithCore();
        }

        const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
        for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
        {
            LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(
                ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
            if (tabView && tabView->getFilename() == file)
                tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerDialog::onBreakpointItemClicked(QTreeWidgetItem *item,
                                                int column)
{
    if (column == 3)
    {
        const QString file = item->data(0, BreakpointFileRole).toString();
        const int64_t lineNumber =
            item->data(0, BreakpointLineRole).toLongLong();
        wslua_debugger_remove_breakpoint(file.toUtf8().constData(), lineNumber);
        updateBreakpoints();

        const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
        for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
        {
            LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(
                ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
            if (tabView && tabView->getFilename() == file)
                tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerDialog::onBreakpointItemDoubleClicked(QTreeWidgetItem *item,
                                                      int column)
{
    Q_UNUSED(column);
    if (!item)
    {
        return;
    }

    const QString file = item->data(0, BreakpointFileRole).toString();
    const int64_t lineNumber = item->data(0, BreakpointLineRole).toLongLong();
    LuaDebuggerCodeView *view = loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(lineNumber));
    }
}

void LuaDebuggerDialog::onCodeViewContextMenu(const QPoint &pos)
{
    LuaDebuggerCodeView *codeView =
        qobject_cast<LuaDebuggerCodeView *>(sender());
    if (!codeView)
        return;

    QMenu menu(this);

    QAction *undoAct = menu.addAction(tr("Undo"));
    undoAct->setEnabled(codeView->document()->isUndoAvailable());
    connect(undoAct, &QAction::triggered, codeView, &QPlainTextEdit::undo);

    QAction *redoAct = menu.addAction(tr("Redo"));
    redoAct->setEnabled(codeView->document()->isRedoAvailable());
    connect(redoAct, &QAction::triggered, codeView, &QPlainTextEdit::redo);

    menu.addSeparator();

    QAction *cutAct = menu.addAction(tr("Cut"));
    cutAct->setEnabled(codeView->textCursor().hasSelection());
    connect(cutAct, &QAction::triggered, codeView, &QPlainTextEdit::cut);

    QAction *copyAct = menu.addAction(tr("Copy"));
    copyAct->setEnabled(codeView->textCursor().hasSelection());
    connect(copyAct, &QAction::triggered, codeView, &QPlainTextEdit::copy);

    QAction *pasteAct = menu.addAction(tr("Paste"));
    pasteAct->setEnabled(codeView->canPaste());
    connect(pasteAct, &QAction::triggered, codeView, &QPlainTextEdit::paste);

    QAction *selAllAct = menu.addAction(tr("Select All"));
    connect(selAllAct, &QAction::triggered, codeView, &QPlainTextEdit::selectAll);

    menu.addSeparator();
    menu.addAction(ui->actionFind);
    menu.addAction(ui->actionGoToLine);

    menu.addSeparator();

    QTextCursor cursor = codeView->cursorForPosition(pos);
    const qint32 lineNumber = static_cast<qint32>(cursor.blockNumber() + 1);

    // Check if breakpoint exists
    const int32_t state = wslua_debugger_get_breakpoint_state(
        codeView->getFilename().toUtf8().constData(), lineNumber);

    if (state == -1)
    {
        QAction *addBp = menu.addAction(tr("Add Breakpoint"));
        connect(addBp, &QAction::triggered,
                [this, codeView, lineNumber]()
                {
                    wslua_debugger_add_breakpoint(
                        codeView->getFilename().toUtf8().constData(),
                        lineNumber);
                    updateBreakpoints();
                    codeView->updateBreakpointMarkers();
                });
    }
    else
    {
        QAction *removeBp = menu.addAction(tr("Remove Breakpoint"));
        connect(removeBp, &QAction::triggered,
                [this, codeView, lineNumber]()
                {
                    wslua_debugger_remove_breakpoint(
                        codeView->getFilename().toUtf8().constData(),
                        lineNumber);
                    updateBreakpoints();
                    codeView->updateBreakpointMarkers();
                });
    }

    if (eventLoop)
    { // Only if paused
        QAction *runToLine = menu.addAction(tr("Run to this line"));
        connect(runToLine, &QAction::triggered,
                [this, codeView, lineNumber]()
                {
                    ensureDebuggerEnabledForActiveBreakpoints();
                    wslua_debugger_run_to_line(
                        codeView->getFilename().toUtf8().constData(),
                        lineNumber);
                    if (eventLoop)
                        eventLoop->quit();
                    debuggerPaused = false;
                    updateWidgets();
                    clearPausedStateUi();
                });

        // Evaluate selection if there is selected text
        QString selectedText = codeView->textCursor().selectedText();
        if (!selectedText.isEmpty())
        {
            menu.addSeparator();
            QAction *addWatch =
                menu.addAction(tr("Add Watch…"));
            connect(addWatch, &QAction::triggered,
                    [this, selectedText]()
                    {
                        const QString t = selectedText.trimmed();
                        if (!watchSpecUsesPathResolution(t))
                        {
                            showPathOnlyVariablePathWatchMessage();
                            return;
                        }
                        insertNewWatchRow(t, false);
                    });
        }
    }

    menu.exec(codeView->mapToGlobal(pos));
}

void LuaDebuggerDialog::onStackItemDoubleClicked(QTreeWidgetItem *item,
                                                 int column)
{
    Q_UNUSED(column);
    if (!item)
    {
        return;
    }
    if (!item->data(0, StackItemNavigableRole).toBool())
    {
        return;
    }
    const QString file = item->data(0, StackItemFileRole).toString();
    const qint64 line = item->data(0, StackItemLineRole).toLongLong();
    if (file.isEmpty() || line <= 0)
    {
        return;
    }
    LuaDebuggerCodeView *view = loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(line));
    }
}

void LuaDebuggerDialog::onMonospaceFontUpdated(const QFont &font)
{
    applyCodeEditorFonts(font);
}

void LuaDebuggerDialog::onMainAppInitialized()
{
    applyMonospaceFonts();
}

void LuaDebuggerDialog::onPreferencesChanged()
{
    applyCodeViewThemes();
    applyMonospaceFonts();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onThemeChanged(int idx)
{
    if (themeComboBox)
    {
        int32_t theme = themeComboBox->itemData(idx).toInt();

        /* Update static theme for CodeView syntax highlighting */
        currentTheme_ = theme;

        /* Store theme in our JSON settings */
        if (theme == WSLUA_DEBUGGER_THEME_DARK)
            settings_["theme"] = "dark";
        else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
            settings_["theme"] = "light";
        else
            settings_["theme"] = "auto";

        applyCodeViewThemes();
    }
}

void LuaDebuggerDialog::onColorsChanged()
{
    /*
     * When Wireshark's color scheme changes and the debugger theme is set to
     * "Auto (follow color scheme)", we need to re-apply themes to all code
     * views. The applyCodeViewThemes() function will query
     * ColorUtils::themeIsDark() to determine the effective theme.
     */
    applyCodeViewThemes();
    refreshWatchDisplay();
}

/**
 * @brief Static callback invoked before Lua plugins are reloaded.
 *
 * This callback is registered with wslua_debugger_register_reload_callback()
 * and is called by wslua_reload_plugins() BEFORE any Lua scripts are
 * unloaded or reloaded.
 *
 * The callback forwards to the dialog instance to reload all open
 * script files from disk. This ensures that when a breakpoint is hit
 * during the reload, the debugger displays the current version of
 * the script (which the user may have edited externally).
 */
void LuaDebuggerDialog::onLuaReloadCallback()
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog)
    {
        /*
         * If the debugger was paused, the UI layer called
         * wslua_debugger_notify_reload() which disabled the debugger
         * (continuing execution) and invoked this callback.
         * Exit the nested event loop so the Lua call stack can unwind.
         * handlePause() will schedule a deferred reload afterwards.
         */
        if (dialog->debuggerPaused && dialog->eventLoop)
        {
            dialog->debuggerPaused = false;
            dialog->clearPausedStateUi();
            dialog->reloadDeferred = true;
            dialog->eventLoop->quit();
            return;
        }

        /*
         * Reload all script files from disk.
         * This must happen BEFORE Lua executes any code.
         */
        dialog->reloadAllScriptFiles();

        /*
         * Update breakpoint markers in all open code views.
         * This ensures the gutter shows correct breakpoint indicators.
         *
         * Note: refreshAvailableScripts() and updateBreakpoints() are now
         * called in onLuaPostReloadCallback() AFTER plugins are loaded,
         * so new scripts appear in the file tree.
         */
        if (dialog->ui->codeTabWidget)
        {
            const qint32 tabCount =
                static_cast<qint32>(dialog->ui->codeTabWidget->count());
            for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
            {
                LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
                    dialog->ui->codeTabWidget->widget(
                        static_cast<int>(tabIndex)));
                if (view)
                {
                    view->updateBreakpointMarkers();
                }
            }
        }
    }
}

/**
 * @brief Static callback invoked AFTER Lua plugins are reloaded.
 *
 * This callback refreshes the file tree with newly loaded scripts.
 * It is called after wslua_init() completes, so the plugin list
 * now contains all the new scripts.
 */
void LuaDebuggerDialog::onLuaPostReloadCallback()
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog)
    {
        /*
         * Refresh the file tree with newly loaded scripts.
         * This is the correct place to do it because we're called
         * AFTER wslua_init() has loaded all plugins.
         */
        dialog->refreshAvailableScripts();
        dialog->updateBreakpoints();
    }
}

/**
 * @brief Static callback invoked when a Lua script is loaded.
 *
 * This callback is called by the Lua loader for each script that is
 * successfully loaded. We add the script to the file tree.
 */
void LuaDebuggerDialog::onScriptLoadedCallback(const char *file_path)
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog && file_path)
    {
        dialog->ensureFileTreeEntry(QString::fromUtf8(file_path));
        dialog->fileTree->sortItems(0, Qt::AscendingOrder);
    }
}

void LuaDebuggerDialog::reloadAllScriptFiles()
{
    if (!ui->codeTabWidget)
    {
        return;
    }

    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            if (view->document()->isModified())
            {
                /* Keep in-memory edits when this reload was not preceded by a
                 * save/discard prompt (e.g. Analyze → Reload Lua Plugins). */
                continue;
            }
            QString filePath = view->getFilename();
            if (!filePath.isEmpty())
            {
                QFile file(filePath);
                if (file.open(QIODevice::ReadOnly | QIODevice::Text))
                {
                    QTextStream in(&file);
                    QString content = in.readAll();
                    file.close();
                    view->setPlainText(content);
                }
            }
        }
    }
}

void LuaDebuggerDialog::applyCodeViewThemes()
{
    ui->luaDebuggerFindFrame->updateStyleSheet();
    ui->luaDebuggerGoToLineFrame->updateStyleSheet();
    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->applyTheme();
        }
    }
}

/**
 * @brief Callback function for wslua_debugger_foreach_loaded_script.
 *
 * This C callback receives each loaded script path from the Lua subsystem
 * and adds it to the file tree via the dialog instance.
 */
static void loaded_script_callback(const char *file_path, void *user_data)
{
    LuaDebuggerDialog *dialog = static_cast<LuaDebuggerDialog *>(user_data);
    if (dialog && file_path)
    {
        dialog->ensureFileTreeEntry(QString::fromUtf8(file_path));
    }
}

void LuaDebuggerDialog::refreshAvailableScripts()
{
    /* Clear existing file tree entries */
    fileTree->clear();

    /*
     * First, scan the plugin directories to show all available .lua files.
     * This includes files that may not be loaded yet.
     */
    const char *envPrefix = application_configuration_environment_prefix();
    if (envPrefix)
    {
        const char *personal = get_plugins_pers_dir(envPrefix);
        const char *global = get_plugins_dir(envPrefix);
        if (personal && personal[0])
        {
            scanScriptDirectory(QString::fromUtf8(personal));
        }
        if (global && global[0])
        {
            scanScriptDirectory(QString::fromUtf8(global));
        }
    }

    /*
     * Then, add any loaded scripts that might be outside the plugin
     * directories (e.g., command-line scripts).
     */
    wslua_debugger_foreach_loaded_script(loaded_script_callback, this);

    fileTree->sortItems(0, Qt::AscendingOrder);
    fileTree->expandAll();
}

void LuaDebuggerDialog::scanScriptDirectory(const QString &dir_path)
{
    if (dir_path.isEmpty())
    {
        return;
    }

    QDir scriptDirectory(dir_path);
    if (!scriptDirectory.exists())
    {
        return;
    }

    QDirIterator scriptIterator(dir_path, QStringList() << "*.lua", QDir::Files,
                                QDirIterator::Subdirectories);
    while (scriptIterator.hasNext())
    {
        ensureFileTreeEntry(scriptIterator.next());
    }
}

bool LuaDebuggerDialog::ensureFileTreeEntry(const QString &file_path)
{
    QString normalized = normalizedFilePath(file_path);
    if (normalized.isEmpty())
    {
        return false;
    }

    QVector<QPair<QString, QString>> components;
    if (!appendPathComponents(normalized, components))
    {
        return false;
    }

    QTreeWidgetItem *parent = nullptr;
    bool createdLeaf = false;
    const qint32 componentCount = static_cast<qint32>(components.size());
    for (qint32 componentIndex = 0; componentIndex < componentCount;
         ++componentIndex)
    {
        const bool isLeaf = (componentIndex == componentCount - 1);
        const QString displayName =
            components.at(static_cast<int>(componentIndex)).first;
        const QString absolutePath =
            components.at(static_cast<int>(componentIndex)).second;
        QTreeWidgetItem *item = findChildItemByPath(parent, absolutePath);
        if (!item)
        {
            item = parent ? new QTreeWidgetItem(parent)
                          : new QTreeWidgetItem(fileTree);
            item->setText(0, displayName);
            item->setToolTip(0, absolutePath);
            item->setData(0, FileTreePathRole, absolutePath);
            item->setData(0, FileTreeIsDirectoryRole, !isLeaf);
            item->setIcon(0, isLeaf ? fileIcon : folderIcon);
            if (parent)
            {
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else
            {
                fileTree->sortItems(0, Qt::AscendingOrder);
            }
            if (isLeaf)
            {
                createdLeaf = true;
            }
        }
        parent = item;
    }

    if (createdLeaf)
    {
        fileTree->expandAll();
    }

    return createdLeaf;
}

QString LuaDebuggerDialog::normalizedFilePath(const QString &file_path) const
{
    QString trimmed = file_path.trimmed();
    if (trimmed.startsWith("@"))
    {
        trimmed = trimmed.mid(1);
    }

    QFileInfo info(trimmed);
    QString absolutePath = info.absoluteFilePath();

    if (info.exists())
    {
        QString canonical = info.canonicalFilePath();
        if (!canonical.isEmpty())
        {
            return canonical;
        }
        return QDir::cleanPath(absolutePath);
    }

    if (!absolutePath.isEmpty())
    {
        return QDir::cleanPath(absolutePath);
    }

    return trimmed;
}

QTreeWidgetItem *
LuaDebuggerDialog::findChildItemByPath(QTreeWidgetItem *parent,
                                       const QString &path) const
{
    if (parent)
    {
        const qint32 childCount = static_cast<qint32>(parent->childCount());
        for (qint32 childIndex = 0; childIndex < childCount; ++childIndex)
        {
            QTreeWidgetItem *child =
                parent->child(static_cast<int>(childIndex));
            if (child->data(0, FileTreePathRole).toString() == path)
            {
                return child;
            }
        }
        return nullptr;
    }

    const qint32 topLevelCount =
        static_cast<qint32>(fileTree->topLevelItemCount());
    for (qint32 topLevelIndex = 0; topLevelIndex < topLevelCount;
         ++topLevelIndex)
    {
        QTreeWidgetItem *item =
            fileTree->topLevelItem(static_cast<int>(topLevelIndex));
        if (item->data(0, FileTreePathRole).toString() == path)
        {
            return item;
        }
    }
    return nullptr;
}

bool LuaDebuggerDialog::appendPathComponents(
    const QString &absolute_path,
    QVector<QPair<QString, QString>> &components) const
{
    QString forwardPath = QDir::fromNativeSeparators(absolute_path);
    QStringList segments = forwardPath.split('/', Qt::SkipEmptyParts);
    const qint32 segmentCount = static_cast<qint32>(segments.size());
    QString currentForward;
    qint32 segmentStartIndex = 0;

    if (absolute_path.startsWith("\\\\") || absolute_path.startsWith("//"))
    {
        if (segmentCount < 2)
        {
            return false;
        }
        currentForward =
            QStringLiteral("//%1/%2").arg(segments.at(0), segments.at(1));
        QString display =
            QStringLiteral("\\\\%1\\%2").arg(segments.at(0), segments.at(1));
        components.append({display, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 2;
    }
    else if (segmentCount > 0 && segments.first().endsWith(QLatin1Char(':')))
    {
        currentForward = segments.first();
        QString storedRoot = currentForward;
        if (!storedRoot.endsWith(QLatin1Char('/')))
        {
            storedRoot += QLatin1Char('/');
        }
        components.append(
            {currentForward, QDir::toNativeSeparators(storedRoot)});
        segmentStartIndex = 1;
    }
    else if (absolute_path.startsWith('/'))
    {
        currentForward = QStringLiteral("/");
        components.append({currentForward, currentForward});
    }
    else if (segmentCount > 0)
    {
        currentForward = segments.first();
        components.append(
            {currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    if (currentForward.isEmpty() && segmentCount > 0)
    {
        currentForward = segments.first();
        components.append(
            {currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    for (qint32 segmentIndex = segmentStartIndex; segmentIndex < segmentCount;
         ++segmentIndex)
    {
        const QString &segment = segments.at(static_cast<int>(segmentIndex));
        if (currentForward.isEmpty() || currentForward == "/")
        {
            currentForward = currentForward == "/"
                                 ? QStringLiteral("/%1").arg(segment)
                                 : segment;
        }
        else
        {
            currentForward += "/" + segment;
        }
        components.append({segment, QDir::toNativeSeparators(currentForward)});
    }

    return !components.isEmpty();
}

void LuaDebuggerDialog::openInitialBreakpointFiles(
    const QVector<QString> &files)
{
    for (const QString &path : files)
    {
        loadFile(path);
    }
}

void LuaDebuggerDialog::configureVariablesTreeColumns()
{
    if (!variablesTree || !variablesTree->header())
    {
        return;
    }
    variablesTree->setColumnCount(2);
    QHeaderView *header = variablesTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    // Initial width for Name column - Value column stretches to fill the rest
    header->resizeSection(0, 150);
}

void LuaDebuggerDialog::configureWatchTreeColumns()
{
    if (!watchTree || !watchTree->header())
    {
        return;
    }
    QHeaderView *header = watchTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    header->resizeSection(0, 200);
}

void LuaDebuggerDialog::configureStackTreeColumns()
{
    if (!stackTree || !stackTree->header())
    {
        return;
    }
    QHeaderView *header = stackTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    // Initial width for Function column - Location column stretches to fill the
    // rest
    header->resizeSection(0, 150);
}

void LuaDebuggerDialog::clearPausedStateUi()
{
    if (variablesTree)
    {
        variablesTree->clear();
    }
    if (stackTree)
    {
        stackTree->clear();
    }
    clearAllCodeHighlights();
}

void LuaDebuggerDialog::resumeDebuggerAndExitLoop()
{
    if (debuggerPaused)
    {
        wslua_debugger_continue();
        debuggerPaused = false;
        clearPausedStateUi();
    }

    if (eventLoop)
    {
        eventLoop->quit();
    }
}

void LuaDebuggerDialog::onVariablesContextMenuRequested(const QPoint &pos)
{
    if (!variablesTree)
    {
        return;
    }

    QTreeWidgetItem *item = variablesTree->itemAt(pos);
    if (!item)
    {
        return;
    }

    const QString nameText = item->text(0);
    const QString valueText = item->text(1);
    const QString bothText =
        valueText.isEmpty() ? nameText : tr("%1 = %2").arg(nameText, valueText);

    QMenu menu(this);
    QAction *copyName = menu.addAction(tr("Copy Name"));
    QAction *copyValue = menu.addAction(tr("Copy Value"));
    QAction *copyBoth = menu.addAction(tr("Copy Name && Value"));

    auto copyToClipboard = [](const QString &text)
    {
        if (QClipboard *clipboard = QGuiApplication::clipboard())
        {
            clipboard->setText(text);
        }
    };

    connect(copyName, &QAction::triggered, this,
            [copyToClipboard, nameText]() { copyToClipboard(nameText); });
    connect(copyValue, &QAction::triggered, this,
            [copyToClipboard, valueText]() { copyToClipboard(valueText); });
    connect(copyBoth, &QAction::triggered, this,
            [copyToClipboard, bothText]() { copyToClipboard(bothText); });

    if (eventLoop)
    {
        menu.addSeparator();
        const QString varPath = item->data(0, VariablePathRole).toString();
        if (!varPath.isEmpty())
        {
            QAction *addWatch =
                menu.addAction(tr("Add Watch: \"%1\"")
                                   .arg(varPath.length() > 48
                                            ? varPath.left(48) +
                                                  QStringLiteral("…")
                                            : varPath));
            connect(addWatch, &QAction::triggered, this,
                    [this, varPath]() { addPathWatch(varPath); });
        }
    }

    menu.exec(variablesTree->viewport()->mapToGlobal(pos));
}

void LuaDebuggerDialog::clearAllCodeHighlights()
{
    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->clearCurrentLineHighlight();
        }
    }
}

void LuaDebuggerDialog::applyMonospaceFonts()
{
    applyCodeEditorFonts(effectiveMonospaceFont(true));
    applyMonospacePanelFonts();
}

void LuaDebuggerDialog::applyCodeEditorFonts(const QFont &monoFont)
{
    QFont font = monoFont;
    if (font.family().isEmpty())
    {
        font = effectiveMonospaceFont(true);
    }

    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->setEditorFont(font);
        }
    }
}

void LuaDebuggerDialog::applyMonospacePanelFonts()
{
    const QFont panelMono = effectiveMonospaceFont(false);
    const QFont headerFont = effectiveRegularFont();

    const QList<QWidget *> widgets = {variablesTree, watchTree, stackTree,
                                      breakpointsTree, evalInputEdit,
                                      evalOutputEdit};
    for (QWidget *widget : widgets)
    {
        if (widget)
        {
            widget->setFont(panelMono);
        }
    }

    const QList<QTreeWidget *> treesWithStandardHeaders = {
        variablesTree, watchTree, stackTree, fileTree, breakpointsTree};
    for (QTreeWidget *tree : treesWithStandardHeaders)
    {
        if (tree && tree->header())
        {
            tree->header()->setFont(headerFont);
        }
    }
}

QFont LuaDebuggerDialog::effectiveMonospaceFont(bool zoomed) const
{
    /* Monospace font for panels and the script editor. */
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->monospaceFont(zoomed);
    }

    /* Fall back to system fixed font */
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QFont LuaDebuggerDialog::effectiveRegularFont() const
{
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->font();
    }
    return QGuiApplication::font();
}

void LuaDebuggerDialog::syncDebuggerToggleWithCore()
{
    if (!enabledCheckBox)
    {
        return;
    }
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    bool previousState = enabledCheckBox->blockSignals(true);
    enabledCheckBox->setChecked(debuggerEnabled);
    enabledCheckBox->blockSignals(previousState);
    updateWidgets();
}

void LuaDebuggerDialog::updateEnabledCheckboxIcon()
{
    if (!enabledCheckBox)
    {
        return;
    }

    const bool debuggerEnabled = wslua_debugger_is_enabled();

    // Create a colored circle icon to indicate enabled/disabled state
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    if (debuggerEnabled)
    {
        // Green circle for enabled
        painter.setBrush(QColor("#28A745"));
        painter.setPen(Qt::NoPen);
        enabledCheckBox->setToolTip(
            tr("Debugger is enabled. Uncheck to disable."));
    }
    else
    {
        // Gray circle for disabled
        painter.setBrush(QColor("#808080"));
        painter.setPen(Qt::NoPen);
        enabledCheckBox->setToolTip(
            tr("Debugger is disabled. Check to enable."));
    }
    painter.drawEllipse(2, 2, 12, 12);
    painter.end();

    enabledCheckBox->setIcon(QIcon(pixmap));
}

void LuaDebuggerDialog::updateStatusLabel()
{
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    /* [*] is required for setWindowModified() to show an unsaved
     * indicator in the title. */
    QString title = QStringLiteral("[*]%1").arg(tr("Lua Debugger"));

#ifdef Q_OS_MAC
        // On macOS we separate with a unicode em dash
        title += QString(" " UTF8_EM_DASH " ");
#else
        title += QString(" - ");
#endif

    if (!debuggerEnabled)
    {
        title += tr("Disabled");
    }
    else if (debuggerPaused)
    {
        title += tr("Paused");
    }
    else
    {
        title += tr("Running");
    }

    setWindowTitle(title);
    updateWindowModifiedState();
}

void LuaDebuggerDialog::updateContinueActionState()
{
    const bool allowContinue = wslua_debugger_is_enabled() && debuggerPaused;
    ui->actionContinue->setEnabled(allowContinue);
    ui->actionStepOver->setEnabled(allowContinue);
    ui->actionStepIn->setEnabled(allowContinue);
    ui->actionStepOut->setEnabled(allowContinue);
}

void LuaDebuggerDialog::updateWidgets()
{
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    updateEvalPanelState();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::ensureDebuggerEnabledForActiveBreakpoints()
{
    if (!wslua_debugger_is_enabled())
    {
        wslua_debugger_set_enabled(true);
        syncDebuggerToggleWithCore();
    }
}

void LuaDebuggerDialog::onOpenFile()
{
    QString startDir = lastOpenDirectory;
    if (startDir.isEmpty())
    {
        startDir = QDir::homePath();
    }

    const QString filePath = WiresharkFileDialog::getOpenFileName(
        this, tr("Open Lua Script"), startDir,
        tr("Lua Scripts (*.lua);;All Files (*)"));

    if (filePath.isEmpty())
    {
        return;
    }

    lastOpenDirectory = QFileInfo(filePath).absolutePath();
    loadFile(filePath);
}

void LuaDebuggerDialog::onReloadLuaPlugins()
{
    if (!ensureUnsavedChangesHandled(tr("Reload Lua Plugins")))
    {
        return;
    }

    // Confirmation dialog
    QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Reload Lua Plugins"),
        tr("Are you sure you want to reload all Lua plugins?\n\nThis will "
           "restart all Lua "
           "scripts and may affect capture analysis."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }

    /*
     * If the debugger is currently paused, disable it (which continues
     * execution), signal the event loop to exit, and let handlePause()
     * schedule a deferred reload after the Lua call stack unwinds.
     */
    if (debuggerPaused)
    {
        wslua_debugger_notify_reload();
        /* onLuaReloadCallback() has already set reloadDeferred,
         * cleared paused UI, and quit the event loop. */
        updateWidgets();
        return;
    }

    /*
     * Not paused — trigger the reload directly via the delayed
     * path so it runs after this dialog method returns.
     */
    if (mainApp)
    {
        mainApp->reloadLuaPluginsDelayed();
    }
}

void LuaDebuggerDialog::updateEvalPanelState()
{
    const bool canEvaluate = debuggerPaused && wslua_debugger_is_paused();
    evalInputEdit->setEnabled(canEvaluate);
    evalButton->setEnabled(canEvaluate);

    if (!canEvaluate)
    {
        evalInputEdit->setPlaceholderText(
            tr("Evaluation available when debugger is paused"));
    }
    else
    {
        evalInputEdit->setPlaceholderText(
            tr("Enter Lua expression (prefix with = to return value)"));
    }
}

void LuaDebuggerDialog::onEvaluate()
{
    if (!debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }

    QString expression = evalInputEdit->toPlainText().trimmed();
    if (expression.isEmpty())
    {
        return;
    }

    char *error_msg = nullptr;
    char *result =
        wslua_debugger_evaluate(expression.toUtf8().constData(), &error_msg);

    QString output;
    if (result)
    {
        output = QString::fromUtf8(result);
        g_free(result);
    }
    else if (error_msg)
    {
        output = tr("Error: %1").arg(QString::fromUtf8(error_msg));
        g_free(error_msg);
    }
    else
    {
        output = tr("Error: Unknown error");
    }

    // Append to output with separator
    QString currentOutput = evalOutputEdit->toPlainText();
    if (!currentOutput.isEmpty())
    {
        currentOutput += QStringLiteral("\n");
    }
    currentOutput += QStringLiteral("> %1\n%2").arg(expression, output);
    evalOutputEdit->setPlainText(currentOutput);

    // Scroll to bottom
    QTextCursor cursor = evalOutputEdit->textCursor();
    cursor.movePosition(QTextCursor::End);
    evalOutputEdit->setTextCursor(cursor);

    // Update all views in case the expression modified state
    updateStack();
    variablesTree->clear();
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshAvailableScripts();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onEvalClear()
{
    evalInputEdit->clear();
    evalOutputEdit->clear();
}

void LuaDebuggerDialog::storeWatchList()
{
    if (!watchTree)
    {
        return;
    }
    /* On disk, "watches" is a flat array of canonical watch spec strings in
     * visual order. Per-row expansion, editor origin, and other runtime state
     * are tracked in QTreeWidgetItem data roles only and are not persisted. */
    QStringList specs;
    const int n = watchTree->topLevelItemCount();
    for (int i = 0; i < n; ++i)
    {
        QTreeWidgetItem *it = watchTree->topLevelItem(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(0, WatchSpecRole).toString();
        if (spec.isEmpty())
        {
            continue;
        }
        specs.append(spec);
    }
    settings_[SettingsKeys::Watches] = specs;
    /* The runtime expansion map is keyed by root spec; drop entries for
     * specs that no longer exist in the tree. `storeWatchList` only runs
     * when the dialog is closing, which is also the last chance to avoid
     * persisting stale expansion data for specs that have since been
     * deleted or renamed. */
    pruneWatchExpansionMap();
}

void LuaDebuggerDialog::storeBreakpointsList()
{
    QVariantList list;
    const unsigned count = wslua_debugger_get_breakpoint_count();
    for (unsigned i = 0; i < count; i++)
    {
        const char *file = nullptr;
        int64_t line = 0;
        bool active = false;
        if (wslua_debugger_get_breakpoint(i, &file, &line, &active))
        {
            QJsonObject bp;
            bp[QStringLiteral("file")] = QString::fromUtf8(file);
            bp[QStringLiteral("line")] = static_cast<qint64>(line);
            bp[QStringLiteral("active")] = active;
            list.append(bp.toVariantMap());
        }
    }
    settings_[SettingsKeys::Breakpoints] = list;
}

void LuaDebuggerDialog::rebuildWatchTreeFromSettings()
{
    if (!watchTree)
    {
        return;
    }
    watchTree->clear();
    /* The watch list on disk is a flat array of canonical spec strings.
     * Values that are not a valid path watch, or that are not strings, are
     * silently dropped (see wslua_debugger_watch_spec_uses_path_resolution). */
    const QVariantList rawList =
        settings_.value(QString::fromUtf8(SettingsKeys::Watches)).toList();
    for (const QVariant &entry : rawList)
    {
        /* Container QVariants (QVariantMap / QVariantList) toString() to an
         * empty string and are dropped here. Scalar-like values (numbers,
         * booleans) convert to a non-empty string but are then rejected by
         * watchSpecUsesPathResolution below. */
        const QString spec = entry.toString();
        if (spec.isEmpty())
        {
            continue;
        }
        if (!watchSpecUsesPathResolution(spec))
        {
            continue;
        }
        QTreeWidgetItem *row = new QTreeWidgetItem(watchTree);
        setupWatchRootItemFromSpec(row, spec);
    }
    refreshWatchDisplay();
    restoreWatchExpansionState();
}

namespace
{
// NOLINTNEXTLINE(misc-no-recursion)
static QTreeWidgetItem *findVariableItemByPathRecursive(QTreeWidgetItem *node,
                                                        const QString &path)
{
    if (!node)
    {
        return nullptr;
    }
    if (node->data(0, VariablePathRole).toString() == path)
    {
        return node;
    }
    const int n = node->childCount();
    for (int i = 0; i < n; ++i)
    {
        QTreeWidgetItem *r =
            findVariableItemByPathRecursive(node->child(i), path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}
} // namespace

void LuaDebuggerDialog::deleteWatchRows(const QList<QTreeWidgetItem *> &items)
{
    if (!watchTree || items.isEmpty())
    {
        return;
    }
    QVector<int> indices;
    indices.reserve(items.size());
    for (QTreeWidgetItem *it : items)
    {
        if (!it || it->parent() != nullptr)
        {
            continue;
        }
        const int idx = watchTree->indexOfTopLevelItem(it);
        if (idx >= 0)
        {
            indices.append(idx);
        }
    }
    if (indices.isEmpty())
    {
        return;
    }
    /* Delete highest-index first so earlier indices remain valid. */
    std::sort(indices.begin(), indices.end(), std::greater<int>());
    for (int idx : indices)
    {
        delete watchTree->takeTopLevelItem(idx);
    }
    refreshWatchDisplay();
}

QTreeWidgetItem *
LuaDebuggerDialog::findVariablesItemByPath(const QString &path) const
{
    if (!variablesTree || path.isEmpty())
    {
        return nullptr;
    }
    const int top = variablesTree->topLevelItemCount();
    for (int i = 0; i < top; ++i)
    {
        QTreeWidgetItem *r =
            findVariableItemByPathRecursive(variablesTree->topLevelItem(i),
                                            path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}

QTreeWidgetItem *
LuaDebuggerDialog::findWatchRootForVariablePath(const QString &path) const
{
    if (!watchTree || path.isEmpty())
    {
        return nullptr;
    }
    const int n = watchTree->topLevelItemCount();
    for (int i = 0; i < n; ++i)
    {
        QTreeWidgetItem *w = watchTree->topLevelItem(i);
        const QString spec = w->data(0, WatchSpecRole).toString();
        QString vp = watchResolvedVariablePathForTooltip(spec);
        if (vp.isEmpty())
        {
            vp = watchVariablePathForSpec(spec);
        }
        if (!vp.isEmpty() && vp == path)
        {
            return w;
        }
        if (w->data(0, VariablePathRole).toString() == path)
        {
            return w;
        }
    }
    return nullptr;
}

void LuaDebuggerDialog::expandAncestorsOf(QTreeWidget *tree,
                                            QTreeWidgetItem *item)
{
    if (!tree || !item)
    {
        return;
    }
    QList<QTreeWidgetItem *> chain;
    for (QTreeWidgetItem *p = item->parent(); p; p = p->parent())
    {
        chain.prepend(p);
    }
    for (QTreeWidgetItem *a : chain)
    {
        tree->expandItem(a);
    }
}

void LuaDebuggerDialog::onVariablesCurrentItemChanged(
    QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !variablesTree || !current)
    {
        return;
    }
    const QString path = current->data(0, VariablePathRole).toString();
    if (path.isEmpty())
    {
        return;
    }
    QTreeWidgetItem *watch = findWatchRootForVariablePath(path);
    if (!watch)
    {
        return;
    }
    syncWatchVariablesSelection_ = true;
    watchTree->setCurrentItem(watch);
    watchTree->scrollToItem(watch);
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::syncVariablesTreeToCurrentWatch()
{
    if (syncWatchVariablesSelection_ || !watchTree || !variablesTree)
    {
        return;
    }
    QTreeWidgetItem *const cur = watchTree->currentItem();
    if (!cur || cur->parent() != nullptr)
    {
        return;
    }
    const QString spec = cur->data(0, WatchSpecRole).toString();
    if (spec.isEmpty())
    {
        return;
    }
    QString path = cur->data(0, VariablePathRole).toString();
    if (path.isEmpty())
    {
        path = watchResolvedVariablePathForTooltip(spec);
        if (path.isEmpty())
        {
            path = watchVariablePathForSpec(spec);
        }
    }
    if (path.isEmpty())
    {
        return;
    }
    QTreeWidgetItem *v = findVariablesItemByPath(path);
    if (!v)
    {
        return;
    }
    syncWatchVariablesSelection_ = true;
    expandAncestorsOf(variablesTree, v);
    variablesTree->setCurrentItem(v);
    variablesTree->scrollToItem(v);
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::onWatchCurrentItemChanged(QTreeWidgetItem *current,
                                                  QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !variablesTree ||
        !current)
    {
        return;
    }
    if (current->parent() != nullptr)
    {
        return;
    }
    const QString spec = current->data(0, WatchSpecRole).toString();
    if (spec.isEmpty())
    {
        return;
    }

    const bool live = wslua_debugger_is_enabled() && debuggerPaused &&
                      wslua_debugger_is_paused();
    if (live)
    {
        const int32_t desired = wslua_debugger_find_stack_level_for_watch_spec(
            spec.toUtf8().constData());
        if (desired >= 0 && desired != stackSelectionLevel)
        {
            stackSelectionLevel = static_cast<int>(desired);
            wslua_debugger_set_variable_stack_level(desired);
            refreshVariablesForCurrentStackFrame();
            updateStack();
        }
    }

    syncVariablesTreeToCurrentWatch();
}

void LuaDebuggerDialog::refreshWatchDisplay()
{
    if (!watchTree)
    {
        return;
    }
    const bool liveContext = wslua_debugger_is_enabled() && debuggerPaused &&
                             wslua_debugger_is_paused();
    const QString muted = QStringLiteral("\u2014");
    const int n = watchTree->topLevelItemCount();
    for (int i = 0; i < n; ++i)
    {
        QTreeWidgetItem *root = watchTree->topLevelItem(i);
        applyWatchItemState(root, liveContext, muted);
        if (liveContext && root && root->isExpanded())
        {
            refreshWatchBranch(root);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemEmpty(QTreeWidgetItem *item,
                                            const QString &muted,
                                            const QString &watchTipExtra)
{
    clearWatchFilterErrorChrome(item, watchTree);
    item->setText(1, muted);
    item->setToolTip(0, watchTipExtra);
    /* Explain the muted em dash instead of leaving an empty tooltip: a blank
     * row has no variable path to evaluate, so there is nothing to show in
     * the Value column. */
    item->setToolTip(
        1,
        capWatchTooltipText(
            tr("No watch path entered yet — enter a variable path in the "
               "Watch column to see a value here.")));
    QFont f1 = item->font(1);
    f1.setBold(false);
    item->setFont(1, f1);
    item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
    while (item->childCount() > 0)
    {
        delete item->takeChild(0);
    }
}

void LuaDebuggerDialog::applyWatchItemNonPath(QTreeWidgetItem *item,
                                              const QString &watchTipExtra)
{
    /* Defensive: normal entry points reject non-path specs before a row is
     * created, but hand-edited lua_debugger.json could still supply one. */
    applyWatchFilterErrorChrome(item, watchTree);
    item->setText(1, tr("Not a variable path"));
    item->setToolTip(
        0,
        capWatchTooltipText(
            QStringLiteral("%1\n%2")
                .arg(item->text(0),
                     tr("Use a Variables-style path (e.g. Locals.x, "
                        "Globals.t.k, t[1], t[\"k\"], or a single identifier).")) +
                watchTipExtra));
    item->setToolTip(
        1, capWatchTooltipText(tr("Only variable paths can be watched.")));
    QFont fe = item->font(1);
    fe.setBold(false);
    item->setFont(1, fe);
    item->setData(0, WatchChildSnapRole, QVariant());
    item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
    while (item->childCount() > 0)
    {
        delete item->takeChild(0);
    }
}

void LuaDebuggerDialog::applyWatchItemNoLiveContext(QTreeWidgetItem *item,
                                                    const QString &muted,
                                                    const QString &watchTipExtra)
{
    item->setText(1, muted);
    item->setForeground(1, watchTree->palette().brush(QPalette::PlaceholderText));
    /* Replace the previous `muted \n Type: muted` tooltip (which just
     * repeated the em dash) with a short explanation so the user knows
     * *why* there is no value: watches are only evaluated while the
     * debugger is paused. */
    const QString mutedReason =
        wslua_debugger_is_enabled()
            ? tr("Value shown only while the debugger is paused.")
            : tr("Value shown only while the debugger is paused. "
                 "The debugger is currently disabled.");
    const QString ttSuf = tr("Type: %1").arg(muted);
    item->setToolTip(
        0,
        capWatchTooltipText(
            QStringLiteral("%1\n%2\n%3")
                .arg(item->text(0), mutedReason, ttSuf) +
            watchTipExtra));
    item->setToolTip(1, capWatchTooltipText(mutedReason));
    QFont f1 = item->font(1);
    f1.setBold(false);
    item->setFont(1, f1);
    item->setData(0, WatchLastValueRole, QVariant());
    item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
    if (item->parent() == nullptr)
    {
        item->setData(0, WatchChildSnapRole, QVariant());
        while (item->childCount() > 0)
        {
            delete item->takeChild(0);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemError(QTreeWidgetItem *item,
                                            const QString &errStr,
                                            const QString &watchTipExtra)
{
    applyWatchFilterErrorChrome(item, watchTree);
    item->setText(1, errStr);
    const QString ttSuf = tr("Type: %1").arg(tr("error"));
    item->setToolTip(
        0,
        capWatchTooltipText(
            QStringLiteral("%1\n%2").arg(item->text(0), ttSuf) + watchTipExtra));
    item->setToolTip(
        1,
        capWatchTooltipText(
            QStringLiteral("%1\n%2\n%3")
                .arg(tr("Invalid watch path."), errStr, ttSuf)));
    item->setData(0, WatchChildSnapRole, QVariant());
    item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
    while (item->childCount() > 0)
    {
        delete item->takeChild(0);
    }
}

void LuaDebuggerDialog::applyWatchItemSuccess(QTreeWidgetItem *item,
                                              const QString &spec,
                                              const char *val, const char *typ,
                                              bool can_expand,
                                              const QString &watchTipExtra)
{
    if (item->parent() == nullptr)
    {
        watchRootSetVariablePathRoleFromSpec(item, spec);
    }
    const QString v = val ? QString::fromUtf8(val) : QString();
    const QString typStr = typ ? QString::fromUtf8(typ) : QString();
    const QString prev = item->data(0, WatchLastValueRole).toString();
    item->setText(1, v);
    const QString ttSuf =
        typStr.isEmpty() ? QString() : tr("Type: %1").arg(typStr);
    item->setToolTip(
        0,
        capWatchTooltipText(
            (ttSuf.isEmpty()
                 ? item->text(0)
                 : QStringLiteral("%1\n%2").arg(item->text(0), ttSuf)) +
            watchTipExtra));
    item->setToolTip(
        1,
        capWatchTooltipText(
            ttSuf.isEmpty() ? v : QStringLiteral("%1\n%2").arg(v, ttSuf)));
    QFont f1 = item->font(1);
    f1.setBold(!prev.isEmpty() && prev != v);
    item->setFont(1, f1);
    item->setData(0, WatchLastValueRole, v);

    if (can_expand)
    {
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        if (item->childCount() == 0)
        {
            QTreeWidgetItem *const ph = new QTreeWidgetItem(item);
            ph->setFlags(Qt::ItemIsEnabled);
        }
    }
    else
    {
        item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
        while (item->childCount() > 0)
        {
            delete item->takeChild(0);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemState(QTreeWidgetItem *item,
                                            bool liveContext,
                                            const QString &muted)
{
    if (!item)
    {
        return;
    }

    const QString spec = item->data(0, WatchSpecRole).toString();
    const QString watchTipExtra = watchPathOriginSuffix(item, spec);

    if (item->parent() == nullptr && spec.isEmpty())
    {
        applyWatchItemEmpty(item, muted, watchTipExtra);
        return;
    }

    if (!watchSpecUsesPathResolution(spec))
    {
        applyWatchItemNonPath(item, watchTipExtra);
        return;
    }

    clearWatchFilterErrorChrome(item, watchTree);
    item->setForeground(1, watchTree->palette().brush(QPalette::Text));

    if (!liveContext)
    {
        applyWatchItemNoLiveContext(item, muted, watchTipExtra);
        return;
    }

    char *val = nullptr;
    char *typ = nullptr;
    bool can_expand = false;
    char *err = nullptr;
    const bool ok = wslua_debugger_watch_read_root(
        spec.toUtf8().constData(), &val, &typ, &can_expand, &err);
    if (!ok)
    {
        const QString errStr = err ? QString::fromUtf8(err) : muted;
        applyWatchItemError(item, errStr, watchTipExtra);
        g_free(err);
        return;
    }

    applyWatchItemSuccess(item, spec, val, typ, can_expand, watchTipExtra);
    g_free(val);
    g_free(typ);
}

void LuaDebuggerDialog::fillWatchPathChildren(QTreeWidgetItem *parent,
                                              const QString &path)
{
    /* Path watches drill down with wslua_debugger_get_variables (same tree as
     * Variables); expression watches use wslua_debugger_watch_* elsewhere. */
    if (watchSubpathBoundaryCount(path) >= WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        QTreeWidgetItem *sent = new QTreeWidgetItem(parent);
        sent->setText(0, QStringLiteral("\u2026"));
        sent->setText(1, tr("Maximum watch depth reached"));
        sent->setFlags(Qt::ItemIsEnabled);
        QTreeWidget *tw = parent->treeWidget();
        if (tw)
        {
            sent->setForeground(
                1, tw->palette().brush(QPalette::PlaceholderText));
        }
        sent->setToolTip(
            1, capWatchTooltipText(tr("Maximum watch depth reached.")));
        return;
    }

    int32_t variableCount = 0;
    wslua_variable_t *variables = wslua_debugger_get_variables(
        path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    if (!variables)
    {
        return;
    }

    for (int32_t variableIndex = 0; variableIndex < variableCount;
         ++variableIndex)
    {
        QTreeWidgetItem *item = new QTreeWidgetItem(parent);

        const VariableRowFields f =
            readVariableRowFields(variables[variableIndex], path);

        item->setText(0, f.name);
        item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        item->setData(0, VariableTypeRole, f.type);
        item->setData(0, VariableCanExpandRole, f.canExpand);
        item->setData(0, VariablePathRole, f.childPath);

        applyWatchChildRowPresentation(item, f.childPath, f.value, f.type);

        applyVariableExpansionIndicator(item, f.canExpand,
                                        /*enabledOnlyPlaceholder=*/true);
    }

    if (variableChildrenShouldSortByName(path))
    {
        parent->sortChildren(0, Qt::AscendingOrder);
    }

    wslua_debugger_free_variables(variables, variableCount);
}

namespace
{
/** Subpath / variable-path key used to address @p item inside a watch root. */
static QString watchItemExpansionKey(const QTreeWidgetItem *item)
{
    if (!item || !item->parent())
    {
        return QString();
    }
    const QString sp = item->data(0, WatchSubpathRole).toString();
    if (!sp.isEmpty())
    {
        return sp;
    }
    return item->data(0, VariablePathRole).toString();
}
} // namespace

void LuaDebuggerDialog::recordTreeSectionRootExpansion(
    QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
    bool expanded)
{
    if (rootKey.isEmpty())
    {
        return;
    }
    if (!expanded && !map.contains(rootKey))
    {
        return;
    }
    TreeSectionExpansionState &e = map[rootKey];
    e.rootExpanded = expanded;
    if (!expanded && e.subpaths.isEmpty())
    {
        map.remove(rootKey);
    }
}

void LuaDebuggerDialog::recordTreeSectionSubpathExpansion(
    QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
    const QString &key, bool expanded)
{
    if (rootKey.isEmpty() || key.isEmpty())
    {
        return;
    }
    if (expanded)
    {
        TreeSectionExpansionState &e = map[rootKey];
        if (!e.subpaths.contains(key))
        {
            e.subpaths.append(key);
        }
    }
    else
    {
        auto it = map.find(rootKey);
        if (it == map.end())
        {
            return;
        }
        it->subpaths.removeAll(key);
        if (!it->rootExpanded && it->subpaths.isEmpty())
        {
            map.erase(it);
        }
    }
}

QStringList LuaDebuggerDialog::treeSectionExpandedSubpaths(
    const QHash<QString, TreeSectionExpansionState> &map,
    const QString &rootKey) const
{
    if (rootKey.isEmpty())
    {
        return QStringList();
    }
    const auto it = map.constFind(rootKey);
    if (it == map.constEnd())
    {
        return QStringList();
    }
    return it->subpaths;
}

void LuaDebuggerDialog::recordWatchRootExpansion(const QString &rootSpec,
                                                 bool expanded)
{
    recordTreeSectionRootExpansion(watchExpansion_, rootSpec, expanded);
}

void LuaDebuggerDialog::recordWatchSubpathExpansion(const QString &rootSpec,
                                                    const QString &key,
                                                    bool expanded)
{
    recordTreeSectionSubpathExpansion(watchExpansion_, rootSpec, key, expanded);
}

QStringList
LuaDebuggerDialog::watchExpandedSubpathsForSpec(const QString &rootSpec) const
{
    return treeSectionExpandedSubpaths(watchExpansion_, rootSpec);
}

void LuaDebuggerDialog::pruneWatchExpansionMap()
{
    if (!watchTree || watchExpansion_.isEmpty())
    {
        return;
    }
    QSet<QString> liveSpecs;
    const int n = watchTree->topLevelItemCount();
    for (int i = 0; i < n; ++i)
    {
        const QTreeWidgetItem *it = watchTree->topLevelItem(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(0, WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            liveSpecs.insert(spec);
        }
    }
    for (auto it = watchExpansion_.begin(); it != watchExpansion_.end();)
    {
        if (!liveSpecs.contains(it.key()))
        {
            it = watchExpansion_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void LuaDebuggerDialog::onWatchItemExpanded(QTreeWidgetItem *item)
{
    if (!item)
    {
        return;
    }
    /* Track expansion in the runtime map. This fires for both user-driven
     * expansion and the programmatic setExpanded(true) calls made by
     * reexpandWatchDescendantsByPathKeys; re-recording an already-tracked
     * key is idempotent. */
    const QTreeWidgetItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(0, WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        recordWatchRootExpansion(rootSpec, true);
    }
    else
    {
        recordWatchSubpathExpansion(rootSpec, watchItemExpansionKey(item),
                                    true);
    }

    if (item->childCount() == 1 && item->child(0)->text(0).isEmpty())
    {
        delete item->takeChild(0);
    }
    else if (item->childCount() > 0)
    {
        return;
    }

    refillWatchChildren(item);
}

void LuaDebuggerDialog::onWatchItemCollapsed(QTreeWidgetItem *item)
{
    if (!item)
    {
        return;
    }
    const QTreeWidgetItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(0, WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        recordWatchRootExpansion(rootSpec, false);
    }
    else
    {
        recordWatchSubpathExpansion(rootSpec, watchItemExpansionKey(item),
                                    false);
    }
}

void LuaDebuggerDialog::refillWatchChildren(QTreeWidgetItem *item)
{
    if (!item)
    {
        return;
    }
    while (item->childCount() > 0)
    {
        delete item->takeChild(0);
    }

    const QTreeWidgetItem *const rootWatch = watchRootItem(item);
    const QString rootSpec = rootWatch->data(0, WatchSpecRole).toString();
    QString path = item->data(0, VariablePathRole).toString();
    if (path.isEmpty())
    {
        path = watchResolvedVariablePathForTooltip(rootSpec);
        if (path.isEmpty())
        {
            path = watchVariablePathForSpec(rootSpec);
        }
    }
    fillWatchPathChildren(item, path);
}

void LuaDebuggerDialog::refreshWatchBranch(QTreeWidgetItem *item)
{
    if (!item || !item->isExpanded())
    {
        return;
    }
    /* refillWatchChildren deletes and re-creates every descendant, so the
     * tree alone cannot remember which sub-elements were expanded. Instead,
     * consult the dialog-level runtime expansion map (watchExpansion_),
     * which is kept up to date by onWatchItemExpanded / onWatchItemCollapsed
     * and survives both refills and the children-clearing that happens while
     * the debugger is not paused. This lets deep subtrees survive stepping,
     * pause / resume, and Variables tree refreshes without being tied to
     * transient QTreeWidgetItem lifetimes. */
    const QTreeWidgetItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(0, WatchSpecRole).toString() : QString();
    refillWatchChildren(item);
    reexpandWatchDescendantsByPathKeys(
        item, watchExpandedSubpathsForSpec(rootSpec));
}

namespace
{
/** Pointers into the context menu built by buildWatchContextMenu(). */
struct WatchContextMenuActions
{
    QAction *addWatch = nullptr;
    QAction *copyValue = nullptr;
    QAction *remove = nullptr;
    QAction *duplicate = nullptr;
    QAction *moveUp = nullptr;
    QAction *moveDown = nullptr;
};
} /* namespace */

/**
 * Populate @a menu with the watch context-menu actions appropriate for
 * @a item (may be null / a child row), returning pointers to each action
 * so the caller can dispatch on the chosen QAction.
 *
 * Sub-element rows (descendants of a watch root) only expose `Add Watch…`
 * and `Copy Value`; the remaining entries (Remove, Duplicate, Move
 * Up/Down) operate on the watch list itself and therefore only make
 * sense on watch roots.
 */
static void buildWatchContextMenu(QMenu &menu, QTreeWidgetItem *item,
                                  WatchContextMenuActions *acts)
{
    acts->addWatch = menu.addAction(QObject::tr("Add Watch…"));
    if (!item)
    {
        return;
    }

    menu.addSeparator();
    acts->copyValue = menu.addAction(QObject::tr("Copy Value"));

    if (item->parent() != nullptr)
    {
        return;
    }

    menu.addSeparator();
    acts->moveUp = menu.addAction(QObject::tr("Move Up"));
    acts->moveDown = menu.addAction(QObject::tr("Move Down"));
    acts->duplicate = menu.addAction(QObject::tr("Duplicate Watch"));
    acts->remove = menu.addAction(QObject::tr("Remove"));
}

void LuaDebuggerDialog::onWatchContextMenuRequested(const QPoint &pos)
{
    if (!watchTree)
    {
        return;
    }

    QTreeWidgetItem *item = watchTree->itemAt(pos);

    QMenu menu(this);
    WatchContextMenuActions acts;
    buildWatchContextMenu(menu, item, &acts);

    QAction *chosen = menu.exec(watchTree->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }

    if (chosen == acts.addWatch)
    {
        insertNewWatchRow(QString(), true);
        return;
    }
    if (!item)
    {
        return;
    }

    auto copyToClipboard = [](const QString &text)
    {
        if (QClipboard *clipboard = QGuiApplication::clipboard())
        {
            clipboard->setText(text);
        }
    };

    /* Copy value works on both watch roots and sub-element rows — the
     * value column is populated uniformly by applyWatchItemState (roots)
     * and applyWatchChildRowPresentation (descendants).
     *
     * The tree's value column shows a truncated preview
     * (WSLUA_DEBUGGER_PREVIEW_MAX_BYTES in the engine); for "Copy Value"
     * we re-read the live, untruncated stringification via
     * wslua_debugger_read_variable_value_full so long strings and
     * Tvb / ByteArray dumps copy in full. If the debugger is not paused
     * we fall back to whatever the tree currently shows — the engine has
     * no live state to re-query then. */
    if (chosen == acts.copyValue)
    {
        QString value;
        const QString varPath = item->data(0, VariablePathRole).toString();
        if (!varPath.isEmpty() && debuggerPaused &&
            wslua_debugger_is_enabled() && wslua_debugger_is_paused())
        {
            char *val = nullptr;
            char *err = nullptr;
            if (wslua_debugger_read_variable_value_full(
                    varPath.toUtf8().constData(), &val, &err))
            {
                value = QString::fromUtf8(val ? val : "");
            }
            g_free(val);
            g_free(err);
        }
        if (value.isNull())
        {
            value = item->text(1);
        }
        copyToClipboard(value);
        return;
    }

    if (item->parent() != nullptr)
    {
        return;
    }

    if (chosen == acts.remove)
    {
        QList<QTreeWidgetItem *> del;
        for (QTreeWidgetItem *it : watchTree->selectedItems())
        {
            if (it && it->parent() == nullptr)
            {
                del.append(it);
            }
        }
        if (del.isEmpty())
        {
            del.append(item);
        }
        deleteWatchRows(del);
        return;
    }

    const int idx = watchTree->indexOfTopLevelItem(item);
    if (chosen == acts.duplicate)
    {
        QTreeWidgetItem *copy = new QTreeWidgetItem();
        copy->setFlags(copy->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                       Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
        copy->setText(0, item->text(0));
        for (int r = WatchSpecRole; r <= WatchPendingNewRole; ++r)
        {
            copy->setData(0, r, item->data(0, r));
        }
        copy->setData(0, WatchPendingNewRole, QVariant(false));
        copy->setData(0, VariablePathRole, item->data(0, VariablePathRole));
        copy->setData(0, VariableTypeRole, item->data(0, VariableTypeRole));
        copy->setData(0, VariableCanExpandRole,
                       item->data(0, VariableCanExpandRole));
        copy->setData(0, WatchLastValueRole, QVariant());
        copy->setData(0, WatchChildSnapRole, QVariant());
        copy->setExpanded(false);
        if (copy->childCount() == 0)
        {
            QTreeWidgetItem *const ph = new QTreeWidgetItem(copy);
            ph->setFlags(Qt::ItemIsEnabled);
        }
        watchTree->insertTopLevelItem(idx + 1, copy);
        refreshWatchDisplay();
        return;
    }
    if (chosen == acts.moveUp && idx > 0)
    {
        QTreeWidgetItem *taken = watchTree->takeTopLevelItem(idx);
        watchTree->insertTopLevelItem(idx - 1, taken);
        return;
    }
    if (chosen == acts.moveDown && idx >= 0 &&
        idx < watchTree->topLevelItemCount() - 1)
    {
        QTreeWidgetItem *taken = watchTree->takeTopLevelItem(idx);
        watchTree->insertTopLevelItem(idx + 1, taken);
        return;
    }
}

void LuaDebuggerDialog::addPathWatch(const QString &debuggerPath)
{
    insertNewWatchRow(debuggerPath, false);
}

void LuaDebuggerDialog::showPathOnlyVariablePathWatchMessage()
{
    QMessageBox::information(
        this, tr("Lua Debugger"),
        tr("Only variable paths can be watched (e.g. Locals.name, Globals.x, "
           "or a single identifier for Locals.name)."));
}

void LuaDebuggerDialog::commitWatchRootSpec(QTreeWidgetItem *item,
                                            const QString &text)
{
    if (!watchTree || !item || item->parent() != nullptr)
    {
        return;
    }

    const QString t = text.trimmed();
    if (t.isEmpty())
    {
        /* Clearing the text of a brand-new row discards it (no persisted
         * entry ever existed); clearing an existing row removes it. */
        if (item->data(0, WatchPendingNewRole).toBool())
        {
            delete item;
            refreshWatchDisplay();
        }
        else
        {
            deleteWatchRows({item});
        }
        return;
    }

    if (t.size() > WATCH_EXPR_MAX_CHARS)
    {
        QMessageBox::warning(
            this, tr("Lua Debugger"),
            tr("Watch path is too long (maximum %Ln characters).", "",
               static_cast<qlonglong>(WATCH_EXPR_MAX_CHARS)));
        return;
    }

    if (!watchSpecUsesPathResolution(t))
    {
        showPathOnlyVariablePathWatchMessage();
        return;
    }

    item->setData(0, WatchSpecRole, t);
    item->setText(0, t);
    item->setData(0, WatchPendingNewRole, QVariant(false));
    watchRootSetVariablePathRoleFromSpec(item, t);
    if (item->childCount() == 0)
    {
        QTreeWidgetItem *const ph = new QTreeWidgetItem(item);
        ph->setFlags(Qt::ItemIsEnabled);
    }
    refreshWatchDisplay();
}

void LuaDebuggerDialog::insertNewWatchRow(const QString &initialSpec,
                                          bool openEditor)
{
    if (!watchTree)
    {
        return;
    }

    const QString init = initialSpec.trimmed();
    if (!init.isEmpty() && !watchSpecUsesPathResolution(init))
    {
        showPathOnlyVariablePathWatchMessage();
        return;
    }

    QTreeWidgetItem *row = new QTreeWidgetItem(watchTree);
    row->setFlags(row->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                  Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    row->setData(0, WatchSpecRole, init);
    row->setText(0, init);
    row->setData(0, WatchSubpathRole, QString());
    row->setData(0, WatchPendingNewRole, init.isEmpty());
    if (!init.isEmpty())
    {
        watchRootSetVariablePathRoleFromSpec(row, init);
    }
    {
        QTreeWidgetItem *const ph = new QTreeWidgetItem(row);
        ph->setFlags(Qt::ItemIsEnabled);
    }
    refreshWatchDisplay();

    if (openEditor)
    {
        QTimer::singleShot(0, this, [this, row]()
                           {
                               watchTree->scrollToItem(row);
                               watchTree->setCurrentItem(row);
                               watchTree->editItem(row, 0);
                           });
    }
}

void LuaDebuggerDialog::restoreWatchExpansionState()
{
    if (!watchTree)
    {
        return;
    }
    /* Re-apply each root's expansion from the runtime map. After a fresh load
     * from lua_debugger.json the map is empty (rows open collapsed). */
    for (int i = 0; i < watchTree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem *root = watchTree->topLevelItem(i);
        const QString spec = root->data(0, WatchSpecRole).toString();
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = watchExpansion_.constFind(spec);
        if (it != watchExpansion_.cend())
        {
            rootExpanded = it->rootExpanded;
            subpaths = it->subpaths;
        }
        if (rootExpanded != root->isExpanded())
        {
            root->setExpanded(rootExpanded);
        }
        if (rootExpanded)
        {
            reexpandTreeDescendantsByPathKeys(root, subpaths,
                                               findWatchItemBySubpathOrPathKey);
        }
    }
}

void LuaDebuggerDialog::restoreVariablesExpansionState()
{
    if (!variablesTree)
    {
        return;
    }
    for (int i = 0; i < variablesTree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem *root = variablesTree->topLevelItem(i);
        const QString section = root->data(0, VariablePathRole).toString();
        if (section.isEmpty())
        {
            continue;
        }
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = variablesExpansion_.constFind(section);
        if (it == variablesExpansion_.cend())
        {
            if (section == QLatin1String("Locals"))
            {
                rootExpanded = true;
            }
        }
        else
        {
            rootExpanded = it->rootExpanded;
            subpaths = it->subpaths;
        }
        if (rootExpanded != root->isExpanded())
        {
            root->setExpanded(rootExpanded);
        }
        if (rootExpanded)
        {
            reexpandTreeDescendantsByPathKeys(root, subpaths,
                                               findVariableTreeItemByPathKey);
        }
    }
}

// Qt-based JSON Settings Persistence
void LuaDebuggerDialog::loadSettingsFile()
{
    const QString path = luaDebuggerSettingsFilePath();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
    {
        return;
    }

    QFile loadFile(path);
    if (!loadFile.open(QIODevice::ReadOnly))
    {
        return;
    }

    QByteArray loadData = loadFile.readAll();
    if (loadData.startsWith("\xef\xbb\xbf"))
    {
        loadData = loadData.mid(3);
    }
    loadData = loadData.trimmed();

    QJsonParseError parseError;
    const QJsonDocument document =
        QJsonDocument::fromJson(loadData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
    {
        return;
    }
    settings_ = document.object().toVariantMap();
}

void LuaDebuggerDialog::saveSettingsFile()
{
    /*
     * Always merge live watch rows and engine breakpoints before writing so
     * callers that only touch theme/splitters (or watches alone) do not persist
     * stale or empty breakpoint/watch entries.
     */
    if (watchTree)
    {
        storeWatchList();
    }
    storeBreakpointsList();

    const QString savePath = luaDebuggerSettingsFilePath();
    QFileInfo fileInfo(savePath);

    QFile saveFile(savePath);
    if (fileInfo.exists() && !fileInfo.isFile())
    {
        return;
    }

    if (saveFile.open(QIODevice::WriteOnly))
    {
        QJsonDocument document(QJsonObject::fromVariantMap(settings_));
        QByteArray saveData = document.toJson(QJsonDocument::Indented);
        saveFile.write(saveData);
    }
}

void LuaDebuggerDialog::applyDialogSettings()
{
    loadSettingsFile();

    /*
     * Load JSON into the engine and watch tree. JSON is read only here (dialog
     * construction); it is written only from closeEvent() (see saveSettingsFile).
     * Apply breakpoints first so that list is never empty before rebuild.
     */
    QJsonArray breakpointsArray =
        jsonArrayFromSettingsMap(settings_, SettingsKeys::Breakpoints);
    for (const QJsonValue &val : breakpointsArray)
    {
        QJsonObject bp = val.toObject();
        QString file = bp.value("file").toString();
        int64_t line = bp.value("line").toVariant().toLongLong();
        bool active = bp.value("active").toBool(true);

        if (!file.isEmpty() && line > 0)
        {
            int32_t state = wslua_debugger_get_breakpoint_state(
                file.toUtf8().constData(), line);
            if (state < 0)
            {
                wslua_debugger_add_breakpoint(file.toUtf8().constData(), line);
            }
            wslua_debugger_set_breakpoint_active(file.toUtf8().constData(),
                                                 line, active);
        }
    }

    rebuildWatchTreeFromSettings();

    // Apply theme setting
    QString themeStr = settings_.value(SettingsKeys::Theme, "auto").toString();
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeStr == "dark")
        theme = WSLUA_DEBUGGER_THEME_DARK;
    else if (themeStr == "light")
        theme = WSLUA_DEBUGGER_THEME_LIGHT;
    currentTheme_ = theme;

    if (themeComboBox)
    {
        int idx = themeComboBox->findData(theme);
        if (idx >= 0)
            themeComboBox->setCurrentIndex(idx);
    }

    QString mainSplitterHex =
        settings_.value(SettingsKeys::MainSplitter).toString();
    QString leftSplitterHex =
        settings_.value(SettingsKeys::LeftSplitter).toString();

    bool splittersRestored = false;
    if (!mainSplitterHex.isEmpty() && ui->mainSplitter)
    {
        ui->mainSplitter->restoreState(
            QByteArray::fromHex(mainSplitterHex.toLatin1()));
        splittersRestored = true;
    }
    if (!leftSplitterHex.isEmpty() && ui->leftSplitter)
    {
        ui->leftSplitter->restoreState(
            QByteArray::fromHex(leftSplitterHex.toLatin1()));
        splittersRestored = true;
    }

    if (!splittersRestored && ui->mainSplitter)
    {
        ui->mainSplitter->setStretchFactor(0, 1);
        ui->mainSplitter->setStretchFactor(1, 2);
        QList<int> sizes;
        sizes << 300 << 600;
        ui->mainSplitter->setSizes(sizes);
    }

    if (variablesSection)
        variablesSection->setExpanded(
            settings_.value(SettingsKeys::SectionVariables, true).toBool());
    if (stackSection)
        stackSection->setExpanded(
            settings_.value(SettingsKeys::SectionStack, true).toBool());
    if (breakpointsSection)
        breakpointsSection->setExpanded(
            settings_.value(SettingsKeys::SectionBreakpoints, true).toBool());
    if (filesSection)
        filesSection->setExpanded(
            settings_.value(SettingsKeys::SectionFiles, false).toBool());
    if (evalSection)
        evalSection->setExpanded(
            settings_.value(SettingsKeys::SectionEval, false).toBool());
    if (settingsSection)
        settingsSection->setExpanded(
            settings_.value(SettingsKeys::SectionSettings, false).toBool());
    if (watchSection)
        watchSection->setExpanded(
            settings_.value(SettingsKeys::SectionWatch, true).toBool());
}

void LuaDebuggerDialog::storeDialogSettings()
{
    /*
     * Refresh settings_ from UI only (no disk I/O). JSON is written from
     * closeEvent() via saveSettingsFile().
     */
    // Store theme from combo box (or current C-side value)
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeComboBox)
    {
        theme = themeComboBox->itemData(themeComboBox->currentIndex()).toInt();
    }
    if (theme == WSLUA_DEBUGGER_THEME_DARK)
        settings_[SettingsKeys::Theme] = "dark";
    else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
        settings_[SettingsKeys::Theme] = "light";
    else
        settings_[SettingsKeys::Theme] = "auto";

    // Store splitter states as hex strings
    if (ui->mainSplitter)
    {
        settings_[SettingsKeys::MainSplitter] =
            QString::fromLatin1(ui->mainSplitter->saveState().toHex());
    }
    if (ui->leftSplitter)
    {
        settings_[SettingsKeys::LeftSplitter] =
            QString::fromLatin1(ui->leftSplitter->saveState().toHex());
    }

    // Store section expanded states
    settings_[SettingsKeys::SectionVariables] =
        variablesSection ? variablesSection->isExpanded() : true;
    settings_[SettingsKeys::SectionStack] =
        stackSection ? stackSection->isExpanded() : true;
    settings_[SettingsKeys::SectionBreakpoints] =
        breakpointsSection ? breakpointsSection->isExpanded() : true;
    settings_[SettingsKeys::SectionFiles] =
        filesSection ? filesSection->isExpanded() : false;
    settings_[SettingsKeys::SectionEval] =
        evalSection ? evalSection->isExpanded() : false;
    settings_[SettingsKeys::SectionSettings] =
        settingsSection ? settingsSection->isExpanded() : false;
    settings_[SettingsKeys::SectionWatch] =
        watchSection ? watchSection->isExpanded() : true;

    if (watchTree)
    {
        storeWatchList();
    }
}
