/* lua_debugger_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lua_debugger_dialog.h"
#include "lua_debugger_code_view.h"
#include "main_application.h"
#include "main_window.h"
#include "ui_lua_debugger_dialog.h"
#include "utils/stock_icon.h"
#include "widgets/collapsible_section.h"

#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPalette>
#include <QPointer>
#include <QScrollArea>
#include <QSet>
#include <QStandardPaths>
#include <QStyle>
#include <QTextStream>
#include <QVBoxLayout>
#include <QtGlobal>

#include <glib.h>

#include "ui/recent.h"
#include "app/application_flavor.h"
#include "wsutil/filesystem.h"
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/utils/qt_ui_utils.h>

#define LUA_DEBUGGER_SETTINGS_FILE "lua_debugger.json"

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
constexpr const char *FontFamily = "fontFamily";
constexpr const char *FontSize = "fontSize";
constexpr const char *DialogWidth = "dialogWidth";
constexpr const char *DialogHeight = "dialogHeight";
constexpr const char *DialogX = "dialogX";
constexpr const char *DialogY = "dialogY";
constexpr const char *MainSplitter = "mainSplitterState";
constexpr const char *LeftSplitter = "leftSplitterState";
constexpr const char *SectionVariables = "sectionVariables";
constexpr const char *SectionStack = "sectionStack";
constexpr const char *SectionFiles = "sectionFiles";
constexpr const char *SectionBreakpoints = "sectionBreakpoints";
constexpr const char *SectionEval = "sectionEval";
constexpr const char *SectionSettings = "sectionSettings";
constexpr const char *Breakpoints = "breakpoints";
} // namespace SettingsKeys

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
constexpr qint32 VariablePathRole = static_cast<qint32>(Qt::UserRole + 7);
constexpr qint32 VariableTypeRole = static_cast<qint32>(Qt::UserRole + 8);
constexpr qint32 VariableCanExpandRole = static_cast<qint32>(Qt::UserRole + 9);

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
} // namespace

LuaDebuggerDialog::LuaDebuggerDialog(QWidget *parent)
    : GeometryStateDialog(parent), ui(new Ui::LuaDebuggerDialog),
      eventLoop(nullptr), enabledCheckBox(nullptr), breakpointTabsPrimed(false),
      debuggerPaused(false), reloadDeferred(false), variablesSection(nullptr),
      stackSection(nullptr), filesSection(nullptr), breakpointsSection(nullptr),
      evalSection(nullptr), settingsSection(nullptr), variablesTree(nullptr),
      stackTree(nullptr), fileTree(nullptr), breakpointsTree(nullptr),
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
    ui->toolBar->setStyleSheet(
        QStringLiteral("QToolBar { spacing: 4px; padding: 2px 4px; }"));
    ui->actionOpenFile->setIcon(StockIcon("document-open"));
    ui->actionContinue->setIcon(StockIcon("media-playback-start"));
    ui->actionStep->setIcon(StockIcon("go-next"));
    ui->actionReloadLuaPlugins->setIcon(StockIcon("view-refresh"));
    ui->actionClearBreakpoints->setIcon(StockIcon("edit-clear"));
    ui->actionOpenFile->setToolTip(tr("Open Lua Script"));
    ui->actionContinue->setToolTip(tr("Continue execution (F5)"));
    ui->actionStep->setToolTip(tr("Step to next line (F10)"));
    ui->actionReloadLuaPlugins->setToolTip(
        tr("Reload Lua Plugins (Ctrl+Shift+L)"));
    ui->actionClearBreakpoints->setToolTip(tr("Remove all breakpoints"));
    ui->actionContinue->setShortcut(QKeySequence(Qt::Key_F5));
    ui->actionContinue->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStep->setShortcut(QKeySequence(Qt::Key_F10));
    ui->actionStep->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionReloadLuaPlugins->setShortcut(
        QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_L));
    ui->actionReloadLuaPlugins->setShortcutContext(
        Qt::WidgetWithChildrenShortcut);
    folderIcon = StockIcon("folder");
    fileIcon = StockIcon("text-x-generic");

    // Toolbar controls - Checkbox for enable/disable
    // Order: Checkbox | Separator | Continue | Step | Separator | Open | Reload
    // | Clear
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
    connect(ui->actionStep, &QAction::triggered, this,
            &LuaDebuggerDialog::onStep);
    connect(ui->actionClearBreakpoints, &QAction::triggered, this,
            &LuaDebuggerDialog::onClearBreakpoints);
    connect(ui->actionOpenFile, &QAction::triggered, this,
            &LuaDebuggerDialog::onOpenFile);
    connect(ui->actionReloadLuaPlugins, &QAction::triggered, this,
            &LuaDebuggerDialog::onReloadLuaPlugins);
    addAction(ui->actionContinue);
    addAction(ui->actionStep);
    addAction(ui->actionReloadLuaPlugins);

    // Tab Widget
    connect(ui->codeTabWidget, &QTabWidget::tabCloseRequested,
            [this](int idx)
            {
                QWidget *w = ui->codeTabWidget->widget(idx);
                ui->codeTabWidget->removeTab(idx);
                delete w;
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
    variablesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(variablesTree, &QTreeWidget::customContextMenuRequested, this,
            &LuaDebuggerDialog::onVariablesContextMenuRequested);

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

    // Evaluate panel
    connect(evalButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvaluate);
    connect(evalClearButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvalClear);

    configureVariablesTreeColumns();
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
                &LuaDebuggerDialog::onMonospaceFontUpdated,
                Qt::UniqueConnection);
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
}

LuaDebuggerDialog::~LuaDebuggerDialog()
{
    /*
     * Store all settings to JSON file (theme, font, geometry, sections,
     * splitters, breakpoints).
     */
    storeDialogSettings();

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
    variablesTree = new QTreeWidget();
    variablesTree->setColumnCount(3);
    variablesTree->setHeaderLabels({tr("Name"), tr("Value"), tr("Type")});
    variablesSection->setContentWidget(variablesTree);
    variablesSection->setExpanded(true);
    splitter->addWidget(variablesSection);

    // --- Stack Trace Section ---
    stackSection = new CollapsibleSection(tr("Stack Trace"), this);
    stackTree = new QTreeWidget();
    stackTree->setColumnCount(2);
    stackTree->setHeaderLabels({tr("Function"), tr("Location")});
    stackTree->setRootIsDecorated(true);
    stackSection->setContentWidget(stackTree);
    stackSection->setExpanded(true);
    splitter->addWidget(stackSection);

    // --- Files Section ---
    filesSection = new CollapsibleSection(tr("Files"), this);
    fileTree = new QTreeWidget();
    fileTree->setColumnCount(1);
    fileTree->setHeaderLabels({tr("Files")});
    fileTree->setRootIsDecorated(false);
    filesSection->setContentWidget(fileTree);
    filesSection->setExpanded(true);
    splitter->addWidget(filesSection);

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
    sizes << 120 << 100 << headerH << 80 << headerH
          << headerH; // Variables, Stack, Files(collapsed), Breakpoints,
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

    updateStack();
    variablesTree->clear();
    updateVariables(nullptr, QString());

    /*
     * If an event loop is already running (e.g. we were called from onStep()
     * which triggered an immediate re-pause), reuse it instead of nesting.
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

void LuaDebuggerDialog::onStep()
{
    if (!debuggerPaused)
    {
        return;
    }

    debuggerPaused = false;
    clearPausedStateUi();

    /*
     * Call wslua_debugger_step() which will immediately fire the line
     * hook. If it hits a pause, handlePause() is called synchronously.
     * handlePause() detects that eventLoop is already set and reuses
     * it instead of nesting a new one — so the stack does NOT grow
     * with each step.
     */
    wslua_debugger_step();

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

void LuaDebuggerDialog::closeEvent(QCloseEvent *event)
{
    /* Disable the debugger so breakpoints won't fire and reopen the
     * dialog after it has been closed. */
    wslua_debugger_set_enabled(false);
    resumeDebuggerAndExitLoop();

    GeometryStateDialog::closeEvent(event);
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
            QString locationText =
                QStringLiteral("%1:%2").arg(normalizedPath).arg(line);
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
    stackTree->clear();
    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);
    if (stack)
    {
        for (int32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex)
        {
            QTreeWidgetItem *item = new QTreeWidgetItem(stackTree);
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
                locationText = QStringLiteral("%1:%2")
                                   .arg(resolvedPath)
                                   .arg(stack[frameIndex].line);
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
                item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
            }
        }
        wslua_debugger_free_stack(stack, frameCount);
    }
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

            const QString nameText = QString::fromUtf8(
                variables[variableIndex].name ? variables[variableIndex].name
                                              : "");
            const QString valueText = QString::fromUtf8(
                variables[variableIndex].value ? variables[variableIndex].value
                                               : "");
            const QString typeText = QString::fromUtf8(
                variables[variableIndex].type ? variables[variableIndex].type
                                              : "");
            const bool canExpand =
                variables[variableIndex].can_expand ? true : false;

            item->setText(0, nameText);
            item->setText(1, valueText);

            const QString tooltipSuffix =
                typeText.isEmpty() ? QString() : tr("Type: %1").arg(typeText);
            item->setToolTip(
                0, tooltipSuffix.isEmpty()
                       ? nameText
                       : QStringLiteral("%1\n%2").arg(nameText, tooltipSuffix));
            item->setToolTip(1, tooltipSuffix.isEmpty()
                                    ? valueText
                                    : QStringLiteral("%1\n%2").arg(
                                          valueText, tooltipSuffix));
            item->setData(0, VariableTypeRole, typeText);
            item->setData(0, VariableCanExpandRole, canExpand);

            // Construct path for child
            QString childPath;
            if (path.isEmpty())
            {
                childPath = nameText;
            }
            else
            {
                if (nameText.startsWith("["))
                {
                    childPath = path + nameText;
                }
                else
                {
                    childPath = path + "." + nameText;
                }
            }
            item->setData(0, VariablePathRole, childPath);

            if (canExpand)
            {
                item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
                new QTreeWidgetItem(item); // Dummy child placeholder
            }
            else
            {
                item->setChildIndicatorPolicy(
                    QTreeWidgetItem::DontShowIndicator);
            }

            if (!parent && nameText == QLatin1String("Locals"))
            {
                item->setExpanded(true);
                /* Expand Locals inline to avoid recursion warning.
                 * This duplicates onVariableItemExpanded logic but breaks
                 * the static call chain that clang-tidy flags. */
                if (item->childCount() == 1 &&
                    item->child(0)->text(0).isEmpty())
                {
                    delete item->takeChild(0);
                    QString localPath =
                        item->data(0, VariablePathRole).toString();
                    updateVariables(item, localPath);
                }
            }
        }
        // Sort Globals alphabetically; preserve declaration order for
        // Locals and Upvalues since that is more natural for debugging.
        bool shouldSort = false;
        if (!path.isEmpty())
        {
            shouldSort = path.startsWith(QLatin1String("Globals"));
        }
        if (shouldSort)
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
    if (item->childCount() == 1 && item->child(0)->text(0).isEmpty())
    {
        // Remove dummy
        delete item->takeChild(0);

        QString path = item->data(0, VariablePathRole).toString();
        updateVariables(item, path);
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
    codeView->setEditorFont(effectiveMonospaceFont());
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

    ui->codeTabWidget->addTab(codeView, QFileInfo(normalizedPath).fileName());
    ui->codeTabWidget->setCurrentWidget(codeView);
    ui->codeTabWidget->show();
    return codeView;
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
        view->setCurrentLine(static_cast<qint32>(lineNumber));
    }
}

void LuaDebuggerDialog::onCodeViewContextMenu(const QPoint &pos)
{
    LuaDebuggerCodeView *codeView =
        qobject_cast<LuaDebuggerCodeView *>(sender());
    if (!codeView)
        return;

    QMenu menu(this);
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
            QAction *evalSelection = menu.addAction(
                tr("Evaluate \"%1\"")
                    .arg(selectedText.length() > 30
                             ? selectedText.left(30) + QStringLiteral("...")
                             : selectedText));
            connect(evalSelection, &QAction::triggered, [this, selectedText]()
                    { evaluateSelection(selectedText); });
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
        view->setCurrentLine(static_cast<qint32>(line));
    }
}

void LuaDebuggerDialog::onMonospaceFontUpdated(const QFont &font)
{
    if (!mainApp || !mainApp->isInitialized())
    {
        return;
    }
    applyMonospaceFonts(font);

    /* Persist the font to our JSON settings */
    settings_[SettingsKeys::FontFamily] = font.family();
    settings_[SettingsKeys::FontSize] = font.pointSize();
    saveSettingsFile();
}

void LuaDebuggerDialog::onMainAppInitialized()
{
    applyMonospaceFonts();
}

void LuaDebuggerDialog::onPreferencesChanged()
{
    applyCodeViewThemes();
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
        saveSettingsFile();

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
        if (dialog->ui && dialog->ui->codeTabWidget)
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
    if (!ui || !ui->codeTabWidget)
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
    if (!ui || !ui->codeTabWidget)
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
    if (!ui || !variablesTree || !variablesTree->header())
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

void LuaDebuggerDialog::configureStackTreeColumns()
{
    if (!ui || !stackTree || !stackTree->header())
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
    if (ui && variablesTree)
    {
        variablesTree->clear();
    }
    if (ui && stackTree)
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
    if (!ui || !variablesTree)
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

    menu.exec(variablesTree->viewport()->mapToGlobal(pos));
}

void LuaDebuggerDialog::clearAllCodeHighlights()
{
    if (!ui || !ui->codeTabWidget)
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
    applyMonospaceFonts(effectiveMonospaceFont());
}

void LuaDebuggerDialog::applyMonospaceFonts(const QFont &font)
{
    QFont monoFont = font;
    if (monoFont.family().isEmpty())
    {
        monoFont = effectiveMonospaceFont();
    }

    QList<QWidget *> widgets;
    widgets << this << variablesTree << stackTree << fileTree << breakpointsTree
            << ui->toolBar << evalInputEdit << evalOutputEdit;
    for (QWidget *widget : widgets)
    {
        if (widget)
        {
            widget->setFont(monoFont);
        }
    }

    const QList<QTreeWidget *> trees = {variablesTree, stackTree, fileTree,
                                        breakpointsTree};
    for (QTreeWidget *tree : trees)
    {
        if (tree && tree->header())
        {
            tree->header()->setFont(monoFont);
        }
    }

    if (ui && ui->codeTabWidget)
    {
        const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
        for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
        {
            LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
                ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
            if (view)
            {
                view->setEditorFont(monoFont);
            }
        }
    }
}

QFont LuaDebuggerDialog::effectiveMonospaceFont() const
{
    /* If mainApp is initialized, use its monospace font */
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->monospaceFont();
    }

    /* Try to use the persisted font from last session (from settings_) */
    QString savedFamily = settings_.value(SettingsKeys::FontFamily).toString();
    int savedSize = settings_.value(SettingsKeys::FontSize, 0).toInt();
    if (!savedFamily.isEmpty() && savedSize > 0)
    {
        QFont savedFont(savedFamily, savedSize);
        savedFont.setStyleHint(QFont::Monospace);
        return savedFont;
    }

    /* Fall back to system fixed font */
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
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
    QString title = tr("Lua Debugger");

    if (!debuggerEnabled)
    {
        title += tr(" - Disabled");
    }
    else if (debuggerPaused)
    {
        title += tr(" - Paused");
    }
    else
    {
        title += tr(" - Running");
    }

    setWindowTitle(title);
}

void LuaDebuggerDialog::updateContinueActionState()
{
    const bool allowContinue = wslua_debugger_is_enabled() && debuggerPaused;
    ui->actionContinue->setEnabled(allowContinue);
    ui->actionStep->setEnabled(allowContinue);
}

void LuaDebuggerDialog::updateWidgets()
{
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    updateEvalPanelState();
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
    variablesTree->clear();
    updateVariables(nullptr, QString());
    updateStack();
    refreshAvailableScripts();
}

void LuaDebuggerDialog::onEvalClear()
{
    evalInputEdit->clear();
    evalOutputEdit->clear();
}

void LuaDebuggerDialog::evaluateSelection(const QString &text)
{
    if (text.isEmpty() || !debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }

    // Set the expression in the input field with '=' prefix for value
    // inspection
    QString expression = text.trimmed();
    if (!expression.startsWith('='))
    {
        expression = QStringLiteral("=%1").arg(expression);
    }
    evalInputEdit->setPlainText(expression);

    // Execute the evaluation
    onEvaluate();
}

// Qt-based JSON Settings Persistence
void LuaDebuggerDialog::loadSettingsFile()
{
    char *lua_debugger_file = get_persconffile_path(LUA_DEBUGGER_SETTINGS_FILE, false, application_configuration_environment_prefix());
    QFileInfo fileInfo(gchar_free_to_qstring(lua_debugger_file));

    QFile loadFile(fileInfo.filePath());
    if (!fileInfo.exists() || !fileInfo.isFile())
    {
        return;
    }

    if (loadFile.open(QIODevice::ReadOnly))
    {
        QByteArray loadData = loadFile.readAll();
        QJsonDocument document = QJsonDocument::fromJson(loadData);
        settings_ = document.object().toVariantMap();
    }
}

void LuaDebuggerDialog::saveSettingsFile()
{
    char *lua_debugger_file = get_persconffile_path(LUA_DEBUGGER_SETTINGS_FILE, false, application_configuration_environment_prefix());
    QFileInfo fileInfo(gchar_free_to_qstring(lua_debugger_file));

    QFile saveFile(fileInfo.filePath());
    if (fileInfo.exists() && !fileInfo.isFile())
    {
        return;
    }

    if (saveFile.open(QIODevice::WriteOnly))
    {
        QJsonDocument document = QJsonDocument::fromVariant(settings_);
        QByteArray saveData = document.toJson(QJsonDocument::Indented);
        saveFile.write(saveData);
    }
}

void LuaDebuggerDialog::applyDialogSettings()
{
    loadSettingsFile();

    // Apply theme setting
    QString themeStr = settings_.value(SettingsKeys::Theme, "auto").toString();
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeStr == "dark")
        theme = WSLUA_DEBUGGER_THEME_DARK;
    else if (themeStr == "light")
        theme = WSLUA_DEBUGGER_THEME_LIGHT;
    currentTheme_ = theme;

    // Apply theme to combo box if it exists
    if (themeComboBox)
    {
        int idx = themeComboBox->findData(theme);
        if (idx >= 0)
            themeComboBox->setCurrentIndex(idx);
    }

    // Font settings are handled by effectiveMonospaceFont() which reads from
    // settings_

    // Apply dialog geometry
    int savedWidth = settings_.value(SettingsKeys::DialogWidth, 0).toInt();
    int savedHeight = settings_.value(SettingsKeys::DialogHeight, 0).toInt();
    int savedX = settings_.value(SettingsKeys::DialogX, -1).toInt();
    int savedY = settings_.value(SettingsKeys::DialogY, -1).toInt();
    if (savedWidth > 0 && savedHeight > 0)
    {
        resize(savedWidth, savedHeight);
        if (savedX >= 0 && savedY >= 0)
        {
            move(savedX, savedY);
        }
    }

    // Apply splitter states
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

    // Apply default splitter sizes if no saved state
    if (!splittersRestored && ui->mainSplitter)
    {
        ui->mainSplitter->setStretchFactor(0, 1);
        ui->mainSplitter->setStretchFactor(1, 2);
        QList<int> sizes;
        sizes << 300 << 600;
        ui->mainSplitter->setSizes(sizes);
    }

    // Apply section expanded states
    if (variablesSection)
        variablesSection->setExpanded(
            settings_.value(SettingsKeys::SectionVariables, true).toBool());
    if (stackSection)
        stackSection->setExpanded(
            settings_.value(SettingsKeys::SectionStack, true).toBool());
    if (filesSection)
        filesSection->setExpanded(
            settings_.value(SettingsKeys::SectionFiles, false).toBool());
    if (breakpointsSection)
        breakpointsSection->setExpanded(
            settings_.value(SettingsKeys::SectionBreakpoints, true).toBool());
    if (evalSection)
        evalSection->setExpanded(
            settings_.value(SettingsKeys::SectionEval, false).toBool());
    if (settingsSection)
        settingsSection->setExpanded(
            settings_.value(SettingsKeys::SectionSettings, false).toBool());

    // Load breakpoints from JSON array
    QJsonArray breakpointsArray =
        settings_.value(SettingsKeys::Breakpoints).toJsonArray();
    for (const QJsonValue &val : breakpointsArray)
    {
        QJsonObject bp = val.toObject();
        QString file = bp.value("file").toString();
        int64_t line = bp.value("line").toVariant().toLongLong();
        bool active = bp.value("active").toBool(true);

        if (!file.isEmpty() && line > 0)
        {
            // Check if breakpoint already exists (from C-side init)
            int32_t state = wslua_debugger_get_breakpoint_state(
                file.toUtf8().constData(), line);
            if (state < 0)
            {
                // Does not exist, add it
                wslua_debugger_add_breakpoint(file.toUtf8().constData(), line);
            }
            // Set active state
            wslua_debugger_set_breakpoint_active(file.toUtf8().constData(),
                                                 line, active);
        }
    }
}

void LuaDebuggerDialog::storeDialogSettings()
{
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

    // Font is stored when it changes
    // (onMonospaceFontUpdated/onMainAppInitialized) No need to store here -
    // settings_ already has current values

    // Store dialog geometry
    settings_[SettingsKeys::DialogWidth] = width();
    settings_[SettingsKeys::DialogHeight] = height();
    settings_[SettingsKeys::DialogX] = x();
    settings_[SettingsKeys::DialogY] = y();

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
    settings_[SettingsKeys::SectionFiles] =
        filesSection ? filesSection->isExpanded() : false;
    settings_[SettingsKeys::SectionBreakpoints] =
        breakpointsSection ? breakpointsSection->isExpanded() : true;
    settings_[SettingsKeys::SectionEval] =
        evalSection ? evalSection->isExpanded() : false;
    settings_[SettingsKeys::SectionSettings] =
        settingsSection ? settingsSection->isExpanded() : false;

    // Store breakpoints as JSON array
    QJsonArray breakpointsArray;
    unsigned count = wslua_debugger_get_breakpoint_count();
    for (unsigned i = 0; i < count; i++)
    {
        const char *file = nullptr;
        int64_t line = 0;
        bool active = false;
        if (wslua_debugger_get_breakpoint(i, &file, &line, &active))
        {
            QJsonObject bp;
            bp["file"] = QString::fromUtf8(file);
            bp["line"] = static_cast<qint64>(line);
            bp["active"] = active;
            breakpointsArray.append(bp);
        }
    }
    settings_[SettingsKeys::Breakpoints] = breakpointsArray;

    saveSettingsFile();
}
