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
#include <QTextStream>
#include <QVBoxLayout>

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
constexpr qint32 StackItemLevelRole = static_cast<qint32>(Qt::UserRole + 7);
constexpr qint32 VariablePathRole = static_cast<qint32>(Qt::UserRole + 8);
constexpr qint32 VariableTypeRole = static_cast<qint32>(Qt::UserRole + 9);
constexpr qint32 VariableCanExpandRole = static_cast<qint32>(Qt::UserRole + 10);

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
} // namespace

LuaDebuggerDialog::LuaDebuggerDialog(QWidget *parent)
    : GeometryStateDialog(parent), ui(new Ui::LuaDebuggerDialog),
      eventLoop(nullptr), enabledCheckBox(nullptr), breakpointTabsPrimed(false),
      debuggerPaused(false), reloadDeferred(false), variablesSection(nullptr),
      stackSection(nullptr), breakpointsSection(nullptr), filesSection(nullptr),
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
    connect(stackTree, &QTreeWidget::currentItemChanged, this,
            &LuaDebuggerDialog::onStackCurrentItemChanged);

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
    variablesSection->setContentWidget(variablesTree);
    variablesSection->setExpanded(true);
    splitter->addWidget(variablesSection);

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

    stackSelectionLevel = 0;
    updateStack();
    variablesTree->clear();
    updateVariables(nullptr, QString());

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

void LuaDebuggerDialog::onCodeTabCloseRequested(int index)
{
    QWidget *widget = ui->codeTabWidget->widget(index);
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

    ui->codeTabWidget->removeTab(index);
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

    const QList<QWidget *> widgets = {variablesTree, stackTree, breakpointsTree,
                                      evalInputEdit, evalOutputEdit};
    for (QWidget *widget : widgets)
    {
        if (widget)
        {
            widget->setFont(panelMono);
        }
    }

    const QList<QTreeWidget *> treesWithStandardHeaders = {
        variablesTree, stackTree, fileTree, breakpointsTree};
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
