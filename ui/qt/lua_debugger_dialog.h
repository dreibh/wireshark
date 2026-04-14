/* lua_debugger_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_DIALOG_H
#define LUA_DEBUGGER_DIALOG_H

#include "geometry_state_dialog.h"
#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QFont>
#include <QPair>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QString>
#include <QToolBar>
#include <QToolButton>
#include <QTreeWidget>
#include <QVariantMap>
#include <QVector>

#include "epan/wslua/wslua_debugger.h"

class CollapsibleSection;

namespace Ui
{
class LuaDebuggerDialog;
}

class LuaDebuggerCodeView;

/**
 * @brief Top-level dialog hosting the Lua debugger UI components.
 */
class LuaDebuggerDialog : public GeometryStateDialog
{
    Q_OBJECT

  public:
    /**
     * @brief Construct the dialog and initialize all child widgets.
     * @param parent Optional parent widget used for ownership and stacking.
     */
    explicit LuaDebuggerDialog(QWidget *parent = nullptr);
    /**
     * @brief Destroy the dialog and disconnect debugger callbacks.
     */
    ~LuaDebuggerDialog();

    /**
     * @brief Get the current theme setting.
     * @return Theme enum value (WSLUA_DEBUGGER_THEME_AUTO, DARK, or LIGHT).
     */
    static int32_t currentTheme();

    /**
     * @brief Retrieve the singleton instance, creating it if needed.
     * @param parent Optional parent widget supplied when instantiating.
     * @return Pointer to the global dialog instance.
     */
    static LuaDebuggerDialog *instance(QWidget *parent = nullptr);

    /**
     * @brief React to the debugger pausing execution at a breakpoint.
     * @param file_path Path of the Lua file that triggered the pause.
     * @param line Line number where execution stopped.
     */
    void handlePause(const char *file_path, int64_t line);

    /**
     * @brief Ensure the hierarchical file tree contains the supplied script
     * path.
     *
     * This is public because it is called from a C callback that iterates
     * loaded Lua scripts.
     *
     * @param file_path Path to split and insert.
     * @return True if a new leaf entry was added.
     */
    bool ensureFileTreeEntry(const QString &file_path);

  protected:
    /**
     * @brief Flush state and resume execution when the dialog closes.
     * @param event Close request metadata from Qt.
     */
    void closeEvent(QCloseEvent *event) override;

  private slots:
    /** @brief Resume Lua execution when the Continue action is triggered. */
    void onContinue();
    /** @brief Step to the next line when the Step action is triggered. */
    void onStep();
    /** @brief Enable or disable the debugger when the toggle button is clicked.
     */
    void onDebuggerToggled(bool checked);
    /** @brief Remove every stored breakpoint. */
    void onClearBreakpoints();
    /** @brief Apply checkbox updates to a specific breakpoint row. */
    void onBreakpointItemChanged(QTreeWidgetItem *item, int column);
    /** @brief Handle single-clicks in the breakpoint list (e.g., delete icon).
     */
    void onBreakpointItemClicked(QTreeWidgetItem *item, int column);
    /** @brief Open the clicked breakpoint's file and focus the line. */
    void onBreakpointItemDoubleClicked(QTreeWidgetItem *item, int column);
    /** @brief Build and show the editor context menu. */
    void onCodeViewContextMenu(const QPoint &pos);
    /** @brief Populate child variable nodes when a tree item expands. */
    void onVariableItemExpanded(QTreeWidgetItem *item);
    /** @brief Provide copy actions for a variable entry. */
    void onVariablesContextMenuRequested(const QPoint &pos);
    /** @brief Prompt the user to open a Lua file into a new tab. */
    void onOpenFile();
    /** @brief Trigger a reload of all Lua plugins. */
    void onReloadLuaPlugins();
    /** @brief Jump to the selected stack frame location. */
    void onStackItemDoubleClicked(QTreeWidgetItem *item, int column);
    /** @brief Reapply fonts when the application monospace font changes. */
    void onMonospaceFontUpdated(const QFont &font);
    /** @brief Refresh fonts once the main application finishes initializing. */
    void onMainAppInitialized();
    /** @brief Update code view themes when preferences change. */
    void onPreferencesChanged();
    /** @brief Update code view themes when Wireshark's color scheme changes. */
    void onColorsChanged();
    /** @brief Evaluate the expression in the eval input field. */
    void onEvaluate();
    /** @brief Clear the eval input and output fields. */
    void onEvalClear();
    /** @brief Evaluate selected text from the code view. */
    void evaluateSelection(const QString &text);
    /** @brief Handle theme selection changes from the Settings section. */
    void onThemeChanged(int idx);

  private:
    Ui::LuaDebuggerDialog *ui;
    static LuaDebuggerDialog *_instance;
    static int32_t currentTheme_;

    /**
     * @brief Static callback invoked before Lua plugins are reloaded.
     *
     * This is registered with wslua_debugger_register_reload_callback()
     * and forwards to the instance method reloadAllScriptFiles().
     */
    static void onLuaReloadCallback();

    /**
     * @brief Static callback invoked after Lua plugins are reloaded.
     *
     * This is registered with wslua_debugger_register_post_reload_callback()
     * and refreshes the file tree with newly loaded scripts.
     */
    static void onLuaPostReloadCallback();

    /**
     * @brief Static callback invoked when a Lua script is loaded.
     *
     * This is registered with wslua_debugger_register_script_loaded_callback()
     * and adds the script to the file tree.
     */
    static void onScriptLoadedCallback(const char *file_path);

    QEventLoop *eventLoop;
    QCheckBox *enabledCheckBox;
    QString lastOpenDirectory;
    bool breakpointTabsPrimed;
    QIcon folderIcon;
    QIcon fileIcon;
    bool debuggerPaused;
    bool reloadDeferred;

    // Collapsible sections (created programmatically)
    CollapsibleSection *variablesSection;
    CollapsibleSection *stackSection;
    CollapsibleSection *filesSection;
    CollapsibleSection *breakpointsSection;
    CollapsibleSection *evalSection;
    CollapsibleSection *settingsSection;

    // Tree widgets (created programmatically)
    QTreeWidget *variablesTree;
    QTreeWidget *stackTree;
    QTreeWidget *fileTree;
    QTreeWidget *breakpointsTree;

    // Eval panel widgets (created programmatically)
    QPlainTextEdit *evalInputEdit;
    QPlainTextEdit *evalOutputEdit;
    QPushButton *evalButton;
    QPushButton *evalClearButton;

    // Settings panel widgets (created programmatically)
    QComboBox *themeComboBox;

    /** @brief Refresh the call stack tree from the debugger back-end. */
    void updateStack();
    /**
     * @brief Populate the variables tree with locals, globals, or nested
     * tables.
     * @param parent Optional parent tree item receiving the children.
     * @param path Resolved variable path used for debugger queries.
     */
    void updateVariables(QTreeWidgetItem *parent = nullptr,
                         const QString &path = QString());
    /** @brief Rebuild the breakpoint list widget from persisted data. */
    void updateBreakpoints();
    /**
     * @brief Load a file into a code tab, creating the tab if necessary.
     * @param file_path Absolute or relative file path to open.
     * @return Pointer to the code view widget that now hosts the file.
     */
    LuaDebuggerCodeView *loadFile(const QString &file_path);
    /** @brief Index all Lua scripts from standard plugin directories. */
    void refreshAvailableScripts();
    /**
     * @brief Scan a specific directory for Lua scripts and add them to the file
     * tree.
     * @param dir_path Directory to scan recursively.
     */
    void scanScriptDirectory(const QString &dir_path);
    /**
     * @brief Normalize a path by trimming prefixes and resolving symbolic
     * components.
     * @param file_path Input path that may be relative or prefixed with '@'.
     * @return Canonical or cleaned absolute path string.
     */
    QString normalizedFilePath(const QString &file_path) const;
    /** @brief Sync the checkbox UI state with the core debugger flag. */
    void syncDebuggerToggleWithCore();
    /** @brief Update the checkbox icon based on the enabled state. */
    void updateEnabledCheckboxIcon();
    /** @brief Enable the debugger if any active breakpoint requires it. */
    void ensureDebuggerEnabledForActiveBreakpoints();
    /**
     * @brief Locate a child item by absolute path beneath a parent node.
     * @param parent Parent item or nullptr for top-level search.
     * @param path Fully qualified path from the role data.
     * @return Matching tree item pointer or nullptr.
     */
    QTreeWidgetItem *findChildItemByPath(QTreeWidgetItem *parent,
                                         const QString &path) const;
    /**
     * @brief Break a path into display + absolute segments for the tree widget.
     * @param file_path Absolute path to split.
     * @param components Output vector receiving ordered components.
     * @return True when at least one path segment was produced.
     */
    bool
    appendPathComponents(const QString &file_path,
                         QVector<QPair<QString, QString>> &components) const;
    /**
     * @brief Open each initial breakpoint file once tabs are ready.
     * @param files Ordered list of canonical script paths to open.
     */
    void openInitialBreakpointFiles(const QVector<QString> &files);
    /** @brief Update the status label to show current debugger state. */
    void updateStatusLabel();
    /** @brief Enable or disable the Continue action based on debugger state. */
    void updateContinueActionState();
    /** @brief Configure the variables tree column sizing rules. */
    void configureVariablesTreeColumns();
    /** @brief Configure the stack tree header layout. */
    void configureStackTreeColumns();
    /** @brief Remove paused-state UI artifacts like stacks and highlights. */
    void clearPausedStateUi();
    /** @brief Remove highlights from every open code view. */
    void clearAllCodeHighlights();
    /** @brief Apply the global monospace font to tree and list widgets. */
    void applyMonospaceFonts();
    /** @brief Apply a supplied monospace font to debugger widgets. */
    void applyMonospaceFonts(const QFont &font);
    /** @brief Apply the current theme preference to all code views. */
    void applyCodeViewThemes();
    /** @brief Reload all script files from disk (e.g., after Lua plugin
     * reload). */
    void reloadAllScriptFiles();
    /** @brief Determine the current monospace font, honoring zoom settings. */
    QFont effectiveMonospaceFont() const;
    /** @brief Resume the debugger (if paused) and exit any nested event loop.
     */
    void resumeDebuggerAndExitLoop();
    /** @brief Update the enabled state of the eval panel based on debugger
     * state. */
    void updateEvalPanelState();
    /** @brief Update all widgets based on the current debugger state. */
    void updateWidgets();
    /** @brief Create the collapsible sections and their content widgets. */
    void createCollapsibleSections();

    // ---- Qt-based JSON settings persistence (like import_hexdump) ----
    /** @brief In-memory settings store, persisted to JSON file. */
    QVariantMap settings_;
    /** @brief Load settings from lua_debugger.json in the profile directory.
     */
    void loadSettingsFile();
    /** @brief Save settings to lua_debugger.json in the profile directory.
     */
    void saveSettingsFile();
    /** @brief Apply loaded settings to UI widgets. */
    void applyDialogSettings();
    /** @brief Store current UI widget state into settings map. */
    void storeDialogSettings();
};

#endif // LUA_DEBUGGER_DIALOG_H
