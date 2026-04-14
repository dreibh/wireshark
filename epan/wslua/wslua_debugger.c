/* wslua_debugger.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "init_wslua.h"
#include "wslua.h"
#include "wslua_debugger.h"
#include <glib.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/ws_assert.h>

/* debugger context */
typedef struct
{
    wslua_debugger_state_t state;
    bool enabled;
    wslua_debugger_ui_update_cb_t ui_update_callback;
    lua_State *L;
    lua_State *paused_L;
    GMutex mutex;
    bool mutex_initialized;
    wslua_breakpoint_t temporary_breakpoint;
    bool step_mode; /**< When true, pause at the next line hook */
    bool was_enabled_before_reload; /**< Saved state across plugin reload */
    bool reload_in_progress; /**< Suppress auto-enable during reload */
} wslua_debugger_t;

static wslua_debugger_t debugger = {
    WSLUA_DEBUGGER_OFF,
    false,
    NULL,
    NULL,
    NULL,
    {0}, /* mutex */
    false,
    {NULL, 0, false}, /* temporary_breakpoint */
    false,            /* step_mode */
    false,            /* was_enabled_before_reload */
    false             /* reload_in_progress */
};

/* Breakpoints (in-memory, persisted by Qt side) */
static GArray *breakpoints_array = NULL;

static GHashTable *canonical_path_cache = NULL;
static GRWLock canonical_path_cache_lock;

/**
 * @brief Ensure the canonical path cache is initialized exactly once.
 */
static void ensure_canonical_path_cache_initialized(void)
{
    static size_t canonical_cache_once = 0;
    if (g_once_init_enter(&canonical_cache_once))
    {
        g_rw_lock_init(&canonical_path_cache_lock);
        canonical_path_cache =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_once_init_leave(&canonical_cache_once, 1);
    }
}

/**
 * @brief Canonicalize a file path while caching results for reuse.
 * @param file_path Path in any user-provided form.
 * @return Pointer to cached canonical path; ownership stays with the cache.
 */
static const char *
wslua_debugger_get_cached_canonical_path(const char *file_path)
{
    if (!file_path || !*file_path)
    {
        return NULL;
    }

    ensure_canonical_path_cache_initialized();

    g_rw_lock_reader_lock(&canonical_path_cache_lock);
    const char *cached_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (cached_path)
    {
        g_rw_lock_reader_unlock(&canonical_path_cache_lock);
        return cached_path;
    }
    g_rw_lock_reader_unlock(&canonical_path_cache_lock);

    char *canonicalized_path = g_canonicalize_filename(file_path, NULL);
    if (!canonicalized_path)
    {
        return NULL;
    }

    g_rw_lock_writer_lock(&canonical_path_cache_lock);
    const char *existing_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (existing_path)
    {
        g_rw_lock_writer_unlock(&canonical_path_cache_lock);
        g_free(canonicalized_path);
        return existing_path;
    }

    char *key_copy = g_strdup(file_path);
    g_hash_table_insert(canonical_path_cache, key_copy, canonicalized_path);
    g_rw_lock_writer_unlock(&canonical_path_cache_lock);
    return canonicalized_path;
}

/**
 * @brief Return a newly allocated canonical path copy for caller ownership.
 */
static char *wslua_debugger_dup_canonical_path(const char *file_path)
{
    const char *cached_path =
        wslua_debugger_get_cached_canonical_path(file_path);
    return cached_path ? g_strdup(cached_path) : NULL;
}

/**
 * @brief Determine if a breakpoint matches a canonical path + line pair.
 */
static bool
wslua_debugger_breakpoint_matches(const wslua_breakpoint_t *breakpoint,
                                  const char *canonical_path, int64_t line)
{
    if (!breakpoint || !canonical_path)
    {
        return false;
    }
    if (breakpoint->line != line)
    {
        return false;
    }

    return g_strcmp0(breakpoint->file_path, canonical_path) == 0;
}

/* Forward declarations */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info);
static void wslua_debugger_update_hook(void);
static void remove_breakpoint_at(unsigned idx);
static int64_t wslua_debugger_count_table_entries(lua_State *L, int idx);
static char *wslua_debugger_describe_value(lua_State *L, int idx);

/**
 * @brief Ensure breakpoints array is initialized.
 */
static void ensure_breakpoints_initialized(void)
{
    if (!breakpoints_array)
    {
        breakpoints_array =
            g_array_new(FALSE, TRUE, sizeof(wslua_breakpoint_t));
    }
}

/**
 * @brief Free a breakpoint's allocated memory.
 */
static void free_breakpoint(wslua_breakpoint_t *bp)
{
    if (bp)
    {
        g_free(bp->file_path);
        bp->file_path = NULL;
    }
}

/**
 * @brief Remove a breakpoint at the specified index.
 */
static void remove_breakpoint_at(unsigned idx)
{
    ensure_breakpoints_initialized();

    if (idx >= breakpoints_array->len)
        return;

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    free_breakpoint(bp);
    g_array_remove_index(breakpoints_array, idx);
}

/**
 * @brief Initialize the debugger subsystem.
 * @param L The Lua state.
 */
void wslua_debugger_init(lua_State *L)
{
    debugger.L = L;
    static bool initialized = false;

    if (!debugger.mutex_initialized)
    {
        g_mutex_init(&debugger.mutex);
        debugger.mutex_initialized = true;
    }

    if (!initialized)
    {
        /* Initialize breakpoints array */
        ensure_breakpoints_initialized();

        /* Note: JSON settings are loaded by the Qt UI (lua_debugger_dialog.cpp)
         * when the dialog is first opened. The C side only maintains in-memory
         * state. */

        initialized = true;
    }

    /*
     * During a reload, do NOT auto-enable the debugger here.
     * The hook would fire inside cf_reload → cf_read → dissectIdle,
     * potentially entering a nested event loop while deep in the
     * reload call stack.  The callers will call
     * wslua_debugger_notify_post_reload() after cf_reload completes.
     */
    if (debugger.reload_in_progress)
    {
        /* Don't auto-enable: the hook would fire during
         * cf_reload / redissect and re-enter the event loop.
         * wslua_debugger_restore_after_reload() handles this. */
        return;
    }

    /* Check if we should auto-enable based on active breakpoints */
    bool has_active = false;
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (bp->active)
        {
            has_active = true;
            break;
        }
    }

    if (has_active)
    {
        wslua_debugger_set_enabled(true);
    }
    else
    {
        /* Ensure hook is updated for new L */
        wslua_debugger_update_hook();
    }
}

/**
 * @brief Check if debugger is enabled.
 * @return true if enabled, false otherwise.
 */
bool wslua_debugger_is_enabled(void)
{
    return debugger.enabled;
}

/**
 * @brief Update the Lua debug hook based on state.
 */
static void wslua_debugger_update_hook(void)
{
    if (!debugger.L)
        return;

    bool should_hook = false;
    g_mutex_lock(&debugger.mutex);
    if (debugger.enabled)
    {
        if (breakpoints_array)
        {
            for (unsigned i = 0; i < breakpoints_array->len; i++)
            {
                wslua_breakpoint_t *bp =
                    &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
                if (bp->active)
                {
                    should_hook = true;
                    break;
                }
            }
        }

        if (!should_hook && debugger.temporary_breakpoint.active)
        {
            should_hook = true;
        }

        if (!should_hook && debugger.step_mode)
        {
            should_hook = true;
        }
    }
    g_mutex_unlock(&debugger.mutex);

    if (should_hook)
    {
        lua_sethook(debugger.L, wslua_debug_hook, LUA_MASKLINE, 0);
    }
    else
    {
        lua_sethook(debugger.L, NULL, 0, 0);
    }
}

/**
 * @brief Set the enabled state of the debugger.
 * @param enabled true to enable, false to disable.
 */
void wslua_debugger_set_enabled(bool enabled)
{
    g_mutex_lock(&debugger.mutex);
    if (!enabled && debugger.state == WSLUA_DEBUGGER_PAUSED)
    {
        g_mutex_unlock(&debugger.mutex);
        wslua_debugger_continue();
        g_mutex_lock(&debugger.mutex);
    }
    debugger.enabled = enabled;
    if (enabled)
    {
        debugger.state = WSLUA_DEBUGGER_RUNNING;
    }
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Register the UI callback.
 * @param cb The callback function.
 */
void wslua_debugger_register_ui_callback(wslua_debugger_ui_update_cb_t cb)
{
    debugger.ui_update_callback = cb;
}

/**
 * @brief Continue execution.
 */
void wslua_debugger_continue(void)
{
    g_mutex_lock(&debugger.mutex);
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    debugger.step_mode = false;
    /* Clear temp breakpoint */
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
    debugger.paused_L = NULL;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Run to a specific line.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_run_to_line(const char *file_path, int64_t line)
{
    char *canonical_copy = wslua_debugger_dup_canonical_path(file_path);
    if (!canonical_copy)
    {
        return;
    }
    g_mutex_lock(&debugger.mutex);
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
    }
    debugger.temporary_breakpoint.file_path = canonical_copy;
    debugger.temporary_breakpoint.line = line;
    debugger.temporary_breakpoint.active = true;

    debugger.step_mode = false;
    debugger.paused_L = NULL;
    debugger.enabled = true;
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Step to the next line.
 *
 * This function sets step mode, which causes the debugger to pause
 * at the very next line hook, regardless of breakpoints.
 * This is a "step over" style operation — it advances to the next
 * Lua source line without descending into called functions.
 *
 * This function should only be called when the debugger is paused.
 */
void wslua_debugger_step(void)
{
    g_mutex_lock(&debugger.mutex);
    /* Clear temp breakpoint since we're stepping */
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
    debugger.paused_L = NULL;

    debugger.step_mode = true;
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Add a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_add_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Check if exists */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            return; /* Already exists */
        }
    }

    wslua_breakpoint_t breakpoint;
    breakpoint.file_path = g_strdup(norm_file_path);
    breakpoint.line = line;
    breakpoint.active = true;

    g_array_append_val(breakpoints_array, breakpoint);
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_set_enabled(true);
    g_free(norm_file_path);
    wslua_debugger_update_hook();
}

/**
 * @brief Remove a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_remove_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    bool removed = false;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            remove_breakpoint_at(i);
            removed = true;
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            if (removed)
            {
                wslua_debugger_update_hook();
            }
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Set breakpoint active state.
 * @param file_path The file path.
 * @param line The line number.
 * @param active The new state.
 */
void wslua_debugger_set_breakpoint_active(const char *file_path, int64_t line,
                                          bool active)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            if (bp->active == active)
            {
                g_mutex_unlock(&debugger.mutex);
                g_free(norm_file_path);
                return;
            }
            bp->active = active;
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            if (active)
            {
                wslua_debugger_set_enabled(true);
            }
            wslua_debugger_update_hook();
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Clear all breakpoints.
 */
void wslua_debugger_clear_breakpoints(void)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Free all breakpoint data */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        free_breakpoint(bp);
    }
    g_array_set_size(breakpoints_array, 0);
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Internal: check breakpoint state using an already-canonical path.
 */
static int32_t
get_breakpoint_state_for_canonical(const char *canonical_path, int64_t line)
{
    if (!canonical_path)
    {
        return -1;
    }

    ensure_breakpoints_initialized();

    int32_t result = -1;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, canonical_path, line))
        {
            result = bp->active ? 1 : 0;
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return -1;
    }
    const int32_t result =
        get_breakpoint_state_for_canonical(norm_file_path, line);
    g_free(norm_file_path);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state_canonical(const char *canonical_path,
                                                      int64_t line)
{
    return get_breakpoint_state_for_canonical(canonical_path, line);
}

char *wslua_debugger_canonical_path(const char *file_path)
{
    return wslua_debugger_dup_canonical_path(file_path);
}

/**
 * @brief The Lua debug hook.
 * @param L The Lua state.
 * @param debug_info The debug info.
 */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info)
{
    if (!debugger.enabled)
        return;

    /* Get info */
    if (lua_getinfo(L, "Sl", debug_info) == 0)
        return;

    /* Check if we are in a C function */
    if (debug_info->currentline < 0)
        return;

    const char *source = debug_info->source;
    if (source && source[0] == '@')
    {
        source++; /* Skip '@' */
    }
    else
    {
        /* Not a file */
        return;
    }

    const char *norm_source = wslua_debugger_get_cached_canonical_path(source);
    if (!norm_source)
    {
        return;
    }

    bool hit = false;

    /* Step mode: pause at every line */
    g_mutex_lock(&debugger.mutex);
    if (debugger.step_mode)
    {
        hit = true;
        debugger.step_mode = false; /* One-shot */
    }
    g_mutex_unlock(&debugger.mutex);

    /* Check regular breakpoints */
    if (!hit)
    {
        g_mutex_lock(&debugger.mutex);
        if (breakpoints_array)
        {
            for (unsigned i = 0; i < breakpoints_array->len; i++)
            {
                wslua_breakpoint_t *bp =
                    &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
                if (bp->active &&
                    wslua_debugger_breakpoint_matches(
                        bp, norm_source, (int64_t)debug_info->currentline))
                {
                    hit = true;
                    break;
                }
            }
        }
        g_mutex_unlock(&debugger.mutex);
    }

    /* Check temp breakpoint */
    if (!hit)
    {
        g_mutex_lock(&debugger.mutex);
        if (debugger.temporary_breakpoint.active &&
            wslua_debugger_breakpoint_matches(&debugger.temporary_breakpoint,
                                              norm_source,
                                              (int64_t)debug_info->currentline))
        {
            hit = true;
            /* Temp breakpoint is one-shot */
            debugger.temporary_breakpoint.active = false;
        }
        g_mutex_unlock(&debugger.mutex);
    }

    if (hit)
    {
        debugger.state = WSLUA_DEBUGGER_PAUSED;
        debugger.paused_L = L;

        if (debugger.ui_update_callback)
        {
            /*
             * Disable the hook while paused.
             *
             * The UI callback runs a nested Qt event loop and may trigger
             * additional Lua activity. Keeping the line hook installed during
             * that time can lead to re-entrancy and crashes.
             */
            lua_sethook(L, NULL, 0, 0);
            debugger.ui_update_callback(source,
                                        (int64_t)debug_info->currentline);
        }

        /*
         * After the UI callback returns (nested event loop exited),
         * execution resumes normally. If a reload was requested while
         * we were paused, the reload was deferred — the UI quit the
         * event loop and scheduled a delayed reload. The hook simply
         * returns here, allowing the Lua script to finish its current
         * execution naturally. The deferred reload will run once the
         * Lua call stack has fully unwound.
         */

        /*
         * Re-install the hook on this thread (L) so that step_mode
         * and breakpoints can fire on subsequent lines within the
         * same dissector call.  The hook was disabled on L above to
         * prevent re-entrancy during the nested event loop; now that
         * the event loop has exited we need it back.  Note: L may be
         * a coroutine thread created by lua_newthread(), which is
         * distinct from debugger.L (the main state).
         */
        if (debugger.enabled)
        {
            lua_sethook(L, wslua_debug_hook, LUA_MASKLINE, 0);
        }
    }
}

/**
 * @brief Get stack trace.
 * @param frame_count Output pointer for frame count.
 * @return Array of stack frames.
 */
wslua_stack_frame_t *wslua_debugger_get_stack(int32_t *frame_count)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        *frame_count = 0;
        return NULL;
    }

    lua_Debug debug_info;
    int32_t level = 0;
    GArray *stack_array =
        g_array_new(false, false, sizeof(wslua_stack_frame_t));

    while (lua_getstack(target_L, level, &debug_info))
    {
        lua_getinfo(target_L, "nSl", &debug_info);
        wslua_stack_frame_t frame;
        frame.source = g_strdup(debug_info.source ? debug_info.source : "?");
        frame.line = (int64_t)debug_info.currentline;
        frame.name = g_strdup(debug_info.name ? debug_info.name : "?");
        g_array_append_val(stack_array, frame);
        level++;
    }

    *frame_count = level;
    return (wslua_stack_frame_t *)g_array_free(stack_array, false);
}

/**
 * @brief Free stack trace.
 * @param stack The stack array.
 * @param frame_count The number of frames.
 */
void wslua_debugger_free_stack(wslua_stack_frame_t *stack, int32_t frame_count)
{
    for (int32_t frame_index = 0; frame_index < frame_count; frame_index++)
    {
        g_free(stack[frame_index].source);
        g_free(stack[frame_index].name);
    }
    g_free(stack);
}

/**
 * @brief Lookup a variable path in Lua state.
 * @param L The Lua state.
 * @param path The path to lookup (e.g. "a.b").
 * @return true if found (value on stack), false otherwise.
 */
static bool wslua_debugger_lookup_path(lua_State *L, const char *path)
{
    if (!path || !*path)
        return false;

    /* Parse first component */
    const char *path_ptr = path;
    const char *end_ptr = path_ptr;
    while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
        end_ptr++;

    char *first_component = g_strndup(path_ptr, end_ptr - path_ptr);
    path_ptr = end_ptr;

    /* Look in locals */
    lua_Debug debug_info;
    if (!lua_getstack(L, 0, &debug_info))
    {
        g_free(first_component);
        return false;
    }

    int32_t local_index = 1;
    const char *name;
    bool found = false;
    while ((name = lua_getlocal(L, &debug_info, local_index++)))
    {
        if (g_strcmp0(name, first_component) == 0)
        {
            found = true;
            break;
        }
        lua_pop(L, 1);
    }

    if (!found)
    {
        /* Look in upvalues */
        lua_getinfo(L, "f", &debug_info); /* Push function */
        local_index = 1;
        while ((name = lua_getupvalue(L, -1, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                found = true;
                lua_remove(L, -2); /* Remove function */
                break;
            }
            lua_pop(L, 1);
        }
        if (!found)
        {
            lua_pop(L, 1); /* Remove function */

            /* Look in globals */
            lua_getglobal(L, first_component);
            if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                g_free(first_component);
                return false;
            }
        }
    }
    g_free(first_component);

    /* Traverse rest */
    while (*path_ptr)
    {
        if (*path_ptr == '.')
        {
            path_ptr++;
            end_ptr = path_ptr;
            while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
                end_ptr++;
            char *key = g_strndup(path_ptr, end_ptr - path_ptr);
            if (lua_istable(L, -1))
            {
                lua_getfield(L, -1, key);
                lua_remove(L, -2); /* Remove parent */
            }
            else
            {
                g_free(key);
                lua_pop(L, 1);
                return false;
            }
            g_free(key);
            path_ptr = end_ptr;
        }
        else if (*path_ptr == '[')
        {
            path_ptr++;
            end_ptr = path_ptr;
            while (*end_ptr && *end_ptr != ']')
                end_ptr++;
            if (*end_ptr != ']')
            {
                lua_pop(L, 1);
                return false; /* Malformed */
            }

            char *key_str = g_strndup(path_ptr, end_ptr - path_ptr);
            path_ptr = end_ptr + 1;

            if (lua_istable(L, -1))
            {
                /* Check if integer */
                char *endptr_conversion;
                int64_t idx = g_ascii_strtoll(key_str, &endptr_conversion, 10);
                if (*endptr_conversion == '\0')
                {
                    lua_pushinteger(L, idx);
                    lua_gettable(L, -2);
                }
                else
                {
                    /* String key in brackets? */
                    lua_pushstring(L, key_str);
                    lua_gettable(L, -2);
                }
                lua_remove(L, -2); /* Remove parent */
            }
            else
            {
                g_free(key_str);
                lua_pop(L, 1);
                return false;
            }
            g_free(key_str);
        }
        else
        {
            break;
        }
    }

    return true;
}

static int wslua_debugger_abs_index(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    return lua_absindex(L, idx);
#else
    if (idx > 0 || idx <= LUA_REGISTRYINDEX)
    {
        return idx;
    }
    return lua_gettop(L) + idx + 1;
#endif
}

static int64_t wslua_debugger_count_table_entries(lua_State *L, int idx)
{
    const int tableIndex = wslua_debugger_abs_index(L, idx);
    int64_t count = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        ++count;
        lua_pop(L, 1);
    }
    return count;
}

static char *wslua_debugger_describe_value(lua_State *L, int idx)
{
    const int valueType = lua_type(L, idx);
    if (valueType == LUA_TFUNCTION)
    {
        return g_strdup("");
    }
    if (valueType == LUA_TTABLE)
    {
        const int64_t entryCount = wslua_debugger_count_table_entries(L, idx);
        return g_strdup_printf("table[%" PRId64 "]", entryCount);
    }
    const char *stringValue = luaL_tolstring(L, idx, NULL);
    char *result = g_strdup(stringValue ? stringValue : "");
    lua_pop(L, 1);
    return result;
}

static bool wslua_debugger_value_can_expand(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (lua_type(L, absIndex) != LUA_TTABLE)
    {
        return false;
    }
    return wslua_debugger_count_table_entries(L, absIndex) > 0;
}

/**
 * @brief Get variables for a path.
 * @param path The path (NULL for root).
 * @param variable_count Output pointer for variable count.
 * @return Array of variables.
 */
wslua_variable_t *wslua_debugger_get_variables(const char *path,
                                               int32_t *variable_count)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        *variable_count = 0;
        return NULL;
    }

    GArray *variables_array =
        g_array_new(false, false, sizeof(wslua_variable_t));

    if (!path || !*path)
    {
        /* Root: Locals, Upvalues, Globals */
        wslua_variable_t variable;

        variable.name = g_strdup("Locals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Upvalues");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Globals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);
    }
    else if (g_strcmp0(path, "Locals") == 0)
    {
        /* Locals */
        lua_Debug debug_info;
        if (lua_getstack(target_L, 0, &debug_info))
        {
            int32_t local_index = 1;
            const char *name;
            while ((name = lua_getlocal(target_L, &debug_info, local_index++)))
            {
                if (g_str_has_prefix(name, "("))
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                wslua_variable_t variable;
                variable.name = g_strdup(name);
                variable.type =
                    g_strdup(lua_typename(target_L, lua_type(target_L, -1)));
                variable.value = wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1);
            }
        }
    }
    else if (g_strcmp0(path, "Upvalues") == 0)
    {
        /* Upvalues */
        lua_Debug debug_info;
        if (lua_getstack(target_L, 0, &debug_info))
        {
            lua_getinfo(target_L, "f", &debug_info);
            int32_t upvalue_index = 1;
            const char *name;
            while ((name = lua_getupvalue(target_L, -1, upvalue_index++)))
            {
                wslua_variable_t variable;
                variable.name = g_strdup(name);
                variable.type =
                    g_strdup(lua_typename(target_L, lua_type(target_L, -1)));
                variable.value = wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1);
            }
            lua_pop(target_L, 1); /* Function */
        }
    }
    else if (g_strcmp0(path, "Globals") == 0)
    {
        /* Globals (_G) — limit to avoid freezing the UI */
#define WSLUA_GLOBALS_DISPLAY_LIMIT 500
        unsigned globals_count = 0;
        lua_pushglobaltable(target_L);
        /* Iterate table */
        lua_pushnil(target_L);
        while (lua_next(target_L, -2) != 0)
        {
            if (globals_count >= WSLUA_GLOBALS_DISPLAY_LIMIT)
            {
                lua_pop(target_L, 2); /* key + value */
                /* Add a sentinel entry so the user knows the list is truncated */
                wslua_variable_t truncated;
                truncated.name = g_strdup_printf(
                    "... (%u+ globals, showing first %u)",
                    WSLUA_GLOBALS_DISPLAY_LIMIT, WSLUA_GLOBALS_DISPLAY_LIMIT);
                truncated.type = g_strdup("");
                truncated.value = g_strdup("");
                truncated.can_expand = false;
                g_array_append_val(variables_array, truncated);
                break;
            }

            wslua_variable_t variable;

            if (lua_type(target_L, -2) == LUA_TSTRING)
            {
                variable.name = g_strdup(lua_tostring(target_L, -2));
            }
            else
            {
                /* Skip non-string globals for now or format them */
                lua_pop(target_L, 1);
                continue;
            }

            variable.type =
                g_strdup(lua_typename(target_L, lua_type(target_L, -1)));
            variable.value = wslua_debugger_describe_value(target_L, -1);
            variable.can_expand = wslua_debugger_value_can_expand(target_L, -1);

            g_array_append_val(variables_array, variable);
            lua_pop(target_L, 1);
            globals_count++;
        }
        lua_pop(target_L, 1); /* Table */
    }
    else
    {
        /* Lookup path */
        /* Strip prefix if present */
        const char *lookup_path = path;
        if (g_str_has_prefix(path, "Locals."))
            lookup_path = path + 7;
        else if (g_str_has_prefix(path, "Upvalues."))
            lookup_path = path + 9;
        else if (g_str_has_prefix(path, "Globals."))
            lookup_path = path + 8;

        if (wslua_debugger_lookup_path(target_L, lookup_path))
        {
            if (lua_istable(target_L, -1))
            {
                lua_pushnil(target_L);
                while (lua_next(target_L, -2) != 0)
                {
                    /* key at -2, value at -1 */
                    wslua_variable_t variable;

                    /* Key */
                    if (lua_type(target_L, -2) == LUA_TSTRING)
                    {
                        variable.name = g_strdup(lua_tostring(target_L, -2));
                    }
                    else if (lua_type(target_L, -2) == LUA_TNUMBER)
                    {
                        /* Use lua_tonumber instead of lua_tostring to avoid
                         * modifying the key on the stack, which would break
                         * lua_next() iteration */
                        lua_Number num_key = lua_tonumber(target_L, -2);
                        variable.name =
                            g_strdup_printf("[%g]", (double)num_key);
                    }
                    else
                    {
                        variable.name = g_strdup(
                            lua_typename(target_L, lua_type(target_L, -2)));
                    }

                    /* Value */
                    variable.type = g_strdup(
                        lua_typename(target_L, lua_type(target_L, -1)));
                    variable.value =
                        wslua_debugger_describe_value(target_L, -1);
                    variable.can_expand =
                        wslua_debugger_value_can_expand(target_L, -1);

                    g_array_append_val(variables_array, variable);
                    lua_pop(target_L, 1);
                }
            }
            lua_pop(target_L, 1); /* Pop result */
        }
    }

    *variable_count = (int32_t)variables_array->len;
    return (wslua_variable_t *)g_array_free(variables_array, false);
}

/**
 * @brief Free variables array.
 * @param variables The array.
 * @param variable_count The count.
 */
void wslua_debugger_free_variables(wslua_variable_t *variables,
                                   int32_t variable_count)
{
    for (int32_t variable_index = 0; variable_index < variable_count;
         variable_index++)
    {
        g_free(variables[variable_index].name);
        g_free(variables[variable_index].value);
        g_free(variables[variable_index].type);
    }
    g_free(variables);
}

/**
 * @brief Get breakpoint count.
 * @return The number of breakpoints.
 */
unsigned wslua_debugger_get_breakpoint_count(void)
{
    ensure_breakpoints_initialized();
    return breakpoints_array->len;
}

/**
 * @brief Get breakpoint at index.
 * @param idx The index.
 * @param file_path Output file path.
 * @param line Output line.
 * @param active Output active state.
 * @return true if found.
 */
bool wslua_debugger_get_breakpoint(unsigned idx, const char **file_path,
                                   int64_t *line, bool *active)
{
    ensure_breakpoints_initialized();

    if (idx >= breakpoints_array->len)
        return false;

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    *file_path = bp->file_path;
    *line = bp->line;
    *active = bp->active;
    return true;
}

/* Reload callback */
static wslua_debugger_reload_callback_t reload_callback = NULL;

/**
 * @brief Register a callback to be notified before Lua plugins are reloaded.
 *
 * The debugger UI uses this to reload script files from disk before
 * Lua executes them, ensuring breakpoints show current code.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_reload_callback(
    wslua_debugger_reload_callback_t callback)
{
    reload_callback = callback;
}

/**
 * @brief Notify the debugger that a reload is about to happen.
 *
 * Saves the debugger enabled state, disables the debugger, detaches
 * from the current Lua state, and calls the reload callback so the
 * UI can refresh script files from disk.
 *
 * If the debugger is paused, it is disabled (which continues execution)
 * and the reload callback is invoked so the UI can exit its nested
 * event loop and schedule a deferred reload.
 *
 * @return true if the caller should proceed with the reload immediately;
 *         false if the reload was deferred (debugger was paused).
 */
bool wslua_debugger_notify_reload(void)
{
    if (!debugger.reload_in_progress)
    {
        debugger.reload_in_progress = true;
        debugger.was_enabled_before_reload = debugger.enabled;
    }

    if (debugger.enabled)
    {
        wslua_debugger_set_enabled(false);
    }

    debugger.L = NULL;

    if (reload_callback)
    {
        reload_callback();
    }

    return !wslua_debugger_is_paused();
}

/**
 * @brief Post-reload callback storage.
 */
static wslua_debugger_post_reload_callback_t post_reload_callback = NULL;

/**
 * @brief Register a callback to be notified after Lua plugins are reloaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_post_reload_callback(
    wslua_debugger_post_reload_callback_t callback)
{
    post_reload_callback = callback;
}

/**
 * @brief Notify listeners that reload has completed.
 *
 * Called by wslua_reload_plugins() AFTER wslua_init() completes.
 * Clears the reload_in_progress flag and fires the post-reload UI
 * callback so the file tree is refreshed with newly loaded scripts.
 *
 * The debugger is NOT re-enabled here.  The UI must call
 * wslua_debugger_restore_after_reload() once cf_reload / redissect
 * has finished, to avoid the debug hook firing while packets are
 * still being re-read.
 */
void wslua_debugger_notify_post_reload(void)
{
    debugger.reload_in_progress = false;

    if (post_reload_callback)
    {
        post_reload_callback();
    }
}

/**
 * @brief Re-enable the debugger after a reload + cf_reload cycle.
 *
 * If the debugger was enabled before the reload, re-enable it now
 * that the file has been fully re-read.  This must be called AFTER
 * cf_reload / redissectPackets completes.
 */
void wslua_debugger_restore_after_reload(void)
{
    if (debugger.was_enabled_before_reload)
    {
        debugger.was_enabled_before_reload = false;
        if (!debugger.enabled && debugger.L)
        {
            wslua_debugger_set_enabled(true);
        }
    }
}

/**
 * @brief Script-loaded callback storage.
 */
static wslua_debugger_script_loaded_callback_t script_loaded_callback = NULL;

/**
 * @brief Register a callback to be notified when a Lua script is loaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_script_loaded_callback(
    wslua_debugger_script_loaded_callback_t callback)
{
    script_loaded_callback = callback;
}

/**
 * @brief Notify the debugger that a Lua script has been loaded.
 *
 * Called by the Lua loader when a script is successfully loaded.
 *
 * @param file_path The full path to the loaded script file.
 */
void wslua_debugger_notify_script_loaded(const char *file_path)
{
    if (script_loaded_callback && file_path)
    {
        script_loaded_callback(file_path);
    }
}

/**
 * @brief Check if the debugger is currently paused.
 * @return true if paused at a breakpoint, false otherwise.
 */
bool wslua_debugger_is_paused(void)
{
    g_mutex_lock(&debugger.mutex);
    bool paused = debugger.state == WSLUA_DEBUGGER_PAUSED &&
                  debugger.paused_L != NULL;
    g_mutex_unlock(&debugger.mutex);
    return paused;
}

/**
 * @brief Maximum number of Lua instructions allowed during evaluation.
 *
 * This prevents infinite loops from hanging Wireshark.  The limit is
 * generous enough for any reasonable inspection expression but will
 * abort runaway code within a fraction of a second.
 */
#define WSLUA_EVAL_INSTRUCTION_LIMIT 1000000

/**
 * @brief Maximum call depth allowed during evaluation.
 *
 * This catches deep recursion that could overflow the C stack before
 * the instruction-count limit triggers.
 */
#define WSLUA_EVAL_MAX_CALL_DEPTH 100

/** @brief Current call depth during expression evaluation. */
static int eval_call_depth;

/**
 * @brief Hook that aborts evaluation on instruction limit or deep recursion.
 */
static void wslua_eval_timeout_hook(lua_State *L, lua_Debug *ar)
{
    if (ar->event == LUA_HOOKCALL || ar->event == LUA_HOOKTAILCALL)
    {
        eval_call_depth++;
        if (eval_call_depth > WSLUA_EVAL_MAX_CALL_DEPTH)
        {
            luaL_error(L, "Evaluation aborted: call depth limit (%d) exceeded "
                       "(possible infinite recursion)",
                       WSLUA_EVAL_MAX_CALL_DEPTH);
        }
        return;
    }
    if (ar->event == LUA_HOOKRET)
    {
        if (eval_call_depth > 0)
        {
            eval_call_depth--;
        }
        return;
    }
    /* LUA_HOOKCOUNT — instruction limit reached */
    luaL_error(L, "Evaluation aborted: instruction limit (%d) exceeded "
               "(possible infinite loop)",
               WSLUA_EVAL_INSTRUCTION_LIMIT);
}

/**
 * @brief Evaluate a Lua expression in the context of the paused debugger.
 *
 * This function evaluates the given expression using the paused Lua state.
 * It supports the '=' prefix shorthand: "=expr" becomes "return expr".
 *
 * An instruction-count hook is installed for the duration of the call so
 * that infinite loops are caught instead of hanging Wireshark.
 *
 * WARNING: The expression runs in the live dissector Lua state.  Modifying
 * globals (e.g. _G.some_proto = nil) can corrupt ongoing analysis.
 *
 * @param expression The Lua expression to evaluate.
 * @param error_msg Output pointer for error message (caller frees).
 * @return Result string (caller frees), or NULL on error.
 */
char *wslua_debugger_evaluate(const char *expression, char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!expression || !*expression)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty expression");
        }
        return NULL;
    }

    g_mutex_lock(&debugger.mutex);
    lua_State *L = debugger.paused_L;
    g_mutex_unlock(&debugger.mutex);
    if (!L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return NULL;
    }

    /* Handle '=' prefix: treat as return statement for easy value inspection */
    char *code_to_eval;
    if (expression[0] == '=')
    {
        code_to_eval = g_strdup_printf("return %s", expression + 1);
    }
    else
    {
        code_to_eval = g_strdup(expression);
    }

    /* Save stack top to detect return values */
    int top_before = lua_gettop(L);

    /* Load the string as a chunk */
    int load_result = luaL_loadstring(L, code_to_eval);
    g_free(code_to_eval);

    if (load_result != LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Syntax error");
        }
        lua_pop(L, 1); /* Pop error message */
        return NULL;
    }

    /*
     * Install hooks to abort runaway code:
     * - LUA_MASKCOUNT: fires after WSLUA_EVAL_INSTRUCTION_LIMIT instructions
     * - LUA_MASKCALL / LUA_MASKRET: tracks call depth to catch deep recursion
     *   that could overflow the C stack before the instruction limit fires
     */
    eval_call_depth = 0;
    lua_sethook(L, wslua_eval_timeout_hook,
                LUA_MASKCOUNT | LUA_MASKCALL | LUA_MASKRET,
                WSLUA_EVAL_INSTRUCTION_LIMIT);

    /* Execute the chunk */
    int call_result = lua_pcall(L, 0, LUA_MULTRET, 0);

    /* Remove the timeout hook regardless of outcome */
    lua_sethook(L, NULL, 0, 0);

    if (call_result != LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Runtime error");
        }
        lua_pop(L, 1); /* Pop error message */
        return NULL;
    }

    /* Check if there are return values */
    int top_after = lua_gettop(L);
    int num_results = top_after - top_before;

    if (num_results == 0)
    {
        return g_strdup(""); /* No return value */
    }

    /* Build result string from all return values */
    GString *result = g_string_new(NULL);
    for (int i = 0; i < num_results; i++)
    {
        int idx = top_before + 1 + i;
        if (i > 0)
        {
            g_string_append(result, "\t");
        }

        /* Use our existing describe_value function */
        char *value_str = wslua_debugger_describe_value(L, idx);
        if (value_str)
        {
            g_string_append(result, value_str);
            g_free(value_str);
        }
        else
        {
            g_string_append(result, "nil");
        }
    }

    /* Pop all return values */
    lua_pop(L, num_results);

    return g_string_free(result, FALSE);
}

/**
 * @brief Helper callback for wslua_debugger_foreach_loaded_script.
 *
 * This callback receives plugin descriptions from
 * wslua_plugins_get_descriptions and forwards only the filename to the user's
 * callback.
 */
static void loaded_script_description_callback(const char *name _U_,
                                               const char *version _U_,
                                               const char *description _U_,
                                               const char *filename,
                                               void *user_data)
{
    /* user_data is a two-element array: [0] = user callback, [1] = user data */
    void **context = (void **)user_data;
    wslua_debugger_loaded_script_callback_t user_callback =
        (wslua_debugger_loaded_script_callback_t)context[0];
    void *user_context = context[1];

    if (user_callback && filename)
    {
        user_callback(filename, user_context);
    }
}

/**
 * @brief Iterate over all currently loaded Lua plugin scripts.
 *
 * This function calls the provided callback once for each Lua script
 * that has been loaded by the Wireshark Lua subsystem.
 *
 * @param callback Function to call for each loaded script.
 * @param user_data Context pointer passed to the callback.
 */
void wslua_debugger_foreach_loaded_script(
    wslua_debugger_loaded_script_callback_t callback, void *user_data)
{
    if (!callback)
    {
        return;
    }

    /* Pack callback and user_data into array for inner callback */
    void *context[2] = {(void *)callback, user_data};
    wslua_plugins_get_descriptions(loaded_script_description_callback, context);
}
