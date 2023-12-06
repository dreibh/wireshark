/* plugins.c
 * plugin routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_PLUGINS
#include "plugins.h"

#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gmodule.h>

#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

typedef struct _plugin {
    GModule        *handle;       /* handle returned by g_module_open */
    char           *name;         /* plugin name */
    struct ws_module *module;
} plugin;

#define TYPE_DIR_EPAN       "epan"
#define TYPE_DIR_WIRETAP    "wiretap"
#define TYPE_DIR_CODECS     "codecs"

static GSList *plugins_module_list = NULL;


static inline const char *
type_to_dir(plugin_type_e type)
{
    switch (type) {
    case WS_PLUGIN_EPAN:
        return TYPE_DIR_EPAN;
    case WS_PLUGIN_WIRETAP:
        return TYPE_DIR_WIRETAP;
    case WS_PLUGIN_CODEC:
        return TYPE_DIR_CODECS;
    default:
        ws_error("Unknown plugin type: %u. Aborting.", (unsigned) type);
        break;
    }
    ws_assert_not_reached();
}

static inline const char *
type_to_name(plugin_type_e type)
{
    switch (type) {
    case WS_PLUGIN_EPAN:
        return "epan";
    case WS_PLUGIN_WIRETAP:
        return "wiretap";
    case WS_PLUGIN_CODEC:
        return "codec";
    default:
        return "unknown";
    }
    ws_assert_not_reached();
}

static inline const char *
flags_to_str(uint32_t flags)
{
    /* XXX: Allow joining multiple types? Our plugins only implement a
     * single type but out in the wild this may not be true. */
    if (flags & WS_PLUGIN_DESC_DISSECTOR)
        return "dissector";
    else if (flags & WS_PLUGIN_DESC_FILE_TYPE)
        return "file type";
    else if (flags & WS_PLUGIN_DESC_CODEC)
        return "codec";
    else if (flags & WS_PLUGIN_DESC_EPAN)
        return "epan";
    else if (flags & WS_PLUGIN_DESC_TAP_LISTENER)
        return "tap listener";
    else if (flags & WS_PLUGIN_DESC_DFILTER)
        return "dfilter";
    else
        return "unknown";
}

static void
free_plugin(void * data)
{
    plugin *p = (plugin *)data;
    g_module_close(p->handle);
    g_free(p->name);
    g_free(p);
}

static int
compare_plugins(gconstpointer a, gconstpointer b)
{
    return g_strcmp0((*(plugin *const *)a)->name, (*(plugin *const *)b)->name);
}

static bool
pass_plugin_compatibility(const char *name, plugin_type_e type,
                            int abi_version)
{
    if (abi_version != plugins_abi_version(type)) {
        report_failure("The plugin '%s' has incompatible ABI, have version %d, expected %d",
                            name, abi_version, plugins_abi_version(type));
        return false;
    }

    return true;
}

// GLib and Qt allow ".dylib" and ".so" on macOS. Should we do the same?
#ifdef _WIN32
#define MODULE_SUFFIX ".dll"
#else
#define MODULE_SUFFIX ".so"
#endif

static void
scan_plugins_dir(GHashTable *plugins_module, const char *dirpath, plugin_type_e type, bool append_type)
{
    GDir          *dir;
    const char    *name;            /* current file name */
    char          *plugin_folder;
    char          *plugin_file;     /* current file full path */
    GModule       *handle;          /* handle returned by g_module_open */
    void          *symbol;
    plugin        *new_plug;
    plugin_type_e have_type;
    int            abi_version;
    struct ws_module *module;

    if (append_type)
        plugin_folder = g_build_filename(dirpath, type_to_dir(type), (char *)NULL);
    else
        plugin_folder = g_strdup(dirpath);

    dir = g_dir_open(plugin_folder, 0, NULL);
    if (dir == NULL) {
        g_free(plugin_folder);
        return;
    }

    ws_debug("Scanning plugins folder \"%s\"", plugin_folder);

    while ((name = g_dir_read_name(dir)) != NULL) {
        /* Skip anything but files with .dll or .so. */
        if (!g_str_has_suffix(name, MODULE_SUFFIX))
            continue;

        /*
         * Check if the same name is already registered.
         */
        if (g_hash_table_lookup(plugins_module, name)) {
            /* Yes, it is. */
            report_warning("The plugin '%s' was found "
                                "in multiple directories", name);
            continue;
        }

        plugin_file = g_build_filename(plugin_folder, name, (char *)NULL);
        handle = g_module_open(plugin_file, G_MODULE_BIND_LOCAL);
        if (handle == NULL) {
            /* g_module_error() provides file path. */
            report_failure("Couldn't load plugin '%s': %s", name,
                            g_module_error());
            g_free(plugin_file);
            continue;
        }

        /* Search for the entry point for the plugin registration function */
        if (!g_module_symbol(handle, "wireshark_load_module", &symbol)) {
            report_failure("The plugin '%s' has no \"wireshark_load_module\" symbol", name);
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

DIAG_OFF_PEDANTIC
        /* Found it, load module. */
        have_type = ((ws_load_module_func)symbol)(&abi_version, NULL, &module);
DIAG_ON_PEDANTIC

        if (have_type != type) {
            // Should not happen. Our filesystem hierarchy uses plugin type.
            report_failure("The plugin '%s' has invalid type, expected %s, have %s",
                                name, type_to_name(type), type_to_name(have_type));
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

        if (!pass_plugin_compatibility(name, type, abi_version)) {
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

        /* Call the plugin registration function. */
        module->register_cb();

        new_plug = g_new(plugin, 1);
        new_plug->handle = handle;
        new_plug->name = g_strdup(name);
        new_plug->module = module;

        /* Add it to the list of plugins. */
        g_hash_table_replace(plugins_module, new_plug->name, new_plug);
        ws_info("Registered plugin: %s (%s)", new_plug->name, plugin_file);
        ws_debug("plugin '%s' meta data: version = %s, flags = 0x%"PRIu32", spdx = %s, blurb = %s",
                    name, module->version, module->flags, module->spdx_id, module->blurb);
        g_free(plugin_file);
    }
    ws_dir_close(dir);
    g_free(plugin_folder);
}

/*
 * Scan for plugins.
 */
plugins_t *
plugins_init(plugin_type_e type)
{
    if (!g_module_supported())
        return NULL; /* nothing to do */

    GHashTable *plugins_module = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_plugin);

    /*
     * Scan the global plugin directory.
     */
    scan_plugins_dir(plugins_module, get_plugins_dir_with_version(), type, true);

    /*
     * If the program wasn't started with special privileges,
     * scan the users plugin directory.  (Even if we relinquish
     * them, plugins aren't safe unless we've *permanently*
     * relinquished them, and we can't do that in Wireshark as,
     * if we need privileges to start capturing, we'd need to
     * reclaim them before each time we start capturing.)
     */
    if (!started_with_special_privs()) {
        scan_plugins_dir(plugins_module, get_plugins_pers_dir_with_version(), type, true);
    }

    plugins_module_list = g_slist_prepend(plugins_module_list, plugins_module);

    return plugins_module;
}

WS_DLL_PUBLIC void
plugins_get_descriptions(plugin_description_callback callback, void *callback_data)
{
    GPtrArray *plugins_array = g_ptr_array_new();
    GHashTableIter iter;
    void * value;

    for (GSList *l = plugins_module_list; l != NULL; l = l->next) {
        g_hash_table_iter_init (&iter, (GHashTable *)l->data);
        while (g_hash_table_iter_next (&iter, NULL, &value)) {
            g_ptr_array_add(plugins_array, value);
        }
    }

    g_ptr_array_sort(plugins_array, compare_plugins);

    for (unsigned i = 0; i < plugins_array->len; i++) {
        plugin *plug = (plugin *)plugins_array->pdata[i];
        callback(plug->name, plug->module->version, plug->module->flags, plug->module->spdx_id,
                    plug->module->blurb, plug->module->home_url, g_module_name(plug->handle), callback_data);
    }

    g_ptr_array_free(plugins_array, true);
}

static void
print_plugin_description(const char *name, const char *version,
                         uint32_t flags, const char *spdx_id _U_,
                         const char *blurb _U_, const char *home_url _U_,
                         const char *filename,
                         void *user_data _U_)
{
    printf("%-16s\t%s\t%s\t%s\n", name, version, flags_to_str(flags), filename);
}

void
plugins_dump_all(void)
{
    plugins_get_descriptions(print_plugin_description, NULL);
}

int
plugins_get_count(void)
{
    unsigned count = 0;

    for (GSList *l = plugins_module_list; l != NULL; l = l->next) {
        count += g_hash_table_size((GHashTable *)l->data);
    }
    return count;
}

void
plugins_cleanup(plugins_t *plugins)
{
    if (!plugins)
        return;

    plugins_module_list = g_slist_remove(plugins_module_list, plugins);
    g_hash_table_destroy((GHashTable *)plugins);
}

bool
plugins_supported(void)
{
    return g_module_supported();
}

int
plugins_abi_version(plugin_type_e type)
{
    switch (type) {
        case WS_PLUGIN_EPAN:    return WIRESHARK_ABI_VERSION_EPAN;
        case WS_PLUGIN_WIRETAP: return WIRESHARK_ABI_VERSION_WIRETAP;
        case WS_PLUGIN_CODEC:   return WIRESHARK_ABI_VERSION_CODEC;
        default: return -1;
    }
    ws_assert_not_reached();
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
