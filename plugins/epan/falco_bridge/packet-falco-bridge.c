/* packet-falco-bridge.c
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// To do:
// - Convert this to C++? It would let us get rid of the glue that is
//   sinsp-span and make string handling a lot easier. However,
//   epan/address.h and driver/ppm_events_public.h both define PT_NONE.
// - Add a configuration preference for configure_plugin?
// - Add a configuration preference for individual conversation filters vs ANDing them?
//   We would need to add deregister_(|log_)conversation_filter before we implement this.
// - Add syscall IP address conversation support

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <dlfcn.h>
#endif

#include <wiretap/wtap.h>

#include <epan/exceptions.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/conversation_filter.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/inet_addr.h>
#include <wsutil/report_message.h>

#include "sinsp-span.h"

typedef enum bridge_field_flags_e {
    BFF_NONE = 0,
    BFF_HIDDEN = 1 << 1, // Unused
    BFF_INFO = 1 << 2,
    BFF_CONVERSATION = 1 << 3
} bridge_field_flags_e;

typedef struct conv_filter_info {
    hf_register_info *field_info;
    bool is_present;
    wmem_strbuf_t *strbuf;
} conv_filter_info;

typedef struct bridge_info {
    sinsp_source_info_t *ssi;
    uint32_t source_id;
    int proto;
    hf_register_info* hf;
    int* hf_ids;
    hf_register_info* hf_v4;
    int *hf_v4_ids;
    hf_register_info* hf_v6;
    int *hf_v6_ids;
    int* hf_id_to_addr_id; // Maps an hf offset to an hf_v[46] offset
    uint32_t visible_fields;
    uint32_t* field_flags;
    int* field_ids;
    uint32_t num_conversation_filters;
    conv_filter_info *conversation_filters;
} bridge_info;

static int proto_falco_bridge;

static int ett_falco_bridge;
static int ett_sinsp_enriched;
static int ett_sinsp_span;
static int ett_address;

static hf_register_info *hf_syscall_category = NULL;
static int *hf_syscall_category_ids = NULL;
static int *syscall_category_etts = NULL;

static dissector_table_t ptype_dissector_table;

static int dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_sinsp_enriched(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *bi_ptr);
static int dissect_sinsp_plugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *bi_ptr);

/*
 * Array of plugin bridges
 */
bridge_info* bridges = NULL;
guint nbridges = 0;
guint n_conv_fields = 0;

/*
 * sinsp extractor span
 */
sinsp_span_t *sinsp_span = NULL;

/*
 * Fields
 */
static int hf_sdp_source_id_size;
static int hf_sdp_lengths;
static int hf_sdp_source_id;

static hf_register_info hf[] = {
    { &hf_sdp_source_id_size,
        { "Plugin ID size", "falcobridge.id.size",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sdp_lengths,
        { "Field Lengths", "falcobridge.lens",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sdp_source_id,
        { "Plugin ID", "falcobridge.id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static void
falco_bridge_cleanup(void) {
    close_sinsp_capture(sinsp_span);
}

// Returns true if the field might contain an IPv4 or IPv6 address.
// XXX This should probably be a preference.
static bool
is_string_address_field(enum ftenum ftype, const char *abbrev) {
    if (ftype != FT_STRINGZ) {
        return false;
    }
    if (strstr(abbrev, ".srcip")) { // ct.srcip
        return true;
    } else if (strstr(abbrev, ".client.ip")) { // okta.client.ip
        return true;
    }
    return false;
}

static gboolean
is_filter_valid(packet_info *pinfo, void *cfi_ptr)
{
    conv_filter_info *cfi = (conv_filter_info *)cfi_ptr;

    if (!cfi->is_present) {
        return FALSE;
    }

    int proto_id = proto_registrar_get_parent(cfi->field_info->hfinfo.id);

    if (proto_id < 0) {
        return false;
    }

    return proto_is_frame_protocol(pinfo->layers, proto_registrar_get_nth(proto_id)->abbrev);
}

static gchar*
build_filter(packet_info *pinfo _U_, void *cfi_ptr)
{
    conv_filter_info *cfi = (conv_filter_info *)cfi_ptr;

    if (!cfi->is_present) {
        return FALSE;
    }

    return ws_strdup_printf("%s eq %s", cfi->field_info->hfinfo.abbrev, cfi->strbuf->str);
}

static void
create_source_hfids(bridge_info* bi)
{
    /*
     * Initialize the plugin
     */
    bi->source_id = get_sinsp_source_id(bi->ssi);

    size_t tot_fields = get_sinsp_source_nfields(bi->ssi);
    bi->visible_fields = 0;
    uint32_t addr_fields = 0;
    sinsp_field_info_t sfi;
    bi->num_conversation_filters = 0;

    for (size_t j = 0; j < tot_fields; j++) {
        get_sinsp_source_field_info(bi->ssi, j, &sfi);
        if (sfi.is_hidden) {
            /*
             * Skip the fields that are marked as hidden.
             * XXX Should we keep them and call proto_item_set_hidden?
             */
            continue;
        }
        if (sfi.is_numeric_address || is_string_address_field(sfi.type, sfi.abbrev)) {
            addr_fields++;
        }
        bi->visible_fields++;

        if (sfi.is_conversation) {
            bi->num_conversation_filters++;
        }
    }

    if (bi->visible_fields) {
        bi->hf = (hf_register_info*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(hf_register_info));
        bi->hf_ids = (int*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
        bi->field_ids = (int*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
        bi->field_flags = (guint32*)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(guint32));

        if (addr_fields) {
            bi->hf_id_to_addr_id = (int *)wmem_alloc(wmem_epan_scope(), bi->visible_fields * sizeof(int));
            bi->hf_v4 = (hf_register_info*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(hf_register_info));
            bi->hf_v4_ids = (int*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(int));
            bi->hf_v6 = (hf_register_info*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(hf_register_info));
            bi->hf_v6_ids = (int*)wmem_alloc(wmem_epan_scope(), addr_fields * sizeof(int));
        }

        if (bi->num_conversation_filters) {
            bi->conversation_filters = (conv_filter_info *)wmem_alloc(wmem_epan_scope(), bi->num_conversation_filters * sizeof (conv_filter_info));
        }

        uint32_t fld_cnt = 0;
        size_t conv_fld_cnt = 0;
        uint32_t addr_fld_cnt = 0;

        for (size_t j = 0; j < tot_fields; j++)
        {
            bi->hf_ids[fld_cnt] = -1;
            bi->field_ids[fld_cnt] = (int) j;
            bi->field_flags[fld_cnt] = BFF_NONE;
            hf_register_info* ri = bi->hf + fld_cnt;

            get_sinsp_source_field_info(bi->ssi, j, &sfi);

            if (sfi.is_hidden) {
                /*
                 * Skip the fields that are marked as hidden
                 */
                continue;
            }

            enum ftenum ftype = sfi.type;
            int fdisplay = BASE_NONE;
            switch (sfi.type) {
            case FT_STRINGZ:
            case FT_BOOLEAN:
            case FT_BYTES:
                break;
            case FT_RELATIVE_TIME:
            case FT_ABSOLUTE_TIME:
                fdisplay = BASE_DEC;
                break;
            case FT_INT8:
            case FT_INT16:
            case FT_INT32:
            case FT_INT64:
            case FT_DOUBLE:
                // This differs from libsinsp
                fdisplay = BASE_DEC;
                break;
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT32:
            case FT_UINT64:
                switch (sfi.display_format) {
                case SFDF_DECIMAL:
                    fdisplay = BASE_DEC;
                    break;
                case SFDF_HEXADECIMAL:
                    fdisplay = BASE_HEX;
                    break;
                case SFDF_OCTAL:
                    fdisplay = BASE_OCT;
                    break;
                default:
                    THROW_FORMATTED(DissectorError, "error in source %s: format %d for field %s is not supported",
                        get_sinsp_source_name(bi->ssi), sfi.display_format, sfi.abbrev);
                }
                break;
            default:
                ftype = FT_NONE;
                ws_warning("plugin %s: type of field %s (%d) is not supported",
                    get_sinsp_source_name(bi->ssi),
                    sfi.abbrev, sfi.type);
            }

            hf_register_info finfo = {
                bi->hf_ids + fld_cnt,
                {
                    wmem_strdup(wmem_epan_scope(), sfi.display), wmem_strdup(wmem_epan_scope(), sfi.abbrev),
                    ftype, fdisplay,
                    NULL, 0x0,
                    wmem_strdup(wmem_epan_scope(), sfi.description), HFILL
                }
            };
            *ri = finfo;

            if (sfi.is_conversation) {
                bi->field_flags[fld_cnt] |= BFF_CONVERSATION;
                bi->conversation_filters[conv_fld_cnt].field_info = ri;
                bi->conversation_filters[conv_fld_cnt].strbuf = wmem_strbuf_new(wmem_epan_scope(), "");

                const char *source_name = get_sinsp_source_name(bi->ssi);
                const char *conv_filter_name = wmem_strdup_printf(wmem_epan_scope(), "%s %s", source_name, ri->hfinfo.name);
                register_log_conversation_filter(source_name, conv_filter_name, is_filter_valid, build_filter, &bi->conversation_filters[conv_fld_cnt]);
                if (conv_fld_cnt == 0) {
                    add_conversation_filter_protocol(source_name);
                }
                conv_fld_cnt++;
            }

            if (sfi.is_info) {
                bi->field_flags[fld_cnt] |= BFF_INFO;
            }

            if (sfi.is_numeric_address || is_string_address_field(sfi.type, sfi.abbrev)) {
                bi->hf_id_to_addr_id[fld_cnt] = addr_fld_cnt;

                bi->hf_v4_ids[addr_fld_cnt] = -1;
                hf_register_info* ri_v4 = bi->hf_v4 + addr_fld_cnt;
                hf_register_info finfo_v4 = {
                    bi->hf_v4_ids + addr_fld_cnt,
                    {
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv4)", sfi.display),
                        wmem_strdup_printf(wmem_epan_scope(), "%s.v4", sfi.abbrev),
                        FT_IPv4, BASE_NONE,
                        NULL, 0x0,
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv4)", sfi.description), HFILL
                    }
                };
                *ri_v4 = finfo_v4;

                bi->hf_v6_ids[addr_fld_cnt] = -1;
                hf_register_info* ri_v6 = bi->hf_v6 + addr_fld_cnt;
                hf_register_info finfo_v6 = {
                    bi->hf_v6_ids + addr_fld_cnt,
                    {
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv6)", sfi.display),
                        wmem_strdup_printf(wmem_epan_scope(), "%s.v6", sfi.abbrev),
                        FT_IPv6, BASE_NONE,
                        NULL, 0x0,
                        wmem_strdup_printf(wmem_epan_scope(), "%s (IPv6)", sfi.description), HFILL
                    }
                };
                *ri_v6 = finfo_v6;
                addr_fld_cnt++;
            } else if (bi->hf_id_to_addr_id) {
                bi->hf_id_to_addr_id[fld_cnt] = -1;
            }
            fld_cnt++;
        }
        proto_register_field_array(proto_falco_bridge, bi->hf, fld_cnt);
        if (addr_fld_cnt) {
            proto_register_field_array(proto_falco_bridge, bi->hf_v4, addr_fld_cnt);
            proto_register_field_array(proto_falco_bridge, bi->hf_v6, addr_fld_cnt);
        }
    }
}

void
import_plugin(char* fname)
{
    nbridges++;
    bridge_info* bi = &bridges[nbridges - 1];

    char *err_str = create_sinsp_plugin_source(sinsp_span, fname, &(bi->ssi));
    if (err_str) {
        nbridges--;
        report_failure("Unable to load sinsp plugin %s: %s.", fname, err_str);
        g_free(err_str);
        return;
    }

    create_source_hfids(bi);

    const char *source_name = get_sinsp_source_name(bi->ssi);
    const char *plugin_name = g_strdup_printf("%s Plugin", source_name);
    bi->proto = proto_register_protocol (
        plugin_name,       /* full name */
        source_name,       /* short name  */
        source_name        /* filter_name */
        );

    static dissector_handle_t ct_handle;
    ct_handle = create_dissector_handle(dissect_sinsp_plugin, bi->proto);
    dissector_add_uint("falcobridge.id", bi->source_id, ct_handle);
}

static void
on_wireshark_exit(void)
{
    // XXX This currently crashes in a sinsp thread.
    // destroy_sinsp_span(sinsp_span);
    sinsp_span = NULL;
}

void
proto_register_falcoplugin(void)
{
    // Opening requires a file path, so we do that in dissect_sinsp_enriched.
    register_cleanup_routine(&falco_bridge_cleanup);

    proto_falco_bridge = proto_register_protocol (
        "Falco Bridge", /* name       */
        "Falco Bridge", /* short name */
        "falcobridge"   /* abbrev     */
        );
    register_dissector("falcobridge", dissect_falco_bridge, proto_falco_bridge);

    /*
     * Create the dissector table that we will use to route the dissection to
     * the appropriate Falco plugin.
     */
    ptype_dissector_table = register_dissector_table("falcobridge.id",
        "Falco Bridge Plugin ID", proto_falco_bridge, FT_UINT32, BASE_DEC);

    /*
     * Load the plugins
     */
    WS_DIR *dir;
    WS_DIRENT *file;
    char *filename;
    char *spdname = g_build_filename(get_plugins_dir(), "falco", NULL);
    char *ppdname = g_build_filename(get_plugins_pers_dir(), "falco", NULL);

    /*
     * We scan the plugins directory twice. The first time we count how many
     * plugins we have, which we need to know in order to allocate the right
     * amount of memory. The second time we actually load and configure
     * each plugin.
     */
    if ((dir = ws_dir_open(spdname, 0, NULL)) != NULL) {
        while ((ws_dir_read_name(dir)) != NULL) {
            nbridges++;
        }
        ws_dir_close(dir);
    }

    if ((dir = ws_dir_open(ppdname, 0, NULL)) != NULL) {
        while ((ws_dir_read_name(dir)) != NULL) {
            nbridges++;
        }
        ws_dir_close(dir);
    }

    sinsp_span = create_sinsp_span();

    bridges = g_new0(bridge_info, nbridges + 1);

    create_sinsp_syscall_source(sinsp_span, &bridges[0].ssi);

    size_t ncategories = get_syscall_source_ncategories(bridges[0].ssi);
    hf_syscall_category = (hf_register_info*)wmem_alloc0(wmem_epan_scope(), ncategories * sizeof(hf_register_info));
    hf_syscall_category_ids = (int*)wmem_alloc0(wmem_epan_scope(), ncategories * sizeof(int));
    syscall_category_etts = (int*)wmem_alloc0(wmem_epan_scope(), ncategories * sizeof(int));
    int **syscall_category_ett_ptrs = (int**)g_new(int **, ncategories);
    sinsp_field_info_t csfi;
    for (size_t i = 0; i < ncategories; i++) {
        get_syscall_source_category_info(bridges[0].ssi, i, &csfi);
        syscall_category_ett_ptrs[i] = &syscall_category_etts[i];

        hf_register_info finfo = {
            &hf_syscall_category_ids[i],
            {
                wmem_strdup(wmem_epan_scope(), csfi.display), wmem_strdup(wmem_epan_scope(), csfi.abbrev),
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                wmem_strdup(wmem_epan_scope(), csfi.description), HFILL
            }
        };

        hf_register_info* ri = &hf_syscall_category[i];
        *ri = finfo;
    }

    create_source_hfids(&bridges[0]);
    nbridges = 1;

    if ((dir = ws_dir_open(spdname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = g_build_filename(spdname, ws_dir_get_name(file), NULL);
            import_plugin(filename);
            g_free(filename);
        }
        ws_dir_close(dir);
    }

    if ((dir = ws_dir_open(ppdname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = g_build_filename(ppdname, ws_dir_get_name(file), NULL);
            import_plugin(filename);
            g_free(filename);
        }
        ws_dir_close(dir);
    }

    g_free(spdname);
    g_free(ppdname);

    /*
     * Setup protocol subtree array
     */
    static int *ett[] = {
        &ett_falco_bridge,
        &ett_sinsp_enriched,
        &ett_sinsp_span,
        &ett_address,
    };

    proto_register_field_array(proto_falco_bridge, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    proto_register_field_array(proto_falco_bridge, hf_syscall_category, (int)ncategories);
    proto_register_subtree_array(syscall_category_ett_ptrs, (int)ncategories);
    g_free(syscall_category_ett_ptrs);

    register_shutdown_routine(on_wireshark_exit);
}

static bridge_info*
get_bridge_info(guint32 source_id)
{
    if (source_id == 0) {
        return &bridges[0];
    }

    for(size_t j = 0; j < nbridges; j++)
    {
        if(bridges[j].source_id == source_id)
        {
            return &bridges[j];
        }
    }

    return NULL;
}

#define FALCO_PPME_PLUGINEVENT_E 322
static int
dissect_falco_bridge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int encoding = pinfo->rec->rec_header.syscall_header.byte_order == G_BIG_ENDIAN ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Falco Bridge");

    // https://github.com/falcosecurity/libs/blob/9c942f27/userspace/libscap/scap.c#L1900
    proto_item *ti = proto_tree_add_item(tree, proto_falco_bridge, tvb, 0, 12, ENC_NA);
    proto_tree *fb_tree = proto_item_add_subtree(ti, ett_falco_bridge);

    guint32 source_id = 0;
    if (pinfo->rec->rec_header.syscall_header.event_type == FALCO_PPME_PLUGINEVENT_E) {
        source_id = tvb_get_guint32(tvb, 8, encoding);
    }
    bridge_info* bi = get_bridge_info(source_id);
    if (source_id) {
        proto_tree_add_item(fb_tree, hf_sdp_source_id_size, tvb, 0, 4, encoding);
        proto_tree_add_item(fb_tree, hf_sdp_lengths, tvb, 4, 4, encoding);
        /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo,COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Plugin ID: %u", source_id);

        proto_item *idti = proto_tree_add_item(fb_tree, hf_sdp_source_id, tvb, 8, 4, encoding);
        if (bi == NULL) {
            proto_item_append_text(idti, " (NOT SUPPORTED)");
            col_append_str(pinfo->cinfo, COL_INFO, " (NOT SUPPORTED)");
            return tvb_captured_length(tvb);
        }

        const char *source_name = get_sinsp_source_name(bi->ssi);
        proto_item_append_text(idti, " (%s)", source_name);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", source_name);
    }


    if (bi->source_id == 0) {
        dissect_sinsp_enriched(tvb, pinfo, fb_tree, bi);
    } else {
        tvbuff_t* plugin_tvb = tvb_new_subset_length(tvb, 12, tvb_captured_length(tvb) - 12);
        dissect_sinsp_plugin(plugin_tvb, pinfo, fb_tree, bi);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_sinsp_enriched(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* bi_ptr)
{
    bridge_info* bi = (bridge_info *) bi_ptr;

    if (!pinfo->fd->visited) {
        if (pinfo->fd->num == 1) {
            // Open the capture file using libsinsp, which reads the meta events
            // at the beginning of the file. We can't call this via register_init_routine
            // because we don't have the file path at that point.
            open_sinsp_capture(sinsp_span, pinfo->rec->rec_header.syscall_header.pathname);
        }
    }

    sinsp_field_extract_t *sinsp_fields = (sinsp_field_extract_t*) wmem_alloc(pinfo->pool, sizeof(sinsp_field_extract_t) * bi->visible_fields);
    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];

        sfe->field_id = bi->field_ids[fld_idx];
        sfe->field_name = hfinfo->abbrev + strlen(FALCO_FIELD_NAME_PREFIX);
        sfe->type = hfinfo->type;
        switch(hfinfo->type) {
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
        case FT_INT64:
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT32:
        case FT_UINT64:
        case FT_STRINGZ:
        case FT_RELATIVE_TIME:
        case FT_ABSOLUTE_TIME:
        case FT_BOOLEAN:
        case FT_DOUBLE:
            break;
        default:
            sfe->type = FT_BYTES;
        }
    }

    guint plen = tvb_captured_length(tvb);
    guint8* payload = (guint8*)tvb_get_ptr(tvb, 0, plen);

    // If we have a failure, try to dissect what we can first, then bail out with an error.
    uint64_t ts = pinfo->abs_ts.secs * 1000000000 + pinfo->abs_ts.nsecs;
    bool rc = extract_syscall_source_fields(bi->ssi, pinfo->rec->rec_header.syscall_header.event_type,
                                            pinfo->rec->rec_header.syscall_header.nparams,
                                            ts, pinfo->rec->rec_header.syscall_header.thread_id, pinfo->rec->rec_header.syscall_header.cpu_id,
                                            payload, plen, pinfo->pool, sinsp_fields, bi->visible_fields);

    if (!rc) {
        REPORT_DISSECTOR_BUG("Falco plugin %s extract error: %s", get_sinsp_source_name(bi->ssi), get_sinsp_source_last_error(bi->ssi));
    }

    size_t ncategories = get_syscall_source_ncategories(bi->ssi);
    proto_tree **parent_trees = wmem_alloc0(wmem_packet_scope(), ncategories * sizeof(proto_tree *));

    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);

        if (!sfe->is_present) {
            continue;
        }

        if (sfe->type != hfinfo->type) {
            REPORT_DISSECTOR_BUG("Field %s has an unrecognized or mismatched type %u != %u",
                                 hfinfo->abbrev, sfe->type, hfinfo->type);
        }

        proto_tree *parent_tree = tree;
        if (sfe->parent_category < ncategories) {
            if (!parent_trees[sfe->parent_category]) {
                proto_tree *ti = proto_tree_add_item(tree, hf_syscall_category_ids[sfe->parent_category], tvb, 0, 0, BASE_NONE);
                parent_trees[sfe->parent_category] = proto_item_add_subtree(ti, syscall_category_etts[sfe->parent_category]);
            }
            parent_tree = parent_trees[sfe->parent_category];
        }

        switch (hfinfo->type) {
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
            proto_tree_add_int(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.i32);
            break;
        case FT_INT64:
            proto_tree_add_int64(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.i64);
            break;
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT32:
            proto_tree_add_uint(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.u32);
            break;
        case FT_UINT64:
        case FT_RELATIVE_TIME:
        case FT_ABSOLUTE_TIME:
            proto_tree_add_uint64(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.u64);
            break;
        case FT_STRINGZ:
        {
            if (sfe->res.str == NULL) {
                ws_debug("Field %s has NULL result string", sfe->field_name);
                continue;
            }
            proto_item *pi = proto_tree_add_string(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.str);
            if (bi->field_flags[fld_idx] & BFF_INFO) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", sfe->res.str);
                // Mark it hidden, otherwise we end up with a bunch of empty "Info" tree items.
                proto_item_set_hidden(pi);
            }
        }
            break;
            case FT_BOOLEAN:
                proto_tree_add_boolean(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.boolean);
                break;
            case FT_DOUBLE:
                proto_tree_add_double(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.dbl);
                break;
            case FT_BYTES:
            {
                int addr_fld_idx = bi->hf_id_to_addr_id[fld_idx];
                if (addr_fld_idx < 0) {
                    proto_tree_add_bytes_with_length(parent_tree, bi->hf_ids[fld_idx], tvb, 0, 0, sfe->res.str, sfe->res_len);
                } else {
                    // XXX Need to differentiate between src and dest. Falco libs supply client vs server and local vs remote.
                    if (sfe->res_len == 4) {
                        ws_in4_addr v4_addr;
                        memcpy(&v4_addr, sfe->res.bytes, 4);
                        proto_tree_add_ipv4(parent_tree, bi->hf_v4_ids[addr_fld_idx], tvb, 0, 0, v4_addr);
                        set_address(&pinfo->net_src, AT_IPv4, sizeof(ws_in4_addr), &v4_addr);
                    } else if (sfe->res_len == 16) {
                        ws_in6_addr v6_addr;
                        memcpy(&v6_addr, sfe->res.bytes, 16);
                        proto_tree_add_ipv6(parent_tree, bi->hf_v6_ids[addr_fld_idx], tvb, 0, 0, &v6_addr);
                        set_address(&pinfo->net_src, AT_IPv6, sizeof(ws_in6_addr), &v6_addr);
                    } else {
                        ws_warning("Invalid length %u for address field %s", sfe->res_len, sfe->field_name);
                    }
                    // XXX Add conversation support.
#if 0
                    if (cur_conv_filter) {
                        wmem_strbuf_append(cur_conv_filter->strbuf, sfe->res.str);
                        cur_conv_filter->is_present = true;
                    }
                    if (cur_conv_els) {
                        cur_conv_els[1].type = CE_ADDRESS;
                        copy_address(&cur_conv_els[1].addr_val, &pinfo->net_src);
                    }
#endif
                }
                break;
            }
            default:
                break;
        }
    }

    return plen;
}

static int
dissect_sinsp_plugin(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* bi_ptr)
{
    bridge_info* bi = (bridge_info *) bi_ptr;
    guint payload_len = tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "oops");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = tree;
    proto_tree* fb_tree = proto_item_add_subtree(ti, ett_sinsp_span);

    guint8* payload = (guint8*)tvb_get_ptr(tvb, 0, payload_len);

    sinsp_field_extract_t *sinsp_fields = (sinsp_field_extract_t*) wmem_alloc(pinfo->pool, sizeof(sinsp_field_extract_t) * bi->visible_fields);
    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];

        sfe->field_id = bi->field_ids[fld_idx];
        sfe->field_name = hfinfo->abbrev;
        sfe->type = hfinfo->type == FT_STRINGZ ? FT_STRINGZ : FT_UINT64;
    }

    // If we have a failure, try to dissect what we can first, then bail out with an error.
    bool rc = extract_plugin_source_fields(bi->ssi, pinfo->rec->rec_header.syscall_header.event_type, pinfo->rec->rec_header.syscall_header.nparams, payload, payload_len, pinfo->pool, sinsp_fields, bi->visible_fields);

    if (!rc) {
        REPORT_DISSECTOR_BUG("Falco plugin %s extract error: %s", get_sinsp_source_name(bi->ssi), get_sinsp_source_last_error(bi->ssi));
    }

    for (uint32_t idx = 0; idx < bi->num_conversation_filters; idx++) {
        bi->conversation_filters[idx].is_present = false;
        wmem_strbuf_truncate(bi->conversation_filters[idx].strbuf, 0);
    }

    conversation_element_t *first_conv_els = NULL; // hfid + field val + CONVERSATION_LOG

    for (uint32_t fld_idx = 0; fld_idx < bi->visible_fields; fld_idx++) {
        sinsp_field_extract_t *sfe = &sinsp_fields[fld_idx];
        header_field_info* hfinfo = &(bi->hf[fld_idx].hfinfo);

        if (!sfe->is_present) {
            continue;
        }

        conv_filter_info *cur_conv_filter = NULL;
        conversation_element_t *cur_conv_els = NULL;
        if ((bi->field_flags[fld_idx] & BFF_CONVERSATION) != 0) {
            for (uint32_t cf_idx = 0; cf_idx < bi->num_conversation_filters; cf_idx++) {
                if (&(bi->conversation_filters[cf_idx].field_info)->hfinfo == hfinfo) {
                    cur_conv_filter = &bi->conversation_filters[cf_idx];
                    if (!first_conv_els) {
                        first_conv_els = wmem_alloc0(pinfo->pool, sizeof(conversation_element_t) * 3);
                        first_conv_els[0].type = CE_INT;
                        first_conv_els[0].int_val = hfinfo->id;
                        cur_conv_els = first_conv_els;
                    }
                    break;
                }
            }
        }


        if (sfe->type == FT_STRINGZ && hfinfo->type == FT_STRINGZ) {
            proto_item *pi = proto_tree_add_string(fb_tree, bi->hf_ids[fld_idx], tvb, 0, payload_len, sfe->res.str);
            if (bi->field_flags[fld_idx] & BFF_INFO) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", sfe->res.str);
                // Mark it hidden, otherwise we end up with a bunch of empty "Info" tree items.
                proto_item_set_hidden(pi);
            }

            int addr_fld_idx = bi->hf_id_to_addr_id[fld_idx];
            if (addr_fld_idx >= 0) {
                ws_in4_addr v4_addr;
                ws_in6_addr v6_addr;
                proto_tree *addr_tree;
                proto_item *addr_item = NULL;
                if (ws_inet_pton4(sfe->res.str, &v4_addr)) {
                    addr_tree = proto_item_add_subtree(pi, ett_address);
                    addr_item = proto_tree_add_ipv4(addr_tree, bi->hf_v4_ids[addr_fld_idx], tvb, 0, 0, v4_addr);
                    set_address(&pinfo->net_src, AT_IPv4, sizeof(ws_in4_addr), &v4_addr);
                } else if (ws_inet_pton6(sfe->res.str, &v6_addr)) {
                    addr_tree = proto_item_add_subtree(pi, ett_address);
                    addr_item = proto_tree_add_ipv6(addr_tree, bi->hf_v6_ids[addr_fld_idx], tvb, 0, 0, &v6_addr);
                    set_address(&pinfo->net_src, AT_IPv6, sizeof(ws_in6_addr), &v6_addr);
                }
                if (addr_item) {
                    proto_item_set_generated(addr_item);
                }
                if (cur_conv_filter) {
                    wmem_strbuf_append(cur_conv_filter->strbuf, sfe->res.str);
                    cur_conv_filter->is_present = true;
                }
                if (cur_conv_els) {
                    cur_conv_els[1].type = CE_ADDRESS;
                    copy_address(&cur_conv_els[1].addr_val, &pinfo->net_src);
                }
            } else {
                if (cur_conv_filter) {
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "\"%s\"", sfe->res.str);
                    cur_conv_filter->is_present = true;
                }
                if (cur_conv_els) {
                    cur_conv_els[1].type = CE_STRING;
                    cur_conv_els[1].str_val = wmem_strdup(pinfo->pool, sfe->res.str);
                }
            }
        }
        else if (sfe->type == FT_UINT64 && hfinfo->type == FT_UINT64) {
            proto_tree_add_uint64(fb_tree, bi->hf_ids[fld_idx], tvb, 0, payload_len, sfe->res.u64);
            if (cur_conv_filter) {
                switch (hfinfo->display) {
                case BASE_HEX:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRIx64, sfe->res.u64);
                    break;
                case BASE_OCT:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRIo64, sfe->res.u64);
                    break;
                default:
                    wmem_strbuf_append_printf(cur_conv_filter->strbuf, "%" PRId64, sfe->res.u64);
                }
                cur_conv_filter->is_present = true;
            }

            if (cur_conv_els) {
                cur_conv_els[1].type = CE_UINT64;
                cur_conv_els[1].uint64_val = sfe->res.u64;
            }
        }
        else {
            REPORT_DISSECTOR_BUG("Field %s has an unrecognized or mismatched type %u != %u",
                hfinfo->abbrev, sfe->type, hfinfo->type);
        }
    }

    if (first_conv_els) {
        first_conv_els[2].type = CE_CONVERSATION_TYPE;
        first_conv_els[2].conversation_type_val = CONVERSATION_LOG;
        pinfo->conv_elements = first_conv_els;
//        conversation_t *conv = find_or_create_conversation(pinfo);
//        if (!conv) {
//            conversation_new_full(pinfo->fd->num, pinfo->conv_elements);
//        }
    }

    return payload_len;
}

void
proto_reg_handoff_sdplugin(void)
{
}
