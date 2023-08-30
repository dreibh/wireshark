/* manuf.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "manuf.h"
#include <stdlib.h>

// MA-L / OUI - MAC Address Block Large (24-bit prefix)
#define MA_L 0
// MA-M - MAC Address Block Medium (28-bit prefix)
#define MA_M 1
// MA-S / OUI-36 - MAC Address Block Small (36-bit prefix)
#define MA_S 2

typedef struct {
    uint8_t oui24[3];
    /* Identifies the 3-byte prefix as part of MA-M or MA-S (or MA-L if none of those). */
    uint8_t kind;
} manuf_registry_t;

typedef struct {
    uint8_t oui24[3];
    const char *short_name;
    const char *long_name;
} manuf_oui24_t;

typedef struct {
    uint8_t oui28[4];
    const char *short_name;
    const char *long_name;
} manuf_oui28_t;

typedef struct {
    uint8_t oui36[5];
    const char *short_name;
    const char *long_name;
} manuf_oui36_t;

#include "manuf-data.c"

static int
compare_oui24_registry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_registry_t *entry = (const manuf_registry_t *)element;

    return memcmp(addr, entry->oui24, 3);
}

static int
compare_oui24_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui24_t *oui = (const manuf_oui24_t *)element;

    return memcmp(addr, oui->oui24, 3);
}

static int
compare_oui28_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui28_t *oui = (const manuf_oui28_t *)element;

    // The caller is expected to have masked out (addr[3] & 0xF0).
    return memcmp(addr, oui->oui28, 4);
}

static int
compare_oui36_entry(const void *key, const void *element)
{
    const uint8_t *addr = (const uint8_t *)key;
    const manuf_oui36_t *oui = (const manuf_oui36_t *)element;

    // The caller is expected to have masked out (addr[4] & 0xF0).
    return memcmp(addr, oui->oui36, 5);
}

static int
select_registry(const uint8_t addr[6])
{
    const manuf_registry_t *entry;

    entry = bsearch(addr, ieee_registry_table, G_N_ELEMENTS(ieee_registry_table), sizeof(manuf_registry_t), compare_oui24_registry);
    if (entry)
        return entry->kind;
    return MA_L;
}

static bool
manuf_oui24_lookup(const uint8_t addr[6], struct ws_manuf *result)
{
    const manuf_oui24_t *oui24 = bsearch(addr, global_manuf_oui24_table, G_N_ELEMENTS(global_manuf_oui24_table), sizeof(manuf_oui24_t), compare_oui24_entry);
    if (!oui24)
        return false;

    memcpy(result->addr, oui24->oui24, sizeof(oui24->oui24));
    result->mask = 24;
    result->short_name = oui24->short_name;
    result->long_name = oui24->long_name;
    return true;
}

static bool
manuf_oui28_lookup(const uint8_t addr[6], struct ws_manuf *result)
{
    const uint8_t addr28[6] = { addr[0], addr[1], addr[2], addr[3] & 0xF0, };
    const manuf_oui28_t *oui28 = bsearch(addr28, global_manuf_oui28_table, G_N_ELEMENTS(global_manuf_oui28_table), sizeof(manuf_oui28_t), compare_oui28_entry);
    if (!oui28)
        return false;

    memcpy(result->addr, oui28->oui28, sizeof(oui28->oui28));
    result->mask = 28;
    result->short_name = oui28->short_name;
    result->long_name = oui28->long_name;
    return true;
}

static bool
manuf_oui36_lookup(const uint8_t addr[6], struct ws_manuf *result)
{
    const uint8_t addr36[6] = { addr[0], addr[1], addr[2], addr[3], addr[4] & 0xF0, };
    const manuf_oui36_t *oui36 = bsearch(addr36, global_manuf_oui36_table, G_N_ELEMENTS(global_manuf_oui36_table), sizeof(manuf_oui36_t), compare_oui36_entry);
    if (!oui36)
        return false;

    memcpy(result->addr, oui36->oui36, sizeof(oui36->oui36));
    result->mask = 36;
    result->short_name = oui36->short_name;
    result->long_name = oui36->long_name;
    return true;
}

bool
ws_manuf_lookup(const uint8_t addr[6], struct ws_manuf *result)
{
    memset(result, 0, sizeof(*result));

    uint8_t addr_copy[6];
    memcpy(addr_copy, addr, 6);
    /* Mask out the broadcast/multicast flag */
    addr_copy[0] &= 0xFE;

    switch (select_registry(addr_copy)) {
        case MA_L:
            return manuf_oui24_lookup(addr_copy, result);
        case MA_M:
            return manuf_oui28_lookup(addr_copy, result);
        case MA_S:
            return manuf_oui36_lookup(addr_copy, result);
    }
    ws_assert_not_reached();
}

void
ws_manuf_iter_init(ws_manuf_iter_t *iter)
{
    memset(iter, 0, sizeof(*iter));
}

/**
 * Iterate between 3 registries in ascending order. This is not the same as
 * fully iterating through one registry followed by another. For example, after
 * visiting "00:55:B1", it could go to  "00:55:DA:00/28", and eventually end up
 * at "00:56:2B" again.
 *
 * The "iter" structure must be zero initialized before the first iteration.
 */
bool
ws_manuf_iter_next(ws_manuf_iter_t *iter, struct ws_manuf *result)
{
    struct ws_manuf manuf[3] = { 0 };
    struct ws_manuf *ptr;

    ptr = manuf;

    /* Read current positions. */
    if (iter->idx24 < G_N_ELEMENTS(global_manuf_oui24_table)) {
        const manuf_oui24_t *ptr24 = &global_manuf_oui24_table[iter->idx24];
        memcpy(ptr->addr, ptr24->oui24, sizeof(ptr24->oui24));
        ptr->mask = 24;
        ptr->short_name = ptr24->short_name;
        ptr->long_name = ptr24->long_name;
        ptr++;
    }
    if (iter->idx28 < G_N_ELEMENTS(global_manuf_oui28_table)) {
        const manuf_oui28_t *ptr28 = &global_manuf_oui28_table[iter->idx28];
        memcpy(ptr->addr, ptr28->oui28, sizeof(ptr28->oui28));
        ptr->mask = 28;
        ptr->short_name = ptr28->short_name;
        ptr->long_name = ptr28->long_name;
        ptr++;
    }
    if (iter->idx36 < G_N_ELEMENTS(global_manuf_oui36_table)) {
        const manuf_oui36_t *ptr36 = &global_manuf_oui36_table[iter->idx36];
        memcpy(ptr->addr, ptr36->oui36, sizeof(ptr36->oui36));
        ptr->mask = 36;
        ptr->short_name = ptr36->short_name;
        ptr->long_name = ptr36->long_name;
    }

    /* None read. */
    if (manuf->mask == 0)
        return false;

    /* Select smallest current prefix out of the 3 registries.
     * There is at least one entry and index 0 is non-empty. */
    ptr = &manuf[0];
    for (size_t i = 1; i < G_N_ELEMENTS(manuf); i++) {
        if (manuf[i].mask && memcmp(manuf[i].addr, ptr->addr, 6) < 0) {
            ptr = &manuf[i];
        }
    }

    /* Advance iterator. */
    if (ptr->mask == 24)
        iter->idx24++;
    else if (ptr->mask == 28)
        iter->idx28++;
    else if (ptr->mask == 36)
        iter->idx36++;
    else
        ws_assert_not_reached();

    *result = *ptr;
    return true;
}

const char *
ws_manuf_block_str(char *buf, size_t buf_size, const struct ws_manuf *ptr)
{
    if (ptr->mask == 24) {
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8,
            ptr->addr[0], ptr->addr[1], ptr->addr[2]);
    }
    else if (ptr->mask == 28) {
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8"/%"PRIu8,
            ptr->addr[0], ptr->addr[1], ptr->addr[2], ptr->addr[3], ptr->mask);
    }
    else if (ptr->mask == 36) {
        snprintf(buf, buf_size, "%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8":%02"PRIX8"/%"PRIu8,
            ptr->addr[0], ptr->addr[1], ptr->addr[2], ptr->addr[3], ptr->addr[4], ptr->mask);
    }
    else {
        ws_assert_not_reached();
    }

    return buf;
}

void
ws_manuf_dump(FILE *fp)
{
    ws_manuf_iter_t iter;
    struct ws_manuf item;
    char strbuf[64];

    ws_manuf_iter_init(&iter);

    while (ws_manuf_iter_next(&iter, &item)) {
        fprintf(fp, "%-17s\t%-12s\t%s\n",
            ws_manuf_block_str(strbuf, sizeof(strbuf), &item),
            item.short_name,
            item.long_name);
    }
}

size_t
ws_manuf_count(void)
{
    return G_N_ELEMENTS(global_manuf_oui24_table) +
            G_N_ELEMENTS(global_manuf_oui28_table) +
            G_N_ELEMENTS(global_manuf_oui36_table);
}
