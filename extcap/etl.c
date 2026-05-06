/* etl.c
 *
 * Copyright 2020, Odysseus Yang
 *           2026, Gabriel Potter
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Reads an ETL file and writes out a pcap file with LINKTYPE_ETW.
 *
 * https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
 */

#include "config.h"
#define WS_LOG_DOMAIN "etwdump"

#include "etl.h"
#include "wsutil/ws_getopt.h"
#include "wsutil/strtoi.h"
#include "etw_message.h"
#include "etw_ndiscap.h"

#include <rpc.h>
#include <winevt.h>

#define MAX_PACKET_SIZE 0xFFFF
#define ADD_OFFSET_TO_POINTER(buffer, offset) (((PBYTE)buffer) + offset)
#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~(((int)(Pow2))-1)) )

extern int g_include_undecidable_event;
extern BOOL g_event_enable_sid;
extern BOOL g_event_enable_tsid;
extern BOOL g_event_enable_event_key;
extern BOOL g_event_enable_property_pstartkey;
extern BOOL g_event_enable_stack_trace;
extern BOOL g_event_enable_silos;
extern BOOL g_event_property_source_container_tracking;

//Microsoft-Windows-Wmbclass-Opn
const GUID mbb_provider = { 0xA42FE227, 0xA7BF, 0x4483, {0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96} };
// Microsoft-Windows-NDIS-PacketCapture
const GUID ndis_capture_provider = { 0x2ed6006e, 0x4729, 0x4609, 0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef };

EXTERN_C const GUID DECLSPEC_SELECTANY EventTraceGuid = { 0x68fdd900, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3} };
EXTERN_C const GUID DECLSPEC_SELECTANY ImageIdGuid = { 0xb3e675d7, 0x2554, 0x4f18, { 0x83, 0xb, 0x27, 0x62, 0x73, 0x25, 0x60, 0xde } };
EXTERN_C const GUID DECLSPEC_SELECTANY SystemConfigExGuid = { 0x9b79ee91, 0xb5fd, 0x41c0, { 0xa2, 0x43, 0x42, 0x48, 0xe2, 0x66, 0xe9, 0xd0 } };
EXTERN_C const GUID DECLSPEC_SELECTANY EventMetadataGuid = { 0xbbccf6c1, 0x6cd1, 0x48c4, {0x80, 0xff, 0x83, 0x94, 0x82, 0xe3, 0x76, 0x71 } };
EXTERN_C const GUID DECLSPEC_SELECTANY ZeroGuid = { 0 };

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        EVENT_HEADER                           |
 * .                             ...                               .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                     ETW_BUFFER_CONTEXT                        |
 * +-------------------------------+-------------------------------+
 * |      ExtendedDataCount        |           TlvCount            |
 * +-------------------------------+-------------------------------+
 * |                       PropertiesCount                         |
 * +---------------------------------------------------------------+
 * |                   Extended Data Headers                       |
 * .      EVENT_HEADER_EXTENDED_DATA_ITEM[ExtendedDataCount]       .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                         TLV Headers                           |
 * .                   WTAP_ETL_TLV[TlvCount]                      .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                       Property Headers                        |
 * .                   ETW_PROPERTY[PropertiesCount]               .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                             DATA                              |
 * .                              ..                               .
 * .                              ..                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 *                     ETL->Wireshark encapsulation
 */

enum ETL_TLV_TYPE {
    TLV_USER_DATA = 0,
    TLV_MESSAGE,
    TLV_PROVIDER_NAME,
};

#pragma pack(push, 1)
typedef struct _WTAP_ETL_TLV {
    enum ETL_TLV_TYPE Type;
    DWORD             Offset;
    DWORD             Length;
} WTAP_ETL_TLV;

typedef struct _WTAP_ETL_RECORD {
    EVENT_HEADER                    EventHeader;            // Event header
    ETW_BUFFER_CONTEXT              BufferContext;          // Buffer context
    USHORT                          ExtendedDataCount;
    USHORT                          TlvCount;
    DWORD                           PropertiesCount;
} WTAP_ETL_RECORD;

typedef struct _WTAP_ETW_PROPERTY
{
    DWORD Offset;
    USHORT KeyLength;
    USHORT ValueLength;
} ETW_PROPERTY;
#pragma pack(pop)

enum {
    OPT_PROVIDER,
    OPT_KEYWORD,
    OPT_LEVEL,
};

static const struct ws_option longopts[] = {
    { "p", ws_required_argument, NULL, OPT_PROVIDER},
    { "k", ws_required_argument, NULL, OPT_KEYWORD},
    { "l", ws_required_argument, NULL, OPT_LEVEL},
    { 0, 0, 0, 0 }
};

typedef struct _PROVIDER_FILTER {
    GUID ProviderId;
    ULONG64 Keyword;
    UCHAR Level;
} PROVIDER_FILTER;

char g_err_info[FILENAME_MAX];
int g_err = ERROR_SUCCESS;
static wtap_dumper* g_pdh;
extern ULONGLONG g_num_events;
static PROVIDER_FILTER g_provider_filters[32];
static BOOL g_is_live_session;

static void WINAPI event_callback(PEVENT_RECORD ev);
static void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info);

static DWORD GetPropertyValue(WCHAR* ProviderId, EVT_PUBLISHER_METADATA_PROPERTY_ID PropertyId, PEVT_VARIANT* Value)
{
    BOOL bRet;
    DWORD err = ERROR_SUCCESS;
    PEVT_VARIANT value = NULL;
    DWORD bufSize = 0;
    DWORD bufUsedOrReqd = 0;

    EVT_HANDLE pubHandle = EvtOpenPublisherMetadata(NULL, ProviderId, NULL, GetThreadLocale(), 0);
    if (pubHandle == NULL)
    {
        return GetLastError();
    }

    /*
     * Get required size for property
     */
    bRet = EvtGetPublisherMetadataProperty(
        pubHandle,
        PropertyId,
        0,
        bufSize,
        value,
        &bufUsedOrReqd);

    if (!bRet && ((err = GetLastError()) != ERROR_INSUFFICIENT_BUFFER))
    {
        return err;
    }
    else if (bRet) /* Didn't expect this to succeed */
    {
        return ERROR_INVALID_STATE;
    }

    value = (PEVT_VARIANT)g_malloc(bufUsedOrReqd);
    if (!value)
    {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    bufSize = bufUsedOrReqd;

    /*
     * Get the property value
     */
    bRet = EvtGetPublisherMetadataProperty(
        pubHandle,
        PropertyId,
        0,
        bufSize,
        value,
        &bufUsedOrReqd);
    if (!bRet)
    {
        g_free(value);
        return GetLastError();
    }

    *Value = value;
    return ERROR_SUCCESS;
}

wtap_open_return_val etw_dump(const char* etl_filename, const char* pcapng_filename, const char* params, int* err, char** err_info)
{
    EVENT_TRACE_LOGFILE log_file = { 0 };
    WCHAR w_etl_filename[FILENAME_MAX] = { 0 };
    wtap_open_return_val returnVal = WTAP_OPEN_MINE;

    SUPER_EVENT_TRACE_PROPERTIES super_trace_properties = { 0 };
    super_trace_properties.prop.Wnode.BufferSize = sizeof(SUPER_EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.Wnode.ClientContext = 2; // "System" Clock Type
    super_trace_properties.prop.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    super_trace_properties.prop.BufferSize = 200;  // 200KB (like traceview)
    super_trace_properties.prop.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    TRACEHANDLE traceControllerHandle = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    TRACEHANDLE trace_handle = INVALID_PROCESSTRACE_HANDLE;

    ENABLE_TRACE_PARAMETERS trace_params;
    trace_params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    trace_params.EnableProperty = 0;
    trace_params.ControlFlags = 0;
    trace_params.EnableFilterDesc = NULL;
    trace_params.FilterDescCount = 0;
    if (g_event_enable_sid)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_SID;
    }
    if (g_event_enable_property_pstartkey)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;
    }
    if (g_event_enable_event_key)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_EVENT_KEY;
    }
    if (g_event_enable_tsid)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_TS_ID;
    }
    if (g_event_enable_stack_trace)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
    }
    if (g_event_enable_silos)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_ENABLE_SILOS;
    }
    if (g_event_property_source_container_tracking)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING;
    }

    SecureZeroMemory(g_provider_filters, sizeof(g_provider_filters));
    SecureZeroMemory(g_err_info, FILENAME_MAX);
    g_err = ERROR_SUCCESS;
    g_num_events = 0;
    g_is_live_session = false;

    if (params)
    {
        int opt_result = 0;
        int option_idx = 0;
        int provider_idx = 0;
        char** params_array = NULL;
        int params_array_num = 0;
        char* endptr = NULL;
        char* endptr_exp = NULL;
        WCHAR provider_id[FILENAME_MAX] = { 0 };
        ULONG convert_level = 0;
        ULONG64 keyword = 0;

        params_array = g_strsplit(params, " ", -1);
        while (params_array[params_array_num])
        {
            params_array_num++;
        }

        ws_optind = 0;
        while ((opt_result = ws_getopt_long(params_array_num, params_array, ":", longopts, &option_idx)) != -1) {
            switch (opt_result) {
            case OPT_PROVIDER:
                mbstowcs(provider_id, ws_optarg, FILENAME_MAX);
                if (UuidFromString(provider_id, &g_provider_filters[provider_idx].ProviderId) == RPC_S_INVALID_STRING_UUID)
                {
                    PEVT_VARIANT value = NULL;

                    *err = GetPropertyValue(
                        provider_id,
                        EvtPublisherMetadataPublisherGuid,
                        &value);

                    /*
                     * Copy returned GUID locally
                     */
                    if (*err == ERROR_SUCCESS)
                    {
                        if (value->Type == EvtVarTypeGuid && value->GuidVal)
                        {
                            g_provider_filters[provider_idx].ProviderId = *(value->GuidVal);
                            /*
                             * Set default logging values (same as traceview.exe)
                             */
                            g_provider_filters[provider_idx].Keyword = 0xffffffffffffffffL;  // ANY
                            g_provider_filters[provider_idx].Level = 5;  // ALL
                        }
                        else
                        {
                            *err = ERROR_INVALID_DATA;
                        }
                    }
                    else
                    {
                        *err_info = ws_strdup_printf("Cannot convert provider %s to a GUID, err is 0x%x", ws_optarg, *err);
                        return WTAP_OPEN_ERROR;
                    }

                    g_free(value);
                }

                if (IsEqualGUID(&g_provider_filters[0].ProviderId, &ZeroGuid))
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Provider %s is zero, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                provider_idx++;
                break;
            case OPT_KEYWORD:
                endptr = ws_optarg + strlen(ws_optarg);
                endptr_exp = endptr;
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-k parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                keyword = _strtoui64(ws_optarg, &endptr, 0);
                if (endptr != endptr_exp)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Keyword %s cannot be converted, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }

                g_provider_filters[provider_idx - 1].Keyword = keyword;
                break;
            case OPT_LEVEL:
                endptr = ws_optarg + strlen(ws_optarg);
                endptr_exp = endptr;
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-l parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                convert_level = strtoul(ws_optarg, &endptr, 0);
                if (convert_level > UCHAR_MAX)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Level %s is bigger than 0xff, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                if (endptr != endptr_exp)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Level %s cannot be converted, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }

                g_provider_filters[provider_idx - 1].Level = (UCHAR)convert_level;
                break;
            }
        }
        g_strfreev(params_array);
    }

    /* do/while(false) is used to jump out of loop so no complex nested if/else is needed */
    do
    {
        /* Read ETW from an etl file */
        if (etl_filename)
        {
            mbstowcs(w_etl_filename, etl_filename, FILENAME_MAX);

            log_file.LogFileName = w_etl_filename;
            log_file.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.EventRecordCallback = event_callback;
            log_file.Context = NULL;
        }
        else
        {
            /*
             * Try the best to stop the leftover session since extcap has no way to cleanup when stop capturing. See issue
             * https://gitlab.com/wireshark/wireshark/-/issues/17131
             */
            ControlTrace((TRACEHANDLE)NULL, LOGGER_NAME, &super_trace_properties.prop, EVENT_TRACE_CONTROL_STOP);

            g_is_live_session = true;

            log_file.LoggerName = LOGGER_NAME;
            log_file.LogFileName = NULL;
            log_file.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.EventRecordCallback = event_callback;
            log_file.BufferCallback = NULL;
            log_file.Context = NULL;

            *err = StartTrace(
                &traceControllerHandle,
                log_file.LoggerName,
                &super_trace_properties.prop);
            if (*err != ERROR_SUCCESS)
            {
                *err_info = ws_strdup_printf("StartTrace failed with 0x%x", *err);
                returnVal = WTAP_OPEN_ERROR;
                break;
            }

            for (int i = 0; i < ARRAYSIZE(g_provider_filters); i++)
            {
                if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ZeroGuid))
                {
                    break;
                }
                *err = EnableTraceEx2(
                    traceControllerHandle,
                    &g_provider_filters[i].ProviderId,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    g_provider_filters[i].Level,
                    g_provider_filters[i].Keyword,
                    0,
                    0,
                    &trace_params);
                if (*err != ERROR_SUCCESS)
                {
                    *err_info = ws_strdup_printf("EnableTraceEx failed with 0x%x", *err);
                    returnVal = WTAP_OPEN_ERROR;
                    break;
                }
            }
        }

        trace_handle = OpenTrace(&log_file);
        if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
            *err = GetLastError();
            *err_info = ws_strdup_printf("OpenTrace failed with 0x%x", *err);
            returnVal = WTAP_OPEN_NOT_MINE;
            break;
        }

        g_pdh = etw_dump_open(pcapng_filename, err, err_info);
        if (g_pdh == NULL)
        {
            returnVal = WTAP_OPEN_ERROR;
            break;
        }

        *err = ProcessTrace(&trace_handle, 1, 0, 0);
        if (*err != ERROR_SUCCESS) {
            returnVal = WTAP_OPEN_ERROR;
            *err_info = ws_strdup_printf("ProcessTrace failed with 0x%x", *err);
            break;
        }

        if (g_err != ERROR_SUCCESS)
        {
            *err = g_err;
            *err_info = g_strdup(g_err_info);
            returnVal = WTAP_OPEN_ERROR;
            break;
        }

        if (!g_num_events) {
            *err = ERROR_NO_DATA;
            *err_info = ws_strdup_printf("Didn't find any etw event");
            returnVal = WTAP_OPEN_NOT_MINE;
            break;
        }
    } while (false);

    if (trace_handle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(trace_handle);
    }
    if (g_pdh != NULL)
    {
        if (*err == ERROR_SUCCESS)
        {
            if (!wtap_dump_close(g_pdh, NULL, err, err_info))
            {
                returnVal = WTAP_OPEN_ERROR;
            }
        }
        else
        {
            int err_ignore;
            char* err_info_ignore = NULL;
            if (!wtap_dump_close(g_pdh, NULL, &err_ignore, &err_info_ignore))
            {
                returnVal = WTAP_OPEN_ERROR;
                g_free(err_info_ignore);
            }
        }
    }
    return returnVal;
}

static BOOL is_event_filtered_out(PEVENT_RECORD ev)
{
    if (g_is_live_session)
    {
        return false;
    }

    if (IsEqualGUID(&g_provider_filters[0].ProviderId, &ZeroGuid))
    {
        return false;
    }

    for (int i = 0; i < ARRAYSIZE(g_provider_filters); i++)
    {
        if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ev->EventHeader.ProviderId))
        {
            return false;
        }
        if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ZeroGuid))
        {
            break;
        }
    }

    return true;
}

static void WINAPI event_callback(PEVENT_RECORD ev)
{
    ULARGE_INTEGER timestamp;
    g_num_events++;

    if (is_event_filtered_out(ev))
    {
        return;
    }

    /*
    * 100ns since 1/1/1601 -> usec since 1/1/1970.
    * The offset of 11644473600 seconds can be calculated with a couple of calls to SystemTimeToFileTime.
    */
    timestamp.QuadPart = (ev->EventHeader.TimeStamp.QuadPart / 10) - 11644473600000000ll;

    /* Write OPN events that needs mbim sub dissector */
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &mbb_provider))
    {
        etw_dump_write_opn_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &ndis_capture_provider))
    {
        etw_dump_write_ndiscap_event(ev, timestamp);
    }
    /* Write any event form other providers other than above */
    else
    {
        etw_dump_write_general_event(ev, timestamp);
    }
}

static wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info)
{
    wtap_dump_params params = { 0 };
    GArray* shb_hdrs = NULL;
    wtap_block_t shb_hdr;
    wtapng_iface_descriptions_t* idb_info;
    GArray* idb_datas;
    wtap_block_t idb_data;
    wtapng_if_descr_mandatory_t* descr_mand;

    wtap_dumper* pdh = NULL;

    shb_hdrs = g_array_new(false, false, sizeof(wtap_block_t));
    shb_hdr = wtap_block_create(WTAP_BLOCK_SECTION);
    g_array_append_val(shb_hdrs, shb_hdr);

    /* In the future, may create multiple WTAP_BLOCK_IF_ID_AND_INFO separately for IP packet */
    idb_info = g_new(wtapng_iface_descriptions_t, 1);
    if (idb_info == NULL)
        return NULL;
    idb_datas = g_array_new(false, false, sizeof(wtap_block_t));
    idb_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb_data);
    descr_mand->tsprecision = WTAP_TSPREC_USEC;
    descr_mand->wtap_encap = WTAP_ENCAP_ETW;
    /* Timestamp for each pcapng packet is usec units, so time_units_per_second need be set to 10^6 */
    descr_mand->time_units_per_second = G_USEC_PER_SEC;
    g_array_append_val(idb_datas, idb_data);
    idb_info->interface_data = idb_datas;

    params.encap = WTAP_ENCAP_ETW;
    params.snaplen = 0;
    params.tsprec = WTAP_TSPREC_USEC;
    params.shb_hdrs = shb_hdrs;
    params.idb_inf = idb_info;

    pdh = wtap_dump_open(pcapng_filename, wtap_pcapng_file_type_subtype(), WS_FILE_UNCOMPRESSED, &params, err, err_info);

    if (shb_hdrs)
    {
        wtap_block_array_free(shb_hdrs);
    }
    if (params.idb_inf)
    {
        if (params.idb_inf->interface_data)
        {
            wtap_block_array_free(params.idb_inf->interface_data);
        }
        g_free(params.idb_inf);
        params.idb_inf = NULL;
    }

    return pdh;
}

static ULONG wtap_etl_record_buffer_init(WTAP_ETL_RECORD** out_etl_record, PEVENT_RECORD ev, BOOLEAN include_user_data, const WCHAR* message, const WCHAR* provider_name, PROPERTY_KEY_VALUE* properties, DWORD properties_count)
{
    // See the top of this file for the file format

    // We use TLVs so that this format can be extended without breaking backwards compatibility
    WTAP_ETL_TLV tlvs[3];
    SecureZeroMemory(tlvs, sizeof(tlvs));
    USHORT tlv_count = 0;

    // Used while building
    ULONG hdr_offset = sizeof(WTAP_ETL_RECORD);
    ULONG data_offset = (
        sizeof(WTAP_ETL_RECORD) +
        sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * ev->ExtendedDataCount +
        sizeof(tlvs) +
        sizeof(ETW_PROPERTY) * properties_count);

    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG extended_data_offset = 0;
    ULONG properties_offset = 0;
    ULONG tlvs_offset = 0;
    char** extended_data_ptrs = NULL;
    ULONG* properties_offsets = NULL;
    ETW_PROPERTY prop = { 0, 0 };

    // Extended Data
    if (ev->ExtendedDataCount != 0)
    {
        extended_data_offset = hdr_offset;
        extended_data_ptrs = g_malloc(sizeof(char*) * ev->ExtendedDataCount);
        USHORT extended_data_length = 0;
        for (USHORT i = 0; i < ev->ExtendedDataCount; i++)
        {
            // It doesn't make sense to send the pointer, so we swap it for
            // the offset to display to the client.
            extended_data_ptrs[i] = ((char*)ev->ExtendedData[i].DataPtr);
            ev->ExtendedData[i].DataPtr = data_offset + extended_data_length;
            extended_data_length += ev->ExtendedData[i].DataSize;
        }
        data_offset += ROUND_UP_COUNT(extended_data_length, sizeof(LONG));
        hdr_offset += sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * ev->ExtendedDataCount;
    }

    // TLVs
    tlvs_offset = hdr_offset;
    if (include_user_data)
    {
        USHORT user_data_length;
        if (ev->UserDataLength < MAX_PACKET_SIZE)
        {
            user_data_length = ev->UserDataLength;
        }
        else
        {
            user_data_length = MAX_PACKET_SIZE;
        }
        tlvs[tlv_count].Type = TLV_USER_DATA;
        tlvs[tlv_count].Offset = data_offset;
        tlvs[tlv_count].Length = user_data_length;
        data_offset += ROUND_UP_COUNT(user_data_length, sizeof(LONG));
        tlv_count++;
    }
    if (message && message[0] != L'\0')
    {
        ULONG message_length = (ULONG)((wcslen(message) + 1) * sizeof(WCHAR));
        tlvs[tlv_count].Type = TLV_MESSAGE;
        tlvs[tlv_count].Offset = data_offset;
        tlvs[tlv_count].Length = message_length;
        data_offset += ROUND_UP_COUNT(message_length, sizeof(LONG));
        tlv_count++;
    }
    if (provider_name && provider_name[0] != L'\0')
    {
        ULONG provider_name_length = (ULONG)((wcslen(provider_name) + 1) * sizeof(WCHAR));
        tlvs[tlv_count].Type = TLV_PROVIDER_NAME;
        tlvs[tlv_count].Offset = data_offset;
        tlvs[tlv_count].Length = provider_name_length;
        data_offset += ROUND_UP_COUNT(provider_name_length, sizeof(LONG));
        tlv_count++;
    }
    hdr_offset += sizeof(WTAP_ETL_TLV) * tlv_count;

    // Properties
    if (properties_count != 0)
    {
        properties_offset = hdr_offset;
        properties_offsets = g_malloc(sizeof(ULONG) * properties_count);
        ULONG properties_length = 0;
        for (DWORD i = 0; i < properties_count; i++)
        {
            properties_offsets[i] = data_offset + properties_length;
            properties_length += properties[i].key_length + properties[i].value_length;
        }
        data_offset += ROUND_UP_COUNT(properties_length, sizeof(LONG));
        hdr_offset += sizeof(ETW_PROPERTY) * properties_count;
    }

    (void)hdr_offset;

    // Start building the actual payload
    etl_record = g_malloc(data_offset);
    SecureZeroMemory(etl_record, data_offset);
    etl_record->EventHeader = ev->EventHeader;
    etl_record->BufferContext = ev->BufferContext;
    etl_record->ExtendedDataCount = ev->ExtendedDataCount;
    etl_record->PropertiesCount = properties_count;
    etl_record->TlvCount = tlv_count;

    if (extended_data_ptrs != NULL)
    {
        for (USHORT i = 0; i < ev->ExtendedDataCount; i++)
        {
            // Copy eData header
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, extended_data_offset + sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * i),
                (void*) &ev->ExtendedData[i],
                sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM));
            // Copy eData data
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, ev->ExtendedData[i].DataPtr),
                extended_data_ptrs[i],
                ev->ExtendedData[i].DataSize);
        }

        g_free(extended_data_ptrs);
    }

    for (USHORT i = 0; i < etl_record->TlvCount; i++)
    {
        WTAP_ETL_TLV* tlv = &tlvs[i];

        // Copy TLV header
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlvs_offset + sizeof(WTAP_ETL_TLV) * i),
               tlv,
               sizeof(WTAP_ETL_TLV));

        // Copy TLV data
        if (tlv->Type == TLV_MESSAGE)
        {
            memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlv->Offset), message, tlv->Length);
        }
        else if (tlv->Type == TLV_PROVIDER_NAME)
        {
            memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlv->Offset), provider_name, tlv->Length);
        }
        else if (tlv->Type == TLV_USER_DATA)
        {
            memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlv->Offset), ev->UserData, tlv->Length);
        }
    }

    if (properties_count != 0)
    {
        for (USHORT i = 0; i < properties_count; i++)
        {
            prop.KeyLength = properties[i].key_length;
            prop.ValueLength = properties[i].value_length;
            prop.Offset = properties_offsets[i];
            // Copy property header
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offset + sizeof(ETW_PROPERTY) * i),
                (void*)&prop,
                sizeof(ETW_PROPERTY));
            // Copy property key and value data
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offsets[i]),
                properties[i].key,
                properties[i].key_length);
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offsets[i] + properties[i].key_length),
                properties[i].value,
                properties[i].value_length);
        }

        g_free(properties_offsets);
    }

    *out_etl_record = etl_record;
    return data_offset;
}

void wtap_etl_add_interface(int pkt_encap, const char* interface_name, unsigned short interface_name_length, const char* interface_desc, unsigned short interface_desc_length)
{
    wtap_block_t idb_data;
    wtapng_if_descr_mandatory_t* descr_mand;
    char* err_info;
    int err;

    idb_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb_data);
    descr_mand->wtap_encap = pkt_encap;
    descr_mand->tsprecision = WTAP_TSPREC_USEC;
    /* Timestamp for each pcapng packet is usec units, so time_units_per_second need be set to 10^6 */
    descr_mand->time_units_per_second = G_USEC_PER_SEC;
    if (interface_name_length) {
        wtap_block_add_string_option(idb_data, OPT_IDB_NAME, interface_name, interface_name_length);
    }
    if (interface_desc_length) {
        wtap_block_add_string_option(idb_data, OPT_IDB_DESCRIPTION, interface_desc, interface_desc_length);
    }
    if(!wtap_dump_add_idb(g_pdh, idb_data, &err, &err_info)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, %s", err_info);
        g_free(err_info);
    }
}

void wtap_etl_rec_dump(char* etl_record, ULONG total_packet_length, ULONG original_packet_length, unsigned int interface_id, BOOLEAN is_inbound, ULARGE_INTEGER timestamp, int pkt_encap, char* comment, unsigned short comment_length)
{
    char* err_info;
    int err;
    wtap_rec rec = { 0 };

    wtap_rec_init(&rec, 2048); // Appropriate size?
    wtap_setup_packet_rec(&rec, pkt_encap);
    rec.rec_header.packet_header.caplen = total_packet_length;
    rec.rec_header.packet_header.len = original_packet_length;
    rec.rec_header.packet_header.interface_id = interface_id;
    rec.presence_flags = WTAP_HAS_INTERFACE_ID;
    rec.block = wtap_block_create(WTAP_BLOCK_PACKET);
    wtap_block_add_uint32_option(rec.block, OPT_PKT_FLAGS, is_inbound ? PACK_FLAGS_DIRECTION_INBOUND : PACK_FLAGS_DIRECTION_OUTBOUND);
    if (comment_length) {
        wtap_block_add_string_option(rec.block, OPT_COMMENT, comment, comment_length);
    }
    /* Convert usec of the timestamp into nstime_t */
    rec.ts.secs = (time_t)(timestamp.QuadPart / G_USEC_PER_SEC);
    rec.ts.nsecs = (int)(((timestamp.QuadPart % G_USEC_PER_SEC) * G_NSEC_PER_SEC) / G_USEC_PER_SEC);

    /* and save the packet */
    ws_buffer_append(&rec.data, (uint8_t*)etl_record, total_packet_length);

    if (!wtap_dump(g_pdh, &rec, &err, &err_info)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, %s", err_info);
        g_free(err_info);
    }

    /* Only flush when live session */
    if (g_is_live_session && !wtap_dump_flush(g_pdh, &err)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, 0x%x", err);
    }
    wtap_rec_cleanup(&rec);
}

static void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    BOOLEAN is_inbound = false;
    /* 0x80000000 mask the function to host message */
    is_inbound = ((*(INT32*)(ev->UserData)) & 0x80000000) ? true : false;
    total_packet_length = wtap_etl_record_buffer_init(&etl_record, ev, true, NULL, NULL, NULL, 0);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, is_inbound, timestamp, WTAP_ENCAP_ETW, NULL, 0);
    g_free(etl_record);
}

static void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    PTRACE_EVENT_INFO pInfo = NULL;
    PBYTE pUserData = NULL;
    PBYTE pEndOfUserData = NULL;
    DWORD PointerSize = 0;
    PROPERTY_KEY_VALUE* prop_arr = NULL;
    DWORD dwTopLevelPropertyCount = 0;
    DWORD dwSizeofArray = 0;
    WCHAR* wszProviderName = NULL;
    WCHAR* wszMessage = NULL;
    bool include_user_data = false;

    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;

    /* Skip EventTrace events */
    if (ev->EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER &&
        IsEqualGUID(&ev->EventHeader.ProviderId, &EventTraceGuid))
    {
        /*
        * The first event in every ETL file contains the data from the file header.
        * This is the same data as was returned in the EVENT_TRACE_LOGFILEW by
        * OpenTrace. Since we've already seen this information, we'll skip this
        * event.
        */
        goto end;
    }

    /* Skip events injected by the XPerf tracemerger - they will never be decodable */
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &ImageIdGuid) ||
        IsEqualGUID(&ev->EventHeader.ProviderId, &SystemConfigExGuid) ||
        IsEqualGUID(&ev->EventHeader.ProviderId, &EventMetadataGuid))
    {
        goto end;
    }

    if (!get_event_information(ev, &pInfo))
    {
        goto end;
    }

    if (pInfo->ProviderNameOffset > 0)
    {
        wszProviderName = (WCHAR*)ADD_OFFSET_TO_POINTER(pInfo, pInfo->ProviderNameOffset);
    }

    if (EVENT_HEADER_FLAG_32_BIT_HEADER == (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
    {
        PointerSize = 4;
    }
    else
    {
        PointerSize = 8;
    }

    pUserData = (PBYTE)ev->UserData;
    pEndOfUserData = (PBYTE)ev->UserData + ev->UserDataLength;

    dwTopLevelPropertyCount = pInfo->TopLevelPropertyCount;
    if (dwTopLevelPropertyCount > 0)
    {
        prop_arr = g_malloc(sizeof(PROPERTY_KEY_VALUE) * dwTopLevelPropertyCount);
        dwSizeofArray = dwTopLevelPropertyCount * sizeof(PROPERTY_KEY_VALUE);
        SecureZeroMemory(prop_arr, dwSizeofArray);
    }

    // Events we don't have a manifest for will have an empty format message
    if (pInfo->EventMessageOffset > 0)
    {
        wszMessage = (LPWSTR)ADD_OFFSET_TO_POINTER(pInfo, pInfo->EventMessageOffset);
    }

    for (USHORT i = 0; i < dwTopLevelPropertyCount; i++)
    {
        pUserData = extract_property(ev, pInfo, PointerSize, i, pUserData, pEndOfUserData, &prop_arr[i]);
        if (NULL == pUserData)
        {
            break;
        }
    }

    if (dwTopLevelPropertyCount == 0 && wszMessage == NULL)
    {
        // We didn't have the manifest / tmh, and we have nothing interesting to show.
        // Skip if "undecidable" isn't checked
        if (!g_include_undecidable_event)
        {
            goto end;
        }

        // If we're asked to include "undecidable", the only thing we can provide is the
        // raw user data.
        include_user_data = true;
    }

    // Dump event
    total_packet_length = wtap_etl_record_buffer_init(&etl_record, ev, include_user_data, wszMessage, wszProviderName, prop_arr, dwTopLevelPropertyCount);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, false, timestamp, WTAP_ENCAP_ETW, NULL, 0);
    g_free(etl_record);

end:
    if (NULL != prop_arr)
    {
        g_free(prop_arr);
        prop_arr = NULL;
    }
    if (NULL != pInfo)
    {
        g_free(pInfo);
        pInfo = NULL;
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
