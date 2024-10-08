/* packet-hencsat.c
 * Routines for the HENCSAT protocols
 * https://www.simula.no/research/projects/hencsat-network-coding-protocols-satellite-terminals-multiple-logical-paths
 *
 * Copyright 2019 by Thomas Dreibholz <dreibh [AT] simula.no>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>


struct NECTORSliceHeader
{
   uint8_t nsh_type;                           // Type
   uint8_t nsh_flags;                          // Flags (currently unused)
   uint16_t nsh_chunk_id;                      // Chunk ID to differentiate slices of different chunks
};


#define NSHT_UNCODED        0x01
#define NSHT_CODED          0x02

struct NECTORUncodedSliceHeader
{
   struct NECTORSliceHeader nush_slice_header; // Common header
   uint16_t                 nush_index;        // Index of slice in chunk
   char                     nush_payload[];    // The slice data
};


struct NECTORCodedSliceHeader
{
   struct NECTORSliceHeader ncsh_slice_header; // Common header
   uint16_t                 ncsh_index;        // Index of slice in chunk (for debug)
   char                     ncsh_payload[];    // The chunk data
};


void proto_register_nector(void);
void proto_reg_handoff_nector(void);

/* Initialize the protocol and registered fields */
static int proto_nector_data    = -1;
static int proto_nector_control = -1;

/* NECTOR Data (binary NECTOR Slice format as defined above) */
static int hf_nsh_type          = -1;
static int hf_nsh_flags         = -1;
static int hf_nsh_chunk_id      = -1;
static int hf_nush_index        = -1;
static int hf_nush_payload      = -1;
static int hf_ncsh_index        = -1;
static int hf_ncsh_payload      = -1;

/* NECTOR Control (length + XML message) */
static int hf_length            = -1;
static int hf_type              = -1;

/* Initialize the subtree pointers */
static int ett_nector_data     = -1;
static int ett_nector_control  = -1;
static int ett_xml             = -1;

/* Reference to XML dissector */
static dissector_handle_t xml_handle;

/* Dissectors for messages. This is specific to ScriptingServiceProtocol */
#define NSH_TYPE_LENGTH         1
#define NSH_FLAGS_LENGTH        1
#define NSH_CHUNK_ID_LENGTH     2
#define NUSH_INDEX_LENGTH       2
#define NCSH_INDEX_LENGTH       2

#define NSH_TYPE_OFFSET         0
#define NSH_FLAGS_OFFSET        (NSH_TYPE_OFFSET     + NSH_TYPE_LENGTH)
#define NSH_CHUNK_ID_OFFSET     (NSH_FLAGS_OFFSET    + NSH_FLAGS_LENGTH)
#define NUSH_INDEX_OFFSET       (NSH_CHUNK_ID_OFFSET + NSH_CHUNK_ID_LENGTH)
#define NUSH_PAYLOAD_OFFSET     (NUSH_INDEX_OFFSET   + NUSH_INDEX_LENGTH)
#define NCSH_INDEX_OFFSET       (NSH_CHUNK_ID_OFFSET + NSH_CHUNK_ID_LENGTH)
#define NCSH_PAYLOAD_OFFSET     (NCSH_INDEX_OFFSET   + NCSH_INDEX_LENGTH)

#define NCTRL_LENGTH_LENGTH     4

#define NCTRL_LENGTH_OFFSET     0
#define NCTRL_MESSAGE_OFFSET    (NCTRL_LENGTH_OFFSET + NCTRL_LENGTH_LENGTH)



static const value_string nsh_type_values[] = {
  { NSHT_UNCODED, "Uncoded Slice" },
  { NSHT_CODED,   "Coded Slice"   },
  { 0,            NULL            }
};


static uint32_t
dissect_nector_data_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *nector_tree)
{
  uint32_t total_length;

  const uint8_t type = tvb_get_uint8(message_tvb, NSH_TYPE_OFFSET);

  proto_tree_add_item(nector_tree, hf_nsh_type, message_tvb, NSH_TYPE_OFFSET, NSH_TYPE_LENGTH, ENC_BIG_ENDIAN);
  /*flags_item = */ proto_tree_add_item(nector_tree, hf_nsh_flags,  message_tvb, NSH_FLAGS_OFFSET, NSH_FLAGS_LENGTH,  ENC_BIG_ENDIAN);
  const uint16_t nsh_chunk_id = tvb_get_ntohs(message_tvb, NSH_CHUNK_ID_OFFSET);
  proto_tree_add_item(nector_tree, hf_nsh_chunk_id, message_tvb, NSH_CHUNK_ID_OFFSET, NSH_CHUNK_ID_LENGTH, ENC_BIG_ENDIAN);
  total_length = NSH_CHUNK_ID_OFFSET + NSH_CHUNK_ID_LENGTH;

  switch (type) {
    case NSHT_UNCODED: {
        proto_tree_add_item(nector_tree, hf_nush_index, message_tvb, NUSH_INDEX_OFFSET, NUSH_INDEX_LENGTH, ENC_BIG_ENDIAN);
        const uint16_t nush_index = tvb_get_ntohs(message_tvb, NUSH_INDEX_OFFSET);
        total_length += NUSH_INDEX_LENGTH;
        if(tvb_captured_length(message_tvb) > NUSH_PAYLOAD_OFFSET) {
          const uint16_t payload_length = tvb_captured_length(message_tvb) - NUSH_PAYLOAD_OFFSET;
          proto_tree_add_item(nector_tree, hf_nush_payload, message_tvb, NUSH_PAYLOAD_OFFSET, payload_length, ENC_BIG_ENDIAN);
          total_length += payload_length;
          col_add_fstr(pinfo->cinfo, COL_INFO, "Uncoded Slice #%u of Chunk #%u: %u B payload",
                       nush_index, nsh_chunk_id, payload_length);
        }
      }
      break;
    case NSHT_CODED: {
        proto_tree_add_item(nector_tree, hf_ncsh_index, message_tvb, NCSH_INDEX_OFFSET, NCSH_INDEX_LENGTH, ENC_BIG_ENDIAN);
        const uint16_t ncsh_index = tvb_get_ntohs(message_tvb, NCSH_INDEX_OFFSET);
        total_length += NCSH_INDEX_LENGTH;
        if(tvb_captured_length(message_tvb) > NCSH_PAYLOAD_OFFSET) {
          const uint16_t payload_length = tvb_captured_length(message_tvb) - NCSH_PAYLOAD_OFFSET;
          proto_tree_add_item(nector_tree, hf_ncsh_payload, message_tvb, NCSH_PAYLOAD_OFFSET, payload_length, ENC_BIG_ENDIAN);
          total_length += payload_length;
          col_add_fstr(pinfo->cinfo, COL_INFO, "Coded Slice #%u of Chunk #%u: %u B payload",
                       ncsh_index, nsh_chunk_id, payload_length);
        }
      }
      break;
    default:
      break;
  }

  return total_length;
}


static uint32_t
dissect_nector_control_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *nector_tree)
{
  const uint32_t xml_length = tvb_get_uint32(message_tvb, NCTRL_LENGTH_OFFSET, ENC_BIG_ENDIAN);

  char* xml = (char*)tvb_get_string_enc(wmem_packet_scope(), message_tvb, NCTRL_MESSAGE_OFFSET, MIN(64, xml_length), ENC_ASCII|ENC_NA);
  char type[64];
  if(sscanf(xml, "<%62s ", (char*)&type) == 1) {
     proto_tree_add_item(nector_tree, hf_type, message_tvb, NCTRL_MESSAGE_OFFSET + 1, strlen(type), ENC_BIG_ENDIAN);
     col_add_fstr(pinfo->cinfo, COL_INFO, "%s", type);
  }
  proto_tree_add_item(nector_tree, hf_length, message_tvb, NCTRL_LENGTH_OFFSET, NCTRL_LENGTH_LENGTH, ENC_BIG_ENDIAN);

  int proto_xml = dissector_handle_get_protocol_index(xml_handle);
  if (proto_is_protocol_enabled(find_protocol_by_id(proto_xml))) {
    tvbuff_t* xml_tvb = tvb_new_subset_remaining(message_tvb, NCTRL_MESSAGE_OFFSET);
    call_dissector_with_data(xml_handle, xml_tvb, pinfo, nector_tree, NULL);

    // proto_item* xml_item = proto_tree_add_item(nector_tree, hf_message, xml_tvb, 0, -1, ENC_NA);
    // proto_tree* xml_tree = proto_item_add_subtree(xml_item, ett_xml);
    // call_dissector_with_data(xml_handle, xml_tvb, pinfo, xml_tree, NULL);
  }

  return NCTRL_MESSAGE_OFFSET + xml_length;
}


static int
dissect_nector_data(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item* nector_item;
  proto_tree* nector_tree;

  if (tvb_reported_length(message_tvb) < (NSH_CHUNK_ID_OFFSET + NSH_CHUNK_ID_LENGTH))
    return(0);
  const uint8_t type = tvb_get_uint8(message_tvb, NSH_TYPE_OFFSET);
  if ((type != NSHT_UNCODED) && (type != NSHT_CODED))
    return(0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NECTOR Data");
  // col_set_str(pinfo->cinfo, COL_PROTOCOL, val_to_str_const(type, nsh_type_values, "Unknown Slice Type"));

  /* Create the NECTOR protocol tree */
  nector_item = proto_tree_add_item(tree, proto_nector_data, message_tvb, 0, -1, ENC_NA);
  nector_tree = proto_item_add_subtree(nector_item, ett_nector_data);

  /* Dissect the message */
  return dissect_nector_data_message(message_tvb, pinfo, nector_tree);
}


static bool
dissect_nector_data_heur(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   return dissect_nector_data(message_tvb, pinfo, tree, data) > 0;
}


static int
dissect_nector_control(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item* nector_item;
  proto_tree* nector_tree;

  if (tvb_reported_length(message_tvb) < 4)
    return(0);
  const uint32_t xml_length = tvb_get_uint32(message_tvb, 0, ENC_BIG_ENDIAN);
  if ((xml_length < 8) || (xml_length > 65536))
    return(0);
  if (tvb_get_uint8(message_tvb, NCTRL_MESSAGE_OFFSET) != (uint8_t)'<')
    return(0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NECTOR Control");

  /* Create the NECTOR protocol tree */
  nector_item = proto_tree_add_item(tree, proto_nector_control, message_tvb, 0, -1, ENC_NA);
  nector_tree = proto_item_add_subtree(nector_item, ett_nector_control);

  /* Dissect the message */
  return dissect_nector_control_message(message_tvb, pinfo, nector_tree);
}


static bool
dissect_nector_control_heur(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   return dissect_nector_control(message_tvb, pinfo, tree, data) > 0;
}


/* Register the protocol */
void
proto_register_nector(void)
{
  /* Setup list of header fields */
  static hf_register_info hf_nector_data[] = {
    { &hf_nsh_type,      { "Type",                "nector-data.nsh_type",     FT_UINT8,  BASE_DEC,  VALS(nsh_type_values),  0x0, NULL, HFILL } },
    { &hf_nsh_flags,     { "Flags",               "nector-data.nsh_flags",    FT_UINT8,  BASE_DEC,  NULL,                   0x0, NULL, HFILL } },
    { &hf_nsh_chunk_id,  { "Chunk ID",            "nector-data.nsh_chunk_id", FT_UINT16, BASE_DEC,  NULL,                   0x0, NULL, HFILL } },
    { &hf_nush_index,    { "Uncoded Slice Index", "nector-data.nush_index",   FT_UINT16, BASE_DEC,  NULL,                   0x0, NULL, HFILL } },
    { &hf_nush_payload,  { "Uncoded Payload",     "nector-data.nush_payload", FT_BYTES,  BASE_NONE, NULL,                   0x0, NULL, HFILL } },
    { &hf_ncsh_index,    { "Coded Slice Index",   "nector-data.ncsh_index",   FT_UINT16, BASE_DEC,  NULL,                   0x0, NULL, HFILL } },
    { &hf_ncsh_payload,  { "Coded Payload",       "nector-data.ncsh_payload", FT_BYTES,  BASE_NONE, NULL,                   0x0, NULL, HFILL } }
  };
  static hf_register_info hf_nector_control[] = {
    { &hf_type,          { "Type",                "nector-control.type",      FT_STRING, BASE_NONE, NULL,                   0x0, NULL, HFILL } },
    { &hf_length,        { "Length",              "nector-control.length",    FT_UINT32, BASE_DEC,  NULL,                   0x0, NULL, HFILL } }
  };

  /* Setup protocol subtree array */
  static int* def_ett_nector_data[] = {
    &ett_nector_data
  };
  static int* def_ett_nector_control[] = {
    &ett_nector_control,
    &ett_xml
  };

  /* Register the protocol name and description */
  proto_nector_data    = proto_register_protocol("NECTOR Data",    "NECTOR Data",    "nector-data");
  proto_nector_control = proto_register_protocol("NECTOR Control", "NECTOR Control", "nector-control");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_nector_data, hf_nector_data, array_length(hf_nector_data));
  proto_register_subtree_array(def_ett_nector_data, array_length(def_ett_nector_data));
  proto_register_field_array(proto_nector_control, hf_nector_control, array_length(hf_nector_control));
  proto_register_subtree_array(def_ett_nector_control, array_length(def_ett_nector_control));
}

void
proto_reg_handoff_nector(void)
{
  heur_dissector_add("udp",  dissect_nector_data_heur,    "NECTOR Data",    "nector_data",    proto_nector_data,    HEURISTIC_ENABLE);
  heur_dissector_add("tcp",  dissect_nector_control_heur, "NECTOR Control", "nector_control", proto_nector_control, HEURISTIC_ENABLE);

  xml_handle = find_dissector_add_dependency("xml", proto_nector_control);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
