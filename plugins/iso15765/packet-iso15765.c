/* packet-iso15765.c
 * Routines for iso15765 protocol packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <wsutil/bits_ctz.h>
#include "packet-iso15765.h"

struct can_identifier
{
    guint32 id;
    guint32 frame_type;
};

typedef struct can_identifier can_identifier_t;

struct iso15765_identifier
{
    guint32 id;
    guint32 frame_type;
    guint32 seq;
    gboolean last;
};

typedef struct iso15765_identifier iso15765_identifier_t;


struct iso15765_frame
{
    guint32 seq;
    guint32 offset;
    guint32 len;
};

typedef struct iso15765_frame iso15765_frame_t;

static value_string iso15765_message_types[] = {
        {ISO15765_MESSAGE_TYPES_SINGLE_FRAME, "Single Frame"},
        {ISO15765_MESSAGE_TYPES_FIRST_FRAME, "First Frame"},
        {ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME, "Consecutive Frame"},
        {ISO15765_MESSAGE_TYPES_FLOW_CONTROL, "Flow control"},
        {0, NULL}
};

#define NORMAL_ADDRESSING 1
#define EXTENDED_ADDRESSING 2

static gint addressing = NORMAL_ADDRESSING;

/* Encoding */
static const enum_val_t enum_addressing[] = {
        {"normal", "Normal addressing", NORMAL_ADDRESSING},
        {"extended", "Extended addressing", EXTENDED_ADDRESSING},
        {NULL, NULL, 0}
};

static int hf_iso15765_message_type = -1;
static int hf_iso15765_data_length = -1;
static int hf_iso15765_frame_length = -1;
static int hf_iso15765_sequence_number = -1;
static int hf_iso15765_flow_status = -1;

static int hf_iso15765_fc_bs = -1;
static int hf_iso15765_fc_stmin = -1;

static gint ett_iso15765 = -1;

static expert_field ei_iso15765_message_type_bad = EI_INIT;

static int proto_iso15765 = -1;

static dissector_table_t subdissector_table;

static reassembly_table iso15765_reassembly_table;
static GHashTable *iso15765_frame_table = NULL;

/* Equal keys */
static gint iso15765_frame_equal_func(gconstpointer v, gconstpointer v2)
{
    /* Key fits in 4 bytes, so just compare pointers! */
    return GPOINTER_TO_UINT(v) == GPOINTER_TO_UINT(v2);
}

/* Compute a hash value for a given key. */
static guint iso15765_frame_hash_func(gconstpointer v)
{
    /* Just use pointer, as the fields are all in this value */
    return GPOINTER_TO_UINT(v);
}

static int hf_iso15765_fragments = -1;
static int hf_iso15765_fragment = -1;
static int hf_iso15765_fragment_overlap = -1;
static int hf_iso15765_fragment_overlap_conflicts = -1;
static int hf_iso15765_fragment_multiple_tails = -1;
static int hf_iso15765_fragment_too_long_fragment = -1;
static int hf_iso15765_fragment_error = -1;
static int hf_iso15765_fragment_count = -1;
static int hf_iso15765_reassembled_in = -1;
static int hf_iso15765_reassembled_length = -1;

static gint ett_iso15765_fragment = -1;
static gint ett_iso15765_fragments = -1;

static const fragment_items iso15765_frag_items = {
        /* Fragment subtrees */
        &ett_iso15765_fragment,
        &ett_iso15765_fragments,
        /* Fragment fields */
        &hf_iso15765_fragments,
        &hf_iso15765_fragment,
        &hf_iso15765_fragment_overlap,
        &hf_iso15765_fragment_overlap_conflicts,
        &hf_iso15765_fragment_multiple_tails,
        &hf_iso15765_fragment_too_long_fragment,
        &hf_iso15765_fragment_error,
        &hf_iso15765_fragment_count,
        /* Reassembled in field */
        &hf_iso15765_reassembled_in,
        /* Reassembled length field */
        &hf_iso15765_reassembled_length,
        /* Reassembled data field */
        NULL,
        "ISO15765 fragments"
};

static void
iso15765_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "CAN id 0x%x as",
               ((can_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0))->id);
}

static gpointer
iso15765_value(packet_info *pinfo _U_)
{
    return GUINT_TO_POINTER(((can_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0))->id);
}

static guint8
masked_guint8_value(const guint8 value, const guint8 mask)
{
    return (value & mask) >> ws_ctz(mask);
}

static int
dissect_iso15765(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data)
{
    static guint32 msg_seqid = 0;

    proto_tree *iso15765_tree;
    proto_item *ti;
    proto_item *message_type_item;
    tvbuff_t*   next_tvb = NULL;
    guint8      pci, message_type;
    can_identifier_t* can_info;
    iso15765_identifier_t* iso15765_info;
    guint8      ae = (addressing == NORMAL_ADDRESSING)?0:1;
    guint32     frag_id;
    guint32     offset;
    gint32      data_length;
    gboolean    fragmented = FALSE;
    gboolean    complete = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO15765");
    col_clear(pinfo->cinfo,COL_INFO);

    DISSECTOR_ASSERT(data);
    can_info = ((can_identifier_t*)data);

    iso15765_info = (iso15765_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0);

    if(!iso15765_info) {
        iso15765_info = wmem_new(wmem_file_scope(), iso15765_identifier_t);
        memcpy(iso15765_info, can_info, sizeof(can_identifier_t));
        iso15765_info->last = FALSE;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0, iso15765_info);
    }

    ti = proto_tree_add_item(tree, proto_iso15765, tvb, 0, -1, ENC_NA);
    iso15765_tree = proto_item_add_subtree(ti, ett_iso15765);
    message_type_item = proto_tree_add_item(iso15765_tree, hf_iso15765_message_type, tvb,
                                            ae + ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);

    pci = tvb_get_guint8(tvb, ae + ISO15765_PCI_OFFSET);
    message_type = masked_guint8_value(pci, ISO15765_MESSAGE_TYPE_MASK);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_type, iso15765_message_types, "Unknown (0x%02x)"));
    if(message_type == ISO15765_MESSAGE_TYPES_SINGLE_FRAME) {
        offset = ae + ISO15765_PCI_OFFSET + ISO15765_PCI_LEN;
        data_length = masked_guint8_value(pci, ISO15765_MESSAGE_DATA_LENGTH_MASK);
        next_tvb = tvb_new_subset(tvb, offset, data_length, data_length);
        complete = TRUE;

        // Show some info
        proto_tree_add_item(iso15765_tree, hf_iso15765_data_length, tvb,
                            ae + ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Len: %d)", data_length);
    } else if(message_type == ISO15765_MESSAGE_TYPES_FIRST_FRAME) {
        guint32 full_len = tvb_get_guint8(tvb, ae + ISO15765_MESSAGE_FRAME_LENGTH_OFFSET);
        full_len += (masked_guint8_value(pci, ISO15765_MESSAGE_EXTENDED_FRAME_LENGTH_MASK) << 8);
        offset = ae + ISO15765_MESSAGE_FRAME_LENGTH_OFFSET + ISO15765_MESSAGE_FRAME_LENGTH_LEN;
        data_length = tvb_reported_length(tvb) - offset;
        frag_id = 0;
        fragmented = TRUE;

        // Save information
        if(!(pinfo->fd->flags.visited)) {
            iso15765_frame_t *iso15765_frame;
            ++msg_seqid;

            iso15765_info->seq = msg_seqid;

            iso15765_frame = wmem_new(wmem_file_scope(), iso15765_frame_t);
            iso15765_frame->seq = msg_seqid;
            iso15765_frame->offset = 0;
            iso15765_frame->len = full_len;

            g_hash_table_insert(iso15765_frame_table, GUINT_TO_POINTER(msg_seqid), iso15765_frame);
        }

        // Show some info
        proto_tree_add_item(iso15765_tree, hf_iso15765_frame_length, tvb,
                            ae + ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Frame Len: %d)", full_len);
    } else if(message_type == ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME) {
        offset = ae + ISO15765_PCI_OFFSET + ISO15765_PCI_LEN;
        data_length = tvb_reported_length(tvb) - offset;
        frag_id = masked_guint8_value(pci, ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK);
        fragmented = TRUE;

        // Save information
        if(!(pinfo->fd->flags.visited)) {
            iso15765_info->seq = msg_seqid;
        }

        // Show some info
        proto_tree_add_item(iso15765_tree, hf_iso15765_sequence_number,
                            tvb, ae + ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Seq: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
    } else if(message_type == ISO15765_MESSAGE_TYPES_FLOW_CONTROL) {
        guint8 status = masked_guint8_value(pci, ISO15765_MESSAGE_DATA_LENGTH_MASK);
        guint8 bs = tvb_get_guint8(tvb, ae + ISO15765_FC_BS_OFFSET);
        guint8 stmin = tvb_get_guint8(tvb, ae + ISO15765_FC_STMIN_OFFSET);
        data_length = -1;
        proto_tree_add_item(iso15765_tree, hf_iso15765_flow_status, tvb,
                            ae + ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(iso15765_tree, hf_iso15765_fc_bs, tvb,
                            ae + ISO15765_FC_BS_OFFSET, ISO15765_FC_BS_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(iso15765_tree, hf_iso15765_fc_stmin, tvb,
                            ae + ISO15765_FC_STMIN_OFFSET, ISO15765_FC_STMIN_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Status: %d, Block size:0x%x, Seperation time minimum: %d ms)", status, bs, stmin);
    } else {
        expert_add_info_format(pinfo, message_type_item, &ei_iso15765_message_type_bad,
                               "Bad Message Type value %u <= 3", message_type);
        return -1;
    }

    // Show data
    if (data_length > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, data_length, ' '));
    }

    if(fragmented) {
        gboolean    save_fragmented = pinfo->fragmented;
        tvbuff_t *new_tvb;
        fragment_head *frag_msg;
        guint32 len = tvb_captured_length_remaining(tvb, offset);
        iso15765_frame_t *iso15765_frame;

        // Get frame information
        iso15765_frame = (iso15765_frame_t *) g_hash_table_lookup(iso15765_frame_table,
                                                                  GUINT_TO_POINTER(iso15765_info->seq));
        DISSECTOR_ASSERT(iso15765_frame);

        // Check if it's the last packet
        if(!(pinfo->fd->flags.visited)) {
            iso15765_frame->offset += len;
            if(iso15765_frame->offset >= iso15765_frame->len) {
                iso15765_info->last = TRUE;
                len -= (iso15765_frame->offset - iso15765_frame->len);
            }
        }
        pinfo->fragmented = TRUE;

        /* Add fragment to fragment table */
        frag_msg = fragment_add_seq_check(&iso15765_reassembly_table, tvb, offset, pinfo, iso15765_info->seq, NULL,
                                          frag_id, len, !iso15765_info->last);

        new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Message", frag_msg,
                                           &iso15765_frag_items, NULL, iso15765_tree);

        if ( frag_msg && frag_msg->reassembled_in != pinfo->num ) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled in #%u]",
                            frag_msg->reassembled_in);
        }

        if (new_tvb) {
            // This is a complete TVB to dissect
            next_tvb = new_tvb;
            complete = TRUE;
        } else {
            next_tvb = tvb_new_subset(tvb, offset, len, len);
        }

        pinfo->fragmented = save_fragmented;
    }

    if (next_tvb) {
        /* Functionality for choosing subdissector is controlled through Decode As as ISO15765 doesn't
            have a unique identifier to determine subdissector */
        if(complete) {
            if (!dissector_try_uint_new(subdissector_table, iso15765_info->id, next_tvb, pinfo, tree, TRUE, NULL)) {
                call_data_dissector(next_tvb, pinfo, tree);
            }
        } else {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

static void
iso15765_init(void)
{
    iso15765_frame_table = g_hash_table_new(iso15765_frame_hash_func, iso15765_frame_equal_func);
    reassembly_table_init(&iso15765_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
iso15765_cleanup(void)
{
    reassembly_table_destroy(&iso15765_reassembly_table);
    g_hash_table_destroy(iso15765_frame_table);
}


void
proto_register_iso15765(void)
{
    static hf_register_info hf[] = {
            {
                    &hf_iso15765_message_type,
                    {
                            "Message Type",    "iso15765.message_type",
                            FT_UINT8,  BASE_HEX,
                            VALS(iso15765_message_types), ISO15765_MESSAGE_TYPE_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_data_length,
                    {
                            "Data length",    "iso15765.data_length",
                            FT_UINT8,  BASE_HEX,
                            NULL, ISO15765_MESSAGE_DATA_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_frame_length,
                    {
                            "Frame length",    "iso15765.frame_length",
                            FT_UINT16,  BASE_HEX,
                            NULL, ISO15765_MESSAGE_EXTENDED_FRAME_LENGTH_MASK << 8 | 0xff,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_sequence_number,
                    {
                            "Sequence number",    "iso15765.sequence_number",
                            FT_UINT8,  BASE_HEX,
                            NULL, ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_flow_status,
                    {
                            "Flow status",    "iso15765.flow_status",
                            FT_UINT8,  BASE_HEX,
                            NULL, ISO15765_MESSAGE_FLOW_STATUS_MASK,
                            NULL, HFILL
                    }
            },

            {
                    &hf_iso15765_fc_bs,
                    {
                            "Block size",    "iso15765.flow_control.bs",
                            FT_UINT8,  BASE_HEX,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },

            {
                    &hf_iso15765_fc_stmin,
                    {
                            "Separation time minimum (ms)",    "iso15765.flow_control.stmin",
                            FT_UINT8,  BASE_DEC,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },

            {
                    &hf_iso15765_fragments,
                    {
                            "Message fragments", "iso15765.fragments",
                            FT_NONE, BASE_NONE,
                            NULL, 0x00,
                            NULL, HFILL
                    },
            },
            {
                    &hf_iso15765_fragment,
                    {
                            "Message fragment", "iso15765.fragment",
                            FT_FRAMENUM, BASE_NONE,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_overlap,
                    {
                            "Message fragment overlap", "iso15765.fragment.overlap",
                            FT_BOOLEAN, 0,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_overlap_conflicts,
                    {
                            "Message fragment overlapping with conflicting data", "iso15765.fragment.overlap.conflicts",
                            FT_BOOLEAN, 0,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_multiple_tails,
                    {
                            "Message has multiple tail fragments", "iso15765.fragment.multiple_tails",
                            FT_BOOLEAN, 0,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_too_long_fragment,
                    {
                            "Message fragment too long", "iso15765.fragment.too_long_fragment",
                            FT_BOOLEAN, 0, NULL,
                            0x00, NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_error,
                    {
                            "Message defragmentation error", "iso15765.fragment.error",
                            FT_FRAMENUM, BASE_NONE,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_fragment_count,
                    {
                            "Message fragment count", "iso15765.fragment.count",
                            FT_UINT32, BASE_DEC,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_reassembled_in,
                    {
                            "Reassembled in", "iso15765.reassembled.in",
                            FT_FRAMENUM, BASE_NONE,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
            {
                    &hf_iso15765_reassembled_length,
                    {
                            "Reassembled length", "iso15765.reassembled.length",
                            FT_UINT32, BASE_DEC,
                            NULL, 0x00,
                            NULL, HFILL
                    }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_iso15765,
                    &ett_iso15765_fragment,
                    &ett_iso15765_fragments,
            };

    static ei_register_info ei[] = {
            {
                    &ei_iso15765_message_type_bad,
                    {
                            "iso15765.message_type.bad", PI_MALFORMED,
                            PI_ERROR, "Bad Message Type value", EXPFILL
                    }
            },
    };

    module_t *iso15765_module;
    expert_module_t* expert_iso15765;

    /* Decode As handling */
    static build_valid_func iso15765_da_build_value[1] = {iso15765_value};
    static decode_as_value_t iso15765_da_values = {iso15765_prompt, 1, iso15765_da_build_value};
    static decode_as_t can_iso15765 = {"iso15765", "Transport", "iso15765.message", 1, 0, &iso15765_da_values,
                                       NULL, NULL, decode_as_default_populate_list, decode_as_default_reset,
                                       decode_as_default_change, NULL};

    proto_iso15765 = proto_register_protocol (
            "ISO15765 Protocol", /* name       */
            "ISO 15765",          /* short name */
            "iso15765"           /* abbrev     */
    );
    register_dissector("iso15765", dissect_iso15765, proto_iso15765);
    expert_iso15765 = expert_register_protocol(proto_iso15765);

    proto_register_field_array(proto_iso15765, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_iso15765, ei, array_length(ei));

    subdissector_table = register_dissector_table("iso15765.message",
                                                  "ISO15765 messages dissector", proto_iso15765,
                                                  FT_UINT32, BASE_HEX, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE);

    iso15765_module = prefs_register_protocol(proto_iso15765, NULL);

    prefs_register_enum_preference(iso15765_module, "addressing",
                                   "Addressing",
                                   "Addressing of ISO15765. Normal or Extended",
                                   &addressing,
                                   enum_addressing, TRUE);

    prefs_register_obsolete_preference(iso15765_module, "protocol");

    register_decode_as(&can_iso15765);

    register_init_routine(iso15765_init);
    register_cleanup_routine(iso15765_cleanup);
}

void
proto_reg_handoff_iso15765(void)
{
    static dissector_handle_t iso15765_handle;

    iso15765_handle = create_dissector_handle(dissect_iso15765, proto_iso15765);
    dissector_add_for_decode_as("can.subdissector", iso15765_handle);
    dissector_add_for_decode_as("can.id", iso15765_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
