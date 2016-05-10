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
#include "packet-iso15765.h"

struct can_identifier
{
    guint32 id;
    guint32 frame_type;
};
typedef struct can_identifier can_identifier_t;

static value_string iso15765_message_types[] = {
        {ISO15765_MESSAGE_TYPES_SINGLE_FRAME, "Single Frame"},
        {ISO15765_MESSAGE_TYPES_FIRST_FRAME, "First Frame"},
        {ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME, "Consecutive Frame"},
        {ISO15765_MESSAGE_TYPES_FLOW_CONTROL, "Flow control"},
        {0, NULL}
};



static int hf_iso15765_message_type = -1;
static int hf_iso15765_data_length = -1;
static int hf_iso15765_extended_frame_length = -1;
static int hf_iso15765_sequence_number = -1;
static int hf_iso15765_flow_status = -1;

static gint ett_iso15765 = -1;

static expert_field ei_iso15765_message_type_bad = EI_INIT;

static int proto_iso15765 = -1;

static dissector_table_t subdissector_table;

static void iso15765_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "CAN id 0x%x as",
               ((can_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0))->id);
}

static gpointer iso15765_value(packet_info *pinfo _U_)
{
    return GUINT_TO_POINTER(((can_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0))->id);
}

static int
dissect_iso15765(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data)
{
    proto_tree *iso15765_tree;
    proto_item *ti;
    proto_item *message_type_item;
    tvbuff_t*   next_tvb;
    guint8      pci, message_type;
    can_identifier_t* can_info;
    can_identifier_t* iso15765_info;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO15765");
    col_clear(pinfo->cinfo,COL_INFO);

    DISSECTOR_ASSERT(data);
    can_info = ((can_identifier_t*)data);

    iso15765_info = (can_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0);

    if(!iso15765_info) {
        iso15765_info = wmem_new(wmem_file_scope(), can_identifier_t);
        memcpy(iso15765_info, can_info, sizeof(can_identifier_t));
        p_add_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0, iso15765_info);
    }

    ti = proto_tree_add_item(tree, proto_iso15765, tvb, 0, -1, ENC_NA);
    iso15765_tree = proto_item_add_subtree(ti, ett_iso15765);
    message_type_item = proto_tree_add_item(iso15765_tree, hf_iso15765_message_type, tvb, ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);

    pci = tvb_get_guint8(tvb, ISO15765_PCI_OFFSET);
    message_type = pci >> 4;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_type, iso15765_message_types, "Unknown (0x%02x)"));
    if(message_type == ISO15765_MESSAGE_TYPES_SINGLE_FRAME) {
        proto_tree_add_item(iso15765_tree, hf_iso15765_data_length, tvb, ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Len: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
    } else if(message_type == ISO15765_MESSAGE_TYPES_FIRST_FRAME) {
        proto_tree_add_item(iso15765_tree, hf_iso15765_extended_frame_length, tvb, ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Len: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
    } else if(message_type == ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME) {
        proto_tree_add_item(iso15765_tree, hf_iso15765_sequence_number, tvb, ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Seq: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
    } else if(message_type == ISO15765_MESSAGE_TYPES_FLOW_CONTROL) {
        proto_tree_add_item(iso15765_tree, hf_iso15765_flow_status, tvb, ISO15765_PCI_OFFSET, ISO15765_PCI_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Status: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
    } else {
        expert_add_info_format(pinfo, message_type_item, &ei_iso15765_message_type_bad, "Bad Message Type value %u <= 3", message_type);
    }

    next_tvb = tvb;
    /* Functionality for choosing subdissector is controlled through Decode As as CAN doesn't
        have a unique identifier to determine subdissector */
    if (!dissector_try_uint_new(subdissector_table, 0, next_tvb, pinfo, tree, FALSE, NULL))
    {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
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
                    &hf_iso15765_extended_frame_length,
                    {
                            "Extended frame length",    "iso15765.extended_frame_length",
                            FT_UINT8,  BASE_HEX,
                            NULL, ISO15765_MESSAGE_EXTENDED_FRAME_LENGTH_MASK,
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_iso15765,
            };

    static ei_register_info ei[] = {
            { &ei_iso15765_message_type_bad, { "iso15765.message_type.bad", PI_MALFORMED, PI_ERROR, "Bad Message Type value", EXPFILL }},
    };

    module_t *iso15765_module;
    expert_module_t* expert_iso15765;

    /* Decode As handling */
    static build_valid_func iso15765_da_build_value[1] = {iso15765_value};
    static decode_as_value_t iso15765_da_values = {iso15765_prompt, 1, iso15765_da_build_value};
    static decode_as_t can_iso15765 = {"iso15765", "Network", "iso15765.subdissector", 1, 0, &iso15765_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    proto_iso15765 = proto_register_protocol (
            "ISO15765 Protocol", /* name       */
            "ISO15765",          /* short name */
            "iso15765"           /* abbrev     */
    );
    register_dissector("iso15765", dissect_iso15765, proto_iso15765);
    expert_iso15765 = expert_register_protocol(proto_iso15765);

    proto_register_field_array(proto_iso15765, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_iso15765, ei, array_length(ei));

    subdissector_table = register_dissector_table("iso15765.subdissector",
                                                  "ISO15765 next level dissector", proto_iso15765, FT_UINT32, BASE_HEX, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE);

    iso15765_module = prefs_register_protocol(proto_iso15765, NULL);

    prefs_register_obsolete_preference(iso15765_module, "protocol");

    register_decode_as(&can_iso15765);
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
