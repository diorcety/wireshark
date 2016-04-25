/* packet-uds.c
 * Routines for uds protocol packet disassembly
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
#include "packet-uds.h"

#define UDS_SERVICE_RDBI 0x22
#define UDS_SERVICE_DSC 0x10

static value_string uds_services[]= {
        {UDS_SERVICE_DSC, "Diagnostic Session Control"},
        {0x11, "ECU Reset"},
        {0x14, "Clear Diagnostic Information"},
        {0x19, "Read DTC Information"},
        {UDS_SERVICE_RDBI, "Read Data By Identifier"},
        {0x23, "Read Memory By Address"},
        {0x24, "Read Scaling Data By Identifier"},
        {0x27, "Security Access"},
        {0x28, "Communication Control"},
        {0x2A, "Read Data By Identifier Periodic"},
        {0x2C, "Dynamically Define Data Identifier"},
        {0x2E, "Write Data By Identifier"},
        {0x2F, "Input Output Control By Identifier"},
        {0x31, "Routine Control"},
        {0x34, "Request Download"},
        {0x35, "Request Upload"},
        {0x36, "Transfer Data"},
        {0x37, "Request Transfer Exit"},
        {0x38, "Request File Transfer"},
        {0x3D, "Write Memory By Address"},
        {0x3E, "Tester Present"},
        {0x83, "Access Timing Parameters"},
        {0x84, "Secured Data Transmission"},
        {0x85, "Control DTC Settings"},
        {0x86, "Response On Event"},
        {0x87, "Link Control"},
        {0, NULL}
};

static value_string uds_dsc_session_type[]= {
        {0x1, "Default Session"},
        {0x2, "Programming Session"},
        {0x3, "Extended Session"},
        {0, NULL}
};

#define UDS_SID_MASK ((guint8)0xBF)
#define UDS_REPLY_MASK ((guint8)0x40)
#define UDS_SID_OFFSET 0
#define UDS_SID_LEN 1
#define UDS_DATA_OFFSET 1

#define UDS_DSC_SESSION_TYPE_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_DSC_SESSION_TYPE_LEN 1
#define UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET (UDS_DSC_SESSION_TYPE_OFFSET + 1)

#define UDS_RDBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_RDBI_DATA_IDENTIFIER_LEN 1
#define UDS_RDBI_DATA_RECORD_OFFSET (UDS_RDBI_DATA_IDENTIFIER_OFFSET + 1)
#define UDS_RDBI_DATA_RECORD_LEN 1

static int hf_uds_service = -1;
static int hf_uds_reply = -1;

static int hf_uds_dsc_session_type = -1;
static int hf_uds_dsc_session_parameter_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;


static gint ett_uds = -1;
static gint ett_uds_dsc = -1;
static gint ett_uds_rdbi = -1;

static int proto_uds = -1;

static int
dissect_uds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
    proto_tree *uds_tree;
    proto_item *ti;
    guint8      sid, service;
    const char *service_name;
    guint32 data_length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    col_clear(pinfo->cinfo,COL_INFO);

    sid = tvb_get_guint8(tvb, UDS_SID_OFFSET);
    service = sid & UDS_SID_MASK;
    service_name = val_to_str(service, uds_services, "Unknown (0x%02x)");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%-7s   %-36s", (sid & UDS_REPLY_MASK)? "Reply": "Request", service_name);

    ti = proto_tree_add_item(tree, proto_uds, tvb, 0, -1, ENC_NA);
    uds_tree = proto_item_add_subtree(ti, ett_uds);
    proto_tree_add_item(uds_tree, hf_uds_service, tvb, UDS_SID_OFFSET, UDS_SID_LEN, ENC_BIG_ENDIAN);
    proto_tree_add_item(uds_tree, hf_uds_reply, tvb, UDS_SID_OFFSET, UDS_SID_LEN, ENC_BIG_ENDIAN);

    if(service == UDS_SERVICE_DSC) {
        proto_tree *uds_dsc_tree;
        guint8 session_type;
        uds_dsc_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_dsc, NULL, service_name);
        proto_tree_add_item(uds_dsc_tree, hf_uds_dsc_session_type, tvb, UDS_DSC_SESSION_TYPE_OFFSET,
                            UDS_DSC_SESSION_TYPE_LEN, ENC_BIG_ENDIAN);
        session_type = tvb_get_guint8(tvb, UDS_DSC_SESSION_TYPE_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", val_to_str(session_type, uds_dsc_session_type, "Unknown (0x%02x)"));

        if(sid & UDS_REPLY_MASK) {
            guint32 record_length = data_length - UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET;
            proto_tree_add_item(uds_dsc_tree, hf_uds_dsc_session_parameter_record, tvb, UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET,
                                record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET,
                                                   record_length, ' '));
        }
    } else if(service == UDS_SERVICE_RDBI) {
        proto_tree *uds_rdbi_tree;
        guint8 data_identifier;

        uds_rdbi_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdbi, NULL, service_name);
        data_identifier = tvb_get_guint8(tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET);
        proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_identifier, tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET,
                            UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN);
        if(sid & UDS_REPLY_MASK) {
            guint8 data_record;

            data_record = tvb_get_guint8(tvb, UDS_RDBI_DATA_RECORD_OFFSET);
            proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_record, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                UDS_RDBI_DATA_RECORD_LEN, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%02x=0x%02x", data_identifier, data_record);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%02x", data_identifier);
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_uds(void)
{
    static hf_register_info hf[] = {
            {
                    &hf_uds_service,
                    {
                            "Identifier",    "uds.sid",
                            FT_UINT8,  BASE_HEX,
                            NULL, UDS_SID_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_reply,
                    {
                            "Reply Flag", "uds.reply",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_REPLY_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_dsc_session_type,
                    {
                            "Session Type", "uds.dsc.session_type",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_dsc_session_parameter_record,
                    {
                            "Session Parameter Record", "uds.dsc.session_parameter_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rdbi_data_identifier,
                    {
                            "Data Identifier", "uds.rdbi.data_identifier",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rdbi_data_record,
                    {
                            "Data Record", "uds.rdbi.data_record",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_uds,
                    &ett_uds_dsc,
                    &ett_uds_rdbi,
            };

    proto_uds = proto_register_protocol (
            "UDS Protocol", /* name       */
            "UDS",          /* short name */
            "uds"           /* abbrev     */
    );

    proto_register_field_array(proto_uds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_uds(void)
{
    static dissector_handle_t uds_handle;

    uds_handle = create_dissector_handle(dissect_uds, proto_uds);
    dissector_add_for_decode_as("can.subdissector", uds_handle);
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
