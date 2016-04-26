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

#define UDS_SERVICE_DSC     0x10
#define UDS_SERVICE_ER      0x11
#define UDS_SERVICE_CDTCI   0x14
#define UDS_SERVICE_RDTCI   0x19
#define UDS_SERVICE_RDBI    0x22
#define UDS_SERVICE_RMBA    0x23
#define UDS_SERVICE_RSDBI   0x24
#define UDS_SERVICE_SA      0x27
#define UDS_SERVICE_CC      0x28
#define UDS_SERVICE_RDBPI   0x2A
#define UDS_SERVICE_DDDI    0x2C
#define UDS_SERVICE_WDBI    0x2E
#define UDS_SERVICE_IOCBI   0x2F
#define UDS_SERVICE_RC      0x31
#define UDS_SERVICE_RD      0x34
#define UDS_SERVICE_RU      0x35
#define UDS_SERVICE_TD      0x36
#define UDS_SERVICE_RTE     0x37
#define UDS_SERVICE_RFT     0x38
#define UDS_SERVICE_WMBA    0x3D
#define UDS_SERVICE_TP      0x3E
#define UDS_SERVICE_ERR     0x3F

static value_string uds_services[]= {
        {UDS_SERVICE_DSC,   "Diagnostic Session Control"},
        {UDS_SERVICE_ER,    "ECU Reset"},
        {UDS_SERVICE_CDTCI, "Clear Diagnostic Information"},
        {UDS_SERVICE_RDTCI, "Read DTC Information"},
        {UDS_SERVICE_RDBI,  "Read Data By Identifier"},
        {UDS_SERVICE_RMBA,  "Read Memory By Address"},
        {UDS_SERVICE_RSDBI, "Read Scaling Data By Identifier"},
        {UDS_SERVICE_SA,    "Security Access"},
        {UDS_SERVICE_CC,    "Communication Control"},
        {UDS_SERVICE_RDBPI, "Read Data By Periodic Identifier"},
        {UDS_SERVICE_DDDI,  "Dynamically Define Data Identifier"},
        {UDS_SERVICE_WDBI,  "Write Data By Identifier"},
        {UDS_SERVICE_IOCBI, "Input Output Control By Identifier"},
        {UDS_SERVICE_RC,    "Routine Control"},
        {UDS_SERVICE_RD,    "Request Download"},
        {UDS_SERVICE_RU,    "Request Upload"},
        {UDS_SERVICE_TD,    "Transfer Data"},
        {UDS_SERVICE_RTE,   "Request Transfer Exit"},
        {UDS_SERVICE_RFT,   "Request File Transfer"},
        {UDS_SERVICE_WMBA,  "Write Memory By Address"},
        {UDS_SERVICE_TP,    "Tester Present"},
        {UDS_SERVICE_ERR,   "Error"},
        {0, NULL}
};

#define UDS_RESPONSE_GR       0x10
#define UDS_RESPONSE_SNS      0x11
#define UDS_RESPONSE_SFNS     0x12
#define UDS_RESPONSE_IMLOIF   0x13
#define UDS_RESPONSE_RTL      0x14
#define UDS_RESPONSE_BRR      0x21
#define UDS_RESPONSE_CNC      0x22
#define UDS_RESPONSE_RSE      0x24
#define UDS_RESPONSE_NRFSC    0x25
#define UDS_RESPONSE_FPEORA   0x26
#define UDS_RESPONSE_ROOR     0x31
#define UDS_RESPONSE_SAD      0x33
#define UDS_RESPONSE_IK       0x35
#define UDS_RESPONSE_ENOA     0x36
#define UDS_RESPONSE_RTDNE    0x37
#define UDS_RESPONSE_UDNA     0x70
#define UDS_RESPONSE_TDS      0x71
#define UDS_RESPONSE_GPF      0x72
#define UDS_RESPONSE_WBSC     0x73
#define UDS_RESPONSE_RCRRP    0x78
#define UDS_RESPONSE_SFNSIAS  0x7E
#define UDS_RESPONSE_SNSIAS   0x7F

static value_string uds_responses[]= {
        {UDS_RESPONSE_GR,      "General reject"},
        {UDS_RESPONSE_SNS,     "Service not supported"},
        {UDS_RESPONSE_SFNS,    "Sub-Function Not Supported"},
        {UDS_RESPONSE_IMLOIF,  "Incorrect Message Length or Invalid Format"},
        {UDS_RESPONSE_RTL,     "Response too long"},
        {UDS_RESPONSE_BRR,     "Busy repeat request"},
        {UDS_RESPONSE_CNC,     "Conditions Not Correct"},
        {UDS_RESPONSE_RSE,     "Request Sequence Error"},
        {UDS_RESPONSE_NRFSC,   "No response from sub-net component"},
        {UDS_RESPONSE_FPEORA,  "Failure prevents execution of requested action"},
        {UDS_RESPONSE_ROOR,    "Request Out of Range"},
        {UDS_RESPONSE_SAD,     "Security Access Denied"},
        {UDS_RESPONSE_IK,      "Invalid Key"},
        {UDS_RESPONSE_ENOA,    "Exceeded Number Of Attempts"},
        {UDS_RESPONSE_RTDNE,   "Required Time Delay Not Expired"},
        {UDS_RESPONSE_UDNA,    "Upload/Download not accepted"},
        {UDS_RESPONSE_TDS,     "Transfer data suspended"},
        {UDS_RESPONSE_GPF,     "General Programming Failure"},
        {UDS_RESPONSE_WBSC,    "Wrong Block Sequence Counter"},
        {UDS_RESPONSE_RCRRP,   "Request correctly received, but response is pending"},
        {UDS_RESPONSE_SFNSIAS, "Sub-Function not supported in active session"},
        {UDS_RESPONSE_SNSIAS,  "Service not supported in active session"},
        {0, NULL}
};

static value_string uds_dsc_session_types[]= {
        {0x1, "Default Session"},
        {0x2, "Programming Session"},
        {0x3, "Extended Session"},
        {0, NULL}
};

static value_string uds_sa_types[]= {
        {0x1, "Request Seed"},
        {0x2, "Send Key"},
        {0x3, "Request Seed"},
        {0x4, "Send Key"},
        {0, NULL}
};

#define UDS_SID_MASK ((guint8)0xBF)
#define UDS_REPLY_MASK ((guint8)0x40)
#define UDS_SID_OFFSET 0
#define UDS_SID_LEN 1
#define UDS_DATA_OFFSET 1

#define UDS_DSC_SESSION_TYPE_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_DSC_SESSION_TYPE_LEN 1
#define UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET (UDS_DSC_SESSION_TYPE_OFFSET + UDS_DSC_SESSION_TYPE_LEN)

#define UDS_RDBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_RDBI_DATA_IDENTIFIER_LEN 2
#define UDS_RDBI_DATA_RECORD_OFFSET (UDS_RDBI_DATA_IDENTIFIER_OFFSET + UDS_RDBI_DATA_IDENTIFIER_LEN)

#define UDS_SA_TYPE_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_SA_TYPE_LEN 1
#define UDS_SA_KEY_OFFSET (UDS_SA_TYPE_OFFSET + UDS_SA_TYPE_LEN)
#define UDS_SA_SEED_OFFSET (UDS_SA_TYPE_OFFSET + UDS_SA_TYPE_LEN)

#define UDS_WDBI_DATA_IDENTIFIER_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_WDBI_DATA_IDENTIFIER_LEN 2
#define UDS_WDBI_DATA_RECORD_OFFSET (UDS_WDBI_DATA_IDENTIFIER_OFFSET + UDS_WDBI_DATA_IDENTIFIER_LEN)

#define UDS_ERR_SID_OFFSET (UDS_DATA_OFFSET + 0)
#define UDS_ERR_SID_LEN 1
#define UDS_ERR_ERROR_OFFSET (UDS_ERR_SID_OFFSET + UDS_ERR_SID_LEN)
#define UDS_ERR_ERROR_LEN 1

static int hf_uds_service = -1;
static int hf_uds_reply = -1;

static int hf_uds_dsc_session_type = -1;
static int hf_uds_dsc_session_parameter_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;

static int hf_uds_sa_type = -1;
static int hf_uds_sa_key = -1;
static int hf_uds_sa_seed = -1;

static int hf_uds_wdbi_data_identifier = -1;
static int hf_uds_wdbi_data_record = -1;

static int hf_uds_err_sid = -1;
static int hf_uds_err_error = -1;

static gint ett_uds = -1;
static gint ett_uds_dsc = -1;
static gint ett_uds_rdbi = -1;
static gint ett_uds_sa = -1;
static gint ett_uds_wdbi = -1;
static gint ett_uds_err = -1;

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
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(session_type, uds_dsc_session_types, "Unknown (0x%02x)"));

        if(sid & UDS_REPLY_MASK) {
            guint32 record_length = data_length - UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET;
            proto_tree_add_item(uds_dsc_tree, hf_uds_dsc_session_parameter_record, tvb,
                                UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET, record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_DSC_SESSION_PARAMETER_RECORD_OFFSET,
                                                   record_length, ' '));
        }
    } else if(service == UDS_SERVICE_RDBI) {
        proto_tree *uds_rdbi_tree;
        guint16 data_identifier;

        uds_rdbi_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdbi, NULL, service_name);
        data_identifier = tvb_get_guint16(tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_identifier, tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET,
                            UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN);
        if(sid & UDS_REPLY_MASK) {
            guint32 record_length = data_length - UDS_RDBI_DATA_RECORD_OFFSET;
            proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_record, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", data_identifier,
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDBI_DATA_RECORD_OFFSET, record_length,
                                                   ' '));
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
        }
    } else if(service == UDS_SERVICE_SA) {
        proto_tree *uds_sa_tree;
        guint8 security_access_type;
        uds_sa_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_sa, NULL, service_name);
        proto_tree_add_item(uds_sa_tree, hf_uds_sa_type, tvb, UDS_SA_TYPE_OFFSET,
                            UDS_SA_TYPE_LEN, ENC_BIG_ENDIAN);
        security_access_type = tvb_get_guint8(tvb, UDS_SA_TYPE_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(security_access_type, uds_sa_types, "Unknown (0x%02x)"));

        if(sid & UDS_REPLY_MASK) {
            guint32 seed_length = data_length - UDS_SA_SEED_OFFSET;
            if(seed_length >0) {
                proto_tree_add_item(uds_sa_tree, hf_uds_sa_seed, tvb, UDS_SA_SEED_OFFSET, seed_length, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_SEED_OFFSET, seed_length, ' '));
            }
        } else {
            guint32 key_length = data_length - UDS_SA_KEY_OFFSET;
            if(key_length > 0) {
                proto_tree_add_item(uds_sa_tree, hf_uds_sa_key, tvb, UDS_SA_KEY_OFFSET, key_length, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_KEY_OFFSET, key_length, ' '));
            }
        }
    } else if(service == UDS_SERVICE_WDBI) {
        proto_tree *uds_wdbi_tree;
        guint16 data_identifier;

        uds_wdbi_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_wdbi, NULL, service_name);
        data_identifier = tvb_get_guint16(tvb, UDS_WDBI_DATA_IDENTIFIER_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_wdbi_tree, hf_uds_wdbi_data_identifier, tvb, UDS_WDBI_DATA_IDENTIFIER_OFFSET,
                            UDS_WDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN);
        if(sid & UDS_REPLY_MASK) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
        } else {
            guint32 record_length = data_length - UDS_WDBI_DATA_RECORD_OFFSET;
            proto_tree_add_item(uds_wdbi_tree, hf_uds_wdbi_data_record, tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", data_identifier,
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_WDBI_DATA_RECORD_OFFSET, record_length,
                                                   ' '));
        }
    } else if(service == UDS_SERVICE_ERR) {
        proto_tree *uds_err_tree;
        guint8 error_sid, error;
        const char *error_service_name, *error_name;
        uds_err_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_err, NULL, service_name);
        error_sid = tvb_get_guint8(tvb, UDS_ERR_SID_OFFSET);
        error_service_name = val_to_str(error_sid, uds_services, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_sid, tvb, UDS_ERR_SID_OFFSET,
                            UDS_ERR_SID_LEN, ENC_BIG_ENDIAN);
        error = tvb_get_guint8(tvb, UDS_ERR_ERROR_OFFSET);
        error_name = val_to_str(error, uds_responses, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_error, tvb, UDS_ERR_ERROR_OFFSET,
                            UDS_ERR_ERROR_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s (SID: %s)", error_name, error_service_name);
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
                            "Service Identifier",    "uds.sid",
                            FT_UINT8,  BASE_HEX,
                            VALS(uds_services), UDS_SID_MASK,
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
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_sa_type,
                    {
                            "Type", "uds.sa.type",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_sa_key,
                    {
                            "Key", "uds.sa.key",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_sa_seed,
                    {
                            "Seed", "uds.sa.seed",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_wdbi_data_identifier,
                    {
                            "Data Identifier", "uds.wdbi.data_identifier",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_wdbi_data_record,
                    {
                            "Data Record", "uds.wdbi.data_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_err_sid,
                    {
                            "Service Identifier", "uds.err.sid",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_services), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_err_error,
                    {
                            "Error", "uds.err.error",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_responses), 0x0,
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
                    &ett_uds_sa,
                    &ett_uds_wdbi,
                    &ett_uds_err,
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
