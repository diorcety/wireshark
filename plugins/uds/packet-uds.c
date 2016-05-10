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
        {UDS_SERVICE_CDTCS, "Control DTC Setting"},
        {0, NULL}
};

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

static value_string uds_dsc_session_types[] = {
        {UDS_DSC_SESSION_TYPES_DEFAULT, "Default Session"},
        {UDS_DSC_SESSION_TYPES_PROGRAMMING, "Programming Session"},
        {UDS_DSC_SESSION_TYPES_EXTENDED, "Extended Session"},
        {0, NULL}
};

static value_string uds_sa_types[] = {
        {UDS_SA_TYPES_SEED, "Request Seed"},
        {UDS_SA_TYPES_KEY, "Send Key"},
        {UDS_SA_TYPES_SEED_2, "Request Seed"},
        {UDS_SA_TYPES_KEY_2, "Send Key"},
        {0, NULL}
};

static value_string uds_rdtci_report_types[] = {
    {UDS_RDTCI_REPORT_TYPES_NUMBER_BY_STATUS_MASK, "Report Number of DTC by Status Mask"},
    {UDS_RDTCI_REPORT_TYPES_BY_STATUS_MASK, "Report DTC by Status Mask"},
    {UDS_RDTCI_REPORT_TYPES_SNAPSHOT_IDENTIFICATION, "Report DTC Snapshot Identification"},
    {UDS_RDTCI_REPORT_TYPES_SNAPSHOT_RECORD_BY_DTC, "Report DTC Snapshot Record by DTC Number"},
    {UDS_RDTCI_REPORT_TYPES_SNAPSHOT_RECORD_BY_RECORD, "Report DTC Snapshot Record by Record Number"},
    {UDS_RDTCI_REPORT_TYPES_EXTENDED_RECARD_BY_DTC, "Report DTC Extended Data Record by DTC Number"},
    {UDS_RDTCI_REPORT_TYPES_SUPPORTED_DTC, "Report Supported DTC"},
    {0, NULL}
};

static value_string uds_rc_actions[] = {
        {UDS_RC_ACTIONS_START, "Start routine"},
        {UDS_RC_ACTIONS_STOP, "Stop routine"},
        {UDS_RC_ACTIONS_REQUEST, "Request routine result"},
        {0, NULL}
};

static value_string uds_cdtcs_actions[] = {
        {UDS_CDTCS_ACTIONS_ON, "On"},
        {UDS_CDTCS_ACTIONS_OFF, "Off"},
        {0, NULL}
};


static int hf_uds_service = -1;
static int hf_uds_reply = -1;

static int hf_uds_dsc_session_type = -1;
static int hf_uds_dsc_session_parameter_record = -1;

static int hf_uds_rdtci_report_type = -1;
static int hf_uds_rdtci_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;

static int hf_uds_sa_type = -1;
static int hf_uds_sa_key = -1;
static int hf_uds_sa_seed = -1;

static int hf_uds_wdbi_data_identifier = -1;
static int hf_uds_wdbi_data_record = -1;

static int hf_uds_rc_action = -1;
static int hf_uds_rc_routine = -1;
static int hf_uds_rc_data = -1;

static int hf_uds_err_sid = -1;
static int hf_uds_err_code = -1;

static int hf_uds_cdtcs_action = -1;

static gint ett_uds = -1;
static gint ett_uds_dsc = -1;
static gint ett_uds_rdtci = -1;
static gint ett_uds_rdbi = -1;
static gint ett_uds_sa = -1;
static gint ett_uds_wdbi = -1;
static gint ett_uds_rc = -1;
static gint ett_uds_err = -1;
static gint ett_uds_cdtcs = -1;

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
    } else if(service == UDS_SERVICE_RDTCI) {
        proto_tree *uds_rtdci_tree;
        guint8 report_type;
        guint32 record_length = data_length - UDS_RDTCI_RECORD_OFFSET;

        uds_rtdci_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdtci, NULL, service_name);
        report_type = tvb_get_guint8(tvb, UDS_RDTCI_REPORT_TYPE_OFFSET);
        proto_tree_add_item(uds_rtdci_tree, hf_uds_rdtci_report_type, tvb, UDS_RDTCI_REPORT_TYPE_OFFSET,
                            UDS_RDTCI_REPORT_TYPE_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rtdci_tree, hf_uds_rdtci_record, tvb,
                            UDS_RDTCI_RECORD_OFFSET, record_length, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s    %s",
                        val_to_str(report_type, uds_rdtci_report_types, "Unknown (0x%02x)"),
                        tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDTCI_RECORD_OFFSET,
                                               record_length, ' '));
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
    } else if(service == UDS_SERVICE_RC) {
        proto_tree *uds_rc_tree;
        gint8 action;
        gint16 routine;

        uds_rc_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rc, NULL, service_name);
        proto_tree_add_item(uds_rc_tree, hf_uds_rc_action, tvb, UDS_RC_ACTION_OFFSET,
                            UDS_RC_ACTION_LEN, ENC_BIG_ENDIAN);
        action = tvb_get_guint8(tvb, UDS_RC_ACTION_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(action, uds_rc_actions, "Unknown (0x%02x)"));

        routine = tvb_get_guint16(tvb, UDS_RC_ROUTINE_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rc_tree, hf_uds_rc_routine, tvb, UDS_RC_ROUTINE_OFFSET,
                            UDS_RC_ROUTINE_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", routine);
        if(sid & UDS_REPLY_MASK) {
            guint32 rc_data_len = data_length - UDS_RC_DATA_OFFSET;
            if (rc_data_len > 0) {
                proto_tree_add_item(uds_rc_tree, hf_uds_rc_data, tvb, UDS_RC_DATA_OFFSET, rc_data_len, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RC_DATA_OFFSET, rc_data_len, ' '));
            }
        }
    } else if(service == UDS_SERVICE_ERR) {
        proto_tree *uds_err_tree;
        guint8 error_sid, error_code;
        const char *error_service_name, *error_name;

        uds_err_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_err, NULL, service_name);
        error_sid = tvb_get_guint8(tvb, UDS_ERR_SID_OFFSET);
        error_service_name = val_to_str(error_sid, uds_services, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_sid, tvb, UDS_ERR_SID_OFFSET,
                            UDS_ERR_SID_LEN, ENC_BIG_ENDIAN);
        error_code = tvb_get_guint8(tvb, UDS_ERR_CODE_OFFSET);
        error_name = val_to_str(error_code, uds_responses, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_code, tvb, UDS_ERR_CODE_OFFSET,
                            UDS_ERR_CODE_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s (SID: %s)", error_name, error_service_name);
    } else if(service == UDS_SERVICE_CDTCS) {
        proto_tree *uds_cdtcs_tree;
        gint8 action;

        uds_cdtcs_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_cdtcs, NULL, service_name);
        action = tvb_get_guint8(tvb, UDS_CDTCS_ACTION_OFFSET);
        proto_tree_add_item(uds_cdtcs_tree, hf_uds_cdtcs_action, tvb, UDS_CDTCS_ACTION_OFFSET,
                            UDS_CDTCS_ACTION_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(action, uds_cdtcs_actions, "Unknown (0x%02x)"));
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
                    &hf_uds_rdtci_report_type,
                    {
                            "Report Type", "uds.rdtci.report_type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rdtci_report_types), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rdtci_record,
                    {
                            "Record", "uds.rdtci.record",
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
                    &hf_uds_rc_action,
                    {
                            "Actionr", "uds.rc.action",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rc_actions), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_routine,
                    {
                            "Routine", "uds.rc.routine",
                            FT_UINT16, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_data,
                    {
                            "Data", "uds.rc.data",
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
                    &hf_uds_err_code,
                    {
                            "Code", "uds.err.code",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_responses), 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_cdtcs_action,
                    {
                            "Action", "uds.cdtcs.action",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_cdtcs_actions), 0x0,
                            NULL, HFILL
                    }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_uds,
                    &ett_uds_dsc,
                    &ett_uds_rdtci,
                    &ett_uds_rdbi,
                    &ett_uds_sa,
                    &ett_uds_wdbi,
                    &ett_uds_rc,
                    &ett_uds_err,
                    &ett_uds_cdtcs,
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
//#ifdef HACK
    dissector_add_for_decode_as("can.subdissector", uds_handle);
    dissector_add_for_decode_as("iso15765.subdissector", uds_handle);
//#endif /* HACK */
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
