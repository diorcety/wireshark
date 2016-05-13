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
#include <wsutil/bits_ctz.h>
#include "packet-uds.h"

//
// Enums
//

// Services
static value_string uds_services[]= {
        {UDS_SERVICES_DSC,   "Diagnostic Session Control"},
        {UDS_SERVICES_ER,    "ECU Reset"},
        {UDS_SERVICES_CDTCI, "Clear Diagnostic Information"},
        {UDS_SERVICES_RDTCI, "Read DTC Information"},
        {UDS_SERVICES_RDBI,  "Read Data By Identifier"},
        {UDS_SERVICES_RMBA,  "Read Memory By Address"},
        {UDS_SERVICES_RSDBI, "Read Scaling Data By Identifier"},
        {UDS_SERVICES_SA,    "Security Access"},
        {UDS_SERVICES_CC,    "Communication Control"},
        {UDS_SERVICES_RDBPI, "Read Data By Periodic Identifier"},
        {UDS_SERVICES_DDDI,  "Dynamically Define Data Identifier"},
        {UDS_SERVICES_WDBI,  "Write Data By Identifier"},
        {UDS_SERVICES_IOCBI, "Input Output Control By Identifier"},
        {UDS_SERVICES_RC,    "Routine Control"},
        {UDS_SERVICES_RD,    "Request Download"},
        {UDS_SERVICES_RU,    "Request Upload"},
        {UDS_SERVICES_TD,    "Transfer Data"},
        {UDS_SERVICES_RTE,   "Request Transfer Exit"},
        {UDS_SERVICES_RFT,   "Request File Transfer"},
        {UDS_SERVICES_WMBA,  "Write Memory By Address"},
        {UDS_SERVICES_TP,    "Tester Present"},
        {UDS_SERVICES_ERR,   "Error"},
        {UDS_SERVICES_CDTCS, "Control DTC Setting"},
        {0, NULL}
};
// Response code
static value_string uds_response_codes[]= {
        {UDS_RESPONSE_CODES_GR,      "General reject"},
        {UDS_RESPONSE_CODES_SNS,     "Service not supported"},
        {UDS_RESPONSE_CODES_SFNS,    "Sub-Function Not Supported"},
        {UDS_RESPONSE_CODES_IMLOIF,  "Incorrect Message Length or Invalid Format"},
        {UDS_RESPONSE_CODES_RTL,     "Response too long"},
        {UDS_RESPONSE_CODES_BRR,     "Busy repeat request"},
        {UDS_RESPONSE_CODES_CNC,     "Conditions Not Correct"},
        {UDS_RESPONSE_CODES_RSE,     "Request Sequence Error"},
        {UDS_RESPONSE_CODES_NRFSC,   "No response from sub-net component"},
        {UDS_RESPONSE_CODES_FPEORA,  "Failure prevents execution of requested action"},
        {UDS_RESPONSE_CODES_ROOR,    "Request Out of Range"},
        {UDS_RESPONSE_CODES_SAD,     "Security Access Denied"},
        {UDS_RESPONSE_CODES_IK,      "Invalid Key"},
        {UDS_RESPONSE_CODES_ENOA,    "Exceeded Number Of Attempts"},
        {UDS_RESPONSE_CODES_RTDNE,   "Required Time Delay Not Expired"},
        {UDS_RESPONSE_CODES_UDNA,    "Upload/Download not accepted"},
        {UDS_RESPONSE_CODES_TDS,     "Transfer data suspended"},
        {UDS_RESPONSE_CODES_GPF,     "General Programming Failure"},
        {UDS_RESPONSE_CODES_WBSC,    "Wrong Block Sequence Counter"},
        {UDS_RESPONSE_CODES_RCRRP,   "Request correctly received, but response is pending"},
        {UDS_RESPONSE_CODES_SFNSIAS, "Sub-Function not supported in active session"},
        {UDS_RESPONSE_CODES_SNSIAS,  "Service not supported in active session"},
        {0, NULL}
};

// DSC
static value_string uds_dsc_sub_functions[] = {
        {0, "Reserved"},
        {UDS_DSC_SUB_FUNCTIONS_DEFAULT_SESSION, "Default Session"},
        {UDS_DSC_SUB_FUNCTIONS_PROGRAMMING_SESSION, "Programming Session"},
        {UDS_DSC_SUB_FUNCTIONS_EXTENDED_DIAGNOSTIC_SESSION, "Extended Diagnostic Session"},
        {UDS_DSC_SUB_FUNCTIONS_SAFTY_SYSTEM_DIAGNOSTIC_SESSION, "Safty System Diagnostic Session"},
        {0, NULL}
};

// ER
static value_string uds_er_sub_functions[] = {
        {0, "Reserved"},
        {UDS_ER_SUB_FUNCTIONS_HARD_RESET, "Hard Reset"},
        {UDS_ER_SUB_FUNCTIONS_KEY_ON_OFF_RESET, "Key On Off Reset"},
        {UDS_ER_SUB_FUNCTIONS_SOFT_RESET, "Soft Reset"},
        {UDS_ER_SUB_FUNCTIONS_ENABLE_RAPID_POWER_SHUTDOWN, "Enable Rapid Power Shutdown"},
        {UDS_ER_SUB_FUNCTIONS_DISABLE_RAPID_POWER_SHUTDOWN, "Disable Rapid Power Shutdown"},
        {0, NULL}
};

// SA
static value_string uds_sa_types[] = {
        {UDS_SA_TYPES_SEED, "Request Seed"},
        {UDS_SA_TYPES_KEY, "Send Key"},
        {UDS_SA_TYPES_SEED_2, "Request Seed"},
        {UDS_SA_TYPES_KEY_2, "Send Key"},
        {0, NULL}
};

// RDTCI
static value_string uds_rdtci_types[] = {
        {UDS_RDTCI_TYPES_NUMBER_BY_STATUS_MASK, "Report Number of DTC by Status Mask"},
        {UDS_RDTCI_TYPES_BY_STATUS_MASK, "Report DTC by Status Mask"},
        {UDS_RDTCI_TYPES_SNAPSHOT_IDENTIFICATION, "Report DTC Snapshot Identification"},
        {UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_DTC, "Report DTC Snapshot Record by DTC Number"},
        {UDS_RDTCI_TYPES_SNAPSHOT_RECORD_BY_RECORD, "Report DTC Snapshot Record by Record Number"},
        {UDS_RDTCI_TYPES_EXTENDED_RECARD_BY_DTC, "Report DTC Extended Data Record by DTC Number"},
        {UDS_RDTCI_TYPES_SUPPORTED_DTC, "Report Supported DTC"},
        {0, NULL}
};

// RC
static value_string uds_rc_types[] = {
        {0, "Reserved"},
        {UDS_RC_TYPES_START, "Start routine"},
        {UDS_RC_TYPES_STOP, "Stop routine"},
        {UDS_RC_TYPES_REQUEST, "Request routine result"},
        {0, NULL}
};

// CDTCS
static value_string uds_cdtcs_types[] = {
        {UDS_CDTCS_ACTIONS_ON, "On"},
        {UDS_CDTCS_ACTIONS_OFF, "Off"},
        {0, NULL}
};

//
// Fields
//
static int hf_uds_service = -1;
static int hf_uds_reply = -1;

static int hf_uds_dsc_sub_function = -1;
static int hf_uds_dsc_parameter_record = -1;

static int hf_uds_er_sub_function = -1;

static int hf_uds_rdtci_type = -1;
static int hf_uds_rdtci_record = -1;

static int hf_uds_rdbi_data_identifier = -1;
static int hf_uds_rdbi_data_record = -1;

static int hf_uds_sa_type = -1;
static int hf_uds_sa_key = -1;
static int hf_uds_sa_seed = -1;

static int hf_uds_wdbi_data_identifier = -1;
static int hf_uds_wdbi_data_record = -1;

static int hf_uds_rc_type = -1;
static int hf_uds_rc_identifier = -1;
static int hf_uds_rc_option_record = -1;
static int hf_uds_rc_info = -1;
static int hf_uds_rc_status_record = -1;

static int hf_uds_rd_compression_method = -1;
static int hf_uds_rd_encrypting_method = -1;
static int hf_uds_rd_memory_size_length = -1;
static int hf_uds_rd_memory_address_length = -1;
static int hf_uds_rd_memory_address = -1;
static int hf_uds_rd_memory_size = -1;
static int hf_uds_rd_max_number_of_block_length_length = -1;
static int hf_uds_rd_max_number_of_block_length = -1;

static int hf_uds_tp_sub_function = -1;
static int hf_uds_tp_suppress_pos_rsp_msg_indification = -1;

static int hf_uds_err_sid = -1;
static int hf_uds_err_code = -1;

static int hf_uds_cdtcs_type = -1;

//
// Trees
//
static gint ett_uds = -1;
static gint ett_uds_dsc = -1;
static gint ett_uds_er = -1;
static gint ett_uds_rdtci = -1;
static gint ett_uds_rdbi = -1;
static gint ett_uds_sa = -1;
static gint ett_uds_wdbi = -1;
static gint ett_uds_rc = -1;
static gint ett_uds_rd = -1;
static gint ett_uds_tp = -1;
static gint ett_uds_err = -1;
static gint ett_uds_cdtcs = -1;

static int proto_uds = -1;

static
guint8 masked_guint8_value(const guint8 value, const guint8 mask)
{
    return (value & mask) >> ws_ctz(mask);
}

static guint64
tvb_get_guintX(tvbuff_t *tvb, const gint offset, const gint size, const guint encoding) {
    switch (size) {
        case 1:
            return tvb_get_guint8(tvb, offset);
        case 2:
            return tvb_get_guint16(tvb, offset, encoding);
        case 3:
            return tvb_get_guint24(tvb, offset, encoding);
        case 4:
            return tvb_get_guint32(tvb, offset, encoding);
        case 5:
            return tvb_get_guint40(tvb, offset, encoding);
        case 6:
            return tvb_get_guint48(tvb, offset, encoding);
        case 7:
            return tvb_get_guint56(tvb, offset, encoding);
        case 8:
            return tvb_get_guint64(tvb, offset, encoding);
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }
}

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

    if (service == UDS_SERVICES_DSC) {
        proto_tree *uds_dsc_tree;
        guint8 sub_function;

        uds_dsc_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_dsc, NULL, service_name);
        proto_tree_add_item(uds_dsc_tree, hf_uds_dsc_sub_function, tvb, UDS_DSC_SUB_FUNCTION_OFFSET,
                            UDS_DSC_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);
        sub_function = tvb_get_guint8(tvb, UDS_DSC_SUB_FUNCTION_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(sub_function, uds_dsc_sub_functions, "Unknown (0x%02x)"));

        if (sid & UDS_REPLY_MASK) {
            guint32 parameter_record_length = data_length - UDS_DSC_PARAMETER_RECORD_OFFSET;
            proto_tree_add_item(uds_dsc_tree, hf_uds_dsc_parameter_record, tvb,
                                UDS_DSC_PARAMETER_RECORD_OFFSET, parameter_record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_DSC_PARAMETER_RECORD_OFFSET,
                                                   parameter_record_length, ' '));
        }
    } else if (service == UDS_SERVICES_ER) {
        proto_tree *uds_er_tree;
        guint8 sub_function;

        uds_er_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_er, NULL, service_name);
        proto_tree_add_item(uds_er_tree, hf_uds_er_sub_function, tvb, UDS_ER_SUB_FUNCTION_OFFSET,
                            UDS_ER_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);
        sub_function = tvb_get_guint8(tvb, UDS_ER_SUB_FUNCTION_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(sub_function, uds_er_sub_functions, "Unknown (0x%02x)"));
    } else if (service == UDS_SERVICES_RDTCI) {
        proto_tree *uds_rtdci_tree;
        guint8 report_type;
        guint32 record_length = data_length - UDS_RDTCI_RECORD_OFFSET;

        uds_rtdci_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdtci, NULL, service_name);
        report_type = tvb_get_guint8(tvb, UDS_RDTCI_TYPE_OFFSET);
        proto_tree_add_item(uds_rtdci_tree, hf_uds_rdtci_type, tvb, UDS_RDTCI_TYPE_OFFSET,
                            UDS_RDTCI_TYPE_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rtdci_tree, hf_uds_rdtci_record, tvb,
                            UDS_RDTCI_RECORD_OFFSET, record_length, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s    %s",
                        val_to_str(report_type, uds_rdtci_types, "Unknown (0x%02x)"),
                        tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDTCI_RECORD_OFFSET,
                                               record_length, ' '));
    } else if (service == UDS_SERVICES_RDBI) {
        proto_tree *uds_rdbi_tree;
        guint16 data_identifier;

        uds_rdbi_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rdbi, NULL, service_name);
        data_identifier = tvb_get_guint16(tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_identifier, tvb, UDS_RDBI_DATA_IDENTIFIER_OFFSET,
                            UDS_RDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN);
        if (sid & UDS_REPLY_MASK) {
            guint32 record_length = data_length - UDS_RDBI_DATA_RECORD_OFFSET;
            proto_tree_add_item(uds_rdbi_tree, hf_uds_rdbi_data_record, tvb, UDS_RDBI_DATA_RECORD_OFFSET,
                                record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", data_identifier,
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_RDBI_DATA_RECORD_OFFSET, record_length,
                                                   ' '));
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
        }
    } else if (service == UDS_SERVICES_SA) {
        proto_tree *uds_sa_tree;
        guint8 security_access_type;

        uds_sa_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_sa, NULL, service_name);
        proto_tree_add_item(uds_sa_tree, hf_uds_sa_type, tvb, UDS_SA_TYPE_OFFSET,
                            UDS_SA_TYPE_LEN, ENC_BIG_ENDIAN);
        security_access_type = tvb_get_guint8(tvb, UDS_SA_TYPE_OFFSET);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(security_access_type, uds_sa_types, "Unknown (0x%02x)"));

        if (sid & UDS_REPLY_MASK) {
            guint32 seed_length = data_length - UDS_SA_SEED_OFFSET;
            if (seed_length >0) {
                proto_tree_add_item(uds_sa_tree, hf_uds_sa_seed, tvb, UDS_SA_SEED_OFFSET, seed_length, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_SEED_OFFSET, seed_length, ' '));
            }
        } else {
            guint32 key_length = data_length - UDS_SA_KEY_OFFSET;
            if (key_length > 0) {
                proto_tree_add_item(uds_sa_tree, hf_uds_sa_key, tvb, UDS_SA_KEY_OFFSET, key_length, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_SA_KEY_OFFSET, key_length, ' '));
            }
        }
    } else if (service == UDS_SERVICES_WDBI) {
        proto_tree *uds_wdbi_tree;
        guint16 data_identifier;

        uds_wdbi_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_wdbi, NULL, service_name);
        data_identifier = tvb_get_guint16(tvb, UDS_WDBI_DATA_IDENTIFIER_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_wdbi_tree, hf_uds_wdbi_data_identifier, tvb, UDS_WDBI_DATA_IDENTIFIER_OFFSET,
                            UDS_WDBI_DATA_IDENTIFIER_LEN, ENC_BIG_ENDIAN);
        if (sid & UDS_REPLY_MASK) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x", data_identifier);
        } else {
            guint32 record_length = data_length - UDS_WDBI_DATA_RECORD_OFFSET;
            proto_tree_add_item(uds_wdbi_tree, hf_uds_wdbi_data_record, tvb, UDS_WDBI_DATA_RECORD_OFFSET,
                                record_length, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%04x   %s", data_identifier,
                            tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, UDS_WDBI_DATA_RECORD_OFFSET, record_length,
                                                   ' '));
        }
    } else if (service == UDS_SERVICES_RC) {
        proto_tree *uds_rc_tree;
        guint8 type;
        guint16 identifier;

        uds_rc_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rc, NULL, service_name);
        proto_tree_add_item(uds_rc_tree, hf_uds_rc_type, tvb, UDS_RC_TYPE_OFFSET,
                            UDS_RC_TYPE_LEN, ENC_BIG_ENDIAN);
        type = tvb_get_guint8(tvb, UDS_RC_TYPE_OFFSET);

        identifier = tvb_get_guint16(tvb, UDS_RC_ROUTINE_OFFSET, ENC_BIG_ENDIAN);
        proto_tree_add_item(uds_rc_tree, hf_uds_rc_identifier, tvb, UDS_RC_ROUTINE_OFFSET,
                            UDS_RC_ROUTINE_LEN, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s 0x%04x",
                        val_to_str(type, uds_rc_types, "Unknown (0x%02x)"), identifier);
        if (sid & UDS_REPLY_MASK) {
            guint32 rc_data_len = data_length - UDS_RC_INFO_OFFSET;
            if (rc_data_len > 0) {
                guint8 info = tvb_get_guint8(tvb, UDS_RC_INFO_OFFSET);
                proto_tree_add_item(uds_rc_tree, hf_uds_rc_info, tvb,
                                    UDS_RC_INFO_OFFSET, UDS_RC_INFO_LEN, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%x", info);
                if (rc_data_len > 1) {
                    guint32 status_record_len = data_length - UDS_RC_STATUS_RECORD_OFFSET;
                    proto_tree_add_item(uds_rc_tree, hf_uds_rc_status_record, tvb,
                                        UDS_RC_STATUS_RECORD_OFFSET, status_record_len, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                    tvb_bytes_to_str_punct(wmem_packet_scope(), tvb,
                                                           UDS_RC_STATUS_RECORD_OFFSET, status_record_len, ' '));
                }
            }
        } else {
            guint32 option_record_len = data_length - UDS_RC_OPTION_RECORD_OFFSET;
            if (option_record_len > 0) {
                proto_tree_add_item(uds_rc_tree, hf_uds_rc_option_record, tvb,
                                    UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                                tvb_bytes_to_str_punct(wmem_packet_scope(), tvb,
                                                       UDS_RC_OPTION_RECORD_OFFSET, option_record_len, ' '));
            }
        }
    } else if (service == UDS_SERVICES_RD) {
        proto_tree *uds_rd_tree;

        uds_rd_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_rd, NULL, service_name);
        if (sid & UDS_REPLY_MASK) {
            guint32 remaining_length = data_length - UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET;
            guint8 length_format_identifier, max_number_of_block_length_length;
            guint64 max_number_of_block_length;

            length_format_identifier = tvb_get_guint8(tvb, UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET);
            max_number_of_block_length_length = masked_guint8_value(length_format_identifier,
                                                                    UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_LENGTH_MASK);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_max_number_of_block_length_length, tvb,
                                UDS_RD_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                UDS_RD_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

            DISSECTOR_ASSERT(max_number_of_block_length_length == remaining_length);

            max_number_of_block_length = tvb_get_guintX(tvb, UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET,
                                                        max_number_of_block_length_length, ENC_BIG_ENDIAN);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_max_number_of_block_length, tvb,
                                UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_OFFSET,
                                max_number_of_block_length_length, ENC_BIG_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   Max Number Of Block Length 0x%lx", max_number_of_block_length);
        } else {
            guint32 remaining_length = data_length - UDS_RD_MEMORY_ADDRESS_OFFSET;
            guint8 data_format_identifier, compression, encryting;
            guint8 address_and_length_format_idenfifier, memory_size_length, memory_address_length;
            guint64 memory_size, memory_address;

            data_format_identifier = tvb_get_guint8(tvb, UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET);

            compression = masked_guint8_value(data_format_identifier, UDS_RD_COMPRESSION_METHOD_MASK);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_compression_method, tvb, UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET,
                                UDS_RD_DATA_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

            encryting = masked_guint8_value(data_format_identifier, UDS_RD_ENCRYPTING_METHOD_MASK);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_encrypting_method, tvb, UDS_RD_DATA_FORMAT_IDENTIFIER_OFFSET,
                                UDS_RD_DATA_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

            address_and_length_format_idenfifier = tvb_get_guint8(tvb,
                                                                  UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET);

            memory_size_length = masked_guint8_value(address_and_length_format_idenfifier,
                                                     UDS_RD_COMPRESSION_METHOD_MASK);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_memory_size_length, tvb,
                                UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

            memory_address_length = masked_guint8_value(address_and_length_format_idenfifier,
                                                        UDS_RD_ENCRYPTING_METHOD_MASK);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_memory_address_length, tvb,
                                UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_OFFSET,
                                UDS_RD_ADDRESS_AND_LENGTH_FORMAT_IDENTIFIER_LEN, ENC_BIG_ENDIAN);

            DISSECTOR_ASSERT((memory_size_length + memory_address_length) == remaining_length);

            memory_address = tvb_get_guintX(tvb, UDS_RD_MEMORY_ADDRESS_OFFSET, memory_address_length, ENC_BIG_ENDIAN);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_memory_address, tvb, UDS_RD_MEMORY_ADDRESS_OFFSET,
                                memory_address_length, ENC_BIG_ENDIAN);
            memory_size = tvb_get_guintX(tvb, UDS_RD_MEMORY_ADDRESS_OFFSET + memory_address_length,
                                         memory_size_length, ENC_BIG_ENDIAN);
            proto_tree_add_item(uds_rd_tree, hf_uds_rd_memory_size, tvb,
                                UDS_RD_MEMORY_ADDRESS_OFFSET + memory_address_length,
                                memory_size_length, ENC_BIG_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   0x%lx bytes at 0x%lx", memory_size, memory_address);

            col_append_fstr(pinfo->cinfo, COL_INFO, "   (Compression:0x%x Encrypting:0x%x)", compression, encryting);
        }
    } else if (service == UDS_SERVICES_TP) {
        proto_tree *uds_tp_tree;
        guint8 sub_function_a, sub_function;
        uds_tp_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_tp, NULL, service_name);

        sub_function_a = tvb_get_guint8(tvb, UDS_TP_SUB_FUNCTION_OFFSET);
        sub_function = masked_guint8_value(sub_function_a, UDS_TP_SUB_FUNCTION_MASK);
        proto_tree_add_item(uds_tp_tree, hf_uds_tp_sub_function, tvb,
                            UDS_TP_SUB_FUNCTION_OFFSET, UDS_TP_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, "   Sub-function %x", sub_function);

        if (!(sid & UDS_REPLY_MASK)) {
            guint8 suppress = masked_guint8_value(sub_function_a, UDS_TP_SUPPRESS_POS_RSP_MSG_INDIFICATION_MASK);

            proto_tree_add_item(uds_tp_tree, hf_uds_tp_suppress_pos_rsp_msg_indification, tvb,
                                UDS_TP_SUB_FUNCTION_OFFSET, UDS_TP_SUB_FUNCTION_LEN, ENC_BIG_ENDIAN);

            if (suppress) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "   (Reply suppressed)");
            }
        }
    } else if (service == UDS_SERVICES_ERR) {
        proto_tree *uds_err_tree;
        guint8 error_sid, error_code;
        const char *error_service_name, *error_name;

        uds_err_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_err, NULL, service_name);
        error_sid = tvb_get_guint8(tvb, UDS_ERR_SID_OFFSET);
        error_service_name = val_to_str(error_sid, uds_services, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_sid, tvb, UDS_ERR_SID_OFFSET, UDS_ERR_SID_LEN, ENC_BIG_ENDIAN);
        error_code = tvb_get_guint8(tvb, UDS_ERR_CODE_OFFSET);
        error_name = val_to_str(error_code, uds_response_codes, "Unknown (0x%02x)");
        proto_tree_add_item(uds_err_tree, hf_uds_err_code, tvb, UDS_ERR_CODE_OFFSET, UDS_ERR_CODE_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s (SID: %s)", error_name, error_service_name);
    } else if (service == UDS_SERVICES_CDTCS) {
        proto_tree *uds_cdtcs_tree;
        guint8 type;

        uds_cdtcs_tree = proto_tree_add_subtree(uds_tree, tvb, 0, -1, ett_uds_cdtcs, NULL, service_name);
        type = tvb_get_guint8(tvb, UDS_CDTCS_TYPE_OFFSET);
        proto_tree_add_item(uds_cdtcs_tree, hf_uds_cdtcs_type, tvb,
                            UDS_CDTCS_TYPE_OFFSET, UDS_CDTCS_TYPE_LEN, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
                        val_to_str(type, uds_cdtcs_types, "Unknown (0x%02x)"));
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
                    &hf_uds_dsc_sub_function,
                    {
                            "Type", "uds.dsc.sub_function",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_dsc_sub_functions), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_dsc_parameter_record,
                    {
                            "Parameter Record", "uds.dsc.paramter_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_er_sub_function,
                    {
                            "Sub Function", "uds.dsc.sub_function",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_er_sub_functions), 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_rdtci_type,
                    {
                            "Type", "uds.rdtci.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rdtci_types), 0x0,
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
                    &hf_uds_rc_type,
                    {
                            "Type", "uds.rc.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_rc_types), 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_identifier,
                    {
                            "Identifier", "uds.rc.identifier",
                            FT_UINT16, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_option_record,
                    {
                            "Option record", "uds.rc.option_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_info,
                    {
                            "Info", "uds.rc.info",
                            FT_UINT8, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rc_status_record,
                    {
                            "Status Record", "uds.rc.status_record",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_rd_compression_method,
                    {
                            "Compression Method", "uds.rd.compression_method",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_COMPRESSION_METHOD_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_encrypting_method,
                    {
                            "Encrypting Method", "uds.rd.encrypting_method",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_ENCRYPTING_METHOD_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_size_length,
                    {
                            "Memory size length", "uds.rd.memory_size_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MEMORY_SIZE_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_address_length,
                    {
                            "Memory address length", "uds.rd.memory_address_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MEMORY_ADDRESS_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_address,
                    {
                            "Memory Address", "uds.rd.memory_address",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_memory_size,
                    {
                            "Memory Size", "uds.rd.memory_size",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_max_number_of_block_length_length,
                    {
                            "Memory address length", "uds.rd.max_number_of_block_length_length",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_RD_MAX_NUMBER_OF_BLOCK_LENGTH_LENGTH_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_rd_max_number_of_block_length,
                    {
                            "Memory Size", "uds.rd.max_number_of_block_length",
                            FT_UINT64, BASE_HEX,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },


            {
                    &hf_uds_tp_sub_function,
                    {
                            "Suppress reply", "uds.rd.suppress_reply",
                            FT_UINT8, BASE_HEX,
                            NULL, UDS_TP_SUB_FUNCTION_MASK,
                            NULL, HFILL
                    }
            },
            {
                    &hf_uds_tp_suppress_pos_rsp_msg_indification,
                    {
                            "Suppress reply", "uds.rd.suppress_reply",
                            FT_BOOLEAN, BASE_HEX,
                            NULL, UDS_TP_SUPPRESS_POS_RSP_MSG_INDIFICATION_MASK,
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
                            VALS(uds_response_codes), 0x0,
                            NULL, HFILL
                    }
            },

            {
                    &hf_uds_cdtcs_type,
                    {
                            "Type", "uds.cdtcs.type",
                            FT_UINT8, BASE_HEX,
                            VALS(uds_cdtcs_types), 0x0,
                            NULL, HFILL
                    }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
            {
                    &ett_uds,
                    &ett_uds_dsc,
                    &ett_uds_er,
                    &ett_uds_rdtci,
                    &ett_uds_rdbi,
                    &ett_uds_sa,
                    &ett_uds_wdbi,
                    &ett_uds_rc,
                    &ett_uds_rd,
                    &ett_uds_tp,
                    &ett_uds_err,
                    &ett_uds_cdtcs,
            };

    proto_uds = proto_register_protocol (
            "Unified Diagnostic Services", /* name       */
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
    dissector_add_for_decode_as("iso15765.message", uds_handle);
#define HACK
#ifdef HACK
    dissector_add_for_decode_as("can.subdissector", uds_handle);
#endif /* HACK */
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
