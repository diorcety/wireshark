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

static int proto_uds = -1;

#define UNUSED(x) (void)(x)

static int
dissect_uds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    UNUSED(tree);
    UNUSED(data);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}

void
proto_register_uds(void)
{
    proto_uds = proto_register_protocol (
            "UDS Protocol", /* name       */
            "UDS",          /* short name */
            "uds"           /* abbrev     */
    );
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
