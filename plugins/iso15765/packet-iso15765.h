#pragma once

#ifndef _ISO15765_H
#define _ISO15765_H

#define ISO15765_PCI_OFFSET 0
#define ISO15765_PCI_LEN 1

#define ISO15765_MESSAGE_TYPE_MASK 0xF0
#define ISO15765_MESSAGE_TYPES_SINGLE_FRAME 0
#define ISO15765_MESSAGE_TYPES_FIRST_FRAME 1
#define ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME 2
#define ISO15765_MESSAGE_TYPES_FLOW_CONTROL 3

#define ISO15765_MESSAGE_DATA_LENGTH_MASK 0x0F
#define ISO15765_MESSAGE_EXTENDED_FRAME_LENGTH_MASK 0x0F
#define ISO15765_MESSAGE_FRAME_LENGTH_OFFSET (ISO15765_PCI_OFFSET + ISO15765_PCI_LEN)
#define ISO15765_MESSAGE_FRAME_LENGTH_LEN 1
#define ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK 0x0F
#define ISO15765_MESSAGE_FLOW_STATUS_MASK 0x0F

#define ISO15765_FC_BS_OFFSET (ISO15765_PCI_OFFSET + ISO15765_PCI_LEN)
#define ISO15765_FC_BS_LEN 1
#define ISO15765_FC_STMIN_OFFSET (ISO15765_FC_BS_OFFSET + ISO15765_FC_BS_LEN)
#define ISO15765_FC_STMIN_LEN 1

#endif /* _ISO15765_H */