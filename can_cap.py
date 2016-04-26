#!/usr/bin/env python

from __future__ import print_function

"""
tcpdump capture file
"""
import sys
from construct import *
from calendar import timegm
from datetime import datetime, date, timedelta
import binascii
import re

class MicrosecAdapter(Adapter):
    def _decode(self, obj, context):
        return datetime.utcfromtimestamp(obj[0] + (obj[1] / 1000000.0))
    def _encode(self, obj, context):
        sec = timegm(obj.utctimetuple())
        usec = obj.microsecond
        return (sec, usec)

can_packet = Struct("can_packet",
    UBInt32("id"),
    ULInt8("dlc"),
    Padding(3),
    HexDumpAdapter(Field("data", lambda ctx: ctx.dlc)),
)

cap_packet = Struct("packet",
    MicrosecAdapter(
        Sequence("time",
            ULInt32("sec"),
            ULInt32("usec"),
        )
    ),
    ULInt32("inc_length"),
    ULInt32("orig_length"),
    HexDumpAdapter(Field("data", lambda ctx: ctx.inc_length)),
)

cap_file = Struct("cap_file",
    Const(ULInt32("magic_number"), 0xa1b2c3d4),
    Const(ULInt16("version_major"), 0x2),
    Const(ULInt16("version_minor"), 0x4),
    SLInt32("thiszone"),
    ULInt32("sigfigs"),
    ULInt32("snaplen"),
    Const(ULInt32("network"), 0xe3),
    Rename("packets", OptionalGreedyRange(cap_packet)),
)

def parse_can_date(date):
    return datetime.strptime(date, '%m/%d/%Y at %H:%M:%S.%f')

def parse_can_data(line):
    entries = [int(x, 16) for x in line.split()]
    assert len(entries) >= 4
    id = entries[0] << 24 & entries[1] << 16 & entries[2] << 8 & entries[3]
    return can_packet.build(Container(
        id = id,
        dlc = len(entries) - 4,
        data = bytearray(entries[4:]),
    ))

if __name__ == "__main__":
    packets = []
    data = ""
    for line in sys.stdin:
        data += line

    data = data.replace('\r\n', '\n')

    groups = data.split('\n\n\n')

    regex = re.compile("On ([^,]+), (\w+?) O:.*" + "\s*RxStatus:\s*([^\n]*)\s*\n" + ".*" + "\s*Data \[\w+\]:\s*([^\n]*)\s*\n" +  ".*", re.DOTALL | re.MULTILINE | re.IGNORECASE)

    def add(date, data):
        data = parse_can_data(data)
        date = parse_can_date(date)
        packets.append(Container(
            time = date,
            inc_length = len(data),
            orig_length = len(data),
            data = data,
        ))

    for g in groups:
        for r in regex.findall(g):
            act = r[1]
            if act == 'PassThruReadMsgs':
                if r[2] == 'No Flags Set':
                    add(r[0], r[3])
            if act == 'PassThruWriteMsgs':
                add(r[0], r[3])

    data = Container(
        magic_number = 0xa1b2c3d4,
        version_major = 0x2,
        version_minor = 0x4,
        network = 0xe3,
        thiszone = 0,
        sigfigs = 0,
        snaplen = 0xfffff,
        packets = packets
    )
    cap_file.build_stream(data, sys.stdout)

