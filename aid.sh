#!/bin/sh

RID="0xD2:0x76:0x00:0x01:0x24"
APP="0x01"
VERSION="0x03:0x00"
MFG="0x00:0x00"
SERIAL=$(dd if=/dev/urandom bs=1 count=4 2>/dev/null | hexdump -e '/1 "0x%02X:"')
RFU="0x00:0x00"
echo "${RID}:${APP}:${VERSION}:${MFG}:${SERIAL}${RFU}"
