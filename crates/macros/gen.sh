#!/bin/bash
LINES=$(grep "u8 \?=\\|i32 \?=" "`dirname $0`/../consts/src/lib.rs" | grep "0x\\|as" | grep -v MASK | grep "pub const BPF" \
  | awk '{ gsub(";", "", $7); print "    (\"" $3 "\", " $7 ")," }')
COUNT=$(echo "$LINES" | wc --lines)

echo "// This file was partly generated from ../gen.sh"
echo
echo "/// Opcode components"
echo "pub const OPCODES: [(&'static str, u8); $COUNT] = ["
echo "$LINES"
echo "];"
