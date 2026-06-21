#!/bin/sh
# gen_shellcode.sh — compile .S → .o → .bin → .h (C header with byte array)
#
# Usage: gen_shellcode.sh <input.S> <output.h> <var_prefix>
#
# Generates a C header with:
#   unsigned char <var_prefix>[] = { 0x90, 0x90, ... };
#   unsigned int <var_prefix>_len = 344;

set -e

SRC="$1"
OUT="$2"
VAR="$3"

TMPD=$(mktemp -d)
trap "rm -rf $TMPD" EXIT

cc -c -fPIC -nostdlib -fno-stack-protector "$SRC" -o "$TMPD/sc.o"
objcopy -O binary -j .text "$TMPD/sc.o" "$TMPD/sc.bin"

python3 - "$TMPD/sc.bin" "$VAR" > "$OUT" <<'PYEOF'
import sys
data = open(sys.argv[1], "rb").read()
name = sys.argv[2]
print(f"unsigned char {name}[] = {{")
for i in range(0, len(data), 12):
    line = ", ".join(f"0x{b:02x}" for b in data[i:i+12])
    print(f"  {line},")
print("};")
print(f"unsigned int {name}_len = {len(data)};")
PYEOF
