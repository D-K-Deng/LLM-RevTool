#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT_DIR/src"
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

CC="${CC:-gcc}"
CFLAGS_BASE="-O0 -g"

echo "[*] Building challenges with $CC"

"$CC" $CFLAGS_BASE "$SRC_DIR/branch_puzzle.c" -o "$BIN_DIR/branch_puzzle"
"$CC" $CFLAGS_BASE -fno-stack-protector -no-pie -z execstack "$SRC_DIR/stack_overflow.c" -o "$BIN_DIR/stack_overflow"
"$CC" $CFLAGS_BASE -fno-stack-protector -no-pie "$SRC_DIR/format_string.c" -o "$BIN_DIR/format_string"
"$CC" $CFLAGS_BASE "$SRC_DIR/integer_edge.c" -o "$BIN_DIR/integer_edge"

echo "[+] Done. Binaries in $BIN_DIR"
