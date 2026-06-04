#!/usr/bin/env bash
#
# build.sh — assemble the modular sources in src/ into a single distributable
# Wireshark plugin: dist/trezor_dissector.lua
#
# Wireshark loads each .lua file in its plugin directory as an independent
# plugin with its own scope, so the development modules in src/ cannot simply be
# require()'d without package.path gymnastics. Instead we concatenate them, in
# order, into one self-contained file. Because every module uses file-local
# `local` declarations, concatenating them places all locals in one shared chunk
# scope — which is exactly what the original single-file plugin had.
#
# Usage:
#   ./build.sh
#
set -euo pipefail

cd "$(dirname "$0")"

OUT="dist/trezor_dissector.lua"
mkdir -p dist

# Order matters: fields/proto first, then constants, utils, the two protocol
# dissectors, the dispatcher, and finally the transport registrations.
MODULES=(
  src/01_proto_fields.lua
  src/02_constants.lua
  src/03_util.lua
  src/04_thp.lua
  src/05_codec_v1.lua
  src/06_dispatch.lua
  src/07_register.lua
)

{
  cat src/_header.lua
  for m in "${MODULES[@]}"; do
    echo ""
    echo "-- ==================================================================="
    echo "-- BEGIN $(basename "$m")"
    echo "-- ==================================================================="
    cat "$m"
  done
} > "$OUT"

echo "Built $OUT ($(wc -l < "$OUT") lines)"

# Optional syntax check if a lua compiler is present.
if command -v luac5.3 >/dev/null 2>&1; then
  luac5.3 -p "$OUT" && echo "Syntax OK (luac5.3)"
elif command -v luac >/dev/null 2>&1; then
  luac -p "$OUT" && echo "Syntax OK (luac)"
fi
