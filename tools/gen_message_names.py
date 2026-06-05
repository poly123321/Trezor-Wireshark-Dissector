#!/usr/bin/env python3
"""
gen_message_names.py — generate the Codec v1 / THP message-type name map for the
trezor_dissector plugin directly from Trezor's messages.proto.

Why: the message-type numbers are the shared protobuf MessageType enum used by
both Codec v1 and THP. Hand-maintaining the Lua table is error-prone (a wrong
number silently mislabels a message).

Usage:
    python tools/gen_message_names.py /path/to/messages.proto > /tmp/names.lua
    python tools/gen_message_names.py /path/to/messages.proto --inplace
"""

import argparse
import re
import sys

ENTRY_RE = re.compile(
    r'MessageType_(?P<name>[A-Za-z0-9_]+)\s*=\s*(?P<num>\d+)\s*(?:\[.*\])?\s*;',
    re.DOTALL,
)


def strip_block_comments(text: str) -> str:
    return re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)


def extract_enum_block(text: str) -> str:
    start = re.search(r'enum\s+MessageType\s*\{', text)
    if not start:
        raise SystemExit("Could not find `enum MessageType {` in the proto file.")
    i = start.end()
    depth = 1
    while i < len(text) and depth > 0:
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
        i += 1
    return text[start.end():i - 1]


def parse_entries(block: str):
    no_line_comments = "\n".join(
        line.split("//", 1)[0] for line in block.splitlines()
    )
    entries = {}
    for stmt in no_line_comments.split(";"):
        stmt = stmt.strip()
        if not stmt or stmt.startswith("reserved") or stmt.startswith("option"):
            continue
        m = ENTRY_RE.match(stmt + ";")
        if m:
            entries[int(m.group("num"))] = m.group("name")
    return entries


def to_lua(entries: dict) -> str:
    out = []
    out.append("-- 02_constants.lua — message-name map (GENERATED, do not edit by hand).")
    out.append("-- Regenerate with: python tools/gen_message_names.py <messages.proto> --inplace")
    out.append("--")
    out.append("-- The MessageType numbers are the shared protobuf enum used by BOTH")
    out.append("-- Codec v1 and THP; only the framing differs. Includes DebugLink (100+)")
    out.append("-- so emulator test traffic is decoded too. Unknown numbers fall back to")
    out.append('-- "MessageType_<n>" at lookup time.')
    out.append("local v1_message_names = {")
    for num in sorted(entries):
        out.append(f'    [{num}] = "{entries[num]}",')
    out.append("}")
    out.append("")
    out.append("local function v1_message_name(msg_type)")
    out.append('    return v1_message_names[msg_type] or string.format("MessageType_%d", msg_type)')
    out.append("end")
    return "\n".join(out)


BEGIN_MARK = "-- >>> BEGIN GENERATED MESSAGE NAMES (gen_message_names.py) >>>"
END_MARK = "-- <<< END GENERATED MESSAGE NAMES <<<"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("proto", help="path to messages.proto")
    ap.add_argument("--inplace", metavar="MODULE",
                    help="rewrite the generated block inside this module",
                    nargs="?", const="src/02_constants.lua")
    args = ap.parse_args()
    with open(args.proto, encoding="utf-8") as f:
        text = f.read()
    text = strip_block_comments(text)
    block = extract_enum_block(text)
    entries = parse_entries(block)
    if not entries:
        raise SystemExit("No MessageType entries parsed — is this the right file?")
    lua = to_lua(entries)

    if args.inplace:
        mod = open(args.inplace, encoding="utf-8").read()
        wrapped = BEGIN_MARK + "\n" + lua + "\n" + END_MARK
        pat = re.compile(re.escape(BEGIN_MARK) + ".*?" + re.escape(END_MARK), re.DOTALL)
        if not pat.search(mod):
            raise SystemExit(
                f"Markers not found in {args.inplace}; add the BEGIN/END markers first.")
        mod = pat.sub(wrapped, mod)
        open(args.inplace, "w", encoding="utf-8").write(mod)
        print(f"Updated {args.inplace} ({len(entries)} entries)", file=sys.stderr)
    else:
        print(lua)
        print(f"\n-- generated {len(entries)} entries", file=sys.stderr)


if __name__ == "__main__":
    main()