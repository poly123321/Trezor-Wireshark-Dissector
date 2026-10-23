#!/usr/bin/env python3
"""
gen_message_fields.py — generate protobuf field maps for the Trezor Wireshark
dissector, so decrypted THP application messages (and Codec v1 messages) can be
shown as named fields instead of raw bytes.

Input is a protoc FileDescriptorSet (binary), produced with:

  protoc --descriptor_set_out=messages.desc --include_imports \
         -I common/protob common/protob/*.proto

The generated Lua block (written into src/02_constants.lua between markers) holds:

  pb_message_fields[<MsgName>][<field_no>] = {
      name=..., kind="varint|len|fixed64|fixed32",
      msg=<nested MsgName or nil>, enum=<EnumName or nil>, repeated=<bool>,
  }
  pb_enums[<EnumName>][<value>] = "<NAME>"

Message and enum names are the short, dotted local names (e.g. "TxRequest",
"TxRequest.TxRequestDetailsType", "TxRequest.RequestType"). The dissector looks
up a message by name, walks its fields, and recurses into nested messages.

Usage:
  python tools/gen_message_fields.py /tmp/messages.desc --inplace
"""

from __future__ import annotations

import argparse
from pathlib import Path

from google.protobuf import descriptor_pb2


BEGIN_MARK = "-- >>> BEGIN GENERATED MESSAGE FIELDS (gen_message_fields.py) >>>"
END_MARK = "-- <<< END GENERATED MESSAGE FIELDS <<<"

# protobuf field type -> wire type + a coarse "kind" the Lua parser switches on.
# wire types: 0 varint, 1 64-bit, 2 length-delimited, 5 32-bit.
T = descriptor_pb2.FieldDescriptorProto

# types carried as varint (wire 0)
VARINT_TYPES = {
    T.TYPE_INT32, T.TYPE_INT64, T.TYPE_UINT32, T.TYPE_UINT64,
    T.TYPE_SINT32, T.TYPE_SINT64, T.TYPE_BOOL, T.TYPE_ENUM,
}
# fixed 64-bit (wire 1)
FIXED64_TYPES = {T.TYPE_FIXED64, T.TYPE_SFIXED64, T.TYPE_DOUBLE}
# fixed 32-bit (wire 5)
FIXED32_TYPES = {T.TYPE_FIXED32, T.TYPE_SFIXED32, T.TYPE_FLOAT}
# length-delimited (wire 2): string, bytes, message, packed repeated
LEN_TYPES = {T.TYPE_STRING, T.TYPE_BYTES, T.TYPE_MESSAGE}


def short_name(fqname: str, package_prefixes: list[str]) -> str:
    """Strip a leading .package. prefix, keep the message-local dotted path."""
    name = fqname.lstrip(".")
    for pkg in package_prefixes:
        if name.startswith(pkg + "."):
            return name[len(pkg) + 1:]
    # fall back: drop everything up to the known message namespaces
    # e.g. hw.trezor.messages.bitcoin.TxRequest.RequestType -> TxRequest.RequestType
    parts = name.split(".")
    # find first capitalized segment (message/enum names are CamelCase)
    for idx, p in enumerate(parts):
        if p[:1].isupper():
            return ".".join(parts[idx:])
    return name


def kind_for(field) -> tuple[str, int]:
    """Return (kind, wire_type) for a field descriptor."""
    t = field.type
    if t in VARINT_TYPES:
        return "varint", 0
    if t in FIXED64_TYPES:
        return "fixed64", 1
    if t in FIXED32_TYPES:
        return "fixed32", 5
    if t in LEN_TYPES:
        return "len", 2
    # default: treat as length-delimited
    return "len", 2


def collect(fds: descriptor_pb2.FileDescriptorSet):
    """Walk all files; return (messages, enums, package_prefixes).

    messages: dict[short_msg_name] -> list of field dicts
    enums:    dict[short_enum_name] -> dict[value]=name
    """
    package_prefixes: list[str] = []
    for f in fds.file:
        if f.package:
            package_prefixes.append(f.package)
    # longest first so the most specific package strips correctly
    package_prefixes.sort(key=len, reverse=True)

    messages: dict[str, list[dict]] = {}
    enums: dict[str, dict[int, str]] = {}

    def walk_enum(en, prefix: str):
        name = prefix + en.name
        enums[name] = {v.number: v.name for v in en.value}

    def walk_message(msg, prefix: str):
        name = prefix + msg.name
        fields = []
        for fld in msg.field:
            kind, wire = kind_for(fld)
            entry = {
                "number": fld.number,
                "name": fld.name,
                "kind": kind,
                "wire": wire,
                "repeated": fld.label == T.LABEL_REPEATED,
                "msg": None,
                "enum": None,
            }
            if fld.type == T.TYPE_MESSAGE:
                entry["msg"] = short_name(fld.type_name, package_prefixes)
            elif fld.type == T.TYPE_ENUM:
                entry["enum"] = short_name(fld.type_name, package_prefixes)
            fields.append(entry)
        messages[name] = fields
        # nested
        for nested in msg.nested_type:
            walk_message(nested, name + ".")
        for en in msg.enum_type:
            walk_enum(en, name + ".")

    for f in fds.file:
        # Skip protobuf's own descriptor types pulled in by --include_imports;
        # we only want Trezor application messages.
        if not f.package.startswith("hw.trezor"):
            continue
        for msg in f.message_type:
            walk_message(msg, "")
        for en in f.enum_type:
            walk_enum(en, "")

    return messages, enums


def lua_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(messages, enums) -> str:
    out: list[str] = []
    out.append(BEGIN_MARK)
    out.append("-- Generated by tools/gen_message_fields.py from a protoc descriptor set.")
    out.append("-- Do not edit by hand; regenerate when the .proto files change.")
    out.append("")

    # enums first, one value per line so large enums (e.g. MessageType) stay
    # readable and regenerating after a .proto change gives a line-per-value diff
    out.append("local pb_enums = {")
    for ename in sorted(enums):
        vals = enums[ename]
        out.append(f"    [{lua_str(ename)}] = {{")
        for num in sorted(vals):
            out.append(f"        [{num}] = {lua_str(vals[num])},")
        out.append("    },")
    out.append("}")
    out.append("")

    # message field maps
    out.append("local pb_message_fields = {")
    for mname in sorted(messages):
        fields = messages[mname]
        if not fields:
            out.append(f"    [{lua_str(mname)}] = {{}},")
            continue
        out.append(f"    [{lua_str(mname)}] = {{")
        for fld in fields:
            bits = [
                f"name={lua_str(fld['name'])}",
                f"kind={lua_str(fld['kind'])}",
            ]
            if fld["repeated"]:
                bits.append("repeated=true")
            if fld["msg"]:
                bits.append(f"msg={lua_str(fld['msg'])}")
            if fld["enum"]:
                bits.append(f"enum={lua_str(fld['enum'])}")
            out.append(f"        [{fld['number']}] = {{ {', '.join(bits)} }},")
        out.append("    },")
    out.append("}")
    out.append(END_MARK)
    return "\n".join(out) + "\n"


def replace_generated_block(constants_path: Path, generated: str) -> None:
    text = constants_path.read_text(encoding="utf-8")
    start = text.find(BEGIN_MARK)
    end = text.find(END_MARK)
    if start == -1 or end == -1:
        # not present yet: append at end of file
        sep = "\n\n"
        constants_path.write_text(text.rstrip() + sep + generated, encoding="utf-8")
        return
    end += len(END_MARK)
    new_text = text[:start] + generated.rstrip() + text[end:]
    constants_path.write_text(new_text, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("descriptor", type=Path, help="protoc FileDescriptorSet (.desc)")
    ap.add_argument("--inplace", action="store_true")
    ap.add_argument("--constants", type=Path, default=Path("src/02_constants.lua"))
    args = ap.parse_args()

    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(args.descriptor.read_bytes())

    messages, enums = collect(fds)
    generated = render(messages, enums)

    if args.inplace:
        replace_generated_block(args.constants, generated)
        print(f"Updated {args.constants}: {len(messages)} messages, {len(enums)} enums")
    else:
        print(generated, end="")


if __name__ == "__main__":
    main()
