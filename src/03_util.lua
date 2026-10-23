-- 03_util.lua — helpers: CRC32, hex, direction resolution, heuristics.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh

local function direction_key(pinfo, cid)
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) ..
           "->" ..
           tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) ..
           "/cid=" .. string.format("0x%04X", cid)
end

local function ceil_div(a, b)
    if a <= 0 then
        return 0
    end
    return math.floor((a + b - 1) / b)
end

local function is_ack(control)
    return bit.band(control, ACK_MASK) == ACK_BASE
end

local function is_data(control)
    return bit.band(control, DATA_DETECT_MASK) == DATA_DETECT_BASE
end

local function is_continuation(control)
    return bit.band(control, CONTINUATION_BIT) ~= 0
end

local function base_data_control(control)
    return bit.band(control, DATA_MASK)
end

local function control_name(control)
    if is_continuation(control) then
        return "CONTINUATION"
    end

    if fixed_names[control] ~= nil then
        return fixed_names[control]
    end

    if is_ack(control) then
        local ack_bit = bit.band(control, ACK_SEQ_BIT) ~= 0
        return ack_bit and "ACK1" or "ACK0"
    end

    if is_data(control) then
        local base_control = base_data_control(control)
        local name = data_names[base_control] or "DATA_RESERVED"
        local seq_bit = bit.band(control, DATA_SEQ_BIT) ~= 0
        local ack_bit = bit.band(control, DATA_ACK_SEQ_BIT) ~= 0
        return string.format("%s seq%d ack%d", name, seq_bit and 1 or 0, ack_bit and 1 or 0)
    end

    return "RESERVED"
end

-- Determine communication direction (who is host, who is Trezor).
-- Combines message type (unambiguous REQ/RES) with transport direction.
-- Returns: src_role, dst_role (strings "Host" / "Trezor")
local HOST_INITIATED = {
    [CHANNEL_ALLOCATION_REQ] = true,
    [HANDSHAKE_INIT_REQ] = true,
    [HANDSHAKE_COMP_REQ] = true,
    [PING] = true,
}
local DEVICE_INITIATED = {
    [CHANNEL_ALLOCATION_RES] = true,
    [HANDSHAKE_INIT_RES] = true,
    [HANDSHAKE_COMP_RES] = true,
    [PONG] = true,
    [ERROR] = true,
}

-- Per-channel remembered identity of the transport side that is the "host".
-- Key = transport src string of whoever sent CHANNEL_ALLOCATION_REQ.
local host_transport_side = {}

-- True if `port` falls within the emulator port spec ("21324", "21324-21400",
-- "21324,21326"). Kept here so the direction heuristic and registration agree.
local function port_in_spec(port, spec)
    if port == nil or spec == nil then return false end
    for part in tostring(spec):gmatch("[^,]+") do
        part = part:gsub("%s", "")
        local lo, hi = part:match("^(%d+)%-(%d+)$")
        if lo ~= nil then
            if port >= tonumber(lo) and port <= tonumber(hi) then return true end
        elseif part:match("^(%d+)$") ~= nil then
            if port == tonumber(part) then return true end
        end
    end
    return false
end

local function resolve_direction(pinfo, control, cid)
    -- 1) Unambiguous by message type.
    local base_control = control
    if is_data(control) then
        base_control = base_data_control(control)
    end

    -- Remember which transport side is the host (sent the REQ).
    local cid_key = string.format("0x%04X", cid)
    if HOST_INITIATED[control] or HOST_INITIATED[base_control] then
        host_transport_side[cid_key] = tostring(pinfo.src)
        return "Host", "Trezor"
    end
    if DEVICE_INITIATED[control] or DEVICE_INITIATED[base_control] then
        -- sender is Trezor
        host_transport_side[cid_key] = tostring(pinfo.dst)
        return "Trezor", "Host"
    end

    -- 2) Bidirectional messages (ENCRYPTED_TRANSPORT, ACK, CONTINUATION):
    --    derive from transport direction using the remembered host.
    local host_side = host_transport_side[cid_key]
    if host_side ~= nil then
        if tostring(pinfo.src) == host_side then
            return "Host", "Trezor"
        else
            return "Trezor", "Host"
        end
    end

    if port_in_spec(tonumber(tostring(pinfo.dst_port)), thp.prefs.udp_ports) then
        return "Host", "Trezor"
    end
    if port_in_spec(tonumber(tostring(pinfo.src_port)), thp.prefs.udp_ports) then
        return "Trezor", "Host"
    end

    -- 4) Cannot determine.
    return nil, nil
end

local function looks_like_thp(buffer)
    if buffer:len() < 2 then
        return false
    end

    local b0 = buffer(0, 1):uint()

    -- Codec v1: "##" magic, optionally preceded by 0x3F report id.
    if b0 == 0x23 and buffer(1, 1):uint() == 0x23 then
        return true
    end
    if b0 == 0x3F and buffer:len() >= 2 then
        -- 0x3F starts both a v1 first packet (3F 23 ...) and a v1
        -- continuation (3F <data>). Either way it's ours.
        return true
    end

    if buffer:len() < 3 then
        return false
    end

    local control = b0

    if fixed_names[control] ~= nil then
        return true
    end

    if is_ack(control) then
        return true
    end

    if is_data(control) then
        return true
    end

    if is_continuation(control) then
        return true
    end

    return false
end

local function add_padding_if_any(subtree, buffer, offset, total_len)
    if offset < total_len then
        subtree:add(f_padding, buffer(offset, total_len - offset))
    end
end

-- Convert possible signed 32-bit Lua value to unsigned display value.
local function u32(value)
    if value < 0 then
        return value + 0x100000000
    end
    return value
end

local function crc32_ieee_bytes(bytes)
    local crc = 0xFFFFFFFF

    for i = 1, #bytes do
        crc = bit.bxor(crc, string.byte(bytes, i))

        for _ = 1, 8 do
            if bit.band(crc, 1) ~= 0 then
                crc = bit.bxor(bit.rshift(crc, 1), 0xEDB88320)
            else
                crc = bit.rshift(crc, 1)
            end
        end
    end

    return u32(bit.bxor(crc, 0xFFFFFFFF))
end

local function crc32_ieee(buffer, offset, length)
    local bytes = ""
    for i = offset, offset + length - 1 do
        bytes = bytes .. string.char(buffer(i, 1):uint())
    end
    return crc32_ieee_bytes(bytes)
end

local function range_to_raw(buffer, offset, length)
    local out = ""
    if length <= 0 then
        return out
    end

    for i = offset, offset + length - 1 do
        out = out .. string.char(buffer(i, 1):uint())
    end
    return out
end

local function bytes_to_hex(bytes)
    return (bytes:gsub('.', function(c)
        return string.format('%02X', string.byte(c))
    end))
end

local function hex_len(hex)
    if hex == nil then
        return 0
    end
    return math.floor(#hex / 2)
end

local function hex_slice(hex, start_byte, byte_len)
    local start_i = start_byte * 2 + 1
    local end_i = start_i + byte_len * 2 - 1
    return string.sub(hex, start_i, end_i)
end

local function read_u32_be_from_bytes(bytes, offset_1_based)
    local b1 = string.byte(bytes, offset_1_based)
    local b2 = string.byte(bytes, offset_1_based + 1)
    local b3 = string.byte(bytes, offset_1_based + 2)
    local b4 = string.byte(bytes, offset_1_based + 3)

    return b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
end

-- THP pairing method names (from ThpPairingMethod enum in the spec).
local PAIRING_METHOD_NAMES = {
    [1] = "SkipPairing",
    [2] = "CodeEntry",
    [3] = "QrCode",
    [4] = "NFC",
}

-- ----------------------------------------------------------------------
-- Minimal protobuf wire-format reader.
-- See https://protobuf.dev/programming-guides/encoding/
--
-- A serialized message is a sequence of fields, each one:
--   tag   varint = (field_number << 3) | wire_type
--   value encoded according to wire_type:
-- ----------------------------------------------------------------------

-- int32/int64/uint32/uint64/sint32/sint64/bool/enum: one varint
local PB_WIRE_VARINT = 0
-- fixed64/sfixed64/double: 8 bytes, little-endian
local PB_WIRE_I64 = 1
-- string/bytes/nested message/packed repeated: varint byte length, then the bytes
local PB_WIRE_LEN = 2
-- fixed32/sfixed32/float: 4 bytes, little-endian
local PB_WIRE_I32 = 5
-- (wire types 3 and 4 are the deprecated proto2 groups; Trezor protos don't use them)

local PB_I64_SIZE = 8
local PB_I32_SIZE = 4

-- Varints store 7 value bits per byte, least significant group first. The
-- high bit is set on every byte except the last, so for a byte b:
-- b % 0x80 is its value bits, and b < 0x80 means it ends the varint.
local PB_VARINT_CONT_BIT = 0x80
local PB_VARINT_GROUP_BITS = 7
local PB_VARINT_MAX_SHIFT = 63   -- a varint encodes at most 64 bits (10 bytes)

-- Split a field tag into (field_number, wire_type).
local PB_WIRE_TYPE_RANGE = 8     -- 2^3: wire type occupies the low 3 bits
local function pb_split_tag(tag)
    return math.floor(tag / PB_WIRE_TYPE_RANGE), tag % PB_WIRE_TYPE_RANGE
end

-- Read a base-128 varint from byte-string `s` at 1-based index `i`.
-- Returns value (integer), next_index.
local function pb_read_varint(s, i)
    local result = 0
    local shift = 0
    while i <= #s do
        local b = string.byte(s, i)
        i = i + 1
        result = result + (b % PB_VARINT_CONT_BIT) * (2 ^ shift)
        if b < PB_VARINT_CONT_BIT then return math.floor(result), i end
        shift = shift + PB_VARINT_GROUP_BITS
        if shift > PB_VARINT_MAX_SHIFT then return math.floor(result), i end
    end
    return math.floor(result), i
end

-- Field numbers of ThpDeviceProperties (common/protob/messages-thp.proto).
local THP_DEVPROP_INTERNAL_MODEL = 1          -- string, e.g. "T3W1"
local THP_DEVPROP_MODEL_VARIANT = 2           -- uint32 (device color etc.)
local THP_DEVPROP_PROTOCOL_VERSION_MAJOR = 3  -- uint32
local THP_DEVPROP_PROTOCOL_VERSION_MINOR = 4  -- uint32
local THP_DEVPROP_PAIRING_METHODS = 5         -- repeated ThpPairingMethod enum

-- Parse a serialized ThpDeviceProperties protobuf (from ChannelAllocationResponse).
-- Returns a table: internal_model, model_variant, protocol_version_major/minor,
-- pairing_methods (list of numbers), warnings (list of strings).
local function parse_device_properties(s)
    local out = { pairing_methods = {}, warnings = {} }
    local i = 1
    while i <= #s do
        local tag
        tag, i = pb_read_varint(s, i)
        local field_no, wire_type = pb_split_tag(tag)
        if wire_type == PB_WIRE_VARINT then
            local v
            v, i = pb_read_varint(s, i)
            if field_no == THP_DEVPROP_MODEL_VARIANT then out.model_variant = v
            elseif field_no == THP_DEVPROP_PROTOCOL_VERSION_MAJOR then out.protocol_version_major = v
            elseif field_no == THP_DEVPROP_PROTOCOL_VERSION_MINOR then out.protocol_version_minor = v
            -- unpacked repeated enum: one varint per element
            elseif field_no == THP_DEVPROP_PAIRING_METHODS then out.pairing_methods[#out.pairing_methods + 1] = v
            else out.warnings[#out.warnings + 1] = string.format("unknown varint field %d", field_no) end
        elseif wire_type == PB_WIRE_LEN then
            local len
            len, i = pb_read_varint(s, i)
            local chunk = string.sub(s, i, i + len - 1)
            i = i + len
            if field_no == THP_DEVPROP_INTERNAL_MODEL then out.internal_model = chunk
            -- packed repeated enum: all elements as consecutive varints in one chunk
            elseif field_no == THP_DEVPROP_PAIRING_METHODS then
                local j = 1
                while j <= #chunk do
                    local v; v, j = pb_read_varint(chunk, j)
                    out.pairing_methods[#out.pairing_methods + 1] = v
                end
            else out.warnings[#out.warnings + 1] = string.format("unknown field %d (%d bytes)", field_no, len) end
        else
            out.warnings[#out.warnings + 1] = string.format("unsupported wire type %d (field %d)", wire_type, field_no)
            break
        end
    end
    return out
end


-- ======================================================================
-- Recursive protobuf field formatter for decrypted application messages.
-- Reads the generated pb_message_fields / pb_enums tables (02_constants.lua)
-- and turns a serialized protobuf into a tree of "name: value" lines, naming
-- fields and translating enums. Nested messages recurse (depth-limited).
-- ======================================================================

local PB_MAX_DEPTH = 6
-- Non-printable bytes fields up to this length are shown in full as hex;
-- longer ones are truncated to a PB_HEX_PREVIEW_LEN-byte preview.
local PB_HEX_FULL_MAX_LEN = 32
local PB_HEX_PREVIEW_LEN = 16

-- Split serialized protobuf `s` into a flat list of raw fields, without any
-- schema. Each entry has field_no, wire_type and the undecoded value:
--   PB_WIRE_VARINT -> varint (number)
--   PB_WIRE_LEN    -> chunk (raw bytes), len
--   PB_WIRE_I64    -> chunk (8 raw bytes), len
--   PB_WIRE_I32    -> chunk (4 raw bytes), len
-- Stops at the first unsupported wire type, since its length is unknown.
local function pb_parse_fields(s)
    local fields = {}
    local i = 1
    while i <= #s do
        local tag
        tag, i = pb_read_varint(s, i)
        local field_no, wire_type = pb_split_tag(tag)
        if wire_type == PB_WIRE_VARINT then
            local v
            v, i = pb_read_varint(s, i)
            fields[#fields + 1] = { field_no = field_no, wire_type = wire_type, varint = v }
        elseif wire_type == PB_WIRE_LEN then
            local len
            len, i = pb_read_varint(s, i)
            local chunk = string.sub(s, i, i + len - 1)
            i = i + len
            fields[#fields + 1] = { field_no = field_no, wire_type = wire_type, chunk = chunk, len = len }
        elseif wire_type == PB_WIRE_I64 then
            local chunk = string.sub(s, i, i + PB_I64_SIZE - 1)
            fields[#fields + 1] = { field_no = field_no, wire_type = wire_type, chunk = chunk, len = PB_I64_SIZE }
            i = i + PB_I64_SIZE
        elseif wire_type == PB_WIRE_I32 then
            local chunk = string.sub(s, i, i + PB_I32_SIZE - 1)
            fields[#fields + 1] = { field_no = field_no, wire_type = wire_type, chunk = chunk, len = PB_I32_SIZE }
            i = i + PB_I32_SIZE
        else
            fields[#fields + 1] = { field_no = field_no, wire_type = wire_type, unsupported = true }
            break
        end
    end
    return fields
end

local function pb_hex(s)
    return (s:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
end

local function pb_printable(s)
    if #s == 0 then return false end
    for k = 1, #s do
        local b = string.byte(s, k)
        if b < 0x20 or b > 0x7e then return false end
    end
    return true
end

local function pb_format_varint(v, enum_name)
    if enum_name and pb_enums[enum_name] then
        local n = pb_enums[enum_name][v]
        if n then
            return string.format("%s (%d)", n, v)
        end
    end
    return string.format("%d", v)
end

local function pb_format_into(out, msg_name, s, depth)
    if depth > PB_MAX_DEPTH then
        out[#out + 1] = { text = "(max depth reached)", depth = depth }
        return
    end
    local fieldmap = pb_message_fields[msg_name]
    for _, f in ipairs(pb_parse_fields(s)) do
        if f.unsupported then
            out[#out + 1] = { text = string.format("field %d: (unsupported wire type %d)", f.field_no, f.wire_type), depth = depth }
        else
            local meta = fieldmap and fieldmap[f.field_no] or nil
            local fname = meta and meta.name or string.format("field %d", f.field_no)
            if f.wire_type == PB_WIRE_VARINT then
                local enum_name = meta and meta.enum or nil
                out[#out + 1] = { text = string.format("%s: %s", fname, pb_format_varint(f.varint, enum_name)), depth = depth }
            elseif f.wire_type == PB_WIRE_LEN then
                -- Length-delimited: a nested message if the schema says so,
                -- otherwise a string (if printable) or raw bytes.
                if meta and meta.msg and pb_message_fields[meta.msg] then
                    out[#out + 1] = { text = string.format("%s: (%s)", fname, meta.msg), depth = depth }
                    pb_format_into(out, meta.msg, f.chunk, depth + 1)
                elseif pb_printable(f.chunk) then
                    out[#out + 1] = { text = string.format("%s: \"%s\"", fname, f.chunk), depth = depth }
                elseif f.len <= PB_HEX_FULL_MAX_LEN then
                    out[#out + 1] = { text = string.format("%s: %s", fname, pb_hex(f.chunk)), depth = depth }
                else
                    local preview = pb_hex(string.sub(f.chunk, 1, PB_HEX_PREVIEW_LEN))
                    out[#out + 1] = { text = string.format("%s: bytes[%d] %s...", fname, f.len, preview), depth = depth }
                end
            elseif f.wire_type == PB_WIRE_I64 then
                out[#out + 1] = { text = string.format("%s: fixed64 %s", fname, pb_hex(f.chunk)), depth = depth }
            elseif f.wire_type == PB_WIRE_I32 then
                out[#out + 1] = { text = string.format("%s: fixed32 %s", fname, pb_hex(f.chunk)), depth = depth }
            end
        end
    end
end

local function pb_format_message(msg_name, s)
    local out = {}
    if #s == 0 then return out end
    pb_format_into(out, msg_name, s, 0)
    return out
end


local function concat_chunks(chunks)
    local out = ""
    for _, chunk in ipairs(chunks) do
        out = out .. chunk
    end
    return out
end