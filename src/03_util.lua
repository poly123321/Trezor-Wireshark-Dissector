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

    -- 3) Fallback: UDP emulator identifies the host by port (device = 21324).
    if tostring(pinfo.dst_port) == "21324" then
        return "Host", "Trezor"
    end
    if tostring(pinfo.src_port) == "21324" then
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

local function concat_chunks(chunks)
    local out = ""
    for _, chunk in ipairs(chunks) do
        out = out .. chunk
    end
    return out
end