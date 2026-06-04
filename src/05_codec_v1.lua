-- 05_codec_v1.lua — Codec v1 (legacy devices) dissection and reassembly.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh
--
-- =====================================================================
-- Codec v1 (legacy) support.
-- Frame (first packet):
--   [report_id 0x3F]? | '#' '#' | msg_type (2B BE) | length (4B BE) | payload...
-- Continuation packets carry [report_id 0x3F]? | payload... (no magic/type/len).
-- Chunked into thp_packet_size-byte packets, same as THP.
-- =====================================================================

local v1_reassembly_state = {}
local v1_frame_info = {}

-- Returns the offset where the v1 frame body begins (after an optional report
-- id), or nil if this does not look like a v1 first packet.
local function v1_header_offset(buffer)
    local len = buffer:len()
    -- With HID report id: 3F 23 23
    if len >= 3
        and buffer(0, 1):uint() == V1_REPORT_ID
        and buffer(1, 1):uint() == V1_MAGIC_BYTE
        and buffer(2, 1):uint() == V1_MAGIC_BYTE then
        return 1
    end
    -- Without report id: 23 23
    if len >= 2
        and buffer(0, 1):uint() == V1_MAGIC_BYTE
        and buffer(1, 1):uint() == V1_MAGIC_BYTE then
        return 0
    end
    return nil
end

-- A v1 continuation packet has the report id but NOT the "##" magic right after.
local function v1_is_continuation_packet(buffer)
    local len = buffer:len()
    if len >= 2 and buffer(0, 1):uint() == V1_REPORT_ID
        and buffer(1, 1):uint() ~= V1_MAGIC_BYTE then
        return true, 1
    end
    return false, 0
end

local function looks_like_v1(buffer)
    return v1_header_offset(buffer) ~= nil
end

local function v1_direction_key(pinfo)
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) ..
           "->" ..
           tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) ..
           "/v1"
end

local function dissect_v1(buffer, pinfo, tree)
    local packet_len = buffer:len()
    pinfo.cols.protocol = "Codec v1"

    local subtree = tree:add(thp, buffer(), "Trezor Codec v1 (legacy)")

    local hdr = v1_header_offset(buffer)

    if hdr ~= nil then
        -- First packet of a message.
        if hdr == 1 then
            subtree:add(f_v1_report_id, buffer(0, 1))
        end
        subtree:add(f_v1_magic, "##")

        local off = hdr + 2  -- skip the two magic bytes
        if packet_len < off + 6 then
            -- Not enough for type(2) + len(4); show what we have.
            pinfo.cols.info = "Codec v1 (truncated header)"
            return packet_len
        end

        local msg_type = buffer(off, 2):uint()        -- big-endian
        local payload_len = buffer(off + 2, 4):uint()  -- big-endian
        local name = v1_message_name(msg_type)

        subtree:add(f_v1_msg_type, buffer(off, 2))
        subtree:add(f_v1_msg_name, name):set_generated()
        subtree:add(f_v1_length, buffer(off + 2, 4))

        local data_offset = off + 6
        local available = packet_len - data_offset
        local in_packet = math.min(available, payload_len)
        local remaining = payload_len - in_packet
        if remaining < 0 then remaining = 0 end

        if in_packet > 0 then
            subtree:add(f_v1_payload, buffer(data_offset, in_packet))
        end
        subtree:add(f_v1_payload_in_packet, buffer(0, 0), in_packet):set_generated()
        subtree:add(f_v1_remaining, buffer(0, 0), remaining):set_generated()
        subtree:add(f_v1_needs_continuation, buffer(0, 0), remaining > 0):set_generated()

        -- Direction (reuse THP role resolver heuristics via ports only).
        if tostring(pinfo.dst_port) == "21324" then
            pinfo.cols.src = "Host"; pinfo.cols.dst = "Trezor"
        elseif tostring(pinfo.src_port) == "21324" then
            pinfo.cols.src = "Trezor"; pinfo.cols.dst = "Host"
        end

        local key = v1_direction_key(pinfo)
        if not pinfo.visited then
            if remaining > 0 then
                v1_reassembly_state[key] = {
                    msg_type = msg_type,
                    name = name,
                    total_len = payload_len,
                    received = in_packet,
                    remaining = remaining,
                    continuation_index = 0,
                    start_frame = pinfo.number,
                }
            else
                v1_reassembly_state[key] = nil
            end
        end

        if remaining > 0 then
            pinfo.cols.info = string.format(
                "v1 %s (type=%d), len=%d, continuation=yes, remaining=%d",
                name, msg_type, payload_len, remaining)
        else
            pinfo.cols.info = string.format(
                "v1 %s (type=%d), len=%d", name, msg_type, payload_len)
        end

        return packet_len
    end

    -- Continuation packet.
    local is_cont, coff = v1_is_continuation_packet(buffer)
    if is_cont then
        if coff == 1 then
            subtree:add(f_v1_report_id, buffer(0, 1))
        end
        local payload_len = packet_len - coff
        if payload_len > 0 then
            subtree:add(f_v1_continuation, buffer(coff, payload_len))
        end

        local key = v1_direction_key(pinfo)
        if not pinfo.visited then
            local state = v1_reassembly_state[key]
            if state ~= nil then
                local useful = math.min(payload_len, state.remaining)
                state.received = state.received + useful
                state.remaining = state.total_len - state.received
                state.continuation_index = state.continuation_index + 1
                local complete = state.remaining <= 0
                v1_frame_info[pinfo.number] = {
                    name = state.name,
                    msg_type = state.msg_type,
                    continuation_index = state.continuation_index,
                    received = state.received,
                    total_len = state.total_len,
                    complete = complete,
                }
                if complete then
                    v1_reassembly_state[key] = nil
                end
            else
                v1_frame_info[pinfo.number] = { no_match = true }
            end
        end

        local info = v1_frame_info[pinfo.number]
        if info ~= nil and not info.no_match then
            subtree:add(buffer(0, 0), string.format(
                "Reassembly: %s, %d/%d bytes%s",
                info.name, info.received, info.total_len,
                info.complete and ", complete" or "")):set_generated()
            pinfo.cols.info = string.format(
                "v1 CONTINUATION %s, index=%d, reassembled=%d/%d%s",
                info.name, info.continuation_index,
                info.received, info.total_len,
                info.complete and ", complete" or "")
        else
            subtree:add(buffer(0, 0), "Reassembly: no matching v1 init packet"):set_generated()
            pinfo.cols.info = "v1 CONTINUATION, no matching init"
        end

        return packet_len
    end

    pinfo.cols.info = "Codec v1 (unrecognized)"
    return packet_len
end