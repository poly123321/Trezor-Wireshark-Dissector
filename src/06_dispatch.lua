-- 06_dispatch.lua — main thp.dissector: routes each packet to THP or Codec v1.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh
--
function thp.dissector(buffer, pinfo, tree)
    local packet_len = buffer:len()

    -- 1) First packet of a v1 message: "[3F] 23 23 ..." — detectable by content.
    if looks_like_v1(buffer) then
        return dissect_v1(buffer, pinfo, tree)
    end
    -- 2) v1 continuation packet: "3F <data>". A continuation has no magic and
    -- its data can start with ANY byte (including 0x23), so we cannot tell it
    -- apart by content. Instead we key off reassembly STATE: if a v1 message is
    -- mid-reassembly for this direction, a 0x3F packet here is its continuation.
    if buffer:len() >= 1 and buffer(0, 1):uint() == V1_REPORT_ID
        and v1_reassembly_in_progress(pinfo) then
        return dissect_v1(buffer, pinfo, tree)
    end
    -- 3) Anything still starting with 0x3F is ours (v1), never THP: 0x3F is the
    -- v1 HID report id, not a THP control byte. Guard against it leaking into
    -- the THP parser (which would misread it as control/cid/length).
    if buffer:len() >= 1 and buffer(0, 1):uint() == V1_REPORT_ID then
        return dissect_v1(buffer, pinfo, tree)
    end
    if not looks_like_thp(buffer) then
        return 0
    end

    local control = buffer(0, 1):uint()
    local name = control_name(control)

    pinfo.cols.protocol = "THP"

    local subtree = tree:add(thp, buffer(), "Trezor Host Protocol")
    subtree:add(f_control, buffer(0, 1))
    subtree:add(f_control_name, name)

    if packet_len < 3 then
        pinfo.cols.info = name
        return packet_len
    end

    local cid = buffer(1, 2):uint()
    subtree:add(f_cid, buffer(1, 2))
    pinfo.cols.info = string.format("%s, cid=0x%04X", name, cid)

    -- Communication direction: rewrite Source/Destination to Host/Trezor
    -- and add filterable fields (trezor_dissector.thp.direction / src_role / dst_role).
    local src_role, dst_role = resolve_direction(pinfo, control, cid)
    if src_role ~= nil then
        pinfo.cols.src = src_role
        pinfo.cols.dst = dst_role
        subtree:add(f_src_role, src_role):set_generated()
        subtree:add(f_dst_role, dst_role):set_generated()
        subtree:add(f_direction, src_role .. "->" .. dst_role):set_generated()
    end

    -- ACK packet:
    -- byte 0 control
    -- byte 1-2 cid
    if is_ack(control) then
        local ack_bit = bit.band(control, ACK_SEQ_BIT) ~= 0
        subtree:add(f_ack, buffer(0, 1), ack_bit)
        pinfo.cols.info = string.format("%s, cid=0x%04X", name, cid)
        return packet_len
    end

    -- Continuation packet:
    -- byte 0 control = 0x80...
    -- byte 1-2 cid
    -- byte 3... continuation payload
    if is_continuation(control) then
        local key = direction_key(pinfo, cid)
        local payload_len = 0

        if packet_len > 3 then
            payload_len = packet_len - 3
            subtree:add(f_payload, buffer(3, payload_len))
        end

        if not pinfo.visited then
            local state = reassembly_state[key]

            if state ~= nil then
                local useful_bytes = math.min(payload_len, state.remaining)

                if useful_bytes > 0 then
                    table.insert(state.chunks, range_to_raw(buffer, 3, useful_bytes))
                end

                state.received = state.received + useful_bytes
                state.remaining = state.total_len - state.received
                state.continuation_index = state.continuation_index + 1

                local complete = state.remaining <= 0
                local data_hex_without_crc = nil
                local crc_valid = nil

                if complete then
                    local payload_crc_raw = concat_chunks(state.chunks)
                    local crc_info = nil
                    if #payload_crc_raw >= state.total_len then
                        payload_crc_raw = string.sub(payload_crc_raw, 1, state.total_len)
                        crc_info = {
                            payload_crc_raw = payload_crc_raw,
                            data_raw = string.sub(payload_crc_raw, 1, #payload_crc_raw - 4),
                        }
                        data_hex_without_crc = bytes_to_hex(crc_info.data_raw)
                    end

                    frame_info[pinfo.number] = {
                        key = key,
                        continuation_index = state.continuation_index,
                        useful_bytes = useful_bytes,
                        received = state.received,
                        total_len = state.total_len,
                        remaining = math.max(state.remaining, 0),
                        complete = complete,
                        header_raw = state.header_raw,
                        payload_crc_raw = payload_crc_raw,
                        original_control = state.original_control,
                        original_control_name = state.control_name,
                        data_hex_without_crc = data_hex_without_crc,
                    }

                    reassembly_state[key] = nil
                else
                    frame_info[pinfo.number] = {
                        key = key,
                        continuation_index = state.continuation_index,
                        useful_bytes = useful_bytes,
                        received = state.received,
                        total_len = state.total_len,
                        remaining = math.max(state.remaining, 0),
                        complete = complete,
                        original_control = state.original_control,
                        original_control_name = state.control_name,
                    }
                end
            else
                frame_info[pinfo.number] = {
                    key = key,
                    no_match = true,
                }
            end
        end

        local info = frame_info[pinfo.number]

        if info ~= nil and not info.no_match then
            subtree:add(buffer(0, 0), string.format("Reassembly ID: %s", info.key))
            subtree:add(buffer(0, 0), string.format("Continuation Index: %d", info.continuation_index))
            subtree:add(buffer(0, 0), string.format("Useful Bytes In This Continuation: %d", info.useful_bytes))
            subtree:add(buffer(0, 0), string.format("Reassembled Bytes So Far: %d / %d", info.received, info.total_len))
            subtree:add(buffer(0, 0), string.format("Remaining Bytes After This Continuation: %d", info.remaining))
            subtree:add(buffer(0, 0), string.format("Reassembly Complete: %s", info.complete and "true" or "false"))

            if info.complete and info.header_raw ~= nil and info.payload_crc_raw ~= nil then
                local crc_info = add_reassembled_crc_validation(subtree, buffer, info.header_raw, info.payload_crc_raw)
                if crc_info ~= nil then
                    info.data_hex_without_crc = crc_info.data_hex
                end

                if info.original_control == HANDSHAKE_INIT_REQ or
                   info.original_control == HANDSHAKE_INIT_RES or
                   info.original_control == HANDSHAKE_COMP_REQ or
                   info.original_control == HANDSHAKE_COMP_RES then
                    add_handshake_from_hex(subtree, buffer, info.original_control, info.data_hex_without_crc or "")
                end

                if info.original_control == ENCRYPTED_TRANSPORT then
                    add_encrypted_transport_from_hex(subtree, buffer, info.data_hex_without_crc or "")
                end
            end

            pinfo.cols.info = string.format(
                "CONTINUATION, cid=0x%04X, index=%d, reassembled=%d/%d%s",
                cid,
                info.continuation_index,
                info.received,
                info.total_len,
                info.complete and ", complete" or ""
            )
        else
            subtree:add(buffer(0, 0), "Reassembly: no matching initiation packet found")
            pinfo.cols.info = string.format("CONTINUATION, cid=0x%04X, no matching init", cid)
        end

        return packet_len
    end

    -- Init-like packet:
    -- byte 0     control
    -- byte 1-2   cid
    -- byte 3-4   length = data + CRC
    -- byte 5...  data + CRC + padding
    if packet_len < 5 then
        return packet_len
    end

    local data_crc_len = buffer(3, 2):uint()
    subtree:add(f_length, buffer(3, 2))

    if is_data(control) then
        local seq_bit = bit.band(control, DATA_SEQ_BIT) ~= 0
        local ack_bit = bit.band(control, DATA_ACK_SEQ_BIT) ~= 0
        subtree:add(f_seq, buffer(0, 1), seq_bit)
        subtree:add(f_ack, buffer(0, 1), ack_bit)
    end

    pinfo.cols.info = string.format("%s, cid=0x%04X, len=%d", name, cid, data_crc_len)

    local data_offset = 5

    if control == CHANNEL_ALLOCATION_REQ then
        dissect_allocation_request(subtree, buffer, data_offset, data_crc_len, packet_len)
        return packet_len
    end

    if control == CHANNEL_ALLOCATION_RES then
        dissect_allocation_response(subtree, buffer, data_offset, data_crc_len, packet_len)
        return packet_len
    end

    if control == ERROR then
        local error_name = dissect_error(subtree, buffer, data_offset, data_crc_len, packet_len)

        if error_name ~= nil then
            pinfo.cols.info = string.format(
                "ERROR %s, cid=0x%04X, len=%d",
                error_name,
                cid,
                data_crc_len
            )
        else
            pinfo.cols.info = string.format(
                "ERROR malformed, cid=0x%04X, len=%d",
                cid,
                data_crc_len
            )
        end

        return packet_len
    end

    if control == PING then
        dissect_ping_pong(subtree, buffer, data_offset, data_crc_len, packet_len, "PING")
        return packet_len
    end

    if control == PONG then
        dissect_ping_pong(subtree, buffer, data_offset, data_crc_len, packet_len, "PONG")
        return packet_len
    end

    local available = packet_len - data_offset
    local in_packet = math.min(available, data_crc_len)
    local remaining = data_crc_len - in_packet

    subtree:add(f_payload_in_packet, buffer(0, 0), in_packet)
    subtree:add(f_remaining, buffer(0, 0), remaining)
    subtree:add(f_needs_continuation, buffer(0, 0), remaining > 0)

    local key = direction_key(pinfo, cid)

    -- CHANGE B: continuation payload size depends on transport packet size.
    -- USB/UDP = 64 -> 61 B; BLE = 244 -> 241 B.
    local cont_payload = thp_packet_size - 3
    local expected_continuations = ceil_div(remaining, cont_payload)

    subtree:add(buffer(0, 0), string.format("Reassembly ID: %s", key))
    subtree:add(buffer(0, 0), string.format("Transport Packet Size: %d", thp_packet_size))
    subtree:add(buffer(0, 0), string.format("Expected Continuation Packets: %d", expected_continuations))

    local base_control = nil
    if is_data(control) then
        base_control = base_data_control(control)
    end

    if not pinfo.visited then
        if remaining > 0 then
            local header_raw = range_to_raw(buffer, 0, 5)
            local first_chunk = ""
            if in_packet > 0 then
                first_chunk = range_to_raw(buffer, data_offset, in_packet)
            end

            reassembly_state[key] = {
                total_len = data_crc_len,
                received = in_packet,
                remaining = remaining,
                continuation_index = 0,
                start_frame = pinfo.number,
                control_name = name,
                header_raw = header_raw,
                chunks = { first_chunk },
                original_control = base_control or control,
            }
        else
            reassembly_state[key] = nil
        end
    end

    if remaining > 0 then
        pinfo.cols.info = string.format(
            "%s, cid=0x%04X, len=%d, continuation=yes, remaining=%d",
            name,
            cid,
            data_crc_len,
            remaining
        )
    end

    if in_packet > 0 then
        if data_crc_len <= available and data_crc_len >= 4 then
            local data_len = data_crc_len - 4
            if data_len > 0 then
                subtree:add(f_data, buffer(data_offset, data_len))
            end
            subtree:add(f_crc, buffer(data_offset + data_len, 4))

            if base_control ~= nil then
                if base_control == HANDSHAKE_INIT_REQ or
                   base_control == HANDSHAKE_INIT_RES or
                   base_control == HANDSHAKE_COMP_REQ or
                   base_control == HANDSHAKE_COMP_RES then
                    dissect_handshake_in_current_packet(subtree, buffer, base_control, data_offset, data_crc_len, packet_len)
                end

                if base_control == ENCRYPTED_TRANSPORT then
                    dissect_encrypted_transport_in_current_packet(subtree, buffer, data_offset, data_crc_len, packet_len)
                end
            end

            add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
        else
            subtree:add(f_payload, buffer(data_offset, in_packet))
            subtree:add(buffer(0, 0), "CRC Validation: skipped, waiting for reassembly")
        end
    end

    add_padding_if_any(subtree, buffer, data_offset + in_packet, packet_len)

    return packet_len
end