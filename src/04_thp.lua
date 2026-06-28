-- 04_thp.lua — THP (Trezor Safe 7) message dissection.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh

local function add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
    -- Works only when the whole THP message fits into this packet.
    -- data_crc_len = data length + 4B CRC.
    if data_crc_len < 4 then
        subtree:add(buffer(0, 0), "CRC Validation: skipped, payload too short")
        return
    end

    if packet_len < data_offset + data_crc_len then
        subtree:add(buffer(0, 0), "CRC Validation: skipped, message continues in continuation packets")
        return
    end

    local data_len = data_crc_len - 4
    local received_crc = buffer(data_offset + data_len, 4):uint()

    -- CRC is computed over:
    -- control byte + cid + length + data
    -- i.e. bytes 0..4 plus data bytes, without CRC and without padding.
    local calculated_crc = crc32_ieee(buffer, 0, data_offset + data_len)

    subtree:add(buffer(0, 0), string.format("CRC32 Received: 0x%08X", received_crc))
    subtree:add(buffer(0, 0), string.format("CRC32 Calculated: 0x%08X", calculated_crc))
    subtree:add(buffer(0, 0), string.format("CRC Valid: %s", received_crc == calculated_crc and "true" or "false"))
end

local function add_reassembled_crc_validation(subtree, buffer, header_raw, payload_crc_raw)
    if payload_crc_raw == nil or #payload_crc_raw < 4 then
        subtree:add(buffer(0, 0), "Reassembled CRC Validation: skipped, payload too short")
        return nil
    end

    local data_raw = string.sub(payload_crc_raw, 1, #payload_crc_raw - 4)
    local crc_raw = string.sub(payload_crc_raw, #payload_crc_raw - 3)

    local received_crc = read_u32_be_from_bytes(crc_raw, 1)
    local calculated_crc = crc32_ieee_bytes(header_raw .. data_raw)

    subtree:add(buffer(0, 0), string.format("Reassembled Data Length Without CRC: %d", #data_raw))
    subtree:add(buffer(0, 0), string.format("Reassembled CRC32 Received: 0x%08X", received_crc))
    subtree:add(buffer(0, 0), string.format("Reassembled CRC32 Calculated: 0x%08X", calculated_crc))
    subtree:add(buffer(0, 0), string.format("Reassembled CRC Valid: %s", received_crc == calculated_crc and "true" or "false"))

    return {
        data_raw = data_raw,
        data_hex = bytes_to_hex(data_raw),
        received_crc = received_crc,
        calculated_crc = calculated_crc,
        crc_valid = received_crc == calculated_crc,
    }
end

local function add_handshake_from_hex(subtree, buffer, original_control, data_hex)
    local data_len = hex_len(data_hex)
    local hs = subtree:add(buffer(0, 0), "Reassembled Handshake Message")

    if original_control == HANDSHAKE_INIT_REQ then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_INIT_REQ")
        hs:add(buffer(0, 0), "Noise pattern step: -> e")
        hs:add(buffer(0, 0), "Host Ephemeral Public Key: " .. hex_slice(data_hex, 0, math.min(32, data_len)))
        if data_len >= 33 then
            hs:add(buffer(0, 0), "Try To Unlock: 0x" .. hex_slice(data_hex, 32, 1))
        end
        if data_len ~= 33 then
            hs:add(buffer(0, 0), string.format("Warning: expected 33 bytes of handshake data, got %d", data_len))
        end
        return
    end

    if original_control == HANDSHAKE_INIT_RES then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_INIT_RES")
        hs:add(buffer(0, 0), "Noise pattern step: <- e, ee, s, es")
        if data_len >= 32 then
            hs:add(buffer(0, 0), "Trezor Ephemeral Public Key: " .. hex_slice(data_hex, 0, 32))
        end
        if data_len >= 80 then
            hs:add(buffer(0, 0), "Encrypted Trezor Static Public Key: " .. hex_slice(data_hex, 32, 48))
        end
        if data_len >= 96 then
            hs:add(buffer(0, 0), "Handshake Tag: " .. hex_slice(data_hex, 80, 16))
        end
        if data_len ~= 96 then
            hs:add(buffer(0, 0), string.format("Warning: expected 96 bytes of handshake data, got %d", data_len))
        end
        return
    end

    if original_control == HANDSHAKE_COMP_REQ then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_COMP_REQ")
        hs:add(buffer(0, 0), "Noise pattern step: -> s, se, payload")
        if data_len >= 48 then
            hs:add(buffer(0, 0), "Encrypted Host Static Public Key: " .. hex_slice(data_hex, 0, 48))
        end
        if data_len > 48 then
            hs:add(buffer(0, 0), "Encrypted Handshake Payload: " .. hex_slice(data_hex, 48, data_len - 48))
        end
        if data_len < 48 then
            hs:add(buffer(0, 0), string.format("Warning: expected at least 48 bytes of handshake data, got %d", data_len))
        end
        return
    end

    if original_control == HANDSHAKE_COMP_RES then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_COMP_RES")
        hs:add(buffer(0, 0), "Noise pattern step: final encrypted Trezor state")
        if data_len > 0 then
            hs:add(buffer(0, 0), "Encrypted Trezor State: " .. data_hex)
        end
        if data_len ~= 17 then
            hs:add(buffer(0, 0), string.format("Warning: expected 17 bytes of handshake data, got %d", data_len))
        end
        return
    end

    hs:add(buffer(0, 0), string.format("Type: unsupported handshake control 0x%02X", original_control))
end

local function dissect_handshake_in_current_packet(subtree, buffer, control, data_offset, data_crc_len, packet_len)
    if data_crc_len < 4 then
        return false
    end

    if packet_len < data_offset + data_crc_len then
        return false
    end

    local data_len = data_crc_len - 4
    local hs = subtree:add(buffer(data_offset, data_len), "Handshake Message")

    if control == HANDSHAKE_INIT_REQ then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_INIT_REQ")
        hs:add(buffer(0, 0), "Noise pattern step: -> e")
        if data_len >= 32 then
            hs:add(f_handshake_host_ephemeral, buffer(data_offset, 32))
        end
        if data_len >= 33 then
            hs:add(f_handshake_try_to_unlock, buffer(data_offset + 32, 1))
        end
        if data_len ~= 33 then
            hs:add(buffer(0, 0), string.format("Warning: expected 33 bytes of handshake data, got %d", data_len))
        end
        return true
    end

    if control == HANDSHAKE_INIT_RES then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_INIT_RES")
        hs:add(buffer(0, 0), "Noise pattern step: <- e, ee, s, es")
        if data_len >= 32 then
            hs:add(f_handshake_trezor_ephemeral, buffer(data_offset, 32))
        end
        if data_len >= 80 then
            hs:add(f_handshake_encrypted_trezor_static, buffer(data_offset + 32, 48))
        end
        if data_len >= 96 then
            hs:add(f_handshake_tag, buffer(data_offset + 80, 16))
        end
        if data_len ~= 96 then
            hs:add(buffer(0, 0), string.format("Warning: expected 96 bytes of handshake data, got %d", data_len))
        end
        return true
    end

    if control == HANDSHAKE_COMP_REQ then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_COMP_REQ")
        hs:add(buffer(0, 0), "Noise pattern step: -> s, se, payload")
        if data_len >= 48 then
            hs:add(f_handshake_encrypted_host_static, buffer(data_offset, 48))
        end
        if data_len > 48 then
            hs:add(f_handshake_encrypted_payload, buffer(data_offset + 48, data_len - 48))
        end
        if data_len < 48 then
            hs:add(buffer(0, 0), string.format("Warning: expected at least 48 bytes of handshake data, got %d", data_len))
        end
        return true
    end

    if control == HANDSHAKE_COMP_RES then
        hs:add(buffer(0, 0), "Type: HANDSHAKE_COMP_RES")
        hs:add(buffer(0, 0), "Noise pattern step: final encrypted Trezor state")
        if data_len > 0 then
            hs:add(f_handshake_encrypted_trezor_state, buffer(data_offset, data_len))
        end
        if data_len ~= 17 then
            hs:add(buffer(0, 0), string.format("Warning: expected 17 bytes of handshake data, got %d", data_len))
        end
        return true
    end

    return false
end


-- -------------------------------------------------------------------
-- Optional THP ENCRYPTED_TRANSPORT decryption via external keylog.
--
-- Keylog format:
-- THP_KEYLOG cid=0x.... encrypt_key=... encrypt_nonce=0 decrypt_key=... decrypt_nonce=1 ...
--
-- encrypt_key = Host -> Trezor
-- decrypt_key = Trezor -> Host
--
-- We try both directions instead of trusting USB direction, because USB endpoint
-- direction is not always equivalent to logical THP message direction.
-- -------------------------------------------------------------------

local thp_keylog_cache = nil
local thp_keylog_loaded_path = nil
local thp_decrypt_state = {}
local thp_decrypt_frame_cache = {}

function reset_thp_decryption_state()
    thp_keylog_cache = nil
    thp_keylog_loaded_path = nil
    thp_decrypt_state = {}
    thp_decrypt_frame_cache = {}
end

local function noise_nonce_hex(n)
    local hi = math.floor(n / 0x100000000)
    local lo = n % 0x100000000
    return string.format("00000000%08x%08x", hi, lo)
end

local function load_thp_keylog()
    local path = thp.prefs.thp_keylog_path

    if path == nil or path == "" then
        return nil, "no THP keylog configured"
    end

    if thp_keylog_cache ~= nil and thp_keylog_loaded_path == path then
        return thp_keylog_cache, nil
    end

    local f, err = io.open(path, "r")
    if f == nil then
        thp_keylog_cache = {}
        thp_keylog_loaded_path = path
        return nil, "could not open THP keylog: " .. tostring(err)
    end

    local entries = {}

    for line in f:lines() do
        local cid_s, enc_key, enc_nonce, dec_key, dec_nonce = line:match(
            "THP_KEYLOG%s+cid=(0x[%da-fA-F]+)%s+encrypt_key=([%da-fA-F]+)%s+encrypt_nonce=(%d+)%s+decrypt_key=([%da-fA-F]+)%s+decrypt_nonce=(%d+)"
        )

        if cid_s ~= nil then
            local cid = tonumber(cid_s:sub(3), 16)
            entries[cid] = {
                encrypt_key = enc_key,
                encrypt_nonce = tonumber(enc_nonce),
                decrypt_key = dec_key,
                decrypt_nonce = tonumber(dec_nonce),
            }
        end
    end

    f:close()

    thp_keylog_cache = entries
    thp_keylog_loaded_path = path
    thp_decrypt_state = {}
    thp_decrypt_frame_cache = {}

    return entries, nil
end

local function aes_gcm_decrypt_noise(key_hex, nonce_value, ciphertext_and_tag_hex)
    local total_len = hex_len(ciphertext_and_tag_hex)

    if total_len < 16 then
        return nil, "ciphertext too short for AES-GCM tag"
    end

    local tag_hex = ciphertext_and_tag_hex:sub(#ciphertext_and_tag_hex - 31)
    local ciphertext_hex = ciphertext_and_tag_hex:sub(1, #ciphertext_and_tag_hex - 32)

    local ok, result = pcall(function()
        local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)
        cipher:setkey(ByteArray.new(key_hex))
        cipher:setiv(ByteArray.new(noise_nonce_hex(nonce_value)))

        local plaintext = cipher:decrypt(NULL, ByteArray.new(ciphertext_hex))
        local tag_ok = cipher:checktag(ByteArray.new(tag_hex))

        if tag_ok ~= 0 then
            error("AES-GCM tag mismatch")
        end

        return plaintext
    end)

    if not ok then
        return nil, tostring(result)
    end

    return result, nil
end

local function try_decrypt_thp(cid, data_hex, pinfo)
    if thp_decrypt_frame_cache[pinfo.number] ~= nil then
        return thp_decrypt_frame_cache[pinfo.number]
    end

    if pinfo.visited then
        return nil
    end

    local keylog, load_err = load_thp_keylog()
    if keylog == nil then
        local res = { ok = false, status = load_err or "THP keylog not available" }
        thp_decrypt_frame_cache[pinfo.number] = res
        return res
    end

    local entry = keylog[cid]
    if entry == nil then
        local res = { ok = false, status = string.format("no THP keylog entry for cid=0x%04X", cid) }
        thp_decrypt_frame_cache[pinfo.number] = res
        return res
    end

    if thp_decrypt_state[cid] == nil then
        thp_decrypt_state[cid] = {
            encrypt_nonce = entry.encrypt_nonce,
            decrypt_nonce = entry.decrypt_nonce,
        }
    end

    local state = thp_decrypt_state[cid]

    local plaintext = aes_gcm_decrypt_noise(entry.encrypt_key, state.encrypt_nonce, data_hex)
    if plaintext ~= nil then
        local res = {
            ok = true,
            status = "ok",
            direction = "Host->Trezor",
            nonce = state.encrypt_nonce,
            plaintext = plaintext,
        }
        state.encrypt_nonce = state.encrypt_nonce + 1
        thp_decrypt_frame_cache[pinfo.number] = res
        return res
    end

    plaintext = aes_gcm_decrypt_noise(entry.decrypt_key, state.decrypt_nonce, data_hex)
    if plaintext ~= nil then
        local res = {
            ok = true,
            status = "ok",
            direction = "Trezor->Host",
            nonce = state.decrypt_nonce,
            plaintext = plaintext,
        }
        state.decrypt_nonce = state.decrypt_nonce + 1
        thp_decrypt_frame_cache[pinfo.number] = res
        return res
    end

    local res = {
        ok = false,
        status = "AES-GCM authentication failed for both THP directions",
    }
    thp_decrypt_frame_cache[pinfo.number] = res
    return res
end


local function add_decrypted_thp_message(dec, pt_tvb, plaintext_len, pinfo)
    -- THP decrypted application frame:
    --   1 byte session/id prefix
    --   2 bytes MessageType, big-endian
    --   N bytes protobuf payload
    if plaintext_len < 3 then
        dec:add(pt_tvb(0, plaintext_len), "Decrypted THP message: too short to parse"):set_generated()
        return
    end

    local session_id = pt_tvb(0, 1):uint()
    local msg_type = pt_tvb(1, 2):uint()
    local msg_name = v1_message_name(msg_type)
    local payload_len = plaintext_len - 3

    dec:add(f_encrypted_session_id, pt_tvb(0, 1))
    dec:add(f_encrypted_msg_type, pt_tvb(1, 2))
    dec:add(f_encrypted_msg_name, pt_tvb(1, 2), msg_name):set_generated()

    if payload_len > 0 then
        local pb_tree = dec:add(f_encrypted_protobuf_payload, pt_tvb(3, payload_len))
        -- Parse the protobuf payload into named fields using the generated
        -- pb_message_fields / pb_enums tables. Nested messages are shown as
        -- indented subtrees (depth-limited inside pb_format_message).
        local ok, lines = pcall(function()
            local raw = range_to_raw(pt_tvb, 3, payload_len)
            return pb_format_message(msg_name, raw)
        end)
        if ok and lines then
            local stack = { [0] = pb_tree }
            for _, ln in ipairs(lines) do
                local parent = stack[ln.depth] or pb_tree
                local node = parent:add(pt_tvb(3, payload_len), ln.text)
                node:set_generated()
                stack[ln.depth + 1] = node
            end
        end
    else
        dec:add(pt_tvb(0, 0), "Decrypted Protobuf Payload: empty"):set_generated()
    end

    pinfo.cols.info:append(string.format(" -> %s", msg_name))
end


local function add_thp_decryption(subtree, buffer, cid, data_hex, pinfo)
    local dec = subtree:add(buffer(0, 0), "THP Decryption")
    local res = try_decrypt_thp(cid, data_hex, pinfo)

    if res == nil then
        dec:add(f_encrypted_decrypt_status, buffer(0, 0), "not available on redissection")
        return
    end

    dec:add(f_encrypted_decrypt_status, buffer(0, 0), res.status or "unknown")

    if not res.ok then
        return
    end

    dec:add(f_encrypted_decrypt_direction, buffer(0, 0), res.direction)
    dec:add(f_encrypted_decrypt_nonce, buffer(0, 0), res.nonce)

    local plaintext_hex = res.plaintext:tohex()
    local plaintext_len = hex_len(plaintext_hex)
    dec:add(f_encrypted_plaintext_len, buffer(0, 0), plaintext_len)

    if plaintext_len > 0 then
        local pt_tvb = res.plaintext:tvb("THP decrypted plaintext")
        dec:add(f_encrypted_plaintext, pt_tvb(0, pt_tvb:len()))
        dec:add(buffer(0, 0), "Decrypted Plaintext Hex: " .. plaintext_hex)
        add_decrypted_thp_message(dec, pt_tvb, plaintext_len, pinfo)
    else
        dec:add(buffer(0, 0), "Decrypted Plaintext: empty")
    end
end


local function add_encrypted_transport_from_hex(subtree, buffer, cid, data_hex, pinfo)
    local data_len = hex_len(data_hex)
    local enc = subtree:add(buffer(0, 0), "Reassembled Encrypted Transport Message")
    enc:add(buffer(0, 0), string.format("Encrypted Payload Length: %d", data_len))

    if data_len > 0 then
        enc:add(buffer(0, 0), "Encrypted Ciphertext: " .. data_hex)
        add_thp_decryption(enc, buffer, cid, data_hex, pinfo)
    else
        enc:add(buffer(0, 0), "Encrypted Ciphertext: empty")
    end
end

local function dissect_encrypted_transport_in_current_packet(subtree, buffer, cid, data_offset, data_crc_len, packet_len, pinfo)
    if data_crc_len < 4 then
        return false
    end

    if packet_len < data_offset + data_crc_len then
        return false
    end

    local data_len = data_crc_len - 4
    local enc = subtree:add(buffer(data_offset, data_len), "Encrypted Transport Message")
    enc:add(f_encrypted_payload_len, buffer(0, 0), data_len)

    if data_len > 0 then
        enc:add(f_encrypted_ciphertext, buffer(data_offset, data_len))
        add_thp_decryption(enc, buffer, cid, buffer(data_offset, data_len):bytes():tohex(), pinfo)
    else
        enc:add(buffer(0, 0), "Encrypted Ciphertext: empty")
    end

    return true
end

local function dissect_error(subtree, buffer, data_offset, data_crc_len, packet_len)
    -- TRANSPORT_ERROR payload:
    -- 1 B error_code + 4 B CRC
    if data_crc_len < 5 then
        subtree:add(buffer(0, 0), string.format(
            "Transport Error: malformed, expected at least 5 bytes including CRC, got %d",
            data_crc_len
        ))
        add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
        add_padding_if_any(subtree, buffer, data_offset + math.max(data_crc_len, 0), packet_len)
        return nil
    end

    if packet_len < data_offset + 1 then
        subtree:add(buffer(0, 0), "Transport Error: packet too short for error code")
        return nil
    end

    local error_code = buffer(data_offset, 1):uint()
    local error_name = transport_error_names[error_code] or "UNKNOWN_ERROR_CODE"

    local tree_len = math.min(data_crc_len, packet_len - data_offset)
    local error_tree = subtree:add(buffer(data_offset, tree_len), "Transport Error")
    error_tree:add(f_error_code, buffer(data_offset, 1))
    error_tree:add(f_error_name, error_name)

    -- Spec says the transport error payload is exactly 1 byte.
    -- If future versions add anything, show it as unexpected extra payload.
    local extra_len = data_crc_len - 1 - 4
    if extra_len > 0 and packet_len >= data_offset + 1 + extra_len then
        error_tree:add(f_error_extra, buffer(data_offset + 1, extra_len))
    end

    if packet_len >= data_offset + data_crc_len then
        subtree:add(f_crc, buffer(data_offset + data_crc_len - 4, 4))
    end

    add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
    add_padding_if_any(subtree, buffer, data_offset + data_crc_len, packet_len)

    return error_name
end

local function dissect_ping_pong(subtree, buffer, data_offset, data_crc_len, packet_len, label)
    if data_crc_len < 4 then
        subtree:add(buffer(0, 0), label .. ": malformed, data+CRC length shorter than CRC")
        return
    end

    local data_len = data_crc_len - 4
    if data_len > 0 and packet_len >= data_offset + data_len then
        subtree:add(f_payload, buffer(data_offset, data_len)):append_text(" (" .. label .. " Payload)")
    else
        subtree:add(buffer(0, 0), label .. " Payload: empty")
    end

    if packet_len >= data_offset + data_crc_len then
        subtree:add(f_crc, buffer(data_offset + data_len, 4))
    end

    add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
    add_padding_if_any(subtree, buffer, data_offset + data_crc_len, packet_len)
end

local function dissect_allocation_request(subtree, buffer, data_offset, data_crc_len, packet_len)
    -- CHANNEL_ALLOCATION_REQ data:
    -- 8 B nonce + 4 B CRC
    if data_crc_len >= 8 and packet_len >= data_offset + 8 then
        subtree:add(f_nonce, buffer(data_offset, 8))
    end

    if data_crc_len >= 4 and packet_len >= data_offset + data_crc_len then
        subtree:add(f_crc, buffer(data_offset + data_crc_len - 4, 4))
    end

    add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
    add_padding_if_any(subtree, buffer, data_offset + data_crc_len, packet_len)
end

local function dissect_allocation_response(subtree, buffer, data_offset, data_crc_len, packet_len)
    -- CHANNEL_ALLOCATION_RES data:
    -- 8 B nonce
    -- 2 B allocated cid
    -- device properties protobuf
    -- 4 B CRC
    if data_crc_len >= 8 and packet_len >= data_offset + 8 then
        subtree:add(f_nonce, buffer(data_offset, 8))
    end

    if data_crc_len >= 10 and packet_len >= data_offset + 10 then
        subtree:add(f_allocated_cid, buffer(data_offset + 8, 2))
    end

local device_props_len = data_crc_len - 10 - 4
    if device_props_len > 0 and packet_len >= data_offset + 10 + device_props_len then
        local dp_range = buffer(data_offset + 10, device_props_len)
        local dp_tree = subtree:add(f_device_properties, dp_range)

        -- Parse the ThpDeviceProperties protobuf so the model, protocol version
        -- and pairing methods are readable instead of raw bytes.
        local raw = range_to_raw(buffer, data_offset + 10, device_props_len)
        local dp = parse_device_properties(raw)

        if dp.internal_model ~= nil then
            dp_tree:add(dp_range, "Internal Model: " .. dp.internal_model):set_generated()
        end
        if dp.model_variant ~= nil then
            dp_tree:add(dp_range, string.format("Model Variant: %d", dp.model_variant)):set_generated()
        end
        if dp.protocol_version_major ~= nil or dp.protocol_version_minor ~= nil then
            dp_tree:add(dp_range, string.format("Protocol Version: %d.%d",
                dp.protocol_version_major or 0, dp.protocol_version_minor or 0)):set_generated()
        end
        if #dp.pairing_methods > 0 then
            local names = {}
            for _, m in ipairs(dp.pairing_methods) do
                names[#names + 1] = string.format("%s(%d)", PAIRING_METHOD_NAMES[m] or "Unknown", m)
            end
            dp_tree:add(dp_range, "Pairing Methods: " .. table.concat(names, ", ")):set_generated()
        end
        for _, w in ipairs(dp.warnings) do
            dp_tree:add(dp_range, "Warning: " .. w):set_generated()
        end
    end

    if data_crc_len >= 4 and packet_len >= data_offset + data_crc_len then
        subtree:add(f_crc, buffer(data_offset + data_crc_len - 4, 4))
    end

    add_crc_validation(subtree, buffer, data_offset, data_crc_len, packet_len)
    add_padding_if_any(subtree, buffer, data_offset + data_crc_len, packet_len)
end
