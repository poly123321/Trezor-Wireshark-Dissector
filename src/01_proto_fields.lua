-- 01_proto_fields.lua — Proto definition and all ProtoField declarations.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh

-- Wireshark Lua dissector for Trezor Host Protocol transport layer.
-- Multi-transport: UDP emulator (port 21324), USB (64 B), BLE (244 B).
-- Features:
-- - THP control byte decoding
-- - CID and length decoding
-- - Channel allocation request/response parsing
-- - ACK/SEQ bit display
-- - Continuation/reassembly progress tracking
-- - CRC32 validation for single-packet and reassembled multi-packet messages
-- - Basic Noise XX handshake payload parsing
-- - Encrypted transport metadata display
-- - Transport ERROR parser

local thp = Proto("trezor_dissector", "Trezor Wire Dissector (THP / Codec v1)")

-- Configurable UDP port range for the emulator(s). Default is just 21324, the
-- stock emulator port. Change it under Edit > Preferences > Protocols > trezor_dissector.
thp.prefs.udp_ports = Pref.string("Emulator UDP port(s)", "21324",
    "UDP port or range the Trezor emulator(s) use, e.g. 21324 or 21324-21400")

    -- Basic fields
local f_control = ProtoField.uint8("trezor_dissector.thp.control", "Control Byte", base.HEX)
local f_control_name = ProtoField.string("trezor_dissector.thp.control_name", "Control Name")
local f_cid = ProtoField.uint16("trezor_dissector.thp.cid", "Channel ID", base.HEX)
local f_length = ProtoField.uint16("trezor_dissector.thp.length", "Data + CRC Length", base.DEC)

-- Payload fields
local f_data = ProtoField.bytes("trezor_dissector.thp.data", "Data")
local f_payload = ProtoField.bytes("trezor_dissector.thp.payload", "Packet Payload")
local f_padding = ProtoField.bytes("trezor_dissector.thp.padding", "Padding")
local f_crc = ProtoField.uint32("trezor_dissector.thp.crc", "CRC32", base.HEX)

-- Channel allocation fields
local f_nonce = ProtoField.bytes("trezor_dissector.thp.nonce", "Nonce")
local f_allocated_cid = ProtoField.uint16("trezor_dissector.thp.allocated_cid", "Allocated Channel ID", base.HEX)
local f_device_properties = ProtoField.bytes("trezor_dissector.thp.device_properties", "Device Properties Protobuf")

-- Transport error fields
local f_error_code = ProtoField.uint8("trezor_dissector.thp.error.code", "Transport Error Code", base.DEC)
local f_error_name = ProtoField.string("trezor_dissector.thp.error.name", "Transport Error Name")
local f_error_extra = ProtoField.bytes("trezor_dissector.thp.error.extra", "Unexpected Extra Error Payload")

-- Handshake fields
local f_handshake_host_ephemeral = ProtoField.bytes("trezor_dissector.thp.handshake.host_ephemeral_pubkey", "Host Ephemeral Public Key")
local f_handshake_try_to_unlock = ProtoField.uint8("trezor_dissector.thp.handshake.try_to_unlock", "Try To Unlock", base.HEX)
local f_handshake_trezor_ephemeral = ProtoField.bytes("trezor_dissector.thp.handshake.trezor_ephemeral_pubkey", "Trezor Ephemeral Public Key")
local f_handshake_encrypted_trezor_static = ProtoField.bytes("trezor_dissector.thp.handshake.encrypted_trezor_static_pubkey", "Encrypted Trezor Static Public Key")
local f_handshake_tag = ProtoField.bytes("trezor_dissector.thp.handshake.tag", "Handshake Tag")
local f_handshake_encrypted_host_static = ProtoField.bytes("trezor_dissector.thp.handshake.encrypted_host_static_pubkey", "Encrypted Host Static Public Key")
local f_handshake_encrypted_payload = ProtoField.bytes("trezor_dissector.thp.handshake.encrypted_payload", "Encrypted Handshake Payload")
local f_handshake_encrypted_trezor_state = ProtoField.bytes("trezor_dissector.thp.handshake.encrypted_trezor_state", "Encrypted Trezor State")

-- Encrypted transport fields
local f_encrypted_payload_len = ProtoField.uint16("trezor_dissector.thp.encrypted.payload_len", "Encrypted Payload Length", base.DEC)
local f_encrypted_ciphertext = ProtoField.bytes("trezor_dissector.thp.encrypted.ciphertext", "Encrypted Ciphertext")

-- Synchronization fields
local f_seq = ProtoField.bool("trezor_dissector.thp.seq", "SEQ Bit")
local f_ack = ProtoField.bool("trezor_dissector.thp.ack", "ACK Bit")

-- Segmentation / reassembly info fields
local f_payload_in_packet = ProtoField.uint16("trezor_dissector.thp.payload_in_packet", "Payload Bytes In This Packet", base.DEC)
local f_remaining = ProtoField.uint16("trezor_dissector.thp.remaining", "Remaining Bytes After This Packet", base.DEC)
local f_needs_continuation = ProtoField.bool("trezor_dissector.thp.needs_continuation", "Needs Continuation")

local f_raw = ProtoField.bytes("trezor_dissector.thp.raw", "Raw")

-- Codec v1 (legacy) fields
local f_v1_report_id = ProtoField.uint8("trezor_dissector.codec_v1.report_id", "V1 HID Report ID", base.HEX)
local f_v1_magic = ProtoField.string("trezor_dissector.codec_v1.magic", "V1 Magic")
local f_v1_msg_type = ProtoField.uint16("trezor_dissector.codec_v1.msg_type", "V1 Message Type", base.DEC)
local f_v1_msg_name = ProtoField.string("trezor_dissector.codec_v1.msg_name", "V1 Message Name")
local f_v1_length = ProtoField.uint32("trezor_dissector.codec_v1.length", "V1 Payload Length", base.DEC)
local f_v1_payload = ProtoField.bytes("trezor_dissector.codec_v1.payload", "V1 Protobuf Payload")
local f_v1_payload_in_packet = ProtoField.uint32("trezor_dissector.codec_v1.payload_in_packet", "V1 Payload Bytes In This Packet", base.DEC)
local f_v1_remaining = ProtoField.uint32("trezor_dissector.codec_v1.remaining", "V1 Remaining Bytes After This Packet", base.DEC)
local f_v1_needs_continuation = ProtoField.bool("trezor_dissector.codec_v1.needs_continuation", "V1 Needs Continuation")
local f_v1_continuation = ProtoField.bytes("trezor_dissector.codec_v1.continuation", "V1 Continuation Payload")

-- Direction / endpoint role (filterable)
local f_direction = ProtoField.string("trezor_dissector.thp.direction", "Direction")
local f_src_role = ProtoField.string("trezor_dissector.thp.src_role", "Source Role")
local f_dst_role = ProtoField.string("trezor_dissector.thp.dst_role", "Destination Role")

thp.fields = {
    f_direction,
    f_src_role,
    f_dst_role,
    f_control,
    f_control_name,
    f_cid,
    f_length,

    f_data,
    f_payload,
    f_padding,
    f_crc,

    f_nonce,
    f_allocated_cid,
    f_device_properties,

    f_error_code,
    f_error_name,
    f_error_extra,

    f_handshake_host_ephemeral,
    f_handshake_try_to_unlock,
    f_handshake_trezor_ephemeral,
    f_handshake_encrypted_trezor_static,
    f_handshake_tag,
    f_handshake_encrypted_host_static,
    f_handshake_encrypted_payload,
    f_handshake_encrypted_trezor_state,

    f_encrypted_payload_len,
    f_encrypted_ciphertext,

    f_seq,
    f_ack,

    f_payload_in_packet,
    f_remaining,
    f_needs_continuation,

    f_raw,

    f_v1_report_id,
    f_v1_magic,
    f_v1_msg_type,
    f_v1_msg_name,
    f_v1_length,
    f_v1_payload,
    f_v1_payload_in_packet,
    f_v1_remaining,
    f_v1_needs_continuation,
    f_v1_continuation,
}

-- Control byte constants
local CONTINUATION_BIT = 0x80

local DATA_MASK = 0xE7
local HANDSHAKE_INIT_REQ = 0x00
local HANDSHAKE_INIT_RES = 0x01
local HANDSHAKE_COMP_REQ = 0x02
local HANDSHAKE_COMP_RES = 0x03
local ENCRYPTED_TRANSPORT = 0x04

local DATA_SEQ_BIT = 0x10
local DATA_ACK_SEQ_BIT = 0x08
local DATA_DETECT_MASK = 0xE0
local DATA_DETECT_BASE = 0x00

local ACK_MASK = 0xF7
local ACK_BASE = 0x20
local ACK_SEQ_BIT = 0x08

local CODEC_V1 = 0x3F
local CHANNEL_ALLOCATION_REQ = 0x40
local CHANNEL_ALLOCATION_RES = 0x41
local ERROR = 0x42
local PING = 0x43
local PONG = 0x44

-- CHANGE A: packet size depends on the transport layer.
-- Spec: USB = 64 B, BLE = 244 B, emulator UDP = 64 B.
-- Set by the per-transport registration wrappers at the bottom of this file.
local thp_packet_size = 64

local fixed_names = {
    [CODEC_V1] = "CODEC_V1",
    [CHANNEL_ALLOCATION_REQ] = "CHANNEL_ALLOCATION_REQ",
    [CHANNEL_ALLOCATION_RES] = "CHANNEL_ALLOCATION_RES",
    [ERROR] = "ERROR",
    [PING] = "PING",
    [PONG] = "PONG",
}

local data_names = {
    [HANDSHAKE_INIT_REQ] = "HANDSHAKE_INIT_REQ",
    [HANDSHAKE_INIT_RES] = "HANDSHAKE_INIT_RES",
    [HANDSHAKE_COMP_REQ] = "HANDSHAKE_COMP_REQ",
    [HANDSHAKE_COMP_RES] = "HANDSHAKE_COMP_RES",
    [ENCRYPTED_TRANSPORT] = "ENCRYPTED_TRANSPORT",
}