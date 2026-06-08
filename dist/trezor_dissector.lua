-- trezor_dissector.lua — Wireshark dissector for Trezor protocols
-- (THP for Trezor Safe 7, Codec v1 for older devices).
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.



-- ===================================================================
-- BEGIN 01_proto_fields.lua
-- ===================================================================
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
-- ===================================================================
-- BEGIN 02_constants.lua
-- ===================================================================
-- 02_constants.lua — control-byte constants, Codec v1 magic, message-name maps.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh
--
-- Codec v1 magic / report id.
local V1_REPORT_ID = 0x3F   -- '?'  HID report id, precedes the frame on USB HID
local V1_MAGIC_BYTE = 0x23  -- '#'  two of these form the v1 frame magic "##"

-- >>> BEGIN GENERATED MESSAGE NAMES (gen_message_names.py) >>>
-- 02_constants.lua — message-name map (GENERATED, do not edit by hand).
-- Regenerate with: python tools/gen_message_names.py <messages.proto> --inplace
--
-- The MessageType numbers are the shared protobuf enum used by BOTH
-- Codec v1 and THP; only the framing differs. Includes DebugLink (100+)
-- so emulator test traffic is decoded too. Unknown numbers fall back to
-- "MessageType_<n>" at lookup time.
local v1_message_names = {
    [0] = "Initialize",
    [1] = "Ping",
    [2] = "Success",
    [3] = "Failure",
    [4] = "ChangePin",
    [5] = "WipeDevice",
    [6] = "FirmwareErase",
    [7] = "FirmwareUpload",
    [8] = "FirmwareRequest",
    [9] = "GetEntropy",
    [10] = "Entropy",
    [11] = "GetPublicKey",
    [12] = "PublicKey",
    [13] = "LoadDevice",
    [14] = "ResetDevice",
    [15] = "SignTx",
    [16] = "SetBusy",
    [17] = "Features",
    [18] = "PinMatrixRequest",
    [19] = "PinMatrixAck",
    [20] = "Cancel",
    [21] = "TxRequest",
    [22] = "TxAck",
    [23] = "CipherKeyValue",
    [24] = "LockDevice",
    [25] = "ApplySettings",
    [26] = "ButtonRequest",
    [27] = "ButtonAck",
    [28] = "ApplyFlags",
    [29] = "GetAddress",
    [30] = "Address",
    [31] = "GetNonce",
    [32] = "ProdTestT1",
    [33] = "Nonce",
    [34] = "BackupDevice",
    [35] = "EntropyRequest",
    [36] = "EntropyAck",
    [37] = "PaymentRequest",
    [38] = "SignMessage",
    [39] = "VerifyMessage",
    [40] = "MessageSignature",
    [41] = "PassphraseRequest",
    [42] = "PassphraseAck",
    [43] = "GetOwnershipId",
    [44] = "OwnershipId",
    [45] = "RecoveryDevice",
    [46] = "WordRequest",
    [47] = "WordAck",
    [48] = "CipheredKeyValue",
    [49] = "GetOwnershipProof",
    [50] = "OwnershipProof",
    [51] = "AuthorizeCoinJoin",
    [52] = "PaymentNotification",
    [53] = "SignIdentity",
    [54] = "SignedIdentity",
    [55] = "GetFeatures",
    [56] = "EthereumGetAddress",
    [57] = "EthereumAddress",
    [58] = "EthereumSignTx",
    [59] = "EthereumTxRequest",
    [60] = "EthereumTxAck",
    [61] = "GetECDHSessionKey",
    [62] = "ECDHSessionKey",
    [63] = "SetU2FCounter",
    [64] = "EthereumSignMessage",
    [65] = "EthereumVerifyMessage",
    [66] = "EthereumMessageSignature",
    [67] = "NEMGetAddress",
    [68] = "NEMAddress",
    [69] = "NEMSignTx",
    [70] = "NEMSignedTx",
    [75] = "NEMDecryptMessage",
    [76] = "NEMDecryptedMessage",
    [77] = "Deprecated_PassphraseStateRequest",
    [78] = "Deprecated_PassphraseStateAck",
    [79] = "SdProtect",
    [80] = "GetNextU2FCounter",
    [81] = "NextU2FCounter",
    [82] = "ChangeWipeCode",
    [83] = "EndSession",
    [84] = "DoPreauthorized",
    [85] = "PreauthorizedRequest",
    [86] = "CancelAuthorization",
    [87] = "RebootToBootloader",
    [88] = "GetFirmwareHash",
    [89] = "FirmwareHash",
    [93] = "UnlockPath",
    [94] = "UnlockedPathRequest",
    [95] = "ShowDeviceTutorial",
    [96] = "UnlockBootloader",
    [97] = "AuthenticateDevice",
    [98] = "AuthenticityProof",
    [99] = "AuthenticityProofSizes",
    [100] = "DebugLinkDecision",
    [101] = "DebugLinkGetState",
    [102] = "DebugLinkState",
    [103] = "DebugLinkStop",
    [104] = "DebugLinkLog",
    [110] = "DebugLinkMemoryRead",
    [111] = "DebugLinkMemory",
    [112] = "DebugLinkMemoryWrite",
    [113] = "DebugLinkFlashErase",
    [150] = "TezosGetAddress",
    [151] = "TezosAddress",
    [152] = "TezosSignTx",
    [153] = "TezosSignedTx",
    [154] = "TezosGetPublicKey",
    [155] = "TezosPublicKey",
    [202] = "StellarSignTx",
    [203] = "StellarTxOpRequest",
    [207] = "StellarGetAddress",
    [208] = "StellarAddress",
    [210] = "StellarCreateAccountOp",
    [211] = "StellarPaymentOp",
    [212] = "StellarPathPaymentStrictReceiveOp",
    [213] = "StellarManageSellOfferOp",
    [214] = "StellarCreatePassiveSellOfferOp",
    [215] = "StellarSetOptionsOp",
    [216] = "StellarChangeTrustOp",
    [217] = "StellarAllowTrustOp",
    [218] = "StellarAccountMergeOp",
    [220] = "StellarManageDataOp",
    [221] = "StellarBumpSequenceOp",
    [222] = "StellarManageBuyOfferOp",
    [223] = "StellarPathPaymentStrictSendOp",
    [225] = "StellarClaimClaimableBalanceOp",
    [230] = "StellarSignedTx",
    [305] = "CardanoGetPublicKey",
    [306] = "CardanoPublicKey",
    [307] = "CardanoGetAddress",
    [308] = "CardanoAddress",
    [313] = "CardanoTxItemAck",
    [314] = "CardanoTxAuxiliaryDataSupplement",
    [315] = "CardanoTxWitnessRequest",
    [316] = "CardanoTxWitnessResponse",
    [317] = "CardanoTxHostAck",
    [318] = "CardanoTxBodyHash",
    [319] = "CardanoSignTxFinished",
    [320] = "CardanoSignTxInit",
    [321] = "CardanoTxInput",
    [322] = "CardanoTxOutput",
    [323] = "CardanoAssetGroup",
    [324] = "CardanoToken",
    [325] = "CardanoTxCertificate",
    [326] = "CardanoTxWithdrawal",
    [327] = "CardanoTxAuxiliaryData",
    [328] = "CardanoPoolOwner",
    [329] = "CardanoPoolRelayParameters",
    [330] = "CardanoGetNativeScriptHash",
    [331] = "CardanoNativeScriptHash",
    [332] = "CardanoTxMint",
    [333] = "CardanoTxCollateralInput",
    [334] = "CardanoTxRequiredSigner",
    [335] = "CardanoTxInlineDatumChunk",
    [336] = "CardanoTxReferenceScriptChunk",
    [337] = "CardanoTxReferenceInput",
    [338] = "CardanoSignMessageInit",
    [339] = "CardanoMessageDataRequest",
    [340] = "CardanoMessageDataResponse",
    [341] = "CardanoMessageSignature",
    [400] = "RippleGetAddress",
    [401] = "RippleAddress",
    [402] = "RippleSignTx",
    [403] = "RippleSignedTx",
    [450] = "EthereumGetPublicKey",
    [451] = "EthereumPublicKey",
    [452] = "EthereumSignTxEIP1559",
    [464] = "EthereumSignTypedData",
    [465] = "EthereumTypedDataStructRequest",
    [466] = "EthereumTypedDataStructAck",
    [467] = "EthereumTypedDataValueRequest",
    [468] = "EthereumTypedDataValueAck",
    [469] = "EthereumTypedDataSignature",
    [470] = "EthereumSignTypedHash",
    [471] = "EthereumDefinitionRequest",
    [472] = "EthereumDefinitionAck",
    [501] = "MoneroTransactionInitRequest",
    [502] = "MoneroTransactionInitAck",
    [503] = "MoneroTransactionSetInputRequest",
    [504] = "MoneroTransactionSetInputAck",
    [507] = "MoneroTransactionInputViniRequest",
    [508] = "MoneroTransactionInputViniAck",
    [509] = "MoneroTransactionAllInputsSetRequest",
    [510] = "MoneroTransactionAllInputsSetAck",
    [511] = "MoneroTransactionSetOutputRequest",
    [512] = "MoneroTransactionSetOutputAck",
    [513] = "MoneroTransactionAllOutSetRequest",
    [514] = "MoneroTransactionAllOutSetAck",
    [515] = "MoneroTransactionSignInputRequest",
    [516] = "MoneroTransactionSignInputAck",
    [517] = "MoneroTransactionFinalRequest",
    [518] = "MoneroTransactionFinalAck",
    [530] = "MoneroKeyImageExportInitRequest",
    [531] = "MoneroKeyImageExportInitAck",
    [532] = "MoneroKeyImageSyncStepRequest",
    [533] = "MoneroKeyImageSyncStepAck",
    [534] = "MoneroKeyImageSyncFinalRequest",
    [535] = "MoneroKeyImageSyncFinalAck",
    [540] = "MoneroGetAddress",
    [541] = "MoneroAddress",
    [542] = "MoneroGetWatchKey",
    [543] = "MoneroWatchKey",
    [546] = "DebugMoneroDiagRequest",
    [547] = "DebugMoneroDiagAck",
    [550] = "MoneroGetTxKeyRequest",
    [551] = "MoneroGetTxKeyAck",
    [552] = "MoneroLiveRefreshStartRequest",
    [553] = "MoneroLiveRefreshStartAck",
    [554] = "MoneroLiveRefreshStepRequest",
    [555] = "MoneroLiveRefreshStepAck",
    [556] = "MoneroLiveRefreshFinalRequest",
    [557] = "MoneroLiveRefreshFinalAck",
    [600] = "EosGetPublicKey",
    [601] = "EosPublicKey",
    [602] = "EosSignTx",
    [603] = "EosTxActionRequest",
    [604] = "EosTxActionAck",
    [605] = "EosSignedTx",
    [800] = "WebAuthnListResidentCredentials",
    [801] = "WebAuthnCredentials",
    [802] = "WebAuthnAddResidentCredential",
    [803] = "WebAuthnRemoveResidentCredential",
    [804] = "WebAuthnCredentialsAck",
    [900] = "SolanaGetPublicKey",
    [901] = "SolanaPublicKey",
    [902] = "SolanaGetAddress",
    [903] = "SolanaAddress",
    [904] = "SolanaSignTx",
    [905] = "SolanaTxSignature",
    [906] = "SolanaSignMessage",
    [907] = "SolanaMessageSignature",
    [908] = "SolanaVerifyMessage",
    [990] = "ChangeLanguage",
    [991] = "DataChunkRequest",
    [992] = "DataChunkAck",
    [993] = "SetBrightness",
    [994] = "EntropyCheckReady",
    [995] = "EntropyCheckContinue",
    [996] = "GetSerialNumber",
    [997] = "SerialNumber",
    [998] = "GetAuthenticityProofChunk",
    [999] = "AuthenticityProofChunk",
    [1000] = "ThpCreateNewSession",
    [1016] = "ThpCredentialRequest",
    [1017] = "ThpCredentialResponse",
    [1100] = "TelemetryGet",
    [1101] = "Telemetry",
    [2001] = "NostrGetPubkey",
    [2002] = "NostrPubkey",
    [2003] = "NostrSignEvent",
    [2004] = "NostrEventSignature",
    [2100] = "EvoluGetNode",
    [2101] = "EvoluNode",
    [2102] = "EvoluSignRegistrationRequest",
    [2103] = "EvoluRegistrationRequest",
    [2104] = "EvoluGetDelegatedIdentityKey",
    [2105] = "EvoluDelegatedIdentityKey",
    [2106] = "EvoluIndexManagement",
    [2107] = "EvoluIndexManagementResponse",
    [2200] = "TronGetAddress",
    [2201] = "TronAddress",
    [2202] = "TronSignTx",
    [2203] = "TronSignature",
    [2204] = "TronContractRequest",
    [2205] = "TronTransferContract",
    [2206] = "TronTriggerSmartContract",
    [2207] = "TronFreezeBalanceV2Contract",
    [2208] = "TronUnfreezeBalanceV2Contract",
    [2209] = "TronWithdrawUnfreeze",
    [2210] = "TronVoteWitnessContract",
    [8001] = "BleUnpair",
    [9001] = "DebugLinkLayout",
    [9002] = "DebugLinkReseedRandom",
    [9003] = "DebugLinkRecordScreen",
    [9005] = "DebugLinkEraseSdCard",
    [9006] = "DebugLinkWatchLayout",
    [9007] = "DebugLinkResetDebugEvents",
    [9008] = "DebugLinkOptigaSetSecMax",
    [9009] = "DebugLinkGetGcInfo",
    [9010] = "DebugLinkGcInfo",
    [9011] = "DebugLinkGetPairingInfo",
    [9012] = "DebugLinkPairingInfo",
    [9013] = "DebugLinkSetLogFilter",
    [9014] = "DebugLinkN4W1Connected",
    [9015] = "DebugLinkN4W1Write",
    [9016] = "DebugLinkN4W1Read",
    [9017] = "DebugLinkN4W1Response",
    [9018] = "DebugLinkSetBatteryState",
    [9100] = "BenchmarkListNames",
    [9101] = "BenchmarkNames",
    [9102] = "BenchmarkRun",
    [9103] = "BenchmarkResult",
}

local function v1_message_name(msg_type)
    return v1_message_names[msg_type] or string.format("MessageType_%d", msg_type)
end
-- <<< END GENERATED MESSAGE NAMES <<<

local transport_error_names = {
    [0] = "RESERVED",
    [1] = "TRANSPORT_BUSY",
    [2] = "UNALLOCATED_CHANNEL",
    [3] = "DECRYPTION_FAILED",
    [4] = "RESERVED",
    [5] = "DEVICE_LOCKED",
}

-- Simple per-direction reassembly tracking.
local reassembly_state = {}
local frame_info = {}
-- ===================================================================
-- BEGIN 03_util.lua
-- ===================================================================
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

-- Read a base-128 varint from byte-string `s` at 1-based index `i`.
-- Returns value (integer), next_index.
local function pb_read_varint(s, i)
    local result = 0
    local shift = 0
    while i <= #s do
        local b = string.byte(s, i)
        i = i + 1
        result = result + (b % 128) * (2 ^ shift)
        if b < 128 then return math.floor(result), i end
        shift = shift + 7
        if shift > 63 then return math.floor(result), i end
    end
    return math.floor(result), i
end

-- Parse a serialized ThpDeviceProperties protobuf (from ChannelAllocationResponse).
-- Returns a table: internal_model, model_variant, protocol_version_major/minor,
-- pairing_methods (list of numbers), warnings (list of strings).
local function parse_device_properties(s)
    local out = { pairing_methods = {}, warnings = {} }
    local i = 1
    while i <= #s do
        local tag
        tag, i = pb_read_varint(s, i)
        local field_no = math.floor(tag / 8)
        local wire_type = tag % 8
        if wire_type == 0 then
            local v
            v, i = pb_read_varint(s, i)
            if field_no == 2 then out.model_variant = v
            elseif field_no == 3 then out.protocol_version_major = v
            elseif field_no == 4 then out.protocol_version_minor = v
            elseif field_no == 5 then out.pairing_methods[#out.pairing_methods + 1] = v
            else out.warnings[#out.warnings + 1] = string.format("unknown varint field %d", field_no) end
        elseif wire_type == 2 then
            local len
            len, i = pb_read_varint(s, i)
            local chunk = string.sub(s, i, i + len - 1)
            i = i + len
            if field_no == 1 then out.internal_model = chunk
            elseif field_no == 5 then
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

local function concat_chunks(chunks)
    local out = ""
    for _, chunk in ipairs(chunks) do
        out = out .. chunk
    end
    return out
end
-- ===================================================================
-- BEGIN 04_thp.lua
-- ===================================================================
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

local function add_encrypted_transport_from_hex(subtree, buffer, data_hex)
    local data_len = hex_len(data_hex)
    local enc = subtree:add(buffer(0, 0), "Reassembled Encrypted Transport Message")
    enc:add(buffer(0, 0), string.format("Encrypted Payload Length: %d", data_len))

    if data_len > 0 then
        enc:add(buffer(0, 0), "Encrypted Ciphertext: " .. data_hex)
    else
        enc:add(buffer(0, 0), "Encrypted Ciphertext: empty")
    end
end

local function dissect_encrypted_transport_in_current_packet(subtree, buffer, data_offset, data_crc_len, packet_len)
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
-- ===================================================================
-- BEGIN 05_codec_v1.lua
-- ===================================================================
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

-- Per-packet record of "this packet was dissected as a v1 continuation",
-- keyed by frame number so it survives Wireshark's multiple dissection
-- passes (the transient v1_reassembly_state does not).
local v1_is_cont_frame = {}

local function v1_reassembly_in_progress(pinfo)
    -- On the first pass, decide from live reassembly state and remember it.
    -- On later passes, trust the remembered decision.
    if v1_is_cont_frame[pinfo.number] ~= nil then
        return v1_is_cont_frame[pinfo.number]
    end
    local in_progress = v1_reassembly_state[v1_direction_key(pinfo)] ~= nil
    v1_is_cont_frame[pinfo.number] = in_progress
    return in_progress
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

    -- Continuation packet. Recognized by reassembly STATE (decided in the
    -- dispatcher and remembered per-frame), NOT by data bytes — continuation
    -- data can start with any byte, including 0x23, so content-based detection
    -- was unreliable. The data offset still depends on the optional report id.
    local is_cont = v1_reassembly_in_progress(pinfo)
    local coff = 0
    if buffer:len() >= 1 and buffer(0, 1):uint() == V1_REPORT_ID then
        coff = 1
    end
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
-- ===================================================================
-- BEGIN 06_dispatch.lua
-- ===================================================================
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
-- ===================================================================
-- BEGIN 07_register.lua
-- ===================================================================
-- 07_register.lua — transport registrations (UDP, USB, BLE, DLT_USER0).
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh


-- UDP emulator, packet size 64. The port(s) come from the configurable
-- preference (default 21324). We register the whole configured range, and
-- re-register whenever the user changes the preference. We also keep the UDP
-- heuristic as a fallback so traffic on an unconfigured port can still match.
local udp_table = DissectorTable.get("udp.port")
local registered_udp_ports = {}

-- Parse "21324" or "21324-21400" or "21324,21326" into a list of port numbers.
local function parse_ports(spec)
    local ports = {}
    if spec == nil then return ports end
    for part in tostring(spec):gmatch("[^,]+") do
        part = part:gsub("%s", "")
        local lo, hi = part:match("^(%d+)%-(%d+)$")
        if lo ~= nil then
            for p = tonumber(lo), tonumber(hi) do ports[#ports + 1] = p end
        else
            local single = part:match("^(%d+)$")
            if single ~= nil then ports[#ports + 1] = tonumber(single) end
        end
    end
    return ports
end

local function register_udp_ports()
    -- Unregister previously added ports.
    for _, p in ipairs(registered_udp_ports) do
        udp_table:remove(p, thp)
    end
    registered_udp_ports = parse_ports(thp.prefs.udp_ports)
    for _, p in ipairs(registered_udp_ports) do
        udp_table:add(p, thp)
    end
end

register_udp_ports()
thp:register_heuristic("udp", thp.dissector)

-- Re-register when the user changes the port preference.
function thp.prefs_changed()
    register_udp_ports()
end

-- DLT_USER0 (link-layer type 147): synthetic pcaps that carry raw Trezor
-- frames from byte 0 with no transport wrapper (produced by an external
-- trezorlib chunk-hook capture script). Packet size 64 (USB/HID).
-- Registering here lets "trezor_dissector" decode User 0 frames. Depending on
-- the Wireshark version you may still need to map it once under
-- Edit > Preferences > Protocols > DLT_USER (User 0 -> trezor_dissector).
pcall(function()
    local wtap_table = DissectorTable.get("wtap_encap")
    local user0 = nil
    if wtap ~= nil and wtap.USER0 ~= nil then
        user0 = wtap.USER0
    end
    if user0 ~= nil then
        wtap_table:add(user0, thp)
    end
end)

-- USB: HID interrupt and WebUSB/vendor bulk, packet size 64.
local USB_PACKET_SIZE = 64
thp:register_heuristic("usb.interrupt", function(buffer, pinfo, tree)
    thp_packet_size = USB_PACKET_SIZE
    local consumed = thp.dissector(buffer, pinfo, tree)
    return consumed and consumed > 0
end)
thp:register_heuristic("usb.bulk", function(buffer, pinfo, tree)
    thp_packet_size = USB_PACKET_SIZE
    local consumed = thp.dissector(buffer, pinfo, tree)
    return consumed and consumed > 0
end)

-- Optional direct bind to Trezor VID:PID (1209:53c1) via usb.product.
-- Works only when Wireshark obtained the device descriptor; in VM USB
-- passthrough it is often missing, in which case the heuristics above apply.
pcall(function()
    DissectorTable.get("usb.product"):add(0x120953c1, function(buffer, pinfo, tree)
        thp_packet_size = USB_PACKET_SIZE
        return thp.dissector(buffer, pinfo, tree)
    end)
end)

-- BLE: Trezor Safe 7, packet size 244. THP travels as a GATT characteristic
-- value, dissected on the Bluetooth ATT layer.
-- NOTE: assumes THP control byte starts at offset 0 of the ATT value.
-- If a real Safe 7 BLE capture shows a leading offset, slice the buffer here.
pcall(function()
    thp:register_heuristic("btatt", function(buffer, pinfo, tree)
        thp_packet_size = 244
        local consumed = thp.dissector(buffer, pinfo, tree)
        return consumed and consumed > 0
    end)
end)