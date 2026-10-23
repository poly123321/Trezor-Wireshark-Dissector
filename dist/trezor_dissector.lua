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

-- Optional THP Noise keylog. Similar to TLS SSLKEYLOGFILE:
-- without a matching keylog, ENCRYPTED_TRANSPORT stays encrypted.
thp.prefs.thp_keylog_path = Pref.string("THP keylog file", "",
    "Path to a THP keylog file captured from the same trezorlib session as the PCAP")

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
local f_encrypted_decrypt_status = ProtoField.string("trezor_dissector.thp.encrypted.decrypt_status", "THP Decryption Status")
local f_encrypted_decrypt_direction = ProtoField.string("trezor_dissector.thp.encrypted.decrypt_direction", "THP Decrypted Direction")
local f_encrypted_decrypt_nonce = ProtoField.uint32("trezor_dissector.thp.encrypted.decrypt_nonce", "THP Noise Nonce", base.DEC)
local f_encrypted_plaintext_len = ProtoField.uint16("trezor_dissector.thp.encrypted.plaintext_len", "Decrypted Plaintext Length", base.DEC)
local f_encrypted_plaintext = ProtoField.bytes("trezor_dissector.thp.encrypted.plaintext", "Decrypted Plaintext")
local f_encrypted_session_id = ProtoField.uint8("trezor_dissector.thp.encrypted.session_id", "Decrypted Session ID", base.DEC)
local f_encrypted_msg_type = ProtoField.uint16("trezor_dissector.thp.encrypted.msg_type", "Decrypted Message Type", base.DEC)
local f_encrypted_msg_name = ProtoField.string("trezor_dissector.thp.encrypted.msg_name", "Decrypted Message Name")
local f_encrypted_protobuf_payload = ProtoField.bytes("trezor_dissector.thp.encrypted.protobuf_payload", "Decrypted Protobuf Payload")

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
    f_encrypted_decrypt_status,
    f_encrypted_decrypt_direction,
    f_encrypted_decrypt_nonce,
    f_encrypted_plaintext_len,
    f_encrypted_plaintext,
    f_encrypted_session_id,
    f_encrypted_msg_type,
    f_encrypted_msg_name,
    f_encrypted_protobuf_payload,

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
local V1_REPORT_ID = 0x3F 
local V1_MAGIC_BYTE = 0x23  

-- >>> BEGIN GENERATED MESSAGE NAMES (gen_message_names.py) >>>
--
-- Generated by tools/gen_message_names.py.
-- Sources:
--   common/protob/messages.proto
--   common/protob/messages-thp.proto
--
-- The message-type numbers are shared by Codec v1 and THP decrypted
-- application messages. Unknown values fall back to MessageType_<n>.
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
    [114] = "LiskGetAddress",
    [115] = "LiskAddress",
    [116] = "LiskSignTx",
    [117] = "LiskSignedTx",
    [118] = "LiskSignMessage",
    [119] = "LiskMessageSignature",
    [120] = "LiskVerifyMessage",
    [121] = "LiskGetPublicKey",
    [122] = "LiskPublicKey",
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
    [1008] = "ThpPairingRequest",
    [1009] = "ThpPairingRequestApproved",
    [1010] = "ThpSelectMethod",
    [1011] = "ThpPairingPreparationsFinished",
    [1016] = "ThpCredentialRequest",
    [1017] = "ThpCredentialResponse",
    [1018] = "ThpEndRequest",
    [1019] = "ThpEndResponse",
    [1024] = "ThpCodeEntryCommitment",
    [1025] = "ThpCodeEntryChallenge",
    [1026] = "ThpCodeEntryCpaceTrezor",
    [1027] = "ThpCodeEntryCpaceHostTag",
    [1028] = "ThpCodeEntrySecret",
    [1032] = "ThpQrCodeTag",
    [1033] = "ThpQrCodeSecret",
    [1040] = "ThpNfcTagHost",
    [1041] = "ThpNfcTagTrezor",
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

-- >>> BEGIN GENERATED MESSAGE FIELDS (gen_message_fields.py) >>>
-- Generated by tools/gen_message_fields.py from a protoc descriptor set.
-- Do not edit by hand; regenerate when the .proto files change.

local pb_enums = {
    ["AmountUnit"] = {
        [0] = "BITCOIN",
        [1] = "MILLIBITCOIN",
        [2] = "MICROBITCOIN",
        [3] = "SATOSHI",
    },
    ["BackupMethod"] = {
        [0] = "Display",
        [1] = "N4W1",
    },
    ["BackupType"] = {
        [0] = "Bip39",
        [1] = "Slip39_Basic",
        [2] = "Slip39_Advanced",
        [3] = "Slip39_Single_Extendable",
        [4] = "Slip39_Basic_Extendable",
        [5] = "Slip39_Advanced_Extendable",
    },
    ["ButtonRequest.ButtonRequestType"] = {
        [1] = "ButtonRequest_Other",
        [2] = "ButtonRequest_FeeOverThreshold",
        [3] = "ButtonRequest_ConfirmOutput",
        [4] = "ButtonRequest_ResetDevice",
        [5] = "ButtonRequest_ConfirmWord",
        [6] = "ButtonRequest_WipeDevice",
        [7] = "ButtonRequest_ProtectCall",
        [8] = "ButtonRequest_SignTx",
        [9] = "ButtonRequest_FirmwareCheck",
        [10] = "ButtonRequest_Address",
        [11] = "ButtonRequest_PublicKey",
        [12] = "ButtonRequest_MnemonicWordCount",
        [13] = "ButtonRequest_MnemonicInput",
        [14] = "_Deprecated_ButtonRequest_PassphraseType",
        [15] = "ButtonRequest_UnknownDerivationPath",
        [16] = "ButtonRequest_RecoveryHomepage",
        [17] = "ButtonRequest_Success",
        [18] = "ButtonRequest_Warning",
        [19] = "ButtonRequest_PassphraseEntry",
        [20] = "ButtonRequest_PinEntry",
    },
    ["CardanoAddressType"] = {
        [0] = "BASE",
        [1] = "BASE_SCRIPT_KEY",
        [2] = "BASE_KEY_SCRIPT",
        [3] = "BASE_SCRIPT_SCRIPT",
        [4] = "POINTER",
        [5] = "POINTER_SCRIPT",
        [6] = "ENTERPRISE",
        [7] = "ENTERPRISE_SCRIPT",
        [8] = "BYRON",
        [14] = "REWARD",
        [15] = "REWARD_SCRIPT",
    },
    ["CardanoCVoteRegistrationFormat"] = {
        [0] = "CIP15",
        [1] = "CIP36",
    },
    ["CardanoCertificateType"] = {
        [0] = "STAKE_REGISTRATION",
        [1] = "STAKE_DEREGISTRATION",
        [2] = "STAKE_DELEGATION",
        [3] = "STAKE_POOL_REGISTRATION",
        [7] = "STAKE_REGISTRATION_CONWAY",
        [8] = "STAKE_DEREGISTRATION_CONWAY",
        [9] = "VOTE_DELEGATION",
    },
    ["CardanoDRepType"] = {
        [0] = "KEY_HASH",
        [1] = "SCRIPT_HASH",
        [2] = "ABSTAIN",
        [3] = "NO_CONFIDENCE",
    },
    ["CardanoDerivationType"] = {
        [0] = "LEDGER",
        [1] = "ICARUS",
        [2] = "ICARUS_TREZOR",
    },
    ["CardanoNativeScriptHashDisplayFormat"] = {
        [0] = "HIDE",
        [1] = "BECH32",
        [2] = "POLICY_ID",
    },
    ["CardanoNativeScriptType"] = {
        [0] = "PUB_KEY",
        [1] = "ALL",
        [2] = "ANY",
        [3] = "N_OF_K",
        [4] = "INVALID_BEFORE",
        [5] = "INVALID_HEREAFTER",
    },
    ["CardanoPoolRelayType"] = {
        [0] = "SINGLE_HOST_IP",
        [1] = "SINGLE_HOST_NAME",
        [2] = "MULTIPLE_HOST_NAME",
    },
    ["CardanoTxAuxiliaryDataSupplementType"] = {
        [0] = "NONE",
        [1] = "CVOTE_REGISTRATION_SIGNATURE",
    },
    ["CardanoTxOutputSerializationFormat"] = {
        [0] = "ARRAY_LEGACY",
        [1] = "MAP_BABBAGE",
    },
    ["CardanoTxSigningMode"] = {
        [0] = "ORDINARY_TRANSACTION",
        [1] = "POOL_REGISTRATION_AS_OWNER",
        [2] = "MULTISIG_TRANSACTION",
        [3] = "PLUTUS_TRANSACTION",
    },
    ["CardanoTxWitnessType"] = {
        [0] = "BYRON_WITNESS",
        [1] = "SHELLEY_WITNESS",
    },
    ["DebugLinkDecision.DebugButton"] = {
        [0] = "NO",
        [1] = "YES",
        [2] = "INFO",
    },
    ["DebugLinkDecision.DebugPhysicalButton"] = {
        [0] = "LEFT_BTN",
        [1] = "MIDDLE_BTN",
        [2] = "RIGHT_BTN",
    },
    ["DebugLinkDecision.DebugSwipeDirection"] = {
        [0] = "UP",
        [1] = "DOWN",
        [2] = "LEFT",
        [3] = "RIGHT",
    },
    ["DebugLinkDecision.DebugTouchEventType"] = {
        [0] = "TOUCH_FULL_CLICK",
        [1] = "TOUCH_START",
        [2] = "TOUCH_END",
    },
    ["DebugLinkGetState.DebugWaitType"] = {
        [0] = "IMMEDIATE",
        [1] = "NEXT_LAYOUT",
        [2] = "CURRENT_LAYOUT",
    },
    ["DecredStakingSpendType"] = {
        [0] = "SSGen",
        [1] = "SSRTX",
    },
    ["DefinitionType"] = {
        [0] = "ETHEREUM_NETWORK",
        [1] = "ETHEREUM_TOKEN",
        [2] = "SOLANA_TOKEN",
        [3] = "ETHEREUM_DISPLAY_FORMAT",
    },
    ["DisplayRotation"] = {
        [0] = "North",
        [90] = "East",
        [180] = "South",
        [270] = "West",
    },
    ["EthereumABIType"] = {
        [0] = "ABI_ADDRESS",
        [1] = "ABI_UINT256",
        [2] = "ABI_UINT248",
        [3] = "ABI_UINT160",
        [4] = "ABI_UINT128",
        [5] = "ABI_UINT120",
        [6] = "ABI_UINT112",
        [7] = "ABI_UINT96",
        [8] = "ABI_UINT72",
        [9] = "ABI_UINT64",
        [10] = "ABI_UINT48",
        [11] = "ABI_UINT40",
        [12] = "ABI_UINT32",
        [13] = "ABI_UINT24",
        [14] = "ABI_UINT16",
        [15] = "ABI_UINT8",
        [16] = "ABI_BOOL",
        [17] = "ABI_BYTES32",
        [20] = "ABI_BYTES",
        [21] = "ABI_STRING",
    },
    ["EthereumERC7730ContainerPath"] = {
        [1] = "FROM",
        [2] = "VALUE",
        [3] = "TO",
    },
    ["EthereumERC7730FieldFormatterType"] = {
        [0] = "FORMATTER_ADDRESS_NAME",
        [1] = "FORMATTER_AMOUNT",
        [2] = "FORMATTER_TOKEN_AMOUNT",
        [3] = "FORMATTER_UNIT",
    },
    ["EthereumTypedDataStructAck.EthereumDataType"] = {
        [1] = "UINT",
        [2] = "INT",
        [3] = "BYTES",
        [4] = "STRING",
        [5] = "BOOL",
        [6] = "ADDRESS",
        [7] = "ARRAY",
        [8] = "STRUCT",
    },
    ["Failure.FailureType"] = {
        [1] = "Failure_UnexpectedMessage",
        [2] = "Failure_ButtonExpected",
        [3] = "Failure_DataError",
        [4] = "Failure_ActionCancelled",
        [5] = "Failure_PinExpected",
        [6] = "Failure_PinCancelled",
        [7] = "Failure_PinInvalid",
        [8] = "Failure_InvalidSignature",
        [9] = "Failure_ProcessError",
        [10] = "Failure_NotEnoughFunds",
        [11] = "Failure_NotInitialized",
        [12] = "Failure_PinMismatch",
        [13] = "Failure_WipeCodeMismatch",
        [14] = "Failure_InvalidSession",
        [15] = "Failure_Busy",
        [16] = "Failure_ThpUnallocatedSession",
        [17] = "Failure_InvalidProtocol",
        [19] = "Failure_InProgress",
        [99] = "Failure_FirmwareError",
    },
    ["Features.BackupAvailability"] = {
        [0] = "NotAvailable",
        [1] = "Required",
        [2] = "Available",
    },
    ["Features.Capability"] = {
        [1] = "Capability_Bitcoin",
        [2] = "Capability_Bitcoin_like",
        [3] = "Capability_Binance",
        [4] = "Capability_Cardano",
        [5] = "Capability_Crypto",
        [6] = "Capability_EOS",
        [7] = "Capability_Ethereum",
        [8] = "Capability_Lisk",
        [9] = "Capability_Monero",
        [10] = "Capability_NEM",
        [11] = "Capability_Ripple",
        [12] = "Capability_Stellar",
        [13] = "Capability_Tezos",
        [14] = "Capability_U2F",
        [15] = "Capability_Shamir",
        [16] = "Capability_ShamirGroups",
        [17] = "Capability_PassphraseEntry",
        [18] = "Capability_Solana",
        [19] = "Capability_Translations",
        [20] = "Capability_Brightness",
        [21] = "Capability_Haptic",
        [22] = "Capability_BLE",
        [23] = "Capability_NFC",
        [24] = "Capability_Tron",
        [25] = "Capability_N4W1",
        [26] = "Capability_TouchWakeup",
    },
    ["Features.RecoveryStatus"] = {
        [0] = "Nothing",
        [1] = "Recovery",
        [2] = "Backup",
    },
    ["GetAuthenticityProofChunk.AuthenticityProofType"] = {
        [0] = "OPTIGA",
        [1] = "TROPIC",
        [2] = "MCU",
    },
    ["HomescreenFormat"] = {
        [1] = "Toif",
        [2] = "Jpeg",
        [3] = "ToiG",
    },
    ["InputScriptType"] = {
        [0] = "SPENDADDRESS",
        [1] = "SPENDMULTISIG",
        [2] = "EXTERNAL",
        [3] = "SPENDWITNESS",
        [4] = "SPENDP2SHWITNESS",
        [5] = "SPENDTAPROOT",
    },
    ["MessageType"] = {
        [0] = "MessageType_Initialize",
        [1] = "MessageType_Ping",
        [2] = "MessageType_Success",
        [3] = "MessageType_Failure",
        [4] = "MessageType_ChangePin",
        [5] = "MessageType_WipeDevice",
        [6] = "MessageType_FirmwareErase",
        [7] = "MessageType_FirmwareUpload",
        [8] = "MessageType_FirmwareRequest",
        [9] = "MessageType_GetEntropy",
        [10] = "MessageType_Entropy",
        [11] = "MessageType_GetPublicKey",
        [12] = "MessageType_PublicKey",
        [13] = "MessageType_LoadDevice",
        [14] = "MessageType_ResetDevice",
        [15] = "MessageType_SignTx",
        [16] = "MessageType_SetBusy",
        [17] = "MessageType_Features",
        [18] = "MessageType_PinMatrixRequest",
        [19] = "MessageType_PinMatrixAck",
        [20] = "MessageType_Cancel",
        [21] = "MessageType_TxRequest",
        [22] = "MessageType_TxAck",
        [23] = "MessageType_CipherKeyValue",
        [24] = "MessageType_LockDevice",
        [25] = "MessageType_ApplySettings",
        [26] = "MessageType_ButtonRequest",
        [27] = "MessageType_ButtonAck",
        [28] = "MessageType_ApplyFlags",
        [29] = "MessageType_GetAddress",
        [30] = "MessageType_Address",
        [31] = "MessageType_GetNonce",
        [32] = "MessageType_ProdTestT1",
        [33] = "MessageType_Nonce",
        [34] = "MessageType_BackupDevice",
        [35] = "MessageType_EntropyRequest",
        [36] = "MessageType_EntropyAck",
        [37] = "MessageType_PaymentRequest",
        [38] = "MessageType_SignMessage",
        [39] = "MessageType_VerifyMessage",
        [40] = "MessageType_MessageSignature",
        [41] = "MessageType_PassphraseRequest",
        [42] = "MessageType_PassphraseAck",
        [43] = "MessageType_GetOwnershipId",
        [44] = "MessageType_OwnershipId",
        [45] = "MessageType_RecoveryDevice",
        [46] = "MessageType_WordRequest",
        [47] = "MessageType_WordAck",
        [48] = "MessageType_CipheredKeyValue",
        [49] = "MessageType_GetOwnershipProof",
        [50] = "MessageType_OwnershipProof",
        [51] = "MessageType_AuthorizeCoinJoin",
        [52] = "MessageType_PaymentNotification",
        [53] = "MessageType_SignIdentity",
        [54] = "MessageType_SignedIdentity",
        [55] = "MessageType_GetFeatures",
        [56] = "MessageType_EthereumGetAddress",
        [57] = "MessageType_EthereumAddress",
        [58] = "MessageType_EthereumSignTx",
        [59] = "MessageType_EthereumTxRequest",
        [60] = "MessageType_EthereumTxAck",
        [61] = "MessageType_GetECDHSessionKey",
        [62] = "MessageType_ECDHSessionKey",
        [63] = "MessageType_SetU2FCounter",
        [64] = "MessageType_EthereumSignMessage",
        [65] = "MessageType_EthereumVerifyMessage",
        [66] = "MessageType_EthereumMessageSignature",
        [67] = "MessageType_NEMGetAddress",
        [68] = "MessageType_NEMAddress",
        [69] = "MessageType_NEMSignTx",
        [70] = "MessageType_NEMSignedTx",
        [75] = "MessageType_NEMDecryptMessage",
        [76] = "MessageType_NEMDecryptedMessage",
        [77] = "MessageType_Deprecated_PassphraseStateRequest",
        [78] = "MessageType_Deprecated_PassphraseStateAck",
        [79] = "MessageType_SdProtect",
        [80] = "MessageType_GetNextU2FCounter",
        [81] = "MessageType_NextU2FCounter",
        [82] = "MessageType_ChangeWipeCode",
        [83] = "MessageType_EndSession",
        [84] = "MessageType_DoPreauthorized",
        [85] = "MessageType_PreauthorizedRequest",
        [86] = "MessageType_CancelAuthorization",
        [87] = "MessageType_RebootToBootloader",
        [88] = "MessageType_GetFirmwareHash",
        [89] = "MessageType_FirmwareHash",
        [93] = "MessageType_UnlockPath",
        [94] = "MessageType_UnlockedPathRequest",
        [95] = "MessageType_ShowDeviceTutorial",
        [96] = "MessageType_UnlockBootloader",
        [97] = "MessageType_AuthenticateDevice",
        [98] = "MessageType_AuthenticityProof",
        [99] = "MessageType_AuthenticityProofSizes",
        [100] = "MessageType_DebugLinkDecision",
        [101] = "MessageType_DebugLinkGetState",
        [102] = "MessageType_DebugLinkState",
        [103] = "MessageType_DebugLinkStop",
        [104] = "MessageType_DebugLinkLog",
        [110] = "MessageType_DebugLinkMemoryRead",
        [111] = "MessageType_DebugLinkMemory",
        [112] = "MessageType_DebugLinkMemoryWrite",
        [113] = "MessageType_DebugLinkFlashErase",
        [150] = "MessageType_TezosGetAddress",
        [151] = "MessageType_TezosAddress",
        [152] = "MessageType_TezosSignTx",
        [153] = "MessageType_TezosSignedTx",
        [154] = "MessageType_TezosGetPublicKey",
        [155] = "MessageType_TezosPublicKey",
        [202] = "MessageType_StellarSignTx",
        [203] = "MessageType_StellarTxOpRequest",
        [207] = "MessageType_StellarGetAddress",
        [208] = "MessageType_StellarAddress",
        [210] = "MessageType_StellarCreateAccountOp",
        [211] = "MessageType_StellarPaymentOp",
        [212] = "MessageType_StellarPathPaymentStrictReceiveOp",
        [213] = "MessageType_StellarManageSellOfferOp",
        [214] = "MessageType_StellarCreatePassiveSellOfferOp",
        [215] = "MessageType_StellarSetOptionsOp",
        [216] = "MessageType_StellarChangeTrustOp",
        [217] = "MessageType_StellarAllowTrustOp",
        [218] = "MessageType_StellarAccountMergeOp",
        [220] = "MessageType_StellarManageDataOp",
        [221] = "MessageType_StellarBumpSequenceOp",
        [222] = "MessageType_StellarManageBuyOfferOp",
        [223] = "MessageType_StellarPathPaymentStrictSendOp",
        [225] = "MessageType_StellarClaimClaimableBalanceOp",
        [230] = "MessageType_StellarSignedTx",
        [305] = "MessageType_CardanoGetPublicKey",
        [306] = "MessageType_CardanoPublicKey",
        [307] = "MessageType_CardanoGetAddress",
        [308] = "MessageType_CardanoAddress",
        [313] = "MessageType_CardanoTxItemAck",
        [314] = "MessageType_CardanoTxAuxiliaryDataSupplement",
        [315] = "MessageType_CardanoTxWitnessRequest",
        [316] = "MessageType_CardanoTxWitnessResponse",
        [317] = "MessageType_CardanoTxHostAck",
        [318] = "MessageType_CardanoTxBodyHash",
        [319] = "MessageType_CardanoSignTxFinished",
        [320] = "MessageType_CardanoSignTxInit",
        [321] = "MessageType_CardanoTxInput",
        [322] = "MessageType_CardanoTxOutput",
        [323] = "MessageType_CardanoAssetGroup",
        [324] = "MessageType_CardanoToken",
        [325] = "MessageType_CardanoTxCertificate",
        [326] = "MessageType_CardanoTxWithdrawal",
        [327] = "MessageType_CardanoTxAuxiliaryData",
        [328] = "MessageType_CardanoPoolOwner",
        [329] = "MessageType_CardanoPoolRelayParameters",
        [330] = "MessageType_CardanoGetNativeScriptHash",
        [331] = "MessageType_CardanoNativeScriptHash",
        [332] = "MessageType_CardanoTxMint",
        [333] = "MessageType_CardanoTxCollateralInput",
        [334] = "MessageType_CardanoTxRequiredSigner",
        [335] = "MessageType_CardanoTxInlineDatumChunk",
        [336] = "MessageType_CardanoTxReferenceScriptChunk",
        [337] = "MessageType_CardanoTxReferenceInput",
        [338] = "MessageType_CardanoSignMessageInit",
        [339] = "MessageType_CardanoMessageDataRequest",
        [340] = "MessageType_CardanoMessageDataResponse",
        [341] = "MessageType_CardanoMessageSignature",
        [400] = "MessageType_RippleGetAddress",
        [401] = "MessageType_RippleAddress",
        [402] = "MessageType_RippleSignTx",
        [403] = "MessageType_RippleSignedTx",
        [450] = "MessageType_EthereumGetPublicKey",
        [451] = "MessageType_EthereumPublicKey",
        [452] = "MessageType_EthereumSignTxEIP1559",
        [464] = "MessageType_EthereumSignTypedData",
        [465] = "MessageType_EthereumTypedDataStructRequest",
        [466] = "MessageType_EthereumTypedDataStructAck",
        [467] = "MessageType_EthereumTypedDataValueRequest",
        [468] = "MessageType_EthereumTypedDataValueAck",
        [469] = "MessageType_EthereumTypedDataSignature",
        [470] = "MessageType_EthereumSignTypedHash",
        [471] = "MessageType_EthereumDefinitionRequest",
        [472] = "MessageType_EthereumDefinitionAck",
        [501] = "MessageType_MoneroTransactionInitRequest",
        [502] = "MessageType_MoneroTransactionInitAck",
        [503] = "MessageType_MoneroTransactionSetInputRequest",
        [504] = "MessageType_MoneroTransactionSetInputAck",
        [507] = "MessageType_MoneroTransactionInputViniRequest",
        [508] = "MessageType_MoneroTransactionInputViniAck",
        [509] = "MessageType_MoneroTransactionAllInputsSetRequest",
        [510] = "MessageType_MoneroTransactionAllInputsSetAck",
        [511] = "MessageType_MoneroTransactionSetOutputRequest",
        [512] = "MessageType_MoneroTransactionSetOutputAck",
        [513] = "MessageType_MoneroTransactionAllOutSetRequest",
        [514] = "MessageType_MoneroTransactionAllOutSetAck",
        [515] = "MessageType_MoneroTransactionSignInputRequest",
        [516] = "MessageType_MoneroTransactionSignInputAck",
        [517] = "MessageType_MoneroTransactionFinalRequest",
        [518] = "MessageType_MoneroTransactionFinalAck",
        [530] = "MessageType_MoneroKeyImageExportInitRequest",
        [531] = "MessageType_MoneroKeyImageExportInitAck",
        [532] = "MessageType_MoneroKeyImageSyncStepRequest",
        [533] = "MessageType_MoneroKeyImageSyncStepAck",
        [534] = "MessageType_MoneroKeyImageSyncFinalRequest",
        [535] = "MessageType_MoneroKeyImageSyncFinalAck",
        [540] = "MessageType_MoneroGetAddress",
        [541] = "MessageType_MoneroAddress",
        [542] = "MessageType_MoneroGetWatchKey",
        [543] = "MessageType_MoneroWatchKey",
        [546] = "MessageType_DebugMoneroDiagRequest",
        [547] = "MessageType_DebugMoneroDiagAck",
        [550] = "MessageType_MoneroGetTxKeyRequest",
        [551] = "MessageType_MoneroGetTxKeyAck",
        [552] = "MessageType_MoneroLiveRefreshStartRequest",
        [553] = "MessageType_MoneroLiveRefreshStartAck",
        [554] = "MessageType_MoneroLiveRefreshStepRequest",
        [555] = "MessageType_MoneroLiveRefreshStepAck",
        [556] = "MessageType_MoneroLiveRefreshFinalRequest",
        [557] = "MessageType_MoneroLiveRefreshFinalAck",
        [600] = "MessageType_EosGetPublicKey",
        [601] = "MessageType_EosPublicKey",
        [602] = "MessageType_EosSignTx",
        [603] = "MessageType_EosTxActionRequest",
        [604] = "MessageType_EosTxActionAck",
        [605] = "MessageType_EosSignedTx",
        [800] = "MessageType_WebAuthnListResidentCredentials",
        [801] = "MessageType_WebAuthnCredentials",
        [802] = "MessageType_WebAuthnAddResidentCredential",
        [803] = "MessageType_WebAuthnRemoveResidentCredential",
        [804] = "MessageType_WebAuthnCredentialsAck",
        [900] = "MessageType_SolanaGetPublicKey",
        [901] = "MessageType_SolanaPublicKey",
        [902] = "MessageType_SolanaGetAddress",
        [903] = "MessageType_SolanaAddress",
        [904] = "MessageType_SolanaSignTx",
        [905] = "MessageType_SolanaTxSignature",
        [906] = "MessageType_SolanaSignMessage",
        [907] = "MessageType_SolanaMessageSignature",
        [908] = "MessageType_SolanaVerifyMessage",
        [990] = "MessageType_ChangeLanguage",
        [991] = "MessageType_DataChunkRequest",
        [992] = "MessageType_DataChunkAck",
        [993] = "MessageType_SetBrightness",
        [994] = "MessageType_EntropyCheckReady",
        [995] = "MessageType_EntropyCheckContinue",
        [996] = "MessageType_GetSerialNumber",
        [997] = "MessageType_SerialNumber",
        [998] = "MessageType_GetAuthenticityProofChunk",
        [999] = "MessageType_AuthenticityProofChunk",
        [1000] = "MessageType_ThpCreateNewSession",
        [1016] = "MessageType_ThpCredentialRequest",
        [1017] = "MessageType_ThpCredentialResponse",
        [1100] = "MessageType_TelemetryGet",
        [1101] = "MessageType_Telemetry",
        [2001] = "MessageType_NostrGetPubkey",
        [2002] = "MessageType_NostrPubkey",
        [2003] = "MessageType_NostrSignEvent",
        [2004] = "MessageType_NostrEventSignature",
        [2100] = "MessageType_EvoluGetNode",
        [2101] = "MessageType_EvoluNode",
        [2102] = "MessageType_EvoluSignRegistrationRequest",
        [2103] = "MessageType_EvoluRegistrationRequest",
        [2104] = "MessageType_EvoluGetDelegatedIdentityKey",
        [2105] = "MessageType_EvoluDelegatedIdentityKey",
        [2106] = "MessageType_EvoluIndexManagement",
        [2107] = "MessageType_EvoluIndexManagementResponse",
        [2200] = "MessageType_TronGetAddress",
        [2201] = "MessageType_TronAddress",
        [2202] = "MessageType_TronSignTx",
        [2203] = "MessageType_TronSignature",
        [2204] = "MessageType_TronContractRequest",
        [2205] = "MessageType_TronTransferContract",
        [2206] = "MessageType_TronTriggerSmartContract",
        [2207] = "MessageType_TronFreezeBalanceV2Contract",
        [2208] = "MessageType_TronUnfreezeBalanceV2Contract",
        [2209] = "MessageType_TronWithdrawUnfreeze",
        [2210] = "MessageType_TronVoteWitnessContract",
        [8001] = "MessageType_BleUnpair",
        [9001] = "MessageType_DebugLinkLayout",
        [9002] = "MessageType_DebugLinkReseedRandom",
        [9003] = "MessageType_DebugLinkRecordScreen",
        [9005] = "MessageType_DebugLinkEraseSdCard",
        [9006] = "MessageType_DebugLinkWatchLayout",
        [9007] = "MessageType_DebugLinkResetDebugEvents",
        [9008] = "MessageType_DebugLinkOptigaSetSecMax",
        [9009] = "MessageType_DebugLinkGetGcInfo",
        [9010] = "MessageType_DebugLinkGcInfo",
        [9011] = "MessageType_DebugLinkGetPairingInfo",
        [9012] = "MessageType_DebugLinkPairingInfo",
        [9013] = "MessageType_DebugLinkSetLogFilter",
        [9014] = "MessageType_DebugLinkN4W1Connected",
        [9015] = "MessageType_DebugLinkN4W1Write",
        [9016] = "MessageType_DebugLinkN4W1Read",
        [9017] = "MessageType_DebugLinkN4W1Response",
        [9018] = "MessageType_DebugLinkSetBatteryState",
        [9100] = "MessageType_BenchmarkListNames",
        [9101] = "MessageType_BenchmarkNames",
        [9102] = "MessageType_BenchmarkRun",
        [9103] = "MessageType_BenchmarkResult",
    },
    ["MoneroNetworkType"] = {
        [0] = "MAINNET",
        [1] = "TESTNET",
        [2] = "STAGENET",
        [3] = "FAKECHAIN",
    },
    ["MultisigPubkeysOrder"] = {
        [0] = "PRESERVED",
        [1] = "LEXICOGRAPHIC",
    },
    ["NEMSignTx.NEMAggregateModification.NEMCosignatoryModification.NEMModificationType"] = {
        [1] = "CosignatoryModification_Add",
        [2] = "CosignatoryModification_Delete",
    },
    ["NEMSignTx.NEMImportanceTransfer.NEMImportanceTransferMode"] = {
        [1] = "ImportanceTransfer_Activate",
        [2] = "ImportanceTransfer_Deactivate",
    },
    ["NEMSignTx.NEMMosaicCreation.NEMMosaicDefinition.NEMMosaicLevy"] = {
        [1] = "MosaicLevy_Absolute",
        [2] = "MosaicLevy_Percentile",
    },
    ["NEMSignTx.NEMMosaicSupplyChange.NEMSupplyChangeType"] = {
        [1] = "SupplyChange_Increase",
        [2] = "SupplyChange_Decrease",
    },
    ["OutputScriptType"] = {
        [0] = "PAYTOADDRESS",
        [1] = "PAYTOSCRIPTHASH",
        [2] = "PAYTOMULTISIG",
        [3] = "PAYTOOPRETURN",
        [4] = "PAYTOWITNESS",
        [5] = "PAYTOP2SHWITNESS",
        [6] = "PAYTOTAPROOT",
    },
    ["PinMatrixRequest.PinMatrixRequestType"] = {
        [1] = "PinMatrixRequestType_Current",
        [2] = "PinMatrixRequestType_NewFirst",
        [3] = "PinMatrixRequestType_NewSecond",
        [4] = "PinMatrixRequestType_WipeCodeFirst",
        [5] = "PinMatrixRequestType_WipeCodeSecond",
    },
    ["RebootToBootloader.BootCommand"] = {
        [0] = "STOP_AND_WAIT",
        [1] = "INSTALL_UPGRADE",
    },
    ["RecoveryDevice.RecoveryDeviceInputMethod"] = {
        [0] = "ScrambledWords",
        [1] = "Matrix",
    },
    ["RecoveryType"] = {
        [0] = "NormalRecovery",
        [1] = "DryRun",
        [2] = "UnlockRepeatedBackup",
    },
    ["SafetyCheckLevel"] = {
        [0] = "Strict",
        [1] = "PromptAlways",
        [2] = "PromptTemporarily",
    },
    ["SdProtect.SdProtectOperationType"] = {
        [0] = "DISABLE",
        [1] = "ENABLE",
        [2] = "REFRESH",
    },
    ["StellarAssetType"] = {
        [0] = "NATIVE",
        [1] = "ALPHANUM4",
        [2] = "ALPHANUM12",
    },
    ["StellarSetOptionsOp.StellarSignerType"] = {
        [0] = "ACCOUNT",
        [1] = "PRE_AUTH",
        [2] = "HASH",
    },
    ["StellarSignTx.StellarMemoType"] = {
        [0] = "NONE",
        [1] = "TEXT",
        [2] = "ID",
        [3] = "HASH",
        [4] = "RETURN",
    },
    ["TezosSignTx.TezosBallotOp.TezosBallotType"] = {
        [0] = "Yay",
        [1] = "Nay",
        [2] = "Pass",
    },
    ["TezosSignTx.TezosContractID.TezosContractType"] = {
        [0] = "Implicit",
        [1] = "Originated",
    },
    ["ThpMessageType"] = {
        [20] = "ThpMessageType_Cancel",
        [26] = "ThpMessageType_ButtonRequest",
        [27] = "ThpMessageType_ButtonAck",
        [1008] = "ThpMessageType_ThpPairingRequest",
        [1009] = "ThpMessageType_ThpPairingRequestApproved",
        [1010] = "ThpMessageType_ThpSelectMethod",
        [1011] = "ThpMessageType_ThpPairingPreparationsFinished",
        [1016] = "ThpMessageType_ThpCredentialRequest",
        [1017] = "ThpMessageType_ThpCredentialResponse",
        [1018] = "ThpMessageType_ThpEndRequest",
        [1019] = "ThpMessageType_ThpEndResponse",
        [1024] = "ThpMessageType_ThpCodeEntryCommitment",
        [1025] = "ThpMessageType_ThpCodeEntryChallenge",
        [1026] = "ThpMessageType_ThpCodeEntryCpaceTrezor",
        [1027] = "ThpMessageType_ThpCodeEntryCpaceHostTag",
        [1028] = "ThpMessageType_ThpCodeEntrySecret",
        [1032] = "ThpMessageType_ThpQrCodeTag",
        [1033] = "ThpMessageType_ThpQrCodeSecret",
        [1040] = "ThpMessageType_ThpNfcTagHost",
        [1041] = "ThpMessageType_ThpNfcTagTrezor",
    },
    ["ThpPairingMethod"] = {
        [1] = "SkipPairing",
        [2] = "CodeEntry",
        [3] = "QrCode",
        [4] = "NFC",
    },
    ["TronRawTransaction.TronRawContract.TronRawContractType"] = {
        [1] = "TransferContract",
        [4] = "VoteWitnessContract",
        [31] = "TriggerSmartContract",
        [54] = "FreezeBalanceV2Contract",
        [55] = "UnfreezeBalanceV2Contract",
        [56] = "WithdrawExpireUnfreezeContract",
    },
    ["TronResourceCode"] = {
        [0] = "BANDWIDTH",
        [1] = "ENERGY",
    },
    ["TxRequest.RequestType"] = {
        [0] = "TXINPUT",
        [1] = "TXOUTPUT",
        [2] = "TXMETA",
        [3] = "TXFINISHED",
        [4] = "TXEXTRADATA",
        [5] = "TXORIGINPUT",
        [6] = "TXORIGOUTPUT",
        [7] = "TXPAYMENTREQ",
    },
    ["WordRequest.WordRequestType"] = {
        [0] = "WordRequestType_Plain",
        [1] = "WordRequestType_Matrix9",
        [2] = "WordRequestType_Matrix6",
    },
}

local pb_message_fields = {
    ["Address"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["ApplyFlags"] = {
        [1] = { name="flags", kind="varint" },
    },
    ["ApplySettings"] = {
        [1] = { name="language", kind="len" },
        [2] = { name="label", kind="len" },
        [3] = { name="use_passphrase", kind="varint" },
        [4] = { name="homescreen", kind="len" },
        [5] = { name="_passphrase_source", kind="varint" },
        [6] = { name="auto_lock_delay_ms", kind="varint" },
        [7] = { name="display_rotation", kind="varint", enum="DisplayRotation" },
        [8] = { name="passphrase_always_on_device", kind="varint" },
        [9] = { name="safety_checks", kind="varint", enum="SafetyCheckLevel" },
        [10] = { name="experimental_features", kind="varint" },
        [11] = { name="hide_passphrase_from_host", kind="varint" },
        [13] = { name="haptic_feedback", kind="varint" },
        [14] = { name="homescreen_length", kind="varint" },
        [15] = { name="auto_lock_delay_battery_ms", kind="varint" },
    },
    ["AuthenticateDevice"] = {
        [1] = { name="challenge", kind="len" },
        [2] = { name="stream", kind="varint" },
    },
    ["AuthenticityProof"] = {
        [1] = { name="optiga_certificates", kind="len", repeated=true },
        [2] = { name="optiga_signature", kind="len" },
        [3] = { name="tropic_certificates", kind="len", repeated=true },
        [4] = { name="tropic_signature", kind="len" },
        [5] = { name="mcu_certificates", kind="len", repeated=true },
        [6] = { name="mcu_signature", kind="len" },
    },
    ["AuthenticityProofChunk"] = {
        [1] = { name="chunk", kind="len" },
    },
    ["AuthenticityProofSizes"] = {
        [1] = { name="optiga_certificates", kind="varint", repeated=true },
        [2] = { name="optiga_signature", kind="varint" },
        [3] = { name="tropic_certificates", kind="varint", repeated=true },
        [4] = { name="tropic_signature", kind="varint" },
        [5] = { name="mcu_certificates", kind="varint", repeated=true },
        [6] = { name="mcu_signature", kind="varint" },
    },
    ["AuthorizeCoinJoin"] = {
        [1] = { name="coordinator", kind="len" },
        [2] = { name="max_rounds", kind="varint" },
        [3] = { name="max_coordinator_fee_rate", kind="varint" },
        [4] = { name="max_fee_per_kvbyte", kind="varint" },
        [5] = { name="address_n", kind="varint", repeated=true },
        [6] = { name="coin_name", kind="len" },
        [7] = { name="script_type", kind="varint", enum="InputScriptType" },
        [8] = { name="amount_unit", kind="varint", enum="AmountUnit" },
    },
    ["BackupDevice"] = {
        [1] = { name="group_threshold", kind="varint" },
        [2] = { name="groups", kind="len", repeated=true, msg="BackupDevice.Slip39Group" },
        [3] = { name="backup_method", kind="varint", enum="BackupMethod" },
    },
    ["BackupDevice.Slip39Group"] = {
        [1] = { name="member_threshold", kind="varint" },
        [2] = { name="member_count", kind="varint" },
    },
    ["BenchmarkListNames"] = {},
    ["BenchmarkNames"] = {
        [1] = { name="names", kind="len", repeated=true },
    },
    ["BenchmarkResult"] = {
        [1] = { name="value", kind="len" },
        [3] = { name="unit", kind="len" },
    },
    ["BenchmarkRun"] = {
        [1] = { name="name", kind="len" },
    },
    ["BleUnpair"] = {
        [1] = { name="all", kind="varint" },
        [2] = { name="addr", kind="len" },
    },
    ["ButtonAck"] = {},
    ["ButtonRequest"] = {
        [1] = { name="code", kind="varint", enum="ButtonRequest.ButtonRequestType" },
        [2] = { name="pages", kind="varint" },
        [4] = { name="name", kind="len" },
    },
    ["Cancel"] = {},
    ["CancelAuthorization"] = {},
    ["CardanoAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["CardanoAddressParametersType"] = {
        [1] = { name="address_type", kind="varint", enum="CardanoAddressType" },
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="address_n_staking", kind="varint", repeated=true },
        [4] = { name="staking_key_hash", kind="len" },
        [5] = { name="certificate_pointer", kind="len", msg="CardanoBlockchainPointerType" },
        [6] = { name="script_payment_hash", kind="len" },
        [7] = { name="script_staking_hash", kind="len" },
    },
    ["CardanoAssetGroup"] = {
        [1] = { name="policy_id", kind="len" },
        [2] = { name="tokens_count", kind="varint" },
    },
    ["CardanoBlockchainPointerType"] = {
        [1] = { name="block_index", kind="varint" },
        [2] = { name="tx_index", kind="varint" },
        [3] = { name="certificate_index", kind="varint" },
    },
    ["CardanoCVoteRegistrationDelegation"] = {
        [1] = { name="vote_public_key", kind="len" },
        [2] = { name="weight", kind="varint" },
    },
    ["CardanoCVoteRegistrationParametersType"] = {
        [1] = { name="vote_public_key", kind="len" },
        [2] = { name="staking_path", kind="varint", repeated=true },
        [3] = { name="payment_address_parameters", kind="len", msg="CardanoAddressParametersType" },
        [4] = { name="nonce", kind="varint" },
        [5] = { name="format", kind="varint", enum="CardanoCVoteRegistrationFormat" },
        [6] = { name="delegations", kind="len", repeated=true, msg="CardanoCVoteRegistrationDelegation" },
        [7] = { name="voting_purpose", kind="varint" },
        [8] = { name="payment_address", kind="len" },
    },
    ["CardanoDRep"] = {
        [1] = { name="type", kind="varint", enum="CardanoDRepType" },
        [2] = { name="key_hash", kind="len" },
        [3] = { name="script_hash", kind="len" },
    },
    ["CardanoGetAddress"] = {
        [2] = { name="show_display", kind="varint" },
        [3] = { name="protocol_magic", kind="varint" },
        [4] = { name="network_id", kind="varint" },
        [5] = { name="address_parameters", kind="len", msg="CardanoAddressParametersType" },
        [6] = { name="derivation_type", kind="varint", enum="CardanoDerivationType" },
        [7] = { name="chunkify", kind="varint" },
    },
    ["CardanoGetNativeScriptHash"] = {
        [1] = { name="script", kind="len", msg="CardanoNativeScript" },
        [2] = { name="display_format", kind="varint", enum="CardanoNativeScriptHashDisplayFormat" },
        [3] = { name="derivation_type", kind="varint", enum="CardanoDerivationType" },
    },
    ["CardanoGetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="derivation_type", kind="varint", enum="CardanoDerivationType" },
    },
    ["CardanoMessageDataRequest"] = {
        [1] = { name="length", kind="varint" },
        [2] = { name="offset", kind="varint" },
    },
    ["CardanoMessageDataResponse"] = {
        [1] = { name="data", kind="len" },
    },
    ["CardanoMessageSignature"] = {
        [1] = { name="signature", kind="len" },
        [2] = { name="address", kind="len" },
        [3] = { name="pub_key", kind="len" },
    },
    ["CardanoNativeScript"] = {
        [1] = { name="type", kind="varint", enum="CardanoNativeScriptType" },
        [2] = { name="scripts", kind="len", repeated=true, msg="CardanoNativeScript" },
        [3] = { name="key_hash", kind="len" },
        [4] = { name="key_path", kind="varint", repeated=true },
        [5] = { name="required_signatures_count", kind="varint" },
        [6] = { name="invalid_before", kind="varint" },
        [7] = { name="invalid_hereafter", kind="varint" },
    },
    ["CardanoNativeScriptHash"] = {
        [1] = { name="script_hash", kind="len" },
    },
    ["CardanoPoolMetadataType"] = {
        [1] = { name="url", kind="len" },
        [2] = { name="hash", kind="len" },
    },
    ["CardanoPoolOwner"] = {
        [1] = { name="staking_key_path", kind="varint", repeated=true },
        [2] = { name="staking_key_hash", kind="len" },
    },
    ["CardanoPoolParametersType"] = {
        [1] = { name="pool_id", kind="len" },
        [2] = { name="vrf_key_hash", kind="len" },
        [3] = { name="pledge", kind="varint" },
        [4] = { name="cost", kind="varint" },
        [5] = { name="margin_numerator", kind="varint" },
        [6] = { name="margin_denominator", kind="varint" },
        [7] = { name="reward_account", kind="len" },
        [10] = { name="metadata", kind="len", msg="CardanoPoolMetadataType" },
        [11] = { name="owners_count", kind="varint" },
        [12] = { name="relays_count", kind="varint" },
    },
    ["CardanoPoolRelayParameters"] = {
        [1] = { name="type", kind="varint", enum="CardanoPoolRelayType" },
        [2] = { name="ipv4_address", kind="len" },
        [3] = { name="ipv6_address", kind="len" },
        [4] = { name="host_name", kind="len" },
        [5] = { name="port", kind="varint" },
    },
    ["CardanoPublicKey"] = {
        [1] = { name="xpub", kind="len" },
        [2] = { name="node", kind="len", msg="HDNodeType" },
    },
    ["CardanoSignMessageInit"] = {
        [1] = { name="protocol_magic", kind="varint" },
        [2] = { name="network_id", kind="varint" },
        [3] = { name="signing_path", kind="varint", repeated=true },
        [4] = { name="payload_size", kind="varint" },
        [5] = { name="prefer_hex_display", kind="varint" },
        [6] = { name="address_parameters", kind="len", msg="CardanoAddressParametersType" },
        [7] = { name="derivation_type", kind="varint", enum="CardanoDerivationType" },
    },
    ["CardanoSignTxFinished"] = {},
    ["CardanoSignTxInit"] = {
        [1] = { name="signing_mode", kind="varint", enum="CardanoTxSigningMode" },
        [2] = { name="protocol_magic", kind="varint" },
        [3] = { name="network_id", kind="varint" },
        [4] = { name="inputs_count", kind="varint" },
        [5] = { name="outputs_count", kind="varint" },
        [6] = { name="fee", kind="varint" },
        [7] = { name="ttl", kind="varint" },
        [8] = { name="certificates_count", kind="varint" },
        [9] = { name="withdrawals_count", kind="varint" },
        [10] = { name="has_auxiliary_data", kind="varint" },
        [11] = { name="validity_interval_start", kind="varint" },
        [12] = { name="witness_requests_count", kind="varint" },
        [13] = { name="minting_asset_groups_count", kind="varint" },
        [14] = { name="derivation_type", kind="varint", enum="CardanoDerivationType" },
        [15] = { name="include_network_id", kind="varint" },
        [16] = { name="script_data_hash", kind="len" },
        [17] = { name="collateral_inputs_count", kind="varint" },
        [18] = { name="required_signers_count", kind="varint" },
        [19] = { name="has_collateral_return", kind="varint" },
        [20] = { name="total_collateral", kind="varint" },
        [21] = { name="reference_inputs_count", kind="varint" },
        [22] = { name="chunkify", kind="varint" },
        [23] = { name="tag_cbor_sets", kind="varint" },
        [24] = { name="payment_req", kind="len", msg="PaymentRequest" },
    },
    ["CardanoToken"] = {
        [1] = { name="asset_name_bytes", kind="len" },
        [2] = { name="amount", kind="varint" },
        [3] = { name="mint_amount", kind="varint" },
    },
    ["CardanoTxAuxiliaryData"] = {
        [1] = { name="cvote_registration_parameters", kind="len", msg="CardanoCVoteRegistrationParametersType" },
        [2] = { name="hash", kind="len" },
    },
    ["CardanoTxAuxiliaryDataSupplement"] = {
        [1] = { name="type", kind="varint", enum="CardanoTxAuxiliaryDataSupplementType" },
        [2] = { name="auxiliary_data_hash", kind="len" },
        [3] = { name="cvote_registration_signature", kind="len" },
    },
    ["CardanoTxBodyHash"] = {
        [1] = { name="tx_hash", kind="len" },
    },
    ["CardanoTxCertificate"] = {
        [1] = { name="type", kind="varint", enum="CardanoCertificateType" },
        [2] = { name="path", kind="varint", repeated=true },
        [3] = { name="pool", kind="len" },
        [4] = { name="pool_parameters", kind="len", msg="CardanoPoolParametersType" },
        [5] = { name="script_hash", kind="len" },
        [6] = { name="key_hash", kind="len" },
        [7] = { name="deposit", kind="varint" },
        [8] = { name="drep", kind="len", msg="CardanoDRep" },
    },
    ["CardanoTxCollateralInput"] = {
        [1] = { name="prev_hash", kind="len" },
        [2] = { name="prev_index", kind="varint" },
    },
    ["CardanoTxHostAck"] = {},
    ["CardanoTxInlineDatumChunk"] = {
        [1] = { name="data", kind="len" },
    },
    ["CardanoTxInput"] = {
        [1] = { name="prev_hash", kind="len" },
        [2] = { name="prev_index", kind="varint" },
    },
    ["CardanoTxItemAck"] = {},
    ["CardanoTxMint"] = {
        [1] = { name="asset_groups_count", kind="varint" },
    },
    ["CardanoTxOutput"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="address_parameters", kind="len", msg="CardanoAddressParametersType" },
        [3] = { name="amount", kind="varint" },
        [4] = { name="asset_groups_count", kind="varint" },
        [5] = { name="datum_hash", kind="len" },
        [6] = { name="format", kind="varint", enum="CardanoTxOutputSerializationFormat" },
        [7] = { name="inline_datum_size", kind="varint" },
        [8] = { name="reference_script_size", kind="varint" },
    },
    ["CardanoTxReferenceInput"] = {
        [1] = { name="prev_hash", kind="len" },
        [2] = { name="prev_index", kind="varint" },
    },
    ["CardanoTxReferenceScriptChunk"] = {
        [1] = { name="data", kind="len" },
    },
    ["CardanoTxRequiredSigner"] = {
        [1] = { name="key_hash", kind="len" },
        [2] = { name="key_path", kind="varint", repeated=true },
    },
    ["CardanoTxWithdrawal"] = {
        [1] = { name="path", kind="varint", repeated=true },
        [2] = { name="amount", kind="varint" },
        [3] = { name="script_hash", kind="len" },
        [4] = { name="key_hash", kind="len" },
    },
    ["CardanoTxWitnessRequest"] = {
        [1] = { name="path", kind="varint", repeated=true },
    },
    ["CardanoTxWitnessResponse"] = {
        [1] = { name="type", kind="varint", enum="CardanoTxWitnessType" },
        [2] = { name="pub_key", kind="len" },
        [3] = { name="signature", kind="len" },
        [4] = { name="chain_code", kind="len" },
    },
    ["ChangeLanguage"] = {
        [1] = { name="data_length", kind="varint" },
        [2] = { name="show_display", kind="varint" },
    },
    ["ChangePin"] = {
        [1] = { name="remove", kind="varint" },
    },
    ["ChangeWipeCode"] = {
        [1] = { name="remove", kind="varint" },
    },
    ["CipherKeyValue"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="key", kind="len" },
        [3] = { name="value", kind="len" },
        [4] = { name="encrypt", kind="varint" },
        [5] = { name="ask_on_encrypt", kind="varint" },
        [6] = { name="ask_on_decrypt", kind="varint" },
        [7] = { name="iv", kind="len" },
    },
    ["CipheredKeyValue"] = {
        [1] = { name="value", kind="len" },
    },
    ["DataChunkAck"] = {
        [1] = { name="data_chunk", kind="len" },
    },
    ["DataChunkRequest"] = {
        [1] = { name="data_length", kind="varint" },
        [2] = { name="data_offset", kind="varint" },
    },
    ["DebugLinkDecision"] = {
        [1] = { name="button", kind="varint", enum="DebugLinkDecision.DebugButton" },
        [2] = { name="swipe", kind="varint", enum="DebugLinkDecision.DebugSwipeDirection" },
        [3] = { name="input", kind="len" },
        [4] = { name="x", kind="varint" },
        [5] = { name="y", kind="varint" },
        [6] = { name="wait", kind="varint" },
        [7] = { name="hold_ms", kind="varint" },
        [8] = { name="physical_button", kind="varint", enum="DebugLinkDecision.DebugPhysicalButton" },
        [9] = { name="touch_event_type", kind="varint", enum="DebugLinkDecision.DebugTouchEventType" },
    },
    ["DebugLinkEraseSdCard"] = {
        [1] = { name="format", kind="varint" },
    },
    ["DebugLinkFlashErase"] = {
        [1] = { name="sector", kind="varint" },
    },
    ["DebugLinkGcInfo"] = {
        [1] = { name="items", kind="len", repeated=true, msg="DebugLinkGcInfo.DebugLinkGcInfoItem" },
    },
    ["DebugLinkGcInfo.DebugLinkGcInfoItem"] = {
        [1] = { name="name", kind="len" },
        [2] = { name="value", kind="varint" },
    },
    ["DebugLinkGetGcInfo"] = {},
    ["DebugLinkGetPairingInfo"] = {
        [1] = { name="channel_id", kind="len" },
        [2] = { name="handshake_hash", kind="len" },
        [3] = { name="nfc_secret_host", kind="len" },
    },
    ["DebugLinkGetState"] = {
        [1] = { name="wait_word_list", kind="varint" },
        [2] = { name="wait_word_pos", kind="varint" },
        [3] = { name="wait_layout", kind="varint", enum="DebugLinkGetState.DebugWaitType" },
        [4] = { name="return_empty_state", kind="varint" },
    },
    ["DebugLinkLayout"] = {
        [1] = { name="tokens", kind="len", repeated=true },
    },
    ["DebugLinkLog"] = {
        [1] = { name="level", kind="varint" },
        [2] = { name="bucket", kind="len" },
        [3] = { name="text", kind="len" },
    },
    ["DebugLinkMemory"] = {
        [1] = { name="memory", kind="len" },
    },
    ["DebugLinkMemoryRead"] = {
        [1] = { name="address", kind="varint" },
        [2] = { name="length", kind="varint" },
    },
    ["DebugLinkMemoryWrite"] = {
        [1] = { name="address", kind="varint" },
        [2] = { name="memory", kind="len" },
        [3] = { name="flash", kind="varint" },
    },
    ["DebugLinkN4W1Connected"] = {},
    ["DebugLinkN4W1Read"] = {
        [1] = { name="key", kind="len" },
    },
    ["DebugLinkN4W1Response"] = {
        [1] = { name="value", kind="len" },
    },
    ["DebugLinkN4W1Write"] = {
        [1] = { name="key", kind="len" },
        [2] = { name="value", kind="len" },
    },
    ["DebugLinkOptigaSetSecMax"] = {},
    ["DebugLinkPairingInfo"] = {
        [1] = { name="channel_id", kind="len" },
        [2] = { name="handshake_hash", kind="len" },
        [3] = { name="code_entry_code", kind="varint" },
        [4] = { name="code_qr_code", kind="len" },
        [5] = { name="nfc_secret_trezor", kind="len" },
    },
    ["DebugLinkRecordScreen"] = {
        [1] = { name="target_directory", kind="len" },
        [2] = { name="refresh_index", kind="varint" },
    },
    ["DebugLinkReseedRandom"] = {
        [1] = { name="value", kind="varint" },
    },
    ["DebugLinkResetDebugEvents"] = {},
    ["DebugLinkSetBatteryState"] = {
        [1] = { name="soc", kind="varint" },
        [2] = { name="usb_connected", kind="varint" },
        [3] = { name="wireless_connected", kind="varint" },
        [4] = { name="ntc_connected", kind="varint" },
        [5] = { name="charging_limited", kind="varint" },
        [6] = { name="temp_control_active", kind="varint" },
        [7] = { name="battery_connected", kind="varint" },
    },
    ["DebugLinkSetLogFilter"] = {
        [1] = { name="filter", kind="len" },
    },
    ["DebugLinkState"] = {
        [1] = { name="layout", kind="len" },
        [2] = { name="pin", kind="len" },
        [3] = { name="matrix", kind="len" },
        [4] = { name="mnemonic_secret", kind="len" },
        [5] = { name="node", kind="len", msg="HDNodeType" },
        [6] = { name="passphrase_protection", kind="varint" },
        [7] = { name="reset_word", kind="len" },
        [8] = { name="reset_entropy", kind="len" },
        [9] = { name="recovery_fake_word", kind="len" },
        [10] = { name="recovery_word_pos", kind="varint" },
        [11] = { name="reset_word_pos", kind="varint" },
        [12] = { name="mnemonic_type", kind="varint", enum="BackupType" },
        [13] = { name="tokens", kind="len", repeated=true },
    },
    ["DebugLinkStop"] = {},
    ["DebugLinkWatchLayout"] = {
        [1] = { name="watch", kind="varint" },
    },
    ["DebugMoneroDiagAck"] = {
        [1] = { name="ins", kind="varint" },
        [2] = { name="p1", kind="varint" },
        [3] = { name="p2", kind="varint" },
        [4] = { name="pd", kind="varint", repeated=true },
        [5] = { name="data1", kind="len" },
        [6] = { name="data2", kind="len" },
    },
    ["DebugMoneroDiagRequest"] = {
        [1] = { name="ins", kind="varint" },
        [2] = { name="p1", kind="varint" },
        [3] = { name="p2", kind="varint" },
        [4] = { name="pd", kind="varint", repeated=true },
        [5] = { name="data1", kind="len" },
        [6] = { name="data2", kind="len" },
    },
    ["Deprecated_PassphraseStateAck"] = {},
    ["Deprecated_PassphraseStateRequest"] = {
        [1] = { name="state", kind="len" },
    },
    ["DoPreauthorized"] = {},
    ["ECDHSessionKey"] = {
        [1] = { name="session_key", kind="len" },
        [2] = { name="public_key", kind="len" },
    },
    ["EndSession"] = {},
    ["Entropy"] = {
        [1] = { name="entropy", kind="len" },
    },
    ["EntropyAck"] = {
        [1] = { name="entropy", kind="len" },
    },
    ["EntropyCheckContinue"] = {
        [1] = { name="finish", kind="varint" },
    },
    ["EntropyCheckReady"] = {},
    ["EntropyRequest"] = {
        [1] = { name="entropy_commitment", kind="len" },
        [2] = { name="prev_entropy", kind="len" },
    },
    ["EosGetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["EosPublicKey"] = {
        [1] = { name="wif_public_key", kind="len" },
        [2] = { name="raw_public_key", kind="len" },
    },
    ["EosSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="chain_id", kind="len" },
        [3] = { name="header", kind="len", msg="EosSignTx.EosTxHeader" },
        [4] = { name="num_actions", kind="varint" },
        [5] = { name="chunkify", kind="varint" },
    },
    ["EosSignTx.EosTxHeader"] = {
        [1] = { name="expiration", kind="varint" },
        [2] = { name="ref_block_num", kind="varint" },
        [3] = { name="ref_block_prefix", kind="varint" },
        [4] = { name="max_net_usage_words", kind="varint" },
        [5] = { name="max_cpu_usage_ms", kind="varint" },
        [6] = { name="delay_sec", kind="varint" },
    },
    ["EosSignedTx"] = {
        [1] = { name="signature", kind="len" },
    },
    ["EosTxActionAck"] = {
        [1] = { name="common", kind="len", msg="EosTxActionAck.EosActionCommon" },
        [2] = { name="transfer", kind="len", msg="EosTxActionAck.EosActionTransfer" },
        [3] = { name="delegate", kind="len", msg="EosTxActionAck.EosActionDelegate" },
        [4] = { name="undelegate", kind="len", msg="EosTxActionAck.EosActionUndelegate" },
        [5] = { name="refund", kind="len", msg="EosTxActionAck.EosActionRefund" },
        [6] = { name="buy_ram", kind="len", msg="EosTxActionAck.EosActionBuyRam" },
        [7] = { name="buy_ram_bytes", kind="len", msg="EosTxActionAck.EosActionBuyRamBytes" },
        [8] = { name="sell_ram", kind="len", msg="EosTxActionAck.EosActionSellRam" },
        [9] = { name="vote_producer", kind="len", msg="EosTxActionAck.EosActionVoteProducer" },
        [10] = { name="update_auth", kind="len", msg="EosTxActionAck.EosActionUpdateAuth" },
        [11] = { name="delete_auth", kind="len", msg="EosTxActionAck.EosActionDeleteAuth" },
        [12] = { name="link_auth", kind="len", msg="EosTxActionAck.EosActionLinkAuth" },
        [13] = { name="unlink_auth", kind="len", msg="EosTxActionAck.EosActionUnlinkAuth" },
        [14] = { name="new_account", kind="len", msg="EosTxActionAck.EosActionNewAccount" },
        [15] = { name="unknown", kind="len", msg="EosTxActionAck.EosActionUnknown" },
    },
    ["EosTxActionAck.EosActionBuyRam"] = {
        [1] = { name="payer", kind="varint" },
        [2] = { name="receiver", kind="varint" },
        [3] = { name="quantity", kind="len", msg="EosTxActionAck.EosAsset" },
    },
    ["EosTxActionAck.EosActionBuyRamBytes"] = {
        [1] = { name="payer", kind="varint" },
        [2] = { name="receiver", kind="varint" },
        [3] = { name="bytes", kind="varint" },
    },
    ["EosTxActionAck.EosActionCommon"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="name", kind="varint" },
        [3] = { name="authorization", kind="len", repeated=true, msg="EosTxActionAck.EosPermissionLevel" },
    },
    ["EosTxActionAck.EosActionDelegate"] = {
        [1] = { name="sender", kind="varint" },
        [2] = { name="receiver", kind="varint" },
        [3] = { name="net_quantity", kind="len", msg="EosTxActionAck.EosAsset" },
        [4] = { name="cpu_quantity", kind="len", msg="EosTxActionAck.EosAsset" },
        [5] = { name="transfer", kind="varint" },
    },
    ["EosTxActionAck.EosActionDeleteAuth"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="permission", kind="varint" },
    },
    ["EosTxActionAck.EosActionLinkAuth"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="code", kind="varint" },
        [3] = { name="type", kind="varint" },
        [4] = { name="requirement", kind="varint" },
    },
    ["EosTxActionAck.EosActionNewAccount"] = {
        [1] = { name="creator", kind="varint" },
        [2] = { name="name", kind="varint" },
        [3] = { name="owner", kind="len", msg="EosTxActionAck.EosAuthorization" },
        [4] = { name="active", kind="len", msg="EosTxActionAck.EosAuthorization" },
    },
    ["EosTxActionAck.EosActionRefund"] = {
        [1] = { name="owner", kind="varint" },
    },
    ["EosTxActionAck.EosActionSellRam"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="bytes", kind="varint" },
    },
    ["EosTxActionAck.EosActionTransfer"] = {
        [1] = { name="sender", kind="varint" },
        [2] = { name="receiver", kind="varint" },
        [3] = { name="quantity", kind="len", msg="EosTxActionAck.EosAsset" },
        [4] = { name="memo", kind="len" },
    },
    ["EosTxActionAck.EosActionUndelegate"] = {
        [1] = { name="sender", kind="varint" },
        [2] = { name="receiver", kind="varint" },
        [3] = { name="net_quantity", kind="len", msg="EosTxActionAck.EosAsset" },
        [4] = { name="cpu_quantity", kind="len", msg="EosTxActionAck.EosAsset" },
    },
    ["EosTxActionAck.EosActionUnknown"] = {
        [1] = { name="data_size", kind="varint" },
        [2] = { name="data_chunk", kind="len" },
    },
    ["EosTxActionAck.EosActionUnlinkAuth"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="code", kind="varint" },
        [3] = { name="type", kind="varint" },
    },
    ["EosTxActionAck.EosActionUpdateAuth"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="permission", kind="varint" },
        [3] = { name="parent", kind="varint" },
        [4] = { name="auth", kind="len", msg="EosTxActionAck.EosAuthorization" },
    },
    ["EosTxActionAck.EosActionVoteProducer"] = {
        [1] = { name="voter", kind="varint" },
        [2] = { name="proxy", kind="varint" },
        [3] = { name="producers", kind="varint", repeated=true },
    },
    ["EosTxActionAck.EosAsset"] = {
        [1] = { name="amount", kind="varint" },
        [2] = { name="symbol", kind="varint" },
    },
    ["EosTxActionAck.EosAuthorization"] = {
        [1] = { name="threshold", kind="varint" },
        [2] = { name="keys", kind="len", repeated=true, msg="EosTxActionAck.EosAuthorizationKey" },
        [3] = { name="accounts", kind="len", repeated=true, msg="EosTxActionAck.EosAuthorizationAccount" },
        [4] = { name="waits", kind="len", repeated=true, msg="EosTxActionAck.EosAuthorizationWait" },
    },
    ["EosTxActionAck.EosAuthorizationAccount"] = {
        [1] = { name="account", kind="len", msg="EosTxActionAck.EosPermissionLevel" },
        [2] = { name="weight", kind="varint" },
    },
    ["EosTxActionAck.EosAuthorizationKey"] = {
        [1] = { name="type", kind="varint" },
        [2] = { name="key", kind="len" },
        [3] = { name="address_n", kind="varint", repeated=true },
        [4] = { name="weight", kind="varint" },
    },
    ["EosTxActionAck.EosAuthorizationWait"] = {
        [1] = { name="wait_sec", kind="varint" },
        [2] = { name="weight", kind="varint" },
    },
    ["EosTxActionAck.EosPermissionLevel"] = {
        [1] = { name="actor", kind="varint" },
        [2] = { name="permission", kind="varint" },
    },
    ["EosTxActionRequest"] = {
        [1] = { name="data_size", kind="varint" },
    },
    ["EthereumABITupleInfo"] = {
        [1] = { name="fields", kind="len", repeated=true, msg="EthereumABIValueInfo" },
        [2] = { name="is_dynamic", kind="varint" },
    },
    ["EthereumABIValueInfo"] = {
        [1] = { name="atomic", kind="varint", enum="EthereumABIType" },
        [2] = { name="dynamic", kind="varint", enum="EthereumABIType" },
        [3] = { name="tuple", kind="len", msg="EthereumABITupleInfo" },
        [4] = { name="array", kind="len", msg="EthereumABIValueInfo" },
    },
    ["EthereumAddress"] = {
        [1] = { name="_old_address", kind="len" },
        [2] = { name="address", kind="len" },
        [3] = { name="mac", kind="len" },
    },
    ["EthereumDefinitionAck"] = {
        [1] = { name="definitions", kind="len", msg="EthereumDefinitions" },
    },
    ["EthereumDefinitionRequest"] = {
        [1] = { name="chain_id", kind="varint" },
        [2] = { name="token_address", kind="len" },
        [3] = { name="func_sig", kind="len" },
    },
    ["EthereumDefinitions"] = {
        [1] = { name="encoded_network", kind="len" },
        [2] = { name="encoded_token", kind="len" },
        [3] = { name="encoded_display_format", kind="len" },
    },
    ["EthereumDisplayFormatInfo"] = {
        [1] = { name="chain_id", kind="varint" },
        [2] = { name="address", kind="len" },
        [3] = { name="func_sig", kind="len" },
        [4] = { name="intent", kind="len" },
        [5] = { name="parameter_definitions", kind="len", repeated=true, msg="EthereumABIValueInfo" },
        [6] = { name="field_definitions", kind="len", repeated=true, msg="EthereumERC7730FieldInfo" },
    },
    ["EthereumERC7730FieldInfo"] = {
        [1] = { name="path", kind="len", msg="EthereumERC7730Path" },
        [2] = { name="label", kind="len" },
        [3] = { name="formatter", kind="varint", enum="EthereumERC7730FieldFormatterType" },
        [4] = { name="token_path", kind="len", msg="EthereumERC7730Path" },
        [5] = { name="threshold", kind="len" },
        [6] = { name="decimals", kind="varint" },
        [7] = { name="base", kind="len" },
        [8] = { name="prefix", kind="varint" },
    },
    ["EthereumERC7730Path"] = {
        [1] = { name="path", kind="varint", repeated=true },
        [2] = { name="container_path", kind="varint", enum="EthereumERC7730ContainerPath" },
    },
    ["EthereumGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="encoded_network", kind="len" },
        [4] = { name="chunkify", kind="varint" },
    },
    ["EthereumGetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
    },
    ["EthereumMessageSignature"] = {
        [2] = { name="signature", kind="len" },
        [3] = { name="address", kind="len" },
    },
    ["EthereumNetworkInfo"] = {
        [1] = { name="chain_id", kind="varint" },
        [2] = { name="symbol", kind="len" },
        [3] = { name="slip44", kind="varint" },
        [4] = { name="name", kind="len" },
    },
    ["EthereumPublicKey"] = {
        [1] = { name="node", kind="len", msg="HDNodeType" },
        [2] = { name="xpub", kind="len" },
    },
    ["EthereumSignMessage"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="message", kind="len" },
        [3] = { name="encoded_network", kind="len" },
        [4] = { name="chunkify", kind="varint" },
    },
    ["EthereumSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="nonce", kind="len" },
        [3] = { name="gas_price", kind="len" },
        [4] = { name="gas_limit", kind="len" },
        [11] = { name="to", kind="len" },
        [6] = { name="value", kind="len" },
        [7] = { name="data_initial_chunk", kind="len" },
        [8] = { name="data_length", kind="varint" },
        [9] = { name="chain_id", kind="varint" },
        [10] = { name="tx_type", kind="varint" },
        [12] = { name="definitions", kind="len", msg="EthereumDefinitions" },
        [13] = { name="chunkify", kind="varint" },
        [14] = { name="payment_req", kind="len", msg="PaymentRequest" },
        [15] = { name="supports_definition_request", kind="varint" },
    },
    ["EthereumSignTxEIP1559"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="nonce", kind="len" },
        [3] = { name="max_gas_fee", kind="len" },
        [4] = { name="max_priority_fee", kind="len" },
        [5] = { name="gas_limit", kind="len" },
        [6] = { name="to", kind="len" },
        [7] = { name="value", kind="len" },
        [8] = { name="data_initial_chunk", kind="len" },
        [9] = { name="data_length", kind="varint" },
        [10] = { name="chain_id", kind="varint" },
        [11] = { name="access_list", kind="len", repeated=true, msg="EthereumSignTxEIP1559.EthereumAccessList" },
        [12] = { name="definitions", kind="len", msg="EthereumDefinitions" },
        [13] = { name="chunkify", kind="varint" },
        [14] = { name="payment_req", kind="len", msg="PaymentRequest" },
        [15] = { name="supports_definition_request", kind="varint" },
    },
    ["EthereumSignTxEIP1559.EthereumAccessList"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="storage_keys", kind="len", repeated=true },
    },
    ["EthereumSignTypedData"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="primary_type", kind="len" },
        [3] = { name="metamask_v4_compat", kind="varint" },
        [4] = { name="definitions", kind="len", msg="EthereumDefinitions" },
        [5] = { name="show_message_hash", kind="len" },
    },
    ["EthereumSignTypedHash"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="domain_separator_hash", kind="len" },
        [3] = { name="message_hash", kind="len" },
        [4] = { name="encoded_network", kind="len" },
    },
    ["EthereumTokenInfo"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="chain_id", kind="varint" },
        [3] = { name="symbol", kind="len" },
        [4] = { name="decimals", kind="varint" },
        [5] = { name="name", kind="len" },
    },
    ["EthereumTxAck"] = {
        [1] = { name="data_chunk", kind="len" },
    },
    ["EthereumTxRequest"] = {
        [1] = { name="data_length", kind="varint" },
        [2] = { name="signature_v", kind="varint" },
        [3] = { name="signature_r", kind="len" },
        [4] = { name="signature_s", kind="len" },
    },
    ["EthereumTypedDataSignature"] = {
        [1] = { name="signature", kind="len" },
        [2] = { name="address", kind="len" },
    },
    ["EthereumTypedDataStructAck"] = {
        [1] = { name="members", kind="len", repeated=true, msg="EthereumTypedDataStructAck.EthereumStructMember" },
    },
    ["EthereumTypedDataStructAck.EthereumFieldType"] = {
        [1] = { name="data_type", kind="varint", enum="EthereumTypedDataStructAck.EthereumDataType" },
        [2] = { name="size", kind="varint" },
        [3] = { name="entry_type", kind="len", msg="EthereumTypedDataStructAck.EthereumFieldType" },
        [4] = { name="struct_name", kind="len" },
    },
    ["EthereumTypedDataStructAck.EthereumStructMember"] = {
        [1] = { name="type", kind="len", msg="EthereumTypedDataStructAck.EthereumFieldType" },
        [2] = { name="name", kind="len" },
    },
    ["EthereumTypedDataStructRequest"] = {
        [1] = { name="name", kind="len" },
    },
    ["EthereumTypedDataValueAck"] = {
        [1] = { name="value", kind="len" },
    },
    ["EthereumTypedDataValueRequest"] = {
        [1] = { name="member_path", kind="varint", repeated=true },
    },
    ["EthereumVerifyMessage"] = {
        [2] = { name="signature", kind="len" },
        [3] = { name="message", kind="len" },
        [4] = { name="address", kind="len" },
        [5] = { name="chunkify", kind="varint" },
    },
    ["EvoluDelegatedIdentityKey"] = {
        [1] = { name="private_key", kind="len" },
        [2] = { name="rotation_index", kind="varint" },
    },
    ["EvoluGetDelegatedIdentityKey"] = {
        [1] = { name="thp_credential", kind="len" },
        [3] = { name="rotation_index", kind="varint" },
        [4] = { name="rotate", kind="varint" },
    },
    ["EvoluGetNode"] = {
        [1] = { name="proof_of_delegated_identity", kind="len" },
        [2] = { name="node_rotation_index", kind="varint" },
    },
    ["EvoluIndexManagement"] = {
        [1] = { name="rotation_index", kind="varint" },
    },
    ["EvoluIndexManagementResponse"] = {
        [1] = { name="rotation_index", kind="varint" },
    },
    ["EvoluNode"] = {
        [1] = { name="data", kind="len" },
    },
    ["EvoluRegistrationRequest"] = {
        [1] = { name="certificate_chain", kind="len", repeated=true },
        [2] = { name="signature", kind="len" },
    },
    ["EvoluSignRegistrationRequest"] = {
        [1] = { name="challenge_from_server", kind="len" },
        [2] = { name="size_to_acquire", kind="varint" },
        [3] = { name="proof_of_delegated_identity", kind="len" },
    },
    ["Failure"] = {
        [1] = { name="code", kind="varint", enum="Failure.FailureType" },
        [2] = { name="message", kind="len" },
    },
    ["Features"] = {
        [1] = { name="vendor", kind="len" },
        [2] = { name="major_version", kind="varint" },
        [3] = { name="minor_version", kind="varint" },
        [4] = { name="patch_version", kind="varint" },
        [61] = { name="build_version", kind="varint" },
        [5] = { name="bootloader_mode", kind="varint" },
        [6] = { name="device_id", kind="len" },
        [7] = { name="pin_protection", kind="varint" },
        [8] = { name="passphrase_protection", kind="varint" },
        [9] = { name="language", kind="len" },
        [10] = { name="label", kind="len" },
        [12] = { name="initialized", kind="varint" },
        [13] = { name="revision", kind="len" },
        [14] = { name="bootloader_hash", kind="len" },
        [15] = { name="imported", kind="varint" },
        [16] = { name="unlocked", kind="varint" },
        [17] = { name="_passphrase_cached", kind="varint" },
        [18] = { name="firmware_present", kind="varint" },
        [19] = { name="backup_availability", kind="varint", enum="Features.BackupAvailability" },
        [20] = { name="flags", kind="varint" },
        [21] = { name="model", kind="len" },
        [22] = { name="fw_major", kind="varint" },
        [23] = { name="fw_minor", kind="varint" },
        [24] = { name="fw_patch", kind="varint" },
        [62] = { name="fw_build", kind="varint" },
        [25] = { name="fw_vendor", kind="len" },
        [27] = { name="unfinished_backup", kind="varint" },
        [28] = { name="no_backup", kind="varint" },
        [29] = { name="recovery_status", kind="varint", enum="Features.RecoveryStatus" },
        [30] = { name="capabilities", kind="varint", repeated=true, enum="Features.Capability" },
        [31] = { name="backup_type", kind="varint", enum="BackupType" },
        [32] = { name="sd_card_present", kind="varint" },
        [33] = { name="sd_protection", kind="varint" },
        [34] = { name="wipe_code_protection", kind="varint" },
        [35] = { name="session_id", kind="len" },
        [36] = { name="passphrase_always_on_device", kind="varint" },
        [37] = { name="safety_checks", kind="varint", enum="SafetyCheckLevel" },
        [38] = { name="auto_lock_delay_ms", kind="varint" },
        [39] = { name="display_rotation", kind="varint", enum="DisplayRotation" },
        [40] = { name="experimental_features", kind="varint" },
        [41] = { name="busy", kind="varint" },
        [42] = { name="homescreen_format", kind="varint", enum="HomescreenFormat" },
        [43] = { name="hide_passphrase_from_host", kind="varint" },
        [44] = { name="internal_model", kind="len" },
        [45] = { name="unit_color", kind="varint" },
        [46] = { name="unit_btconly", kind="varint" },
        [47] = { name="homescreen_width", kind="varint" },
        [48] = { name="homescreen_height", kind="varint" },
        [49] = { name="bootloader_locked", kind="varint" },
        [50] = { name="language_version_matches", kind="varint" },
        [51] = { name="unit_packaging", kind="varint" },
        [52] = { name="haptic_feedback", kind="varint" },
        [53] = { name="recovery_type", kind="varint", enum="RecoveryType" },
        [54] = { name="optiga_sec", kind="varint" },
        [55] = { name="soc", kind="varint" },
        [56] = { name="firmware_corrupted", kind="varint" },
        [57] = { name="auto_lock_delay_battery_ms", kind="varint" },
        [58] = { name="led", kind="varint" },
        [59] = { name="usb_connected", kind="varint" },
        [60] = { name="wireless_connected", kind="varint" },
        [63] = { name="tap_to_wake", kind="varint" },
    },
    ["FirmwareErase"] = {
        [1] = { name="length", kind="varint" },
    },
    ["FirmwareHash"] = {
        [1] = { name="hash", kind="len" },
    },
    ["FirmwareRequest"] = {
        [1] = { name="offset", kind="varint" },
        [2] = { name="length", kind="varint" },
    },
    ["FirmwareUpload"] = {
        [1] = { name="payload", kind="len" },
        [2] = { name="hash", kind="len" },
    },
    ["GetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="coin_name", kind="len" },
        [3] = { name="show_display", kind="varint" },
        [4] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [5] = { name="script_type", kind="varint", enum="InputScriptType" },
        [6] = { name="ignore_xpub_magic", kind="varint" },
        [7] = { name="chunkify", kind="varint" },
    },
    ["GetAuthenticityProofChunk"] = {
        [1] = { name="proof_type", kind="varint", enum="GetAuthenticityProofChunk.AuthenticityProofType" },
        [2] = { name="index", kind="varint" },
        [3] = { name="offset", kind="varint" },
        [4] = { name="size", kind="varint" },
    },
    ["GetECDHSessionKey"] = {
        [1] = { name="identity", kind="len", msg="IdentityType" },
        [2] = { name="peer_public_key", kind="len" },
        [3] = { name="ecdsa_curve_name", kind="len" },
    },
    ["GetEntropy"] = {
        [1] = { name="size", kind="varint" },
    },
    ["GetFeatures"] = {},
    ["GetFirmwareHash"] = {
        [1] = { name="challenge", kind="len" },
    },
    ["GetNextU2FCounter"] = {},
    ["GetNonce"] = {},
    ["GetOwnershipId"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="coin_name", kind="len" },
        [3] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [4] = { name="script_type", kind="varint", enum="InputScriptType" },
    },
    ["GetOwnershipProof"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="coin_name", kind="len" },
        [3] = { name="script_type", kind="varint", enum="InputScriptType" },
        [4] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [5] = { name="user_confirmation", kind="varint" },
        [6] = { name="ownership_ids", kind="len", repeated=true },
        [7] = { name="commitment_data", kind="len" },
    },
    ["GetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="ecdsa_curve_name", kind="len" },
        [3] = { name="show_display", kind="varint" },
        [4] = { name="coin_name", kind="len" },
        [5] = { name="script_type", kind="varint", enum="InputScriptType" },
        [6] = { name="ignore_xpub_magic", kind="varint" },
    },
    ["GetSerialNumber"] = {},
    ["HDNodeType"] = {
        [1] = { name="depth", kind="varint" },
        [2] = { name="fingerprint", kind="varint" },
        [3] = { name="child_num", kind="varint" },
        [4] = { name="chain_code", kind="len" },
        [5] = { name="private_key", kind="len" },
        [6] = { name="public_key", kind="len" },
    },
    ["IdentityType"] = {
        [1] = { name="proto", kind="len" },
        [2] = { name="user", kind="len" },
        [3] = { name="host", kind="len" },
        [4] = { name="port", kind="len" },
        [5] = { name="path", kind="len" },
        [6] = { name="index", kind="varint" },
    },
    ["Initialize"] = {
        [1] = { name="session_id", kind="len" },
        [2] = { name="_skip_passphrase", kind="varint" },
        [3] = { name="derive_cardano", kind="varint" },
    },
    ["LoadDevice"] = {
        [1] = { name="mnemonics", kind="len", repeated=true },
        [3] = { name="pin", kind="len" },
        [4] = { name="passphrase_protection", kind="varint" },
        [5] = { name="language", kind="len" },
        [6] = { name="label", kind="len" },
        [7] = { name="skip_checksum", kind="varint" },
        [8] = { name="u2f_counter", kind="varint" },
        [9] = { name="needs_backup", kind="varint" },
        [10] = { name="no_backup", kind="varint" },
        [11] = { name="unfinished_backup", kind="varint" },
    },
    ["LockDevice"] = {},
    ["MessageSignature"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="signature", kind="len" },
    },
    ["MoneroAddress"] = {
        [1] = { name="address", kind="len" },
    },
    ["MoneroGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
        [4] = { name="account", kind="varint" },
        [5] = { name="minor", kind="varint" },
        [6] = { name="payment_id", kind="len" },
        [7] = { name="chunkify", kind="varint" },
    },
    ["MoneroGetTxKeyAck"] = {
        [1] = { name="salt", kind="len" },
        [2] = { name="tx_keys", kind="len" },
        [3] = { name="tx_derivations", kind="len" },
    },
    ["MoneroGetTxKeyRequest"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
        [3] = { name="salt1", kind="len" },
        [4] = { name="salt2", kind="len" },
        [5] = { name="tx_enc_keys", kind="len" },
        [6] = { name="tx_prefix_hash", kind="len" },
        [7] = { name="reason", kind="varint" },
        [8] = { name="view_public_key", kind="len" },
    },
    ["MoneroGetWatchKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
    },
    ["MoneroKeyImageExportInitAck"] = {},
    ["MoneroKeyImageExportInitRequest"] = {
        [1] = { name="num", kind="varint" },
        [2] = { name="hash", kind="len" },
        [3] = { name="address_n", kind="varint", repeated=true },
        [4] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
        [5] = { name="subs", kind="len", repeated=true, msg="MoneroKeyImageExportInitRequest.MoneroSubAddressIndicesList" },
    },
    ["MoneroKeyImageExportInitRequest.MoneroSubAddressIndicesList"] = {
        [1] = { name="account", kind="varint" },
        [2] = { name="minor_indices", kind="varint", repeated=true },
    },
    ["MoneroKeyImageSyncFinalAck"] = {
        [1] = { name="enc_key", kind="len" },
    },
    ["MoneroKeyImageSyncFinalRequest"] = {},
    ["MoneroKeyImageSyncStepAck"] = {
        [1] = { name="kis", kind="len", repeated=true, msg="MoneroKeyImageSyncStepAck.MoneroExportedKeyImage" },
    },
    ["MoneroKeyImageSyncStepAck.MoneroExportedKeyImage"] = {
        [1] = { name="iv", kind="len" },
        [3] = { name="blob", kind="len" },
    },
    ["MoneroKeyImageSyncStepRequest"] = {
        [1] = { name="tdis", kind="len", repeated=true, msg="MoneroKeyImageSyncStepRequest.MoneroTransferDetails" },
    },
    ["MoneroKeyImageSyncStepRequest.MoneroTransferDetails"] = {
        [1] = { name="out_key", kind="len" },
        [2] = { name="tx_pub_key", kind="len" },
        [3] = { name="additional_tx_pub_keys", kind="len", repeated=true },
        [4] = { name="internal_output_index", kind="varint" },
        [5] = { name="sub_addr_major", kind="varint" },
        [6] = { name="sub_addr_minor", kind="varint" },
    },
    ["MoneroLiveRefreshFinalAck"] = {},
    ["MoneroLiveRefreshFinalRequest"] = {},
    ["MoneroLiveRefreshStartAck"] = {},
    ["MoneroLiveRefreshStartRequest"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
    },
    ["MoneroLiveRefreshStepAck"] = {
        [1] = { name="salt", kind="len" },
        [2] = { name="key_image", kind="len" },
    },
    ["MoneroLiveRefreshStepRequest"] = {
        [1] = { name="out_key", kind="len" },
        [2] = { name="recv_deriv", kind="len" },
        [3] = { name="real_out_idx", kind="varint" },
        [4] = { name="sub_addr_major", kind="varint" },
        [5] = { name="sub_addr_minor", kind="varint" },
    },
    ["MoneroTransactionAllInputsSetAck"] = {
        [1] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
    },
    ["MoneroTransactionAllInputsSetRequest"] = {},
    ["MoneroTransactionAllOutSetAck"] = {
        [1] = { name="extra", kind="len" },
        [2] = { name="tx_prefix_hash", kind="len" },
        [4] = { name="rv", kind="len", msg="MoneroTransactionAllOutSetAck.MoneroRingCtSig" },
        [5] = { name="full_message_hash", kind="len" },
    },
    ["MoneroTransactionAllOutSetAck.MoneroRingCtSig"] = {
        [1] = { name="txn_fee", kind="varint" },
        [2] = { name="message", kind="len" },
        [3] = { name="rv_type", kind="varint" },
    },
    ["MoneroTransactionAllOutSetRequest"] = {
        [1] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
    },
    ["MoneroTransactionDestinationEntry"] = {
        [1] = { name="amount", kind="varint" },
        [2] = { name="addr", kind="len", msg="MoneroTransactionDestinationEntry.MoneroAccountPublicAddress" },
        [3] = { name="is_subaddress", kind="varint" },
        [4] = { name="original", kind="len" },
        [5] = { name="is_integrated", kind="varint" },
    },
    ["MoneroTransactionDestinationEntry.MoneroAccountPublicAddress"] = {
        [1] = { name="spend_public_key", kind="len" },
        [2] = { name="view_public_key", kind="len" },
    },
    ["MoneroTransactionFinalAck"] = {
        [1] = { name="cout_key", kind="len" },
        [2] = { name="salt", kind="len" },
        [3] = { name="rand_mult", kind="len" },
        [4] = { name="tx_enc_keys", kind="len" },
        [5] = { name="opening_key", kind="len" },
    },
    ["MoneroTransactionFinalRequest"] = {},
    ["MoneroTransactionInitAck"] = {
        [1] = { name="hmacs", kind="len", repeated=true },
        [2] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
    },
    ["MoneroTransactionInitRequest"] = {
        [1] = { name="version", kind="varint" },
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="network_type", kind="varint", enum="MoneroNetworkType" },
        [4] = { name="tsx_data", kind="len", msg="MoneroTransactionInitRequest.MoneroTransactionData" },
    },
    ["MoneroTransactionInitRequest.MoneroTransactionData"] = {
        [1] = { name="version", kind="varint" },
        [2] = { name="payment_id", kind="len" },
        [3] = { name="unlock_time", kind="varint" },
        [4] = { name="outputs", kind="len", repeated=true, msg="MoneroTransactionDestinationEntry" },
        [5] = { name="change_dts", kind="len", msg="MoneroTransactionDestinationEntry" },
        [6] = { name="num_inputs", kind="varint" },
        [7] = { name="mixin", kind="varint" },
        [8] = { name="fee", kind="varint" },
        [9] = { name="account", kind="varint" },
        [10] = { name="minor_indices", kind="varint", repeated=true },
        [11] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
        [12] = { name="integrated_indices", kind="varint", repeated=true },
        [13] = { name="client_version", kind="varint" },
        [14] = { name="hard_fork", kind="varint" },
        [15] = { name="monero_version", kind="len" },
        [16] = { name="chunkify", kind="varint" },
    },
    ["MoneroTransactionInputViniAck"] = {},
    ["MoneroTransactionInputViniRequest"] = {
        [1] = { name="src_entr", kind="len", msg="MoneroTransactionSourceEntry" },
        [2] = { name="vini", kind="len" },
        [3] = { name="vini_hmac", kind="len" },
        [4] = { name="pseudo_out", kind="len" },
        [5] = { name="pseudo_out_hmac", kind="len" },
        [6] = { name="orig_idx", kind="varint" },
    },
    ["MoneroTransactionRsigData"] = {
        [1] = { name="rsig_type", kind="varint" },
        [2] = { name="offload_type", kind="varint" },
        [3] = { name="grouping", kind="varint", repeated=true },
        [4] = { name="mask", kind="len" },
        [5] = { name="rsig", kind="len" },
        [6] = { name="rsig_parts", kind="len", repeated=true },
        [7] = { name="bp_version", kind="varint" },
    },
    ["MoneroTransactionSetInputAck"] = {
        [1] = { name="vini", kind="len" },
        [2] = { name="vini_hmac", kind="len" },
        [3] = { name="pseudo_out", kind="len" },
        [4] = { name="pseudo_out_hmac", kind="len" },
        [5] = { name="pseudo_out_alpha", kind="len" },
        [6] = { name="spend_key", kind="len" },
    },
    ["MoneroTransactionSetInputRequest"] = {
        [1] = { name="src_entr", kind="len", msg="MoneroTransactionSourceEntry" },
    },
    ["MoneroTransactionSetOutputAck"] = {
        [1] = { name="tx_out", kind="len" },
        [2] = { name="vouti_hmac", kind="len" },
        [3] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
        [4] = { name="out_pk", kind="len" },
        [5] = { name="ecdh_info", kind="len" },
    },
    ["MoneroTransactionSetOutputRequest"] = {
        [1] = { name="dst_entr", kind="len", msg="MoneroTransactionDestinationEntry" },
        [2] = { name="dst_entr_hmac", kind="len" },
        [3] = { name="rsig_data", kind="len", msg="MoneroTransactionRsigData" },
        [4] = { name="is_offloaded_bp", kind="varint" },
    },
    ["MoneroTransactionSignInputAck"] = {
        [1] = { name="signature", kind="len" },
        [2] = { name="pseudo_out", kind="len" },
    },
    ["MoneroTransactionSignInputRequest"] = {
        [1] = { name="src_entr", kind="len", msg="MoneroTransactionSourceEntry" },
        [2] = { name="vini", kind="len" },
        [3] = { name="vini_hmac", kind="len" },
        [4] = { name="pseudo_out", kind="len" },
        [5] = { name="pseudo_out_hmac", kind="len" },
        [6] = { name="pseudo_out_alpha", kind="len" },
        [7] = { name="spend_key", kind="len" },
        [8] = { name="orig_idx", kind="varint" },
    },
    ["MoneroTransactionSourceEntry"] = {
        [1] = { name="outputs", kind="len", repeated=true, msg="MoneroTransactionSourceEntry.MoneroOutputEntry" },
        [2] = { name="real_output", kind="varint" },
        [3] = { name="real_out_tx_key", kind="len" },
        [4] = { name="real_out_additional_tx_keys", kind="len", repeated=true },
        [5] = { name="real_output_in_tx_index", kind="varint" },
        [6] = { name="amount", kind="varint" },
        [7] = { name="rct", kind="varint" },
        [8] = { name="mask", kind="len" },
        [9] = { name="multisig_kLRki", kind="len", msg="MoneroTransactionSourceEntry.MoneroMultisigKLRki" },
        [10] = { name="subaddr_minor", kind="varint" },
    },
    ["MoneroTransactionSourceEntry.MoneroMultisigKLRki"] = {
        [1] = { name="K", kind="len" },
        [2] = { name="L", kind="len" },
        [3] = { name="R", kind="len" },
        [4] = { name="ki", kind="len" },
    },
    ["MoneroTransactionSourceEntry.MoneroOutputEntry"] = {
        [1] = { name="idx", kind="varint" },
        [2] = { name="key", kind="len", msg="MoneroTransactionSourceEntry.MoneroOutputEntry.MoneroRctKeyPublic" },
    },
    ["MoneroTransactionSourceEntry.MoneroOutputEntry.MoneroRctKeyPublic"] = {
        [1] = { name="dest", kind="len" },
        [2] = { name="commitment", kind="len" },
    },
    ["MoneroWatchKey"] = {
        [1] = { name="watch_key", kind="len" },
        [2] = { name="address", kind="len" },
    },
    ["MultisigRedeemScriptType"] = {
        [1] = { name="pubkeys", kind="len", repeated=true, msg="MultisigRedeemScriptType.HDNodePathType" },
        [2] = { name="signatures", kind="len", repeated=true },
        [3] = { name="m", kind="varint" },
        [4] = { name="nodes", kind="len", repeated=true, msg="HDNodeType" },
        [5] = { name="address_n", kind="varint", repeated=true },
        [6] = { name="pubkeys_order", kind="varint", enum="MultisigPubkeysOrder" },
    },
    ["MultisigRedeemScriptType.HDNodePathType"] = {
        [1] = { name="node", kind="len", msg="HDNodeType" },
        [2] = { name="address_n", kind="varint", repeated=true },
    },
    ["NEMAddress"] = {
        [1] = { name="address", kind="len" },
    },
    ["NEMDecryptMessage"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network", kind="varint" },
        [3] = { name="public_key", kind="len" },
        [4] = { name="payload", kind="len" },
    },
    ["NEMDecryptedMessage"] = {
        [1] = { name="payload", kind="len" },
    },
    ["NEMGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network", kind="varint" },
        [3] = { name="show_display", kind="varint" },
        [4] = { name="chunkify", kind="varint" },
    },
    ["NEMSignTx"] = {
        [1] = { name="transaction", kind="len", msg="NEMSignTx.NEMTransactionCommon" },
        [2] = { name="multisig", kind="len", msg="NEMSignTx.NEMTransactionCommon" },
        [3] = { name="transfer", kind="len", msg="NEMSignTx.NEMTransfer" },
        [4] = { name="cosigning", kind="varint" },
        [5] = { name="provision_namespace", kind="len", msg="NEMSignTx.NEMProvisionNamespace" },
        [6] = { name="mosaic_creation", kind="len", msg="NEMSignTx.NEMMosaicCreation" },
        [7] = { name="supply_change", kind="len", msg="NEMSignTx.NEMMosaicSupplyChange" },
        [8] = { name="aggregate_modification", kind="len", msg="NEMSignTx.NEMAggregateModification" },
        [9] = { name="importance_transfer", kind="len", msg="NEMSignTx.NEMImportanceTransfer" },
        [10] = { name="chunkify", kind="varint" },
    },
    ["NEMSignTx.NEMAggregateModification"] = {
        [1] = { name="modifications", kind="len", repeated=true, msg="NEMSignTx.NEMAggregateModification.NEMCosignatoryModification" },
        [2] = { name="relative_change", kind="varint" },
    },
    ["NEMSignTx.NEMAggregateModification.NEMCosignatoryModification"] = {
        [1] = { name="type", kind="varint", enum="NEMSignTx.NEMAggregateModification.NEMCosignatoryModification.NEMModificationType" },
        [2] = { name="public_key", kind="len" },
    },
    ["NEMSignTx.NEMImportanceTransfer"] = {
        [1] = { name="mode", kind="varint", enum="NEMSignTx.NEMImportanceTransfer.NEMImportanceTransferMode" },
        [2] = { name="public_key", kind="len" },
    },
    ["NEMSignTx.NEMMosaicCreation"] = {
        [1] = { name="definition", kind="len", msg="NEMSignTx.NEMMosaicCreation.NEMMosaicDefinition" },
        [2] = { name="sink", kind="len" },
        [3] = { name="fee", kind="varint" },
    },
    ["NEMSignTx.NEMMosaicCreation.NEMMosaicDefinition"] = {
        [1] = { name="name", kind="len" },
        [2] = { name="ticker", kind="len" },
        [3] = { name="namespace", kind="len" },
        [4] = { name="mosaic", kind="len" },
        [5] = { name="divisibility", kind="varint" },
        [6] = { name="levy", kind="varint", enum="NEMSignTx.NEMMosaicCreation.NEMMosaicDefinition.NEMMosaicLevy" },
        [7] = { name="fee", kind="varint" },
        [8] = { name="levy_address", kind="len" },
        [9] = { name="levy_namespace", kind="len" },
        [10] = { name="levy_mosaic", kind="len" },
        [11] = { name="supply", kind="varint" },
        [12] = { name="mutable_supply", kind="varint" },
        [13] = { name="transferable", kind="varint" },
        [14] = { name="description", kind="len" },
        [15] = { name="networks", kind="varint", repeated=true },
    },
    ["NEMSignTx.NEMMosaicSupplyChange"] = {
        [1] = { name="namespace", kind="len" },
        [2] = { name="mosaic", kind="len" },
        [3] = { name="type", kind="varint", enum="NEMSignTx.NEMMosaicSupplyChange.NEMSupplyChangeType" },
        [4] = { name="delta", kind="varint" },
    },
    ["NEMSignTx.NEMProvisionNamespace"] = {
        [1] = { name="namespace", kind="len" },
        [2] = { name="parent", kind="len" },
        [3] = { name="sink", kind="len" },
        [4] = { name="fee", kind="varint" },
    },
    ["NEMSignTx.NEMTransactionCommon"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="network", kind="varint" },
        [3] = { name="timestamp", kind="varint" },
        [4] = { name="fee", kind="varint" },
        [5] = { name="deadline", kind="varint" },
        [6] = { name="signer", kind="len" },
    },
    ["NEMSignTx.NEMTransfer"] = {
        [1] = { name="recipient", kind="len" },
        [2] = { name="amount", kind="varint" },
        [3] = { name="payload", kind="len" },
        [4] = { name="public_key", kind="len" },
        [5] = { name="mosaics", kind="len", repeated=true, msg="NEMSignTx.NEMTransfer.NEMMosaic" },
    },
    ["NEMSignTx.NEMTransfer.NEMMosaic"] = {
        [1] = { name="namespace", kind="len" },
        [2] = { name="mosaic", kind="len" },
        [3] = { name="quantity", kind="varint" },
    },
    ["NEMSignedTx"] = {
        [1] = { name="data", kind="len" },
        [2] = { name="signature", kind="len" },
    },
    ["NextU2FCounter"] = {
        [1] = { name="u2f_counter", kind="varint" },
    },
    ["Nonce"] = {
        [1] = { name="nonce", kind="len" },
    },
    ["NostrEventSignature"] = {
        [1] = { name="pubkey", kind="len" },
        [2] = { name="id", kind="len" },
        [3] = { name="signature", kind="len" },
    },
    ["NostrGetPubkey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
    },
    ["NostrPubkey"] = {
        [1] = { name="pubkey", kind="len" },
    },
    ["NostrSignEvent"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="created_at", kind="varint" },
        [3] = { name="kind", kind="varint" },
        [4] = { name="tags", kind="len", repeated=true, msg="NostrTag" },
        [5] = { name="content", kind="len" },
    },
    ["NostrTag"] = {
        [1] = { name="key", kind="len" },
        [2] = { name="value", kind="len" },
        [3] = { name="extra", kind="len", repeated=true },
    },
    ["OwnershipId"] = {
        [1] = { name="ownership_id", kind="len" },
    },
    ["OwnershipProof"] = {
        [1] = { name="ownership_proof", kind="len" },
        [2] = { name="signature", kind="len" },
    },
    ["PassphraseAck"] = {
        [1] = { name="passphrase", kind="len" },
        [2] = { name="_state", kind="len" },
        [3] = { name="on_device", kind="varint" },
    },
    ["PassphraseRequest"] = {
        [1] = { name="_on_device", kind="varint" },
    },
    ["PaymentNotification"] = {
        [1] = { name="payment_req", kind="len", msg="PaymentRequest" },
    },
    ["PaymentRequest"] = {
        [1] = { name="nonce", kind="len" },
        [2] = { name="recipient_name", kind="len" },
        [3] = { name="memos", kind="len", repeated=true, msg="PaymentRequest.PaymentRequestMemo" },
        [6] = { name="amount", kind="len" },
        [5] = { name="signature", kind="len" },
    },
    ["PaymentRequest.CoinPurchaseMemo"] = {
        [1] = { name="coin_type", kind="varint" },
        [2] = { name="amount", kind="len" },
        [3] = { name="address", kind="len" },
        [4] = { name="address_n", kind="varint", repeated=true },
        [5] = { name="mac", kind="len" },
    },
    ["PaymentRequest.PaymentRequestMemo"] = {
        [1] = { name="text_memo", kind="len", msg="PaymentRequest.TextMemo" },
        [2] = { name="refund_memo", kind="len", msg="PaymentRequest.RefundMemo" },
        [3] = { name="coin_purchase_memo", kind="len", msg="PaymentRequest.CoinPurchaseMemo" },
        [4] = { name="text_details_memo", kind="len", msg="PaymentRequest.TextDetailsMemo" },
    },
    ["PaymentRequest.RefundMemo"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="mac", kind="len" },
    },
    ["PaymentRequest.TextDetailsMemo"] = {
        [1] = { name="title", kind="len" },
        [2] = { name="text", kind="len" },
    },
    ["PaymentRequest.TextMemo"] = {
        [1] = { name="text", kind="len" },
    },
    ["PinMatrixAck"] = {
        [1] = { name="pin", kind="len" },
    },
    ["PinMatrixRequest"] = {
        [1] = { name="type", kind="varint", enum="PinMatrixRequest.PinMatrixRequestType" },
    },
    ["Ping"] = {
        [1] = { name="message", kind="len" },
        [2] = { name="button_protection", kind="varint" },
    },
    ["PreauthorizedRequest"] = {},
    ["PrevInput"] = {
        [2] = { name="prev_hash", kind="len" },
        [3] = { name="prev_index", kind="varint" },
        [4] = { name="script_sig", kind="len" },
        [5] = { name="sequence", kind="varint" },
        [9] = { name="decred_tree", kind="varint" },
    },
    ["PrevOutput"] = {
        [1] = { name="amount", kind="varint" },
        [2] = { name="script_pubkey", kind="len" },
        [3] = { name="decred_script_version", kind="varint" },
    },
    ["PrevTx"] = {
        [1] = { name="version", kind="varint" },
        [4] = { name="lock_time", kind="varint" },
        [6] = { name="inputs_count", kind="varint" },
        [7] = { name="outputs_count", kind="varint" },
        [9] = { name="extra_data_len", kind="varint" },
        [10] = { name="expiry", kind="varint" },
        [12] = { name="version_group_id", kind="varint" },
        [13] = { name="timestamp", kind="varint" },
        [14] = { name="branch_id", kind="varint" },
    },
    ["ProdTestT1"] = {
        [1] = { name="payload", kind="len" },
    },
    ["PublicKey"] = {
        [1] = { name="node", kind="len", msg="HDNodeType" },
        [2] = { name="xpub", kind="len" },
        [3] = { name="root_fingerprint", kind="varint" },
        [4] = { name="descriptor", kind="len" },
    },
    ["RebootToBootloader"] = {
        [1] = { name="boot_command", kind="varint", enum="RebootToBootloader.BootCommand" },
        [2] = { name="firmware_header", kind="len" },
    },
    ["RecoveryDevice"] = {
        [1] = { name="word_count", kind="varint" },
        [2] = { name="passphrase_protection", kind="varint" },
        [3] = { name="pin_protection", kind="varint" },
        [4] = { name="language", kind="len" },
        [5] = { name="label", kind="len" },
        [6] = { name="enforce_wordlist", kind="varint" },
        [8] = { name="input_method", kind="varint", enum="RecoveryDevice.RecoveryDeviceInputMethod" },
        [9] = { name="u2f_counter", kind="varint" },
        [10] = { name="type", kind="varint", enum="RecoveryType" },
        [11] = { name="backup_method", kind="varint", enum="BackupMethod" },
    },
    ["ResetDevice"] = {
        [2] = { name="strength", kind="varint" },
        [3] = { name="passphrase_protection", kind="varint" },
        [4] = { name="pin_protection", kind="varint" },
        [5] = { name="language", kind="len" },
        [6] = { name="label", kind="len" },
        [7] = { name="u2f_counter", kind="varint" },
        [8] = { name="skip_backup", kind="varint" },
        [9] = { name="no_backup", kind="varint" },
        [10] = { name="backup_type", kind="varint", enum="BackupType" },
        [11] = { name="entropy_check", kind="varint" },
        [12] = { name="backup_method", kind="varint", enum="BackupMethod" },
    },
    ["RippleAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["RippleGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["RippleSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="fee", kind="varint" },
        [3] = { name="flags", kind="varint" },
        [4] = { name="sequence", kind="varint" },
        [5] = { name="last_ledger_sequence", kind="varint" },
        [6] = { name="payment", kind="len", msg="RippleSignTx.RipplePayment" },
        [7] = { name="chunkify", kind="varint" },
        [8] = { name="payment_req", kind="len", msg="PaymentRequest" },
        [9] = { name="account_delete", kind="len", msg="RippleSignTx.RippleAccountDelete" },
    },
    ["RippleSignTx.RippleAccountDelete"] = {
        [1] = { name="destination", kind="len" },
    },
    ["RippleSignTx.RipplePayment"] = {
        [1] = { name="amount", kind="varint" },
        [2] = { name="destination", kind="len" },
        [3] = { name="destination_tag", kind="varint" },
    },
    ["RippleSignedTx"] = {
        [1] = { name="signature", kind="len" },
        [2] = { name="serialized_tx", kind="len" },
    },
    ["SdProtect"] = {
        [1] = { name="operation", kind="varint", enum="SdProtect.SdProtectOperationType" },
    },
    ["SerialNumber"] = {
        [1] = { name="serial_number", kind="len" },
    },
    ["SetBrightness"] = {
        [1] = { name="value", kind="varint" },
    },
    ["SetBusy"] = {
        [1] = { name="expiry_ms", kind="varint" },
    },
    ["SetU2FCounter"] = {
        [1] = { name="u2f_counter", kind="varint" },
    },
    ["ShowDeviceTutorial"] = {},
    ["SignIdentity"] = {
        [1] = { name="identity", kind="len", msg="IdentityType" },
        [2] = { name="challenge_hidden", kind="len" },
        [3] = { name="challenge_visual", kind="len" },
        [4] = { name="ecdsa_curve_name", kind="len" },
    },
    ["SignMessage"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="message", kind="len" },
        [3] = { name="coin_name", kind="len" },
        [4] = { name="script_type", kind="varint", enum="InputScriptType" },
        [5] = { name="no_script_type", kind="varint" },
        [6] = { name="chunkify", kind="varint" },
    },
    ["SignTx"] = {
        [1] = { name="outputs_count", kind="varint" },
        [2] = { name="inputs_count", kind="varint" },
        [3] = { name="coin_name", kind="len" },
        [4] = { name="version", kind="varint" },
        [5] = { name="lock_time", kind="varint" },
        [6] = { name="expiry", kind="varint" },
        [7] = { name="overwintered", kind="varint" },
        [8] = { name="version_group_id", kind="varint" },
        [9] = { name="timestamp", kind="varint" },
        [10] = { name="branch_id", kind="varint" },
        [11] = { name="amount_unit", kind="varint", enum="AmountUnit" },
        [12] = { name="decred_staking_ticket", kind="varint" },
        [13] = { name="serialize", kind="varint" },
        [14] = { name="coinjoin_request", kind="len", msg="SignTx.CoinJoinRequest" },
        [15] = { name="chunkify", kind="varint" },
    },
    ["SignTx.CoinJoinRequest"] = {
        [1] = { name="fee_rate", kind="varint" },
        [2] = { name="no_fee_threshold", kind="varint" },
        [3] = { name="min_registrable_amount", kind="varint" },
        [4] = { name="mask_public_key", kind="len" },
        [5] = { name="signature", kind="len" },
    },
    ["SignedIdentity"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="public_key", kind="len" },
        [3] = { name="signature", kind="len" },
    },
    ["SolanaAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["SolanaGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["SolanaGetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
    },
    ["SolanaMessageSignature"] = {
        [1] = { name="signature", kind="len" },
    },
    ["SolanaPublicKey"] = {
        [1] = { name="public_key", kind="len" },
    },
    ["SolanaSignMessage"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="message", kind="len" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["SolanaSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="serialized_tx", kind="len" },
        [3] = { name="additional_info", kind="len", msg="SolanaTxAdditionalInfo" },
        [4] = { name="payment_req", kind="len", msg="PaymentRequest" },
    },
    ["SolanaTokenInfo"] = {
        [1] = { name="mint", kind="len" },
        [2] = { name="symbol", kind="len" },
        [3] = { name="name", kind="len" },
    },
    ["SolanaTxAdditionalInfo"] = {
        [1] = { name="token_accounts_infos", kind="len", repeated=true, msg="SolanaTxTokenAccountInfo" },
        [2] = { name="encoded_token", kind="len" },
    },
    ["SolanaTxSignature"] = {
        [1] = { name="signature", kind="len" },
    },
    ["SolanaTxTokenAccountInfo"] = {
        [1] = { name="base_address", kind="len" },
        [2] = { name="token_program", kind="len" },
        [3] = { name="token_mint", kind="len" },
        [4] = { name="token_account", kind="len" },
    },
    ["SolanaVerifyMessage"] = {
        [1] = { name="envelope", kind="len" },
        [2] = { name="chunkify", kind="varint" },
    },
    ["StellarAccountMergeOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="destination_account", kind="len" },
    },
    ["StellarAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["StellarAllowTrustOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="trusted_account", kind="len" },
        [3] = { name="asset_type", kind="varint", enum="StellarAssetType" },
        [4] = { name="asset_code", kind="len" },
        [5] = { name="is_authorized", kind="varint" },
    },
    ["StellarAsset"] = {
        [1] = { name="type", kind="varint", enum="StellarAssetType" },
        [2] = { name="code", kind="len" },
        [3] = { name="issuer", kind="len" },
    },
    ["StellarBumpSequenceOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="bump_to", kind="varint" },
    },
    ["StellarChangeTrustOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="asset", kind="len", msg="StellarAsset" },
        [3] = { name="limit", kind="varint" },
    },
    ["StellarClaimClaimableBalanceOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="balance_id", kind="len" },
    },
    ["StellarCreateAccountOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="new_account", kind="len" },
        [3] = { name="starting_balance", kind="varint" },
    },
    ["StellarCreatePassiveSellOfferOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="selling_asset", kind="len", msg="StellarAsset" },
        [3] = { name="buying_asset", kind="len", msg="StellarAsset" },
        [4] = { name="amount", kind="varint" },
        [5] = { name="price_n", kind="varint" },
        [6] = { name="price_d", kind="varint" },
    },
    ["StellarGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["StellarManageBuyOfferOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="selling_asset", kind="len", msg="StellarAsset" },
        [3] = { name="buying_asset", kind="len", msg="StellarAsset" },
        [4] = { name="amount", kind="varint" },
        [5] = { name="price_n", kind="varint" },
        [6] = { name="price_d", kind="varint" },
        [7] = { name="offer_id", kind="varint" },
    },
    ["StellarManageDataOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="key", kind="len" },
        [3] = { name="value", kind="len" },
    },
    ["StellarManageSellOfferOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="selling_asset", kind="len", msg="StellarAsset" },
        [3] = { name="buying_asset", kind="len", msg="StellarAsset" },
        [4] = { name="amount", kind="varint" },
        [5] = { name="price_n", kind="varint" },
        [6] = { name="price_d", kind="varint" },
        [7] = { name="offer_id", kind="varint" },
    },
    ["StellarPathPaymentStrictReceiveOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="send_asset", kind="len", msg="StellarAsset" },
        [3] = { name="send_max", kind="varint" },
        [4] = { name="destination_account", kind="len" },
        [5] = { name="destination_asset", kind="len", msg="StellarAsset" },
        [6] = { name="destination_amount", kind="varint" },
        [7] = { name="paths", kind="len", repeated=true, msg="StellarAsset" },
    },
    ["StellarPathPaymentStrictSendOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="send_asset", kind="len", msg="StellarAsset" },
        [3] = { name="send_amount", kind="varint" },
        [4] = { name="destination_account", kind="len" },
        [5] = { name="destination_asset", kind="len", msg="StellarAsset" },
        [6] = { name="destination_min", kind="varint" },
        [7] = { name="paths", kind="len", repeated=true, msg="StellarAsset" },
    },
    ["StellarPaymentOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="destination_account", kind="len" },
        [3] = { name="asset", kind="len", msg="StellarAsset" },
        [4] = { name="amount", kind="varint" },
    },
    ["StellarSetOptionsOp"] = {
        [1] = { name="source_account", kind="len" },
        [2] = { name="inflation_destination_account", kind="len" },
        [3] = { name="clear_flags", kind="varint" },
        [4] = { name="set_flags", kind="varint" },
        [5] = { name="master_weight", kind="varint" },
        [6] = { name="low_threshold", kind="varint" },
        [7] = { name="medium_threshold", kind="varint" },
        [8] = { name="high_threshold", kind="varint" },
        [9] = { name="home_domain", kind="len" },
        [10] = { name="signer_type", kind="varint", enum="StellarSetOptionsOp.StellarSignerType" },
        [11] = { name="signer_key", kind="len" },
        [12] = { name="signer_weight", kind="varint" },
    },
    ["StellarSignTx"] = {
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="network_passphrase", kind="len" },
        [4] = { name="source_account", kind="len" },
        [5] = { name="fee", kind="varint" },
        [6] = { name="sequence_number", kind="varint" },
        [8] = { name="timebounds_start", kind="varint" },
        [9] = { name="timebounds_end", kind="varint" },
        [10] = { name="memo_type", kind="varint", enum="StellarSignTx.StellarMemoType" },
        [11] = { name="memo_text", kind="len" },
        [12] = { name="memo_id", kind="varint" },
        [13] = { name="memo_hash", kind="len" },
        [14] = { name="num_operations", kind="varint" },
        [15] = { name="payment_req", kind="len", msg="PaymentRequest" },
    },
    ["StellarSignedTx"] = {
        [1] = { name="public_key", kind="len" },
        [2] = { name="signature", kind="len" },
    },
    ["StellarTxOpRequest"] = {},
    ["Success"] = {
        [1] = { name="message", kind="len" },
    },
    ["Telemetry"] = {
        [1] = { name="min_temp_c", kind="varint" },
        [2] = { name="max_temp_c", kind="varint" },
        [3] = { name="battery_errors", kind="varint" },
        [4] = { name="battery_cycles", kind="varint" },
    },
    ["TelemetryGet"] = {},
    ["TezosAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["TezosGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["TezosGetPublicKey"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["TezosPublicKey"] = {
        [1] = { name="public_key", kind="len" },
    },
    ["TezosSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="branch", kind="len" },
        [3] = { name="reveal", kind="len", msg="TezosSignTx.TezosRevealOp" },
        [4] = { name="transaction", kind="len", msg="TezosSignTx.TezosTransactionOp" },
        [5] = { name="origination", kind="len", msg="TezosSignTx.TezosOriginationOp" },
        [6] = { name="delegation", kind="len", msg="TezosSignTx.TezosDelegationOp" },
        [7] = { name="proposal", kind="len", msg="TezosSignTx.TezosProposalOp" },
        [8] = { name="ballot", kind="len", msg="TezosSignTx.TezosBallotOp" },
        [9] = { name="chunkify", kind="varint" },
    },
    ["TezosSignTx.TezosBallotOp"] = {
        [1] = { name="source", kind="len" },
        [2] = { name="period", kind="varint" },
        [3] = { name="proposal", kind="len" },
        [4] = { name="ballot", kind="varint", enum="TezosSignTx.TezosBallotOp.TezosBallotType" },
    },
    ["TezosSignTx.TezosContractID"] = {
        [1] = { name="tag", kind="varint", enum="TezosSignTx.TezosContractID.TezosContractType" },
        [2] = { name="hash", kind="len" },
    },
    ["TezosSignTx.TezosDelegationOp"] = {
        [7] = { name="source", kind="len" },
        [2] = { name="fee", kind="varint" },
        [3] = { name="counter", kind="varint" },
        [4] = { name="gas_limit", kind="varint" },
        [5] = { name="storage_limit", kind="varint" },
        [6] = { name="delegate", kind="len" },
    },
    ["TezosSignTx.TezosOriginationOp"] = {
        [12] = { name="source", kind="len" },
        [2] = { name="fee", kind="varint" },
        [3] = { name="counter", kind="varint" },
        [4] = { name="gas_limit", kind="varint" },
        [5] = { name="storage_limit", kind="varint" },
        [6] = { name="manager_pubkey", kind="len" },
        [7] = { name="balance", kind="varint" },
        [8] = { name="spendable", kind="varint" },
        [9] = { name="delegatable", kind="varint" },
        [10] = { name="delegate", kind="len" },
        [11] = { name="script", kind="len" },
    },
    ["TezosSignTx.TezosProposalOp"] = {
        [1] = { name="source", kind="len" },
        [2] = { name="period", kind="varint" },
        [4] = { name="proposals", kind="len", repeated=true },
    },
    ["TezosSignTx.TezosRevealOp"] = {
        [7] = { name="source", kind="len" },
        [2] = { name="fee", kind="varint" },
        [3] = { name="counter", kind="varint" },
        [4] = { name="gas_limit", kind="varint" },
        [5] = { name="storage_limit", kind="varint" },
        [6] = { name="public_key", kind="len" },
    },
    ["TezosSignTx.TezosTransactionOp"] = {
        [9] = { name="source", kind="len" },
        [2] = { name="fee", kind="varint" },
        [3] = { name="counter", kind="varint" },
        [4] = { name="gas_limit", kind="varint" },
        [5] = { name="storage_limit", kind="varint" },
        [6] = { name="amount", kind="varint" },
        [7] = { name="destination", kind="len", msg="TezosSignTx.TezosContractID" },
        [8] = { name="parameters", kind="len" },
        [10] = { name="parameters_manager", kind="len", msg="TezosSignTx.TezosTransactionOp.TezosParametersManager" },
    },
    ["TezosSignTx.TezosTransactionOp.TezosParametersManager"] = {
        [1] = { name="set_delegate", kind="len" },
        [2] = { name="cancel_delegate", kind="varint" },
        [3] = { name="transfer", kind="len", msg="TezosSignTx.TezosTransactionOp.TezosParametersManager.TezosManagerTransfer" },
    },
    ["TezosSignTx.TezosTransactionOp.TezosParametersManager.TezosManagerTransfer"] = {
        [1] = { name="destination", kind="len", msg="TezosSignTx.TezosContractID" },
        [2] = { name="amount", kind="varint" },
    },
    ["TezosSignedTx"] = {
        [1] = { name="signature", kind="len" },
        [2] = { name="sig_op_contents", kind="len" },
        [3] = { name="operation_hash", kind="len" },
    },
    ["ThpAuthenticatedCredentialData"] = {
        [1] = { name="host_static_public_key", kind="len" },
        [2] = { name="cred_metadata", kind="len", msg="ThpCredentialMetadata" },
    },
    ["ThpCodeEntryChallenge"] = {
        [1] = { name="challenge", kind="len" },
    },
    ["ThpCodeEntryCommitment"] = {
        [1] = { name="commitment", kind="len" },
    },
    ["ThpCodeEntryCpaceHostTag"] = {
        [1] = { name="cpace_host_public_key", kind="len" },
        [2] = { name="tag", kind="len" },
    },
    ["ThpCodeEntryCpaceTrezor"] = {
        [1] = { name="cpace_trezor_public_key", kind="len" },
    },
    ["ThpCodeEntrySecret"] = {
        [1] = { name="secret", kind="len" },
    },
    ["ThpCreateNewSession"] = {
        [1] = { name="passphrase", kind="len" },
        [2] = { name="on_device", kind="varint" },
        [3] = { name="derive_cardano", kind="varint" },
    },
    ["ThpCredentialMetadata"] = {
        [1] = { name="host_name", kind="len" },
        [2] = { name="autoconnect", kind="varint" },
        [3] = { name="app_name", kind="len" },
    },
    ["ThpCredentialRequest"] = {
        [1] = { name="host_static_public_key", kind="len" },
        [2] = { name="autoconnect", kind="varint" },
        [3] = { name="credential", kind="len" },
    },
    ["ThpCredentialResponse"] = {
        [1] = { name="trezor_static_public_key", kind="len" },
        [2] = { name="credential", kind="len" },
    },
    ["ThpDeviceProperties"] = {
        [1] = { name="internal_model", kind="len" },
        [2] = { name="model_variant", kind="varint" },
        [3] = { name="protocol_version_major", kind="varint" },
        [4] = { name="protocol_version_minor", kind="varint" },
        [5] = { name="pairing_methods", kind="varint", repeated=true, enum="ThpPairingMethod" },
    },
    ["ThpEndRequest"] = {},
    ["ThpEndResponse"] = {},
    ["ThpHandshakeCompletionReqNoisePayload"] = {
        [1] = { name="host_pairing_credential", kind="len" },
    },
    ["ThpNfcTagHost"] = {
        [1] = { name="tag", kind="len" },
    },
    ["ThpNfcTagTrezor"] = {
        [1] = { name="tag", kind="len" },
    },
    ["ThpPairedCache"] = {
        [1] = { name="entries", kind="len", repeated=true, msg="ThpPairedCache.ThpPairedCacheEntry" },
    },
    ["ThpPairedCache.ThpPairedCacheEntry"] = {
        [1] = { name="mac_addr", kind="len" },
        [2] = { name="host_name", kind="len" },
        [3] = { name="app_name", kind="len" },
    },
    ["ThpPairingCredential"] = {
        [1] = { name="cred_metadata", kind="len", msg="ThpCredentialMetadata" },
        [2] = { name="mac", kind="len" },
    },
    ["ThpPairingPreparationsFinished"] = {},
    ["ThpPairingRequest"] = {
        [1] = { name="host_name", kind="len" },
        [2] = { name="app_name", kind="len" },
    },
    ["ThpPairingRequestApproved"] = {},
    ["ThpQrCodeSecret"] = {
        [1] = { name="secret", kind="len" },
    },
    ["ThpQrCodeTag"] = {
        [1] = { name="tag", kind="len" },
    },
    ["ThpSelectMethod"] = {
        [1] = { name="selected_pairing_method", kind="varint", enum="ThpPairingMethod" },
    },
    ["TronAddress"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="mac", kind="len" },
    },
    ["TronContractRequest"] = {},
    ["TronFreezeBalanceV2Contract"] = {
        [1] = { name="owner_address", kind="len" },
        [2] = { name="balance", kind="varint" },
        [3] = { name="resource", kind="varint", enum="TronResourceCode" },
    },
    ["TronGetAddress"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="show_display", kind="varint" },
        [3] = { name="chunkify", kind="varint" },
    },
    ["TronRawTransaction"] = {
        [1] = { name="ref_block_bytes", kind="len" },
        [4] = { name="ref_block_hash", kind="len" },
        [8] = { name="expiration", kind="varint" },
        [10] = { name="data", kind="len" },
        [11] = { name="contract", kind="len", repeated=true, msg="TronRawTransaction.TronRawContract" },
        [14] = { name="timestamp", kind="varint" },
        [18] = { name="fee_limit", kind="varint" },
    },
    ["TronRawTransaction.TronRawContract"] = {
        [1] = { name="type", kind="varint", enum="TronRawTransaction.TronRawContract.TronRawContractType" },
        [2] = { name="parameter", kind="len", msg="TronRawTransaction.TronRawContract.TronRawParameter" },
    },
    ["TronRawTransaction.TronRawContract.TronRawParameter"] = {
        [1] = { name="type_url", kind="len" },
        [2] = { name="value", kind="len" },
    },
    ["TronSignTx"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="ref_block_bytes", kind="len" },
        [3] = { name="ref_block_hash", kind="len" },
        [4] = { name="expiration", kind="varint" },
        [5] = { name="data", kind="len" },
        [6] = { name="timestamp", kind="varint" },
        [7] = { name="fee_limit", kind="varint" },
    },
    ["TronSignature"] = {
        [1] = { name="signature", kind="len" },
    },
    ["TronTransferContract"] = {
        [1] = { name="owner_address", kind="len" },
        [2] = { name="to_address", kind="len" },
        [3] = { name="amount", kind="varint" },
    },
    ["TronTriggerSmartContract"] = {
        [1] = { name="owner_address", kind="len" },
        [2] = { name="contract_address", kind="len" },
        [4] = { name="data", kind="len" },
    },
    ["TronUnfreezeBalanceV2Contract"] = {
        [1] = { name="owner_address", kind="len" },
        [2] = { name="balance", kind="varint" },
        [3] = { name="resource", kind="varint", enum="TronResourceCode" },
    },
    ["TronVoteWitnessContract"] = {
        [1] = { name="owner_address", kind="len" },
        [2] = { name="votes", kind="len", repeated=true, msg="TronVoteWitnessContract.TronVote" },
    },
    ["TronVoteWitnessContract.TronVote"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="count", kind="varint" },
    },
    ["TronWithdrawUnfreeze"] = {
        [1] = { name="owner_address", kind="len" },
    },
    ["TxAck"] = {
        [1] = { name="tx", kind="len", msg="TxAck.TransactionType" },
    },
    ["TxAck.TransactionType"] = {
        [1] = { name="version", kind="varint" },
        [2] = { name="inputs", kind="len", repeated=true, msg="TxAck.TransactionType.TxInputType" },
        [3] = { name="bin_outputs", kind="len", repeated=true, msg="TxAck.TransactionType.TxOutputBinType" },
        [4] = { name="lock_time", kind="varint" },
        [5] = { name="outputs", kind="len", repeated=true, msg="TxAck.TransactionType.TxOutputType" },
        [6] = { name="inputs_cnt", kind="varint" },
        [7] = { name="outputs_cnt", kind="varint" },
        [8] = { name="extra_data", kind="len" },
        [9] = { name="extra_data_len", kind="varint" },
        [10] = { name="expiry", kind="varint" },
        [11] = { name="overwintered", kind="varint" },
        [12] = { name="version_group_id", kind="varint" },
        [13] = { name="timestamp", kind="varint" },
        [14] = { name="branch_id", kind="varint" },
    },
    ["TxAck.TransactionType.TxInputType"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="prev_hash", kind="len" },
        [3] = { name="prev_index", kind="varint" },
        [4] = { name="script_sig", kind="len" },
        [5] = { name="sequence", kind="varint" },
        [6] = { name="script_type", kind="varint", enum="InputScriptType" },
        [7] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [8] = { name="amount", kind="varint" },
        [9] = { name="decred_tree", kind="varint" },
        [13] = { name="witness", kind="len" },
        [14] = { name="ownership_proof", kind="len" },
        [15] = { name="commitment_data", kind="len" },
        [16] = { name="orig_hash", kind="len" },
        [17] = { name="orig_index", kind="varint" },
        [18] = { name="decred_staking_spend", kind="varint", enum="DecredStakingSpendType" },
        [19] = { name="script_pubkey", kind="len" },
        [20] = { name="coinjoin_flags", kind="varint" },
    },
    ["TxAck.TransactionType.TxOutputBinType"] = {
        [1] = { name="amount", kind="varint" },
        [2] = { name="script_pubkey", kind="len" },
        [3] = { name="decred_script_version", kind="varint" },
    },
    ["TxAck.TransactionType.TxOutputType"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="amount", kind="varint" },
        [4] = { name="script_type", kind="varint", enum="OutputScriptType" },
        [5] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [6] = { name="op_return_data", kind="len" },
        [10] = { name="orig_hash", kind="len" },
        [11] = { name="orig_index", kind="varint" },
        [12] = { name="payment_req_index", kind="varint" },
    },
    ["TxAckInput"] = {
        [1] = { name="tx", kind="len", msg="TxAckInput.TxAckInputWrapper" },
    },
    ["TxAckInput.TxAckInputWrapper"] = {
        [2] = { name="input", kind="len", msg="TxInput" },
    },
    ["TxAckOutput"] = {
        [1] = { name="tx", kind="len", msg="TxAckOutput.TxAckOutputWrapper" },
    },
    ["TxAckOutput.TxAckOutputWrapper"] = {
        [5] = { name="output", kind="len", msg="TxOutput" },
    },
    ["TxAckPrevExtraData"] = {
        [1] = { name="tx", kind="len", msg="TxAckPrevExtraData.TxAckPrevExtraDataWrapper" },
    },
    ["TxAckPrevExtraData.TxAckPrevExtraDataWrapper"] = {
        [8] = { name="extra_data_chunk", kind="len" },
    },
    ["TxAckPrevInput"] = {
        [1] = { name="tx", kind="len", msg="TxAckPrevInput.TxAckPrevInputWrapper" },
    },
    ["TxAckPrevInput.TxAckPrevInputWrapper"] = {
        [2] = { name="input", kind="len", msg="PrevInput" },
    },
    ["TxAckPrevMeta"] = {
        [1] = { name="tx", kind="len", msg="PrevTx" },
    },
    ["TxAckPrevOutput"] = {
        [1] = { name="tx", kind="len", msg="TxAckPrevOutput.TxAckPrevOutputWrapper" },
    },
    ["TxAckPrevOutput.TxAckPrevOutputWrapper"] = {
        [3] = { name="output", kind="len", msg="PrevOutput" },
    },
    ["TxInput"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="prev_hash", kind="len" },
        [3] = { name="prev_index", kind="varint" },
        [4] = { name="script_sig", kind="len" },
        [5] = { name="sequence", kind="varint" },
        [6] = { name="script_type", kind="varint", enum="InputScriptType" },
        [7] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [8] = { name="amount", kind="varint" },
        [9] = { name="decred_tree", kind="varint" },
        [13] = { name="witness", kind="len" },
        [14] = { name="ownership_proof", kind="len" },
        [15] = { name="commitment_data", kind="len" },
        [16] = { name="orig_hash", kind="len" },
        [17] = { name="orig_index", kind="varint" },
        [18] = { name="decred_staking_spend", kind="varint", enum="DecredStakingSpendType" },
        [19] = { name="script_pubkey", kind="len" },
        [20] = { name="coinjoin_flags", kind="varint" },
    },
    ["TxOutput"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="address_n", kind="varint", repeated=true },
        [3] = { name="amount", kind="varint" },
        [4] = { name="script_type", kind="varint", enum="OutputScriptType" },
        [5] = { name="multisig", kind="len", msg="MultisigRedeemScriptType" },
        [6] = { name="op_return_data", kind="len" },
        [10] = { name="orig_hash", kind="len" },
        [11] = { name="orig_index", kind="varint" },
        [12] = { name="payment_req_index", kind="varint" },
    },
    ["TxRequest"] = {
        [1] = { name="request_type", kind="varint", enum="TxRequest.RequestType" },
        [2] = { name="details", kind="len", msg="TxRequest.TxRequestDetailsType" },
        [3] = { name="serialized", kind="len", msg="TxRequest.TxRequestSerializedType" },
    },
    ["TxRequest.TxRequestDetailsType"] = {
        [1] = { name="request_index", kind="varint" },
        [2] = { name="tx_hash", kind="len" },
        [3] = { name="extra_data_len", kind="varint" },
        [4] = { name="extra_data_offset", kind="varint" },
    },
    ["TxRequest.TxRequestSerializedType"] = {
        [1] = { name="signature_index", kind="varint" },
        [2] = { name="signature", kind="len" },
        [3] = { name="serialized_tx", kind="len" },
    },
    ["UnlockBootloader"] = {},
    ["UnlockPath"] = {
        [1] = { name="address_n", kind="varint", repeated=true },
        [2] = { name="mac", kind="len" },
    },
    ["UnlockedPathRequest"] = {
        [1] = { name="mac", kind="len" },
    },
    ["VerifyMessage"] = {
        [1] = { name="address", kind="len" },
        [2] = { name="signature", kind="len" },
        [3] = { name="message", kind="len" },
        [4] = { name="coin_name", kind="len" },
        [5] = { name="chunkify", kind="varint" },
    },
    ["WebAuthnAddResidentCredential"] = {
        [1] = { name="credential_id", kind="len" },
    },
    ["WebAuthnCredentials"] = {
        [1] = { name="credentials", kind="len", repeated=true, msg="WebAuthnCredentials.WebAuthnCredential" },
        [2] = { name="is_done", kind="varint" },
    },
    ["WebAuthnCredentials.WebAuthnCredential"] = {
        [1] = { name="index", kind="varint" },
        [2] = { name="id", kind="len" },
        [3] = { name="rp_id", kind="len" },
        [4] = { name="rp_name", kind="len" },
        [5] = { name="user_id", kind="len" },
        [6] = { name="user_name", kind="len" },
        [7] = { name="user_display_name", kind="len" },
        [8] = { name="creation_time", kind="varint" },
        [9] = { name="hmac_secret", kind="varint" },
        [10] = { name="use_sign_count", kind="varint" },
        [11] = { name="algorithm", kind="varint" },
        [12] = { name="curve", kind="varint" },
    },
    ["WebAuthnCredentialsAck"] = {},
    ["WebAuthnListResidentCredentials"] = {
        [1] = { name="batch_size", kind="varint" },
    },
    ["WebAuthnRemoveResidentCredential"] = {
        [1] = { name="index", kind="varint" },
    },
    ["WipeDevice"] = {},
    ["WordAck"] = {
        [1] = { name="word", kind="len" },
    },
    ["WordRequest"] = {
        [1] = { name="type", kind="varint", enum="WordRequest.WordRequestType" },
    },
}
-- <<< END GENERATED MESSAGE FIELDS <<<

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

-- Noise AESGCM nonce (Noise spec, "The AESGCM cipher functions"): 32 bits of
-- zeros followed by the 64-bit big-endian message counter n, i.e. a 12-byte
-- GCM IV.
-- GcryptCipher needs Wireshark >= 4.6, which runs Lua 5.3+ with native 64-bit
-- integers, so %016x formats the full counter directly.
local function noise_nonce_hex(n)
    return string.format("00000000%016x", n)
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


local function add_decrypted_thp_message(dec, plaintext_buffer, plaintext_len, pinfo)
    -- THP decrypted application frame:
    --   1 byte session/id prefix
    --   2 bytes MessageType, big-endian
    --   N bytes protobuf payload
    if plaintext_len < 3 then
        dec:add(plaintext_buffer(0, plaintext_len), "Decrypted THP message: too short to parse"):set_generated()
        return
    end

    local session_id = plaintext_buffer(0, 1):uint()
    local msg_type = plaintext_buffer(1, 2):uint()
    local msg_name = v1_message_name(msg_type)
    local payload_len = plaintext_len - 3

    dec:add(f_encrypted_session_id, plaintext_buffer(0, 1))
    dec:add(f_encrypted_msg_type, plaintext_buffer(1, 2))
    dec:add(f_encrypted_msg_name, plaintext_buffer(1, 2), msg_name):set_generated()

    if payload_len > 0 then
        local pb_tree = dec:add(f_encrypted_protobuf_payload, plaintext_buffer(3, payload_len))
        -- Parse the protobuf payload into named fields using the generated
        -- pb_message_fields / pb_enums tables. Nested messages are shown as
        -- indented subtrees (depth-limited inside pb_format_message).
        local ok, lines = pcall(function()
            local raw = range_to_raw(plaintext_buffer, 3, payload_len)
            return pb_format_message(msg_name, raw)
        end)
        if ok and lines then
            local stack = { [0] = pb_tree }
            for _, ln in ipairs(lines) do
                local parent = stack[ln.depth] or pb_tree
                local node = parent:add(plaintext_buffer(3, payload_len), ln.text)
                node:set_generated()
                stack[ln.depth + 1] = node
            end
        end
    else
        dec:add(plaintext_buffer(0, 0), "Decrypted Protobuf Payload: empty"):set_generated()
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
        -- Wrap the decrypted bytes (a ByteArray) in a new Tvb ("testy virtual
        -- buffer", Wireshark's packet-data buffer, the same type as `buffer`).
        -- It shows up as a separate "THP decrypted plaintext" tab in the
        -- packet bytes pane, so the fields added below highlight the plaintext
        -- bytes they were parsed from rather than the ciphertext.
        local plaintext_buffer = res.plaintext:tvb("THP decrypted plaintext")
        dec:add(f_encrypted_plaintext, plaintext_buffer(0, plaintext_buffer:len()))
        dec:add(buffer(0, 0), "Decrypted Plaintext Hex: " .. plaintext_hex)
        add_decrypted_thp_message(dec, plaintext_buffer, plaintext_len, pinfo)
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
                    add_encrypted_transport_from_hex(subtree, buffer, cid, info.data_hex_without_crc or "", pinfo)
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
                    dissect_encrypted_transport_in_current_packet(subtree, buffer, cid, data_offset, data_crc_len, packet_len, pinfo)
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
    if reset_thp_decryption_state ~= nil then
        reset_thp_decryption_state()
    end
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