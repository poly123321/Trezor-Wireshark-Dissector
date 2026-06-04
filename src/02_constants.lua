-- 02_constants.lua — control-byte constants, Codec v1 magic, message-name maps.
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh
--
-- Codec v1 magic / report id.
local V1_REPORT_ID = 0x3F   -- '?'  HID report id, precedes the frame on USB HID
local V1_MAGIC_BYTE = 0x23  -- '#'  two of these form the v1 frame magic "##"

-- Codec v1 message type -> name (from trezor-common messages.proto).
-- Only stable, verified wire numbers are listed; unknown types fall back to
-- "MessageType_<n>". Ethereum/altcoin numbers are intentionally omitted because
-- they shifted between firmware generations and would be ambiguous.
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
    [16] = "SimpleSignTx",
    [17] = "Features",
    [18] = "PinMatrixRequest",
    [19] = "PinMatrixAck",
    [20] = "Cancel",
    [21] = "TxRequest",
    [22] = "TxAck",
    [23] = "CipherKeyValue",
    [24] = "ClearSession",
    [25] = "ApplySettings",
    [26] = "ButtonRequest",
    [27] = "ButtonAck",
    [28] = "ApplyFlags",
    [29] = "GetAddress",
    [30] = "Address",
    [32] = "SelfTest",
    [34] = "BackupDevice",
    [35] = "EntropyRequest",
    [36] = "EntropyAck",
    [38] = "SignMessage",
    [39] = "VerifyMessage",
    [40] = "MessageSignature",
    [41] = "GetFeatures",
    [43] = "GetOwnershipId",
    [44] = "OwnershipId",
    [45] = "RecoveryDevice",
    [46] = "WordRequest",
    [47] = "WordAck",
    [49] = "GetOwnershipProof",
    [50] = "OwnershipProof",
    [51] = "AuthorizeCoinJoin",
    [55] = "GetFeatures",
    [63] = "SetU2FCounter",
    [79] = "SdProtect",
    [82] = "ChangeWipeCode",
    [83] = "EndSession",
    [84] = "DoPreauthorized",
    [85] = "PreauthorizedRequest",
    [86] = "CancelAuthorization",
    [87] = "RebootToBootloader",
    [88] = "GetFirmwareHash",
    [89] = "FirmwareHash",
}

local function v1_message_name(msg_type)
    return v1_message_names[msg_type] or string.format("MessageType_%d", msg_type)
end

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