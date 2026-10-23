# THP Keylog Decryption

The Trezor Wireshark dissector can optionally decrypt THP `ENCRYPTED_TRANSPORT`
payloads when supplied with a matching **keylog** file, analogous to how
Wireshark uses `SSLKEYLOGFILE` to decrypt TLS.

Without a keylog, encrypted transport stays encrypted. This feature only reads
keys from a session you control; it is a development/debugging aid, not an
attack on THP.

---

## Security warning

A THP keylog contains the **real Noise session keys** for a channel. It does not
contain the seed, PIN, or recovery words, but with the keylog anyone can read
that session's traffic (message types, addresses, public metadata, confirmation
workflow).

---

## What you get

With a matching keylog configured, each `ENCRYPTED_TRANSPORT` frame gains a
**THP Decryption** subtree exposing the decryption status, logical direction,
Noise nonce, decrypted plaintext, session ID, message type/name, and protobuf
payload.

Instead of an opaque ciphertext blob you see the actual application messages:
`SignTx`, `TxRequest`, `TxAck`, `ButtonRequest`, `ButtonAck`, `GetFeatures`,
`Features`, `ThpPairingRequest`, and so on.

The protobuf payload is further decoded into named fields, with enum values
translated and nested messages expanded as a subtree. For example a decrypted
`TxRequest` shows `request_type: TXINPUT (0)` and its nested `details`
sub-fields, rather than raw bytes. Field and enum names are generated from the
`.proto` definitions (see below), so all message types are covered; unknown or
unrecognised fields fall back to a generic `field N: <value>` dump.

---

## 1. Install the dissector

```bash
bash build.sh
cp dist/trezor_dissector.lua "$HOME/.config/wireshark/plugins/trezor_dissector.lua"
```

Restart Wireshark. A **THP keylog file** option appears under
**Preferences -> Protocols -> TREZOR_DISSECTOR**.

## 2. Instrument trezorlib to write the keylog

Stock `trezorlib` does not export session keys. The patch in
[`tools/trezorlib-thp-keylog.patch`](../tools/trezorlib-thp-keylog.patch) adds
a hook to `trezorlib/thp/channel.py`: after each successful THP handshake, if
the `THP_KEYLOG` environment variable is set, it appends one line with that
channel's keys to the file it names. Without `THP_KEYLOG` nothing changes.

Apply it to a `trezor-firmware` checkout and use `trezorlib` from that checkout
(an editable install, so `trezorctl` picks up the change):

```bash
cd trezor-firmware
git apply /path/to/Trezor-Wireshark-Dissector/tools/trezorlib-thp-keylog.patch
pip install -e python/   # skip if trezorlib is already installed from python/
```

The patch was made against `trezor-firmware` commit `a3bc309b63`. If it no
longer applies, the change is small enough to port by hand: write the line
right after `Handshake completed for channel ...` is logged in
`Channel` (see the keylog format under "How it works").

To undo it: `git apply -R` with the same patch.

## 3. Generate a matching PCAP + keylog

With the patched `trezorlib`, set `THP_KEYLOG` and run a capture and the
command in parallel: `get-features` is a simple choice that produces a short,
complete session.

List capture interfaces with `tshark -D` and pick the right one for your setup.
USB interface names differ by platform — for example a USB bus on Linux
(`usbmonN`, requires `usbmon`) versus the macOS USB capture interface (`XHCN`).

**Real device (USB):**

```bash
# terminal 1 — capture on the USB interface (see `tshark -D`)
tshark -i <usb-iface> -w session.pcapng

# terminal 2 — run a command, writing the keylog
THP_KEYLOG=session.keylog TREZOR_PATH="webusb:..." \
  trezorctl get-features
```

**Emulator (UDP loopback, port 21324) — reproducible without hardware:**

```bash
# terminal 1 — capture loopback, filtered to the emulator port
tshark -i lo -w session.pcapng -f "udp port 21324"   # macOS: -i lo0

# terminal 2 — run a command against the emulator
env -u TREZOR_PATH THP_KEYLOG=session.keylog \
  trezorctl -p udp:127.0.0.1:21324 get-features
```

This yields a matching `session.pcapng` + `session.keylog` pair.

## 4. Verify with tshark

```bash
tshark \
  -o trezor_dissector.thp_keylog_path:session.keylog \
  -r session.pcapng \
  -Y 'trezor_dissector.thp.encrypted.msg_name' \
  -T fields -E separator='|' \
  -e frame.number \
  -e trezor_dissector.thp.cid \
  -e trezor_dissector.thp.encrypted.decrypt_direction \
  -e trezor_dissector.thp.encrypted.msg_name
```

Decoded message names appear. Running the same command **without** the `-o`
keylog option yields none - confirming decryption is keylog-gated.

## 5. Open in the Wireshark GUI

Open the PCAP, set **Preferences -> Protocols -> TREZOR_DISSECTOR -> THP keylog
file** to the keylog, and re-read the capture. Filter with
`trezor_dissector.thp.encrypted.msg_name` and expand a frame under
**Trezor Host Protocol -> Encrypted Transport Message -> THP Decryption**.

---

## How it works

THP encrypts application messages with the Noise protocol (AES-GCM). After the
handshake, each channel (identified by its `cid`) holds two cipher states:

- `encrypt_key` - the Host -> Trezor direction
- `decrypt_key` - the Trezor -> Host direction

The instrumented `trezorlib` writes these keys, the handshake hash, and the
starting nonces to the keylog as each channel is established - one entry per
channel:

```
THP_KEYLOG cid=0x.... encrypt_key=... encrypt_nonce=0 decrypt_key=... decrypt_nonce=1 handshake_hash=...
```

To decrypt an `ENCRYPTED_TRANSPORT` frame the dissector:

1. **Looks up the channel** by `cid` to retrieve its two cipher states.
2. **Reassembles the full ciphertext first.** A message split across
   `CONTINUATION` frames cannot be decrypted until complete, since AES-GCM
   authenticates the whole message. The decrypted result therefore appears on
   the frame where reassembly completes, not on the first fragment.
3. **Determines direction by trying both cipher states.** Frame direction can be
   misleading (notably on USB), so instead of trusting it the dissector attempts
   the decrypt with the Host->Trezor key and that direction's current nonce; if
   the GCM authentication tag fails, it tries the Trezor->Host key and nonce.
   Whichever passes the tag is the correct direction, and that direction's nonce
   is advanced. The GCM tag is what makes this reliable - a wrong key or nonce
   fails authentication, so a successful decrypt is strong evidence the choice
   is correct.
4. **Parses the decrypted THP frame header** to extract `session_id`,
   `msg_type`, and the protobuf payload, mapping `msg_type` to a name via
   `messages.proto` and `messages-thp.proto`.

---

## Limitations

- **Field names come from generated tables.** They are produced from the
  `.proto` files (see "Regenerating field maps"); if the firmware's protocol
  changes, regenerate so new or renamed fields show correctly. Unknown fields
  still render generically.
- **Nested messages are expanded depth-first up to a fixed depth.** Extremely
  deep structures are truncated with a `(max depth reached)` marker.
- **Keylog entries are matched by `cid`.** Sufficient for a normal capture; a
  more robust scheme could match on handshake order or `handshake_hash` if the
  same `cid` were reused within one long capture.
- **No keylog, no decryption** - by design.

## Regenerating field maps

The named-field tables in `src/02_constants.lua` are generated from the Trezor
`.proto` definitions and should not be edited by hand. To regenerate after a
protocol change:

```bash
# from the trezor-firmware checkout, build a descriptor set
protoc --descriptor_set_out=/tmp/messages.desc --include_imports \
       -I common/protob common/protob/*.proto

# then regenerate the Lua tables in place
python tools/gen_message_fields.py /tmp/messages.desc --inplace
```

Message-type names are regenerated separately via `tools/gen_message_names.py`.
After regenerating, rebuild the dissector with `bash build.sh`.
