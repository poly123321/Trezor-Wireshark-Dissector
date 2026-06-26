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

---

## 1. Install the dissector

```bash
bash build.sh
cp dist/trezor_dissector.lua "$HOME/.config/wireshark/plugins/trezor_dissector.lua"
```

Restart Wireshark. A **THP keylog file** option appears under
**Preferences -> Protocols -> TREZOR_DISSECTOR**.

## 2. Generate a matching PCAP + keylog

The keylog is written by an instrumented `trezorlib` when the `THP_KEYLOG`
environment variable is set. Run a capture and the command in parallel:
`get-features` is a simple choice that produces a short, complete session.

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

## 3. Verify with tshark

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

## 4. Open in the Wireshark GUI

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

- **Inner protobuf fields are not parsed** - you get the message name and the
  raw protobuf payload, but not the individual fields within it.
- **Keylog entries are matched by `cid`.** Sufficient for a normal capture; a
  more robust scheme could match on handshake order or `handshake_hash` if the
  same `cid` were reused within one long capture.
- **No keylog, no decryption** - by design.
