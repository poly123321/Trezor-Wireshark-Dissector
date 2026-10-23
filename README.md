# Trezor Wireshark Dissector

A Wireshark/`tshark` dissector for Trezor's protocols:

- **THP** (Trezor Host Protocol) — the encrypted, channel-based protocol used by **Trezor Safe 7**.
- **Codec v1** — the legacy framing used by older devices (**Trezor Safe 5**, Trezor One, Model T, etc.).

The dissector auto-detects which protocol a packet uses and decodes message types, lengths, direction (host ↔ device), and reassembles multi-packet messages. THP channels are exposed for filtering; Codec v1 messages are decoded by type and direction.

## Repository layout

```
trezor-wireshark/
├── dist/
│   └── trezor_dissector.lua     # ← the plugin to install (generated, single file)
├── src/                         # development modules (edit these)
│   ├── _header.lua
│   ├── 01_proto_fields.lua
│   ├── 02_constants.lua
│   ├── 03_util.lua
│   ├── 04_thp.lua
│   ├── 05_codec_v1.lua
│   ├── 06_dispatch.lua
│   └── 07_register.lua
├── build.sh                     # concatenates src/ → dist/trezor_dissector.lua
├── docs/
│   └── THP_DECRYPTION.md        # decrypting THP traffic with a keylog
├── tools/
│   ├── gen_message_names.py     # regenerate the message-name map from messages.proto
│   ├── gen_message_fields.py    # regenerate protobuf field/enum maps from a .proto descriptor set
│   └── trezorlib-thp-keylog.patch  # trezorlib hook that writes a THP keylog (see docs/)
└── config/
    └── colorfilters             # coloring rules for the Wireshark profile
```

The plugin is **developed as modules in `src/`** but **shipped as one file** (`dist/trezor_dissector.lua`). Wireshark loads each `.lua` in its plugin folder as an isolated plugin, so a single self-contained file is the most reliable thing to install. Run `./build.sh` after editing any module to regenerate `dist/`.

---

## Installation

### 1. Install the plugin

Copy `dist/trezor_dissector.lua` into your Wireshark **personal plugins** folder:

| OS | Path |
|----|------|
| macOS / Linux | `~/.config/wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |

You can confirm the exact path in Wireshark under **Help → About Wireshark → Folders → Personal Lua Plugins**.

Then restart Wireshark, or press **Analyze → Reload Lua Plugins**.

Verify it loaded under **Help → About Wireshark → Plugins** — you should see `trezor_dissector.lua` listed.

### 2. (Optional) Install the coloring rules

Copy `config/colorfilters` into the same Wireshark config folder (one level up from `plugins/`), or import it via **View → Coloring Rules → Import**. This colors host→device vs device→host, handshakes, errors, and Codec v1 traffic.

---

## Getting traffic into Wireshark

The plugin only decodes frames — you still need to get Trezor traffic in front of it. There are two practical ways, depending on whether you're working with the **emulator** or a **physical device**.

### Option A — Trezor emulator over loopback (live capture)

The Trezor emulator (from `trezor-firmware`) speaks THP/Codec v1 over **UDP on localhost, port 21324** (this is the built-in default in `trezorlib` and `trezord-go`, the same for everyone running a stock emulator). This is the easiest way to watch traffic live, because it needs no special capture setup — it's just UDP on the loopback interface.

1. Start the emulator (e.g. `./emu.py` in `trezor-firmware/core`).
2. In Wireshark, start a capture on the **loopback** interface:
   - macOS / Linux: the interface is usually called `lo` or `lo0`.
3. Apply a capture or display filter to cut the noise: `udp.port == 21324` or generally `trezor_dissector`.
4. Drive the emulator with `trezorctl` or your own script. The frames appear live, and the **Protocol** column shows `THP` or `Codec v1`.

The dissector is registered on UDP port 21324 automatically, so no manual setup is required for the stock emulator.

#### Running emulators on other ports (or several at once)

The UDP port is **configurable**, which matters when you run multiple emulators concurrently (e.g. parallel device tests), each on its own port. Set the port(s) under **Wireshark → Preferences → Protocols → Trezor Wire Dissector → "Emulator UDP port(s)"**. The field accepts:

- a single port — `21324`
- a range — `21324-21400`
- a comma-separated list — `21324,21326,21328`

The dissector decodes traffic on every port in that set, and it re-registers immediately when you change the value.

### Option B — Physical device (build your own pcap)

A real device talks over **USB** (WebUSB / HID), not loopback, so you capture it differently. There is no sample capture in this repo — **you create your own** from your device. Two common approaches:

**B1. Native USB capture in Wireshark.** On Linux use `usbmon`; on macOS enable the USB capture interface (e.g. `sudo ifconfig XHC20 up`, then pick the `XHC*` interface in Wireshark). You'll capture the USB frames with their USB wrapper — the dissector's USB heuristics attempt to pick the Trezor frames out of the bulk/interrupt transfers.

**B2. Tap `trezorlib` and write a `DLT_USER0` pcap.** A small Python script can wrap `trezorlib`'s WebUSB chunk I/O (`WebUsbTransport.write_chunk` / `read_chunk`), capturing each 64-byte frame with no USB wrapper, and write them into a pcap with link-layer type **DLT_USER0 (147)**. This gives the cleanest input — raw Trezor frames from byte 0. (This repo does not ship such a script; it's a few dozen lines if you want to build one.)

#### Mapping DLT_USER0 so Wireshark decodes it

A `DLT_USER0` pcap (from B2) carries raw frames Wireshark can't attribute on its own. The first time you open one you'll see:

> `User encapsulation not handled: DLT=147, check your Preferences→Protocols→DLT_USER`

Map it once:

1. **Wireshark → Preferences** → **Protocols → DLT_USER → Edit…**
2. Add an entry:
   - **DLT** = `User 0 (DLT=147)`
   - **Payload protocol** = `trezor_dissector`
3. **OK** → **OK**.

The capture now decodes as Codec v1 / THP. This setting is saved in your profile, so you only do it once.

---

## Filtering

THP exposes the channel id and message metadata; Codec v1 exposes message type/name and direction. Codec v1 has **no channel concept** (it is a strictly sequential request→response protocol), so there is no CID to filter on — you filter by message type and direction instead, and read request/response pairs from their order.

| What | Filter |
|------|--------|
| Only THP | `trezor_dissector.thp` |
| Only Codec v1 | `trezor_dissector.codec_v1` |
| THP on one channel | `trezor_dissector.thp.cid == 0xd557` |
| THP errors | `trezor_dissector.thp.control == 0x42` |
| THP by direction | `trezor_dissector.thp.src_role == "Host"` |
| Codec v1 message by name | `trezor_dissector.codec_v1.msg_name == "Features"` |
| Codec v1 by type number | `trezor_dissector.codec_v1.msg_type == 17` |

---

## Developing

Edit modules in `src/`, then rebuild:

```bash
./build.sh
```

This regenerates `dist/trezor_dissector.lua` and runs a syntax check if a Lua compiler is present. **Do not edit `dist/` directly** — it is overwritten on every build.

Module responsibilities:

| Module | Contents |
|--------|----------|
| `01_proto_fields.lua` | `Proto` object and all `ProtoField` definitions |
| `02_constants.lua` | control-byte constants, Codec v1 magic, message-name map (generated) |
| `03_util.lua` | CRC32, hex helpers, direction resolution, protocol heuristics |
| `04_thp.lua` | THP dissection (handshake, encrypted transport, errors, ping, channel allocation) |
| `05_codec_v1.lua` | Codec v1 dissection and multi-packet reassembly |
| `06_dispatch.lua` | the main `thp.dissector` that routes each packet to THP or Codec v1 |
| `07_register.lua` | transport registrations (UDP 21324, USB, BLE, DLT_USER0) |

### Message-name map

The message-name map in `src/02_constants.lua` is **generated** from Trezor's `messages.proto`, not hand-maintained. The `MessageType` numbers are the shared protobuf enum used by both Codec v1 and THP, including the DebugLink messages (100+) that show up in emulator test traffic. To refresh it:

```bash
python tools/gen_message_names.py /path/to/trezor-firmware/common/protob/messages.proto --inplace
./build.sh
```

This rewrites only the block between the `BEGIN/END GENERATED` markers in `src/02_constants.lua`; the hand-written constants in that file are left untouched.

**When to regenerate:** whenever Trezor adds or changes message types in `messages.proto` (e.g. after pulling a newer `trezor-firmware`), re-run the command above and rebuild. The map is a snapshot taken at generation time — the dissector does not read `messages.proto` or the device at runtime, so new message types won't appear until someone regenerates. Missing types still decode safely as `MessageType_<n>`, so regenerating is only needed when you want the proper names.
