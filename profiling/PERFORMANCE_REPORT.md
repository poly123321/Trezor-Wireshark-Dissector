# Bitcoin Signing Flow — Performance Report

---

## 1. Summary

The Bitcoin signing flow was captured on both Trezor hardware protocols using the Wireshark dissector and post-processed for per-message-type and transport-level timing. The same transaction (`test_lots_of_outputs`, 1 input -> 255 outputs) was signed on each model so the two captures are directly comparable.

Key results:

- **Codec v1:** the dissector decodes every application message, so a full per-message-type breakdown is available. The signing time is dominated by the **per-output confirmation loop** (`ButtonRequest`/`ButtonAck`), not by cryptography or transport.
- **THP:** application messages are encrypted inside `ENCRYPTED_TRANSPORT` frames and are not visible at packet level. Only transport-level metrics are extractable. THP time is dominated by the **ACK round-trip mechanism**, plus reassembly and handshake overhead.
- The same signing flow takes **~8.9 s on Codec v1 vs ~12.8 s on THP** and produces roughly **2× as many packets** on THP (5 017 vs 2 612 decoded messages), the difference being encryption framing, per-frame ACKs and reassembly.

---

## 2. Method

Each capture was produced by running the device test against the emulator on UDP port 21324 while recording loopback traffic:

```
# capture
tshark -i lo0 -w btc_outputs_tsX.pcapng -f "udp port 21324"

# test (model = T3T1 for Safe 5, T3W1 for Safe 7)
TREZOR_MODEL=<model> TESTOPTS="-k test_lots_of_outputs -s --ignore-gc-leak" \
  uv run make -C core test_emu
```

Captures were exported to CSV with `tshark -T fields` using the dissector's fields (`trezor_dissector.codec_v1.*` for Codec v1, `trezor_dissector.thp.*` for THP) and analysed with a small Python profiler (`profile_signing.py`, included). The profiler auto-detects the protocol, produces a per-type breakdown, adjacent request/response latencies, time attributed per message type, and — for THP — ACK round-trip latency.

PCAP samples: `btc_outputs_ts5.pcapng`, `btc_outputs_ts7.pcapng`.

---

## 3. Codec v1 (Safe 5 / T3T1) — per-message-type

Decoded messages: **2 612**, capture span **8.925 s**.

### Message-type distribution

| Message | Count | Total bytes | Avg len |
|---|---:|---:|---:|
| TxRequest | 773 | 17 148 | 22.2 |
| TxAck | 772 | 34 899 | 45.2 |
| ButtonRequest | 512 | 10 242 | 20.0 |
| ButtonAck | 512 | 0 | 0.0 |
| Features | 8 | 2 121 | 265.1 |
| Success | 6 | 105 | 17.5 |
| Failure | 6 | 78 | 13.0 |
| Cancel | 6 | 0 | 0.0 |
| Initialize | 5 | 2 | 0.4 |
| Ping | 4 | 88 | 22.0 |
| GetFeatures | 3 | 0 | 0.0 |
| SignTx | 1 | 24 | 24.0 |
| PublicKey | 1 | 353 | 353.0 |
| LoadDevice | 1 | 63 | 63.0 |
| GetPublicKey | 1 | 32 | 32.0 |
| EndSession | 1 | 0 | 0.0 |

### Signing-loop timing

| Transition | n | mean | median | min | max |
|---|---:|---:|---:|---:|---:|
| TxRequest → TxAck (host fulfilment) | 772 | 0.20 ms | 0.14 ms | 0.07 ms | 1.23 ms |
| TxAck → TxRequest (device processing) | 517 | 2.02 ms | 1.92 ms | 0.81 ms | 6.26 ms |
| TxAck → ButtonRequest (confirm prompt) | 255 | 2.32 ms | 2.31 ms | 1.57 ms | 3.91 ms |
| ButtonAck → TxRequest (resume after confirm) | 255 | 11.92 ms | 12.15 ms | 9.62 ms | 37.34 ms |

### Time attributed per message type (gap to next message)

| Message | n | Total (s) | Mean (ms) | Share |
|---|---:|---:|---:|---:|
| ButtonAck | 512 | 6.195 | 12.10 | 69 % |
| TxAck | 772 | 1.636 | 2.12 | 18 % |
| Features | 8 | 0.771 | 96.33 | 9 % |
| TxRequest | 772 | 0.157 | 0.20 | 2 % |
| (everything else) | — | ~0.17 | — | 2 % |

For a many-output transaction, the bottleneck is the **user-confirmation loop**: each output triggers a `ButtonRequest`/`ButtonAck` round, and the time spent waiting after a confirmation before the next request (`ButtonAck -> …`, ~12 ms) dominates. The actual protocol work is cheap — host fulfilment of a `TxRequest` is ~0.2 ms and device processing of a `TxAck` is ~2 ms. Cryptography and serialization are not the limiting factor here; the interaction loop is.

---

## 4. THP (Safe 7 / T3W1) — transport-level

Decoded messages: **5 017**, capture span **12.789 s**. Application message types are encrypted and not visible.

### Transport-type distribution

| Control type | Count | Total bytes | Avg len |
|---|---:|---:|---:|
| ENCRYPTED_TRANSPORT | 2 604 | 123 816 | 47.5 |
| CONTINUATION (reassembly) | 1 061 | — | — |
| ACK0 | 663 | — | — |
| ACK1 | 663 | — | — |
| PING / PONG | 4 / 4 | 48 / 48 | 12.0 |
| CHANNEL_ALLOCATION_REQ / RES | 3 / 3 | 36 / 102 | 12 / 34 |
| HANDSHAKE_INIT_REQ / RES | 3 / 3 | 111 / 300 | 37 / 100 |
| HANDSHAKE_COMP_REQ / RES | 3 / 3 | 204 / 63 | 68 / 21 |


### ACK round-trip latency

| Metric | Value |
|---|---:|
| ENCRYPTED_TRANSPORT → ACK | n = 1 322 |
| mean | 1.65 ms |
| median | 1.51 ms |
| min | 0.05 ms |
| max | 12.01 ms |

### Time attributed per transport type (gap to next message)

| Control type | n | Total (s) | Mean (ms) | Share |
|---|---:|---:|---:|---:|
| ACK1 | 662 | 5.577 | 8.42 | 44 % |
| ACK0 | 663 | 4.831 | 7.29 | 38 % |
| CONTINUATION | 1 061 | 1.324 | 1.25 | 10 % |
| ENCRYPTED_TRANSPORT | 2 604 | 0.986 | 0.38 | 8 % |
| (handshake / ping) | — | ~0.07 | — | <1 % |

On THP, **the ACK round-trip mechanism dominates** — ACK0 + ACK1 together account for ~10.4 s of the 12.8 s span (~81 %). Each data frame must be acknowledged (alternating-bit protocol), and that round-trip (~1.65 ms mean) plus the reassembly of larger messages (1 061 continuation frames) is where the time goes. The encrypted payloads themselves are small and fast to move (`ENCRYPTED_TRANSPORT` ~0.38 ms gap each).

---

## 5. Comparison: TS5 vs TS7 vs TS7-without-THP

| | TS5 (Codec v1) | TS7 (THP) | TS7 without THP |
|---|---|---|---|
| Per-message-type visible | Yes | No (encrypted) | (not built — see below) |
| Decoded messages | 2 612 | 5 017 | — |
| Capture span | 8.925 s | 12.789 s | — |
| Dominant cost | Button confirmation (~6.2 s) | ACK round-trip (~10.4 s) | — |
| ACK round-trip latency | n/a | 1.65 ms mean | — |
| Reassembly frames | minimal | 1 061 continuations | — |

**TS7 without THP (Codec v1) — not attempted (super-optional).** THP is controlled by the SCons build argument `THP=0/1` (default `0`), but the standard build tool `xtask` does not expose it as a flag (unlike e.g. `--disable-animation`), and THP is wired in as a Cargo feature in `embed/projects/{firmware,unix}/Cargo.toml`. Disabling it would require bypassing `xtask` and building through SCons directly; moreover T3W1 is designed around THP (pairing, BLE, secure session), so there is no guarantee a non-THP firmware would boot or that trezorlib would connect to it over Codec v1. This matches the "deep build issues" the task description anticipates for this optional item. The TS5-vs-TS7 comparison already isolates the protocol difference: the same transaction, decoded in full on Codec v1 and as transport-only on THP.

**Headline difference.** The same signing flow costs ~43 % more wall-clock time and ~2× the packets on THP. That overhead buys encryption and the channel/ACK reliability layer — at the cost of packet-level visibility into message types.

---

## 6. Tool feedback (bugs, issues, observations)

Findings encountered while using the dissector on this real-world test:

1. **Codec v1 continuation `0x23` bug — found and fixed.** Continuation packets whose payload began with byte `0x23` were misdetected and leaked into the THP parser (producing bogus `THP CODEC_V1, cid=0x23E2, …`). Fixed by detecting continuations from reassembly **state** rather than from the data bytes. Verified live on Safe 5.

2. **THP encryption prevents packet-level per-message-type profiling — by design, not a tool limitation.** On THP, `SignTx`/`TxRequest`/`TxAck`/`ButtonRequest` travel inside `ENCRYPTED_TRANSPORT` (Noise-encrypted), so the dissector can only label the transport layer. Per-message-type timing is therefore only available on Codec v1 (TS5). (Roman's suggestion: later, synchronise the v1 and THP message streams — the same transaction sends the same ordered messages — to map types onto THP frames by correlation. Recorded here as a follow-up; not yet implemented.)

3. **Safe 5 signing tests deadlock unless the emulator runs with `--disable-animation` (runtime).** Launching the emulator manually (`./emu.py --executable …`) without `--disable-animation` causes `test_lots_of_outputs` to fail with `timeout waiting for DebugLinkState (5s)` → `layout deadlock detected`, reproducibly, after ~2 `confirm_output` confirmations. The **build-time** `DISABLE_ANIMATION=1` (present in the frozen build, all 141 compile units) is **not sufficient** on its own — the **runtime** `--disable-animation` flag is required. Running via `make test_emu` (which passes `emu.py --disable-animation --headless --temporary-profile`) resolves it and the test passes. Related to upstream issues #1142 ("Trezor does not respond to DebugLinkGetState") and #1479. Not a dissector issue.

4. **`DebugLinkGcInfo` vs `DebugLinkState` mismatch in teardown.** When the deadlock above occurs, teardown also raises `Expected DebugLinkGcInfo but Trezor sent DebugLinkState`. Disappears once the animation issue is resolved.

5. **Dissector device_properties parsing matches trezorlib.** The dissector's `ThpDeviceProperties` decode (Internal Model `T3W1`, protocol `2.1`, pairing methods `CodeEntry / SkipPairing / NFC / QrCode`) is byte-for-byte identical to what trezorlib logs during channel allocation — independent confirmation the parser is correct.

**Overall:** the dissector handled both protocols on a real signing flow without issues after the `0x23` fix. It correctly decodes Codec v1 message types and reassembly, and the THP transport layer (handshake, ABP seq/ack, ACKs, reassembly, device properties). The encryption limitation on THP is a property of the protocol, not the tool.

---

## 7. Deliverables

- **This report** — per-message-type timing (TS5), transport metrics + ACK latency (TS7), comparison.
- **PCAP samples** — `btc_outputs_ts5.pcapng` (Codec v1), `btc_outputs_ts7.pcapng` (THP).
- **`profile_signing.py`** — the post-processing script (auto-detects Codec v1 / THP).
