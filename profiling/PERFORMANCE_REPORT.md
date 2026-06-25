# Bitcoin Signing Flow — Performance Report

---

## 1. Summary

The Bitcoin signing flow was profiled with the Trezor Wireshark dissector and a
small post-processing script (`profile_signing.py`), across **two transactions**,
**two protocols**, and **two capture environments**:

- **Transactions:** `test_lots_of_outputs` (1 input → 255 outputs, confirmation-heavy)
  and `test_lots_of_inputs` (100 inputs → 1 output, data-heavy).
- **Protocols:** Codec v1 (Safe 5 / T3T1) and THP (Safe 7 / T3W1).
- **Environments:** the emulator (UDP loopback) and HW over USB.

Key results:

- **Codec v1** decodes every application message, giving a full per-message-type
  breakdown. **THP** encrypts messages inside `ENCRYPTED_TRANSPORT`, so only
  transport-level metrics are visible.
- **The two transactions have opposite cost profiles**, confirmed on emulator and
  on hardware: `test_lots_of_outputs` is dominated by the **per-output
  confirmation loop**; `test_lots_of_inputs` is dominated by **streaming the
  transaction data** (the `TxRequest`/`TxAck` loop) and per-input device
  processing. Confirmations in the inputs case are marginal (4 prompts vs 255).
- **The emulator significantly underestimates real-device cost.** Per-input device
  processing is 1.30 ms on emu vs **7.34 ms** on TS5; THP ACK round-trip is
  2.75 ms on emu vs **~20 ms** on TS7. Loopback hides per-transaction USB
  and device latency, so emulator timing is unreliable for round-trip-bound work.

---

## 2. Method

### Emulator (UDP loopback)

```
# capture
tshark -i lo0 -w btc_<tx>_tsX.pcapng -f "udp port 21324"

# test (model = T3T1 for Safe 5, T3W1 for Safe 7)
TREZOR_MODEL=<model> TESTOPTS="-k test_lots_of_<tx> -s --ignore-gc-leak" \
  uv run make -C core test_emu
```

### HW device (USB)

Debug firmware was built (`--debug-link true --unsafe-fw --pyopt false
--disable-animation`, i.e. `PYOPT=0`, which also disables animations) and flashed
to physical Safe 5 and Safe 7. The device test then runs over USB with DebugLink
auto-confirm:

```
# capture (USB interface)
tshark -i XHC0 -w hw_<tx>_tsX.pcapng

# test
TREZOR_PATH="webusb:..." uv run pytest \
  tests/device_tests/bitcoin/test_signtx.py -k test_lots_of_<tx> -s
```

Captures are exported to CSV (`tshark -T fields`, dissector fields
`trezor_dissector.codec_v1.*` / `trezor_dissector.thp.*`) and analysed with
`profile_signing.py`, which auto-detects the protocol and reports a per-type
breakdown, request/response latencies, time attributed per type, and — for THP —
ACK round-trip latency.

**USB vs UDP caveats.** On USB there are no UDP ports; the THP dissector exposes
`thp.direction`, which the profiler reads. THP control names on USB carry a
`seqN ackM` suffix — collapsed to the base type for grouping, and ACKs are paired
by **seq bit** (`ENCRYPTED_TRANSPORT seqN → ACKN`, same channel) rather than by
direction. The Codec v1 dissector exposes no direction field, so the
"adjacent request/response latency" table is omitted for USB Codec v1 captures
(order-based signing-loop timing is unaffected).

**DebugLink overhead.** Auto-confirm runs over DebugLink, which adds significant
traffic. On Codec v1 it is *visible* (`DebugLinkState` / `DebugLinkGetState` /
`DebugLinkDecision`); on THP it is *hidden* inside `ENCRYPTED_TRANSPORT`. It is
left in the HW captures and commented on rather than filtered, so both models are
measured consistently. **Wall-clock spans on HW therefore include DebugLink cost;
the per-message signing-loop timings do not** (they are computed from specific
transitions DebugLink is not part of).

PCAP samples: `btc_outputs_ts{5,7}.pcapng` (emu), `hw_{inputs,outputs}_ts{5,7}.pcapng` (HW).

---

## 3. Codec v1 (Safe 5 / T3T1) — per-message-type

### 3.1 outputs — emulator (1 input → 255 outputs)

Decoded messages: **2 612**, capture span **8.925 s**.

| Message | Count | Total bytes | Avg len |
|---|---:|---:|---:|
| TxRequest | 773 | 17 148 | 22.2 |
| TxAck | 772 | 34 899 | 45.2 |
| ButtonRequest | 512 | 10 242 | 20.0 |
| ButtonAck | 512 | 0 | 0.0 |
| Features | 8 | 2 121 | 265.1 |
| (others) | — | — | — |

Signing-loop timing:

| Transition | n | mean | median | min | max |
|---|---:|---:|---:|---:|---:|
| TxRequest → TxAck (host fulfilment) | 772 | 0.20 ms | 0.14 ms | 0.07 ms | 1.23 ms |
| TxAck → TxRequest (device processing) | 517 | 2.02 ms | 1.92 ms | 0.81 ms | 6.26 ms |
| TxAck → ButtonRequest (confirm prompt) | 255 | 2.32 ms | 2.31 ms | 1.57 ms | 3.91 ms |
| ButtonAck → TxRequest (resume after confirm) | 255 | 11.92 ms | 12.15 ms | 9.62 ms | 37.34 ms |

Time attributed: **ButtonAck 6.195 s (69 %)**, TxAck 1.636 s (18 %), Features
0.771 s (9 %), TxRequest 0.157 s (2 %). The bottleneck is the **user-confirmation
loop** — each output triggers a `ButtonRequest`/`ButtonAck`, and the wait after a
confirmation before the next request (~12 ms) dominates. Protocol work is cheap
(~0.2 ms host, ~2 ms device); the interaction loop is the limit.

### 3.2 outputs — Safe 5 (USB)

Capture span **476.0 s**. Confirmation messages now visible directly:
TxRequest 773 / TxAck 772 / **ButtonRequest 512 / ButtonAck 512**. DebugLink
dominates wall-clock (`DebugLinkState` 324 s ≈ 68 %, `DebugLinkGetState` 121 s ≈ 25 %)
— an artifact of auto-confirm, not of signing.

Signing-loop timing (DebugLink-independent):

| Transition | n | mean | median |
|---|---:|---:|---:|
| TxRequest → TxAck (host fulfilment) | 772 | 2.03 ms | 1.97 ms |
| TxAck → TxRequest (device processing) | 517 | 9.57 ms | 9.01 ms |
| TxAck → ButtonRequest (confirm prompt) | **255** | **28.21 ms** | 27.04 ms |

The **255 confirm prompts at ~28 ms each** are the signing-side cost of the
output-heavy case — the confirmation loop, on hardware.

### 3.3 inputs — emulator (100 inputs → 1 output)

Capture span **42.794 s**. TxRequest 20 503 / TxAck 20 502 ; **ButtonRequest 4**.

| Transition | n | mean | median |
|---|---:|---:|---:|
| TxRequest → TxAck (host fulfilment) | 20 502 | 0.74 ms | 0.66 ms |
| TxAck → TxRequest (device processing) | 20 501 | **1.30 ms** | 1.59 ms |

Time attributed: TxAck 26.6 s (62 %), TxRequest 15.2 s (35 %) → signing loop
≈ 97 %. Confirmations marginal (4 prompts). The mirror image of the output case.

### 3.4 inputs — Safe 5 (USB)

Capture span **281.0 s** (≈ 5.9× the emulator). TxRequest 20 503 / TxAck 20 502.

| Transition | n | mean | median |
|---|---:|---:|---:|
| TxRequest → TxAck (host fulfilment) | 20 502 | 5.91 ms | 2.99 ms |
| TxAck → TxRequest (device processing) | 20 501 | **7.34 ms** | 8.99 ms |

> Device processing per input is **7.34 ms** on Safe 5 vs **1.30 ms** on emu —
> the emulator underestimates per-input cost ~5.6×. (A single ~59 s host-fulfilment
> outlier skews that mean; the **median 2.99 ms** is the reliable host figure.)
> Signing loop is ≈ 97 % of wall-clock; confirmations marginal (4 prompts).

---

## 4. THP (Safe 7 / T3W1) — transport-level

Application messages are encrypted; only transport metrics are visible. On HW,
DebugLink traffic is also inside `ENCRYPTED_TRANSPORT` and cannot be separated.

### 4.1 outputs — emulator

Decoded **5 017**, span **12.789 s**. ENCRYPTED_TRANSPORT 2 604, CONTINUATION 1 061,
ACK0/ACK1 663 each. **ACK round-trip: mean 1.65 ms, median 1.51 ms** (n=1 322).
Time: ACK0+ACK1 ≈ 10.4 s (**81 %**) — the alternating-bit ACK mechanism dominates.

### 4.2 outputs — Safe 7 (USB)

Span **314.0 s**. ENCRYPTED_TRANSPORT 2 596, CONTINUATION 1 055, ACK0/ACK1 658 each.
**ACK round-trip: mean 126.13 ms, median 33.25 ms** (n=2 594).
Time: ACK0+ACK1 ≈ 293 s (**93 %**), data transfer ≈ 14 s.

> The ACK **mean balloons to 126 ms** while the **median stays ~33 ms**: the 255
> confirmations inject long waits (max ~700 ms) that skew the mean — the
> confirmation loop showing up at the transport layer.

### 4.3 inputs — emulator

Span **53.393 s**. ENCRYPTED_TRANSPORT 41 048, CONTINUATION 21 230, ACK0/ACK1
10 274 each. **ACK round-trip: mean 2.75 ms, median 3.40 ms** (n=41 047).
Time: CONTINUATION 26.4 s (50 %), ENCRYPTED_TRANSPORT 10.2 s (19 %),
ACK0+ACK1 16.7 s (31 %) — data transfer dominates, as expected for inputs.

### 4.4 inputs — Safe 7 (USB)

Span **481.2 s** (≈ 8.6× the emulator). ENCRYPTED_TRANSPORT 41 040,
CONTINUATION 21 224, ACK0/ACK1 10 269 each.
**ACK round-trip: mean 20.09 ms, median 26.61 ms** (n=41 039).
Time: ACK0+ACK1 ≈ 270 s (**56 %**), CONTINUATION 112 s (23 %),
ENCRYPTED_TRANSPORT 92 s (19 %).

> ACK round-trip on HW is **~20 ms** vs **2.75 ms** on emu — ~7×. The
> loopback emulator makes ACKs almost free; on USB each ACK pays a real
> poll/processing cost, which at 41 000 ACKs accounts for the bulk of the run.

---

## 5. Comparison

### Emulator vs real hardware (same tests)

| Run | Proto | Span (emu) | Span (HW) | HW factor | Key metric (emu → HW) |
|---|---|---:|---:|---:|---|
| inputs | Codec v1 | 42.8 s | 281 s | 6.6× | device proc 1.30 → **7.34 ms** |
| outputs | Codec v1 | 8.9 s | 476 s | — * | confirm 2.3 → **28 ms** ×255 |
| inputs | THP | 53.4 s | 481 s | 9.0× | ACK 2.75 → **20 ms** |
| outputs | THP | 12.8 s | 314 s | — * | ACK 1.65 → **126 ms** mean |

\* outputs HW spans are inflated by DebugLink auto-confirm overhead and are not
directly comparable to the emulator span; the per-message timings are.

### inputs vs outputs (the cost-profile contrast)

| | inputs | outputs |
|---|---|---|
| Transaction | 100 in → 1 out | 1 in → 255 out |
| Confirm prompts | 4 | 255 |
| Codec v1 dominant cost | TxRequest/TxAck loop (~97 %) | confirmation loop |
| THP dominant cost | data transfer + ACK | ACK (confirm-driven) |
| Bound by | streaming + per-input device work | user confirmation |

### Findings

1. **Emulator underestimates real cost** (~5–7× on the key per-message metrics).
   Loopback hides USB/device round-trip latency; emu profiling misleads for
   ACK- or round-trip-bound operations.
2. **inputs = streaming/processing-bound, outputs = confirmation-bound** — on both
   protocols, on real hardware. Confirms the hypothesis behind testing
   `test_lots_of_inputs`.
3. **Codec v1 vs THP, same transaction (inputs):** Safe 5 / Codec v1 finishes in
   281 s vs Safe 7 / THP 481 s — THP's per-frame ACK reliability layer adds real
   wall-clock cost the simpler Codec v1 framing does not.
4. **DebugLink dominates HW wall-clock and must be read around** — visible
   (~68 %) on Codec v1, hidden in ENCRYPTED_TRANSPORT on THP.

---

## 6. Tool feedback (bugs, issues, observations)

1. **Codec v1 continuation `0x23` bug — found and fixed.** Continuation packets
   whose payload began with byte `0x23` were misdetected and leaked into the THP
   parser (bogus `THP CODEC_V1, cid=0x23E2, …`). Fixed by detecting continuations
   from reassembly **state** rather than data bytes. Verified live on Safe 5.

2. **USB capture works with the dissector** (Safe 5 Codec v1 and Safe 7 THP both
   decode on the `XHC0` interface), and a passive `tshark` USB monitor coexists
   with trezorlib's interface claim. Two USB-specific profiler adjustments were
   needed: read direction from `thp.direction` (no UDP ports), and pair THP ACKs by
   seq bit rather than by direction (USB frame ordering differs from UDP).

3. **DebugLink auto-confirm overhead is large on real hardware** — ~68 % of
   wall-clock on Codec v1 (visible), hidden inside ENCRYPTED_TRANSPORT on THP.
   Anyone profiling over DebugLink should read signing-loop timings, not totals.

**Overall:** the dissector handled both protocols, on emulator and real hardware,
without issues after the `0x23` fix. The encryption limitation on THP is a property
of the protocol, not the tool.

---

## 7. Deliverables

- **This report** — per-message-type timing (Codec v1) and transport metrics + ACK
  latency (THP), for `test_lots_of_outputs` and `test_lots_of_inputs`, on emulator
  and hw devices.
- **PCAP samples** — `btc_outputs_ts{5,7}.pcapng` (emulator),
  `hw_{inputs,outputs}_ts{5,7}.pcapng` (real Safe 5 / Safe 7 over USB).
- **`profile_signing.py`** — post-processing script (auto-detects Codec v1 / THP;
  reads `thp.direction` and pairs ACKs by seq bit for USB captures).
