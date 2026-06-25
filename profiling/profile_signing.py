#!/usr/bin/env python3
"""
Trezor Bitcoin signing-flow profiler (Codec v1 + THP).

Reads a tshark field-export CSV (separator '|') produced from a capture
dissected by the Trezor Wireshark dissector, and computes per-message-type
timing, round-trip latency, and (for THP) ACK latency.

Usage: python3 profile_signing.py <export.csv> [--label NAME]

Expected columns (header row required), in this order:
frame.number | frame.time_epoch | <name> | <type_or_cid> | <length> | udp.srcport | udp.dstport

For Codec v1 export <name>=codec_v1.msg_name, <type_or_cid>=codec_v1.msg_type (decimal).
For THP export      <name>=thp.control_name, <type_or_cid>=thp.cid (e.g. 0x81f7, 0xFFFF).
"""
import sys, csv, statistics, re
from collections import defaultdict

DEVICE_PORT = "21324"

def load(path):
    rows = []
    with open(path, newline="") as f:
        r = csv.reader(f, delimiter="|")
        header = next(r)
        for line in r:
            if not line or len(line) < 7:
                continue
            frame, tepoch, name, type_or_cid, length, src, dst = line[:7]
            try:
                t = float(tepoch)
            except ValueError:
                continue
            # length may be empty (continuation / non-message frames)
            try:
                ln = int(length) if length else None
            except ValueError:
                ln = None
            
            # USB captures put a direction string in the src column
            # ("Host->Trezor" / "Trezor->Host") instead of UDP ports.
            direction_str = None
            if src in ("Host->Trezor", "Trezor->Host"):
                direction_str = src
            rows.append({
                "frame": int(frame) if frame else None,
                "t": t,
                "name": name or None,
                "cid": type_or_cid or None,   # decimal type (v1) or hex cid (THP), kept as string
                "len": ln,
                "src": src, "dst": dst,
                "dir": direction_str,
            })
    return rows

def direction(row):
    # USB capture: explicit direction string takes precedence
    d = row.get("dir")
    if d == "Host->Trezor":
        return "host->device"
    if d == "Trezor->Host":
        return "device->host"
    # UDP/emulator capture: infer from ports
    if row["dst"] == DEVICE_PORT:
        return "host->device"
    if row["src"] == DEVICE_PORT:
        return "device->host"
    return "?"

def main():
    if len(sys.argv) < 2:
        print("usage: profile_signing.py <export.csv> [--label NAME]")
        sys.exit(1)
    path = sys.argv[1]
    label = "capture"
    if "--label" in sys.argv:
        label = sys.argv[sys.argv.index("--label")+1]

    rows = load(path)
    msgs = [r for r in rows if r["name"]]
    if not msgs:
        print("No decoded messages found — check field names in the export.")
        sys.exit(1)

    # THP control_name carries seq/ack suffix (e.g. "ENCRYPTED_TRANSPORT seq0 ack1").
    # Collapse to the base control type so grouping/latency aren't fragmented.
    def base_name(n):
        if not n:
            return n
        return n.split(" seq")[0].split(" ack")[0].strip()
    for m in msgs:
        m["full_name"] = m["name"]
        m["name"] = base_name(m["name"])

    # detect THP mode: control names are ALL_CAPS like ENCRYPTED_TRANSPORT / ACK0
    thp_mode = any(m["name"] and m["name"].isupper() and "_" in m["name"]
                   for m in msgs[:50]) or any(
                   m["name"] in ("ACK0", "ACK1") for m in msgs[:200])

    t0 = msgs[0]["t"]; t_end = msgs[-1]["t"]; span = t_end - t0
    print(f"=== Trezor signing profile: {label} ===")
    print(f"file: {path}")
    print(f"mode: {'THP (transport-level)' if thp_mode else 'Codec v1 (per-message-type)'}")
    print(f"decoded messages: {len(msgs)}   total packets in export: {len(rows)}")
    print(f"capture span: {span:.3f} s")
    print()

    # --- per-name breakdown ---
    by_name = defaultdict(list)
    for m in msgs:
        by_name[m["name"]].append(m)
    print("--- Per-type breakdown ---")
    print(f"{'name':<22}{'count':>6}{'tot_bytes':>11}{'avg_len':>9}")
    for name, items in sorted(by_name.items(), key=lambda kv: -len(kv[1])):
        lens = [i["len"] for i in items if i["len"] is not None]
        tot = sum(lens); avg = (tot/len(lens)) if lens else 0
        print(f"{name:<22}{len(items):>6}{tot:>11}{avg:>9.1f}")
    print()

    # --- adjacent direction-flip latency ---
    print("--- Adjacent request/response latency ---")
    pair_lat = defaultdict(list)
    for a, b in zip(msgs, msgs[1:]):
        da, db = direction(a), direction(b)
        if da != db and da != "?" and db != "?":
            pair_lat[f"{a['name']} -> {b['name']}"].append(b["t"] - a["t"])
    rows_lat = sorted(((len(v), k, statistics.mean(v), min(v), max(v))
                       for k, v in pair_lat.items()), reverse=True)
    print(f"{'transition':<40}{'n':>5}{'mean':>10}{'min':>10}{'max':>10}")
    for n, k, mean, lo, hi in rows_lat[:12]:
        print(f"{k:<40}{n:>5}{mean*1000:>9.2f}m{lo*1000:>9.2f}m{hi*1000:>9.2f}m")
    print()

    if thp_mode:
        # --- THP ACK latency: data frame (seq bit N) -> its ACK (ACK{N}) ---
        # THP uses an alternating-bit protocol: a data frame carrying "seqN" is
        # acknowledged by "ACKN" on the same channel. Pair by seq/ack number
        # (from full_name) rather than by direction, since on USB captures data
        # and ACK do not follow the clean opposite-direction pattern that UDP does.
        print("--- THP ACK round-trip latency ---")
        import re as _re

        def seq_of(m):
            # extract seq bit from full_name, e.g. "ENCRYPTED_TRANSPORT seq0 ack1" -> 0
            fn = m.get("full_name") or ""
            mt = _re.search(r"seq([01])", fn)
            return mt.group(1) if mt else None

        def ack_num(m):
            # "ACK0" -> "0", "ACK1" -> "1"
            if m["name"] == "ACK0":
                return "0"
            if m["name"] == "ACK1":
                return "1"
            return None

        acks = []
        for i, a in enumerate(msgs):
            if a["name"] != "ENCRYPTED_TRANSPORT":
                continue
            s = seq_of(a)
            if s is None:
                continue
            # search forward for the first ACK with matching number on the same cid
            for b in msgs[i + 1 : i + 12]:
                if ack_num(b) == s and b["cid"] == a["cid"]:
                    acks.append(b["t"] - a["t"])
                    break
        if acks:
            print(f"ENCRYPTED_TRANSPORT(seqN) -> ACKN: n={len(acks)} "
                  f"mean={statistics.mean(acks)*1000:.2f}ms "
                  f"median={statistics.median(acks)*1000:.2f}ms "
                  f"min={min(acks)*1000:.2f}ms max={max(acks)*1000:.2f}ms")
        else:
            print("(no ENCRYPTED_TRANSPORT(seqN)->ACKN pairs matched)")
        print()
    else:
        # --- Codec v1 signing-loop focus ---
        def focused(a_name, b_name, title):
            lat = [b["t"]-a["t"] for a, b in zip(msgs, msgs[1:])
                   if a["name"] == a_name and b["name"] == b_name]
            if lat:
                print(f"{title}: n={len(lat)} mean={statistics.mean(lat)*1000:.2f}ms "
                      f"median={statistics.median(lat)*1000:.2f}ms "
                      f"min={min(lat)*1000:.2f}ms max={max(lat)*1000:.2f}ms")
            else:
                print(f"{title}: (no pairs)")
        print("--- Bitcoin signing-loop timing ---")
        focused("TxRequest", "TxAck", "TxRequest->TxAck (host fulfilment)")
        focused("TxAck", "TxRequest", "TxAck->TxRequest (device processing)")
        focused("TxAck", "ButtonRequest", "TxAck->ButtonRequest (confirm prompt)")
        focused("ButtonAck", "TxRequest", "ButtonAck->TxRequest (resume after confirm)")
        print()

    # --- time attributed per type (gap to next msg) ---
    print("--- Time attributed per type (gap to next msg) ---")
    gap = defaultdict(list)
    for a, b in zip(msgs, msgs[1:]):
        gap[a["name"]].append(b["t"] - a["t"])
    print(f"{'name':<22}{'n':>5}{'tot_s':>10}{'mean_ms':>10}")
    grand = 0.0
    for name, gaps in sorted(gap.items(), key=lambda kv: -sum(kv[1])):
        tot = sum(gaps); grand += tot
        print(f"{name:<22}{len(gaps):>5}{tot:>10.3f}{(tot/len(gaps))*1000:>10.2f}")
    print(f"{'(accounted)':<22}{'':>5}{grand:>10.3f}")
    print()
    print("--- Notes ---")
    if thp_mode:
        print("THP transport: application message types are encrypted inside")
        print("ENCRYPTED_TRANSPORT frames and not visible at packet level.")
        print("Per-message-type timing requires the Codec v1 (TS5) capture.")
    print("Continuation/reassembly frames are not counted as separate messages.")

if __name__ == "__main__":
    main()
