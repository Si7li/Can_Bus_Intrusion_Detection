"""Live demo: replay a ROAD (or CAN-MIRGU) recording on the real CAN bus and watch the Nucleo detect it.

    python pc/live_demo.py --list                                   # recordings you can replay
    python pc/live_demo.py max_speedometer_attack_1_masquerade      # 5 s before the attack .. 3 s after
    python pc/live_demo.py reverse_light_on_attack_1_masquerade --full
    python pc/live_demo.py ambient_dyno_drive_basic_short --full    # clean drive: are there false alarms?
    python pc/live_demo.py --latency                                # transport delay alone (no detector delay)
    python pc/live_demo.py --all-test                               # every test recording (~35 min), table
    python pc/live_demo.py --dataset mirgu --all-test               # CAN-MIRGU test split (flash the MIRGU firmware first)

The PC plays the car: each frame is sent through the USB-CAN adapter at its
original time. The Nucleo runs the detector on every frame and reports
incidents as JSON lines on /dev/ttyACM0, which this script prints in plain words
(attack type from signals.py) and compares with the ground truth of the recording.
"""

import argparse
import json
import re
import sys
import threading
import time
from pathlib import Path

import numpy as np
import pandas as pd
import serial

sys.path.insert(0, str(Path(__file__).resolve().parent))
from robotell import SERIAL_BAUD, encode, road_frame  # noqa: E402
from signals import describe                          # noqa: E402
from signed_link import KEY_FILE, Verifier            # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ROAD = ROOT / "data" / "processed" / "road"
RESULTS = ROOT / "results"
BYTES = [f"b{i}" for i in range(8)]
NUCLEO_BAUD = 921_600
DATASET = {"name": "road", "data": ROAD, "results": RESULTS}    # changed by --dataset mirgu
ROAD_CLEAN_TEST = ["ambient_dyno_drive_basic_short", "ambient_dyno_drive_benign_anomaly",
                   "ambient_highway_street_driving_diagnostics"]


def use_dataset(name: str):
    import signals
    DATASET.update(name=name, data=ROOT / "data" / "processed" / name,
                   results=RESULTS if name == "road" else RESULTS / name)
    signals.use_dataset(name)


# ------------------------------------------------------------------ data
def all_captures() -> list[str]:
    return sorted(p.stem for p in DATASET["data"].glob("*/*.parquet"))


def is_test(name: str) -> bool:
    """Same split as ml/src: ROAD attack instance 1 and coolant are test; CAN-MIRGU see mirgu_split.py."""
    if DATASET["name"] == "mirgu":
        sys.path.insert(0, str(ROOT / "ml" / "src"))
        import mirgu_split
        return (mirgu_split.ambient_split(name) if name.startswith("benign_")
                else mirgu_split.attack_split(name)) == "test"
    return name.startswith("max_engine_coolant_temp") or re.search(r"_attack_1(_masquerade)?$", name) is not None


def clean_test_drives() -> list[str]:
    if DATASET["name"] == "mirgu":
        return [n for n in all_captures() if n.startswith("benign_") and is_test(n)]
    return ROAD_CLEAN_TEST


def load(name: str) -> pd.DataFrame:
    path = next(DATASET["data"].glob(f"*/{name}.parquet"), None)
    if path is None:
        sys.exit(f"unknown recording {name!r}; see --list")
    return pd.read_parquet(path, columns=["t", "id", "dlc", "label"] + BYTES)


def window(df: pd.DataFrame, full: bool, before: float = 5.0, after: float = 3.0) -> pd.DataFrame:
    forged = df.loc[df["label"] == 1, "t"]
    if full or forged.empty:
        return df
    return df[(df["t"] >= forged.iloc[0] - before) & (df["t"] <= forged.iloc[-1] + after)]


# ------------------------------------------------------------------ Nucleo output
class Monitor(threading.Thread):
    """Reads the Nucleo's JSON lines; prints them in plain words."""

    def __init__(self, port: str, verbose: bool):
        super().__init__(daemon=True)
        self.ser = serial.Serial(port, NUCLEO_BAUD, timeout=0.1)
        self.events: list[tuple[float, dict]] = []
        self.verbose, self.stop, self.t0 = verbose, False, time.perf_counter()
        self.last_status_print = 0.0
        self.verifier = Verifier()                   # every JSON line is signed with the device secret
        self.warned = set()

    def run(self):
        buf = b""
        skip_until = time.perf_counter() + 0.5       # drop output buffered before we started listening
        while not self.stop:
            data = self.ser.read(4096)
            if time.perf_counter() < skip_until:
                continue
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                now = time.perf_counter()
                text = line.decode(errors="replace").strip()
                try:
                    ev = json.loads(text)
                except ValueError:
                    if text and self.verbose:
                        print(f"  nucleo: {text}")
                    continue
                verdict = self.verifier.check(text)
                if verdict in ("forged", "replayed"):    # never acted on: shown and counted only
                    print(f"  UNTRUSTED LINE ({verdict}), ignored: {text[:100]}")
                    continue
                if verdict in ("unsigned", "no_key") and verdict not in self.warned:
                    self.warned.add(verdict)
                    print("  note: the Nucleo's lines are unsigned (device secret missing or erased)" if verdict == "unsigned"
                          else f"  note: no {KEY_FILE.name} on this PC: line signatures not checked")
                self.events.append((now, ev))
                self.show(now, ev)

    def show(self, now: float, ev: dict):
        t = now - self.t0
        kind = ev.get("type")
        if kind == "alert":
            print(f"[{t:7.2f} s] {ev['level']:7s} {describe(ev)}  (p={ev['p']}%)")
        elif kind == "incident_end" and self.verbose:
            ids = ", ".join(f"{e['id']}" for e in ev["ids"]) or "-"
            unk = f", {ev['unknown_id_frames']} frames with unknown IDs" if ev["unknown_id_frames"] else ""
            print(f"[{t:7.2f} s]         incident over: {ev['level']}, {ev['duration_ms'] / 1000:.1f} s, "
                  f"{ev['frames']} flagged frames, IDs {ids}{unk}")
        elif kind == "status" and self.verbose and now - self.last_status_print >= 5:
            self.last_status_print = now
            print(f"[{t:7.2f} s]         bus {ev['fps']} frames/s | detector CPU {ev['cpu_pct']}% | "
                  f"queue max {ev['queue_max']} | overflow {ev['overflow']} | CAN errors TEC {ev['tec']} REC {ev['rec']}")
        elif kind == "boot":            # always shown: a reset in the middle of a run matters
            print(f"[{t:7.2f} s] NUCLEO RESTARTED (reset cause: {ev['reset']}) | read protection {ev['rdp']}, "
                  f"brown-out reset {ev['bor']}, write-protected sectors {ev['wrp_sectors'] or 'none'}, "
                  f"device secret {ev.get('secret', '?')}")
        elif kind == "tamper":          # always shown
            print(f"[{t:7.2f} s] TAMPER: {ev['msg']}")
        elif kind == "info" and self.verbose:
            print(f"[{t:7.2f} s]         nucleo: {ev['msg']}")

    def close(self):
        self.stop = True
        self.join(1)
        self.ser.close()


# ------------------------------------------------------------------ replay
def replay(df: pd.DataFrame, port: str) -> dict:
    """Send every frame at its recorded time. Returns the actual send time of each frame."""
    # frames without a length (ROAD, frames built by live_attacks.py) are sent with 8 bytes
    dlc = df["dlc"].fillna(8).astype(int).to_numpy() if "dlc" in df.columns else np.full(len(df), 8)
    packets = [road_frame(int(i), bytes(row[:n])) for i, row, n in zip(df["id"], df[BYTES].to_numpy(np.uint8), dlc)]
    times = (df["t"] - df["t"].iloc[0]).to_numpy()
    sent = np.empty(len(times))
    with serial.Serial(port, SERIAL_BAUD, timeout=0) as s:
        stop = threading.Event()

        def drain():                    # discard whatever the adapter sends back
            while not stop.is_set():
                s.read(4096)
                time.sleep(0.01)

        threading.Thread(target=drain, daemon=True).start()
        t0 = time.perf_counter() + 0.2
        i, n = 0, len(times)
        while i < n:
            now = time.perf_counter() - t0
            j = int(np.searchsorted(times, now, side="right"))
            if j > i:
                s.write(b"".join(packets[i:j]))
                sent[i:j] = time.perf_counter()
                i = j
            else:
                wait = times[i] - now
                if wait > 0.002:
                    time.sleep(wait - 0.001)
        s.flush()
        stop.set()
    late = sent - (t0 + times)
    return {"sent": sent, "t0": t0, "late_ms_p50": float(np.median(late) * 1e3),
            "late_ms_p99": float(np.percentile(late, 99) * 1e3), "late_ms_max": float(late.max() * 1e3)}


# ------------------------------------------------------------------ ground truth
def summarize(name: str, df: pd.DataFrame, rp: dict, events: list) -> dict:
    lab = df["label"].to_numpy() == 1
    attack = lab.any()
    t1, t2 = (rp["sent"][lab][0], rp["sent"][lab][-1]) if attack else (None, None)

    incidents, cur = [], None
    for t, ev in events:
        if ev.get("type") == "alert":
            if cur is None:
                cur = {"start": t, "level": ev["level"], "first_alert": None, "what": describe(ev), "end": None}
                incidents.append(cur)
            cur["level"] = "ALERT" if ev["level"] == "ALERT" else cur["level"]
            if ev["level"] == "ALERT" and cur["first_alert"] is None:
                cur["first_alert"] = t
                cur["what"] = describe(ev)
        elif ev.get("type") == "incident_end" and cur is not None:
            cur["end"] = t - 1.0          # the Nucleo closes an incident 1 s after its last flagged frame
            cur = None
    for inc in incidents:
        inc["end"] = inc["end"] if inc["end"] is not None else inc["start"]
        inc["during_attack"] = bool(attack and inc["end"] >= t1 and inc["start"] <= t2 + 1.0)
        # an ALERT raised BEFORE the first forged frame is a false alarm, even when its
        # incident lasts into the attack: the Nucleo then sends nothing new for the attack
        # (it only reports a start or an escalation), so the attack cannot be credited
        inc["early"] = inc["during_attack"] and inc["first_alert"] is not None and inc["first_alert"] < t1

    hits = [i for i in incidents if i["during_attack"] and i["level"] == "ALERT" and not i["early"]]
    first = min((i["first_alert"] for i in hits), default=None)
    false = [i for i in incidents if not i["during_attack"] or i["early"]]
    masked = any(i["early"] for i in incidents)
    status = [ev for _, ev in events if ev.get("type") == "status" and ev["fps"] > 0]
    return {
        "recording": name, "frames": int(len(df)), "forged_frames": int(lab.sum()),
        "seconds": round(float(df["t"].iloc[-1] - df["t"].iloc[0]), 1),
        "detected": (True if hits else "masked" if masked else False) if attack else None,
        "delay_ms": round((first - t1) * 1000) if first is not None else None,
        "attack_described_as": hits[0]["what"] if hits else None,
        "false_alert_incidents": sum(i["level"] == "ALERT" for i in false),
        "false_warning_incidents": sum(i["level"] == "WARNING" for i in false),
        "nucleo_fps_max": max((s["fps"] for s in status), default=0),
        "nucleo_cpu_pct_max": max((float(s["cpu_pct"]) for s in status), default=0.0),
        "nucleo_queue_max": max((s["queue_max"] for s in status), default=0),
        "nucleo_overflow": (status[-1]["overflow"] - status[0]["overflow"]) if status else 0,   # counter since boot
        "can_errors_max": max((max(s["tec"], s["rec"]) for s in status), default=0),
        "replay_late_ms_p99": round(rp["late_ms_p99"], 2),
        "nucleo_resets": [ev["reset"] for _, ev in events if ev.get("type") == "boot"],
    }


def print_summary(r: dict):
    print(f"\n=== {r['recording']}: {r['frames']:,} frames in {r['seconds']} s, {r['forged_frames']} forged ===")
    if r["detected"] is not None:
        verdict = {True: "YES", False: "NO", "masked": "UNKNOWN (a false ALERT started before the attack and was still open)"}
        print(f"  attack detected (ALERT): {verdict[r['detected']]}"
              + (f", {r['delay_ms']} ms after the first forged frame" if r["delay_ms"] is not None else ""))
        if r["attack_described_as"]:
            print(f"  described as: {r['attack_described_as']}")
    print(f"  false incidents (outside the attack): {r['false_alert_incidents']} ALERT, "
          f"{r['false_warning_incidents']} WARNING")
    print(f"  Nucleo: up to {r['nucleo_fps_max']} frames/s, detector CPU max {r['nucleo_cpu_pct_max']}%, "
          f"queue max {r['nucleo_queue_max']}, overflow {r['nucleo_overflow']}, CAN errors {r['can_errors_max']}")
    print(f"  replay timing: 99% of frames sent within {r['replay_late_ms_p99']} ms of their recorded time")
    if "signed_lines" in r:
        c = r["signed_lines"]
        print(f"  serial link: {c['ok']} lines verified (HMAC), {c['forged']} forged, {c['replayed']} replayed, "
              f"{c['unsigned']} unsigned")
    if r["nucleo_resets"]:
        print(f"  WARNING: the Nucleo restarted during the run ({', '.join(r['nucleo_resets'])})")


def run_one(name: str, full: bool, args, verbose: bool = True, max_minutes: float | None = None) -> dict:
    df = window(load(name), full)
    if max_minutes is not None:
        df = df[df["t"] - df["t"].iloc[0] <= 60 * max_minutes]
    mon = Monitor(args.nucleo, verbose)
    mon.start()
    time.sleep(1.5)                     # bus idle > 1 s: the Nucleo starts with a fresh history
    mon.t0 = time.perf_counter()
    print(f"Replaying {name} ({len(df):,} frames, {df['t'].iloc[-1] - df['t'].iloc[0]:.1f} s)...")
    rp = replay(df, args.can)
    time.sleep(2.0)                     # let the last incident close (1 s without flagged frames)
    mon.close()
    r = summarize(name, df, rp, mon.events)
    r["signed_lines"] = dict(mon.verifier.counts)
    print_summary(r)
    return r


def latency(args, n: int = 20):
    """Transport delay alone: a frame with an unknown ID is alerted at once (no smoothing),
    so PC -> adapter -> CAN -> Nucleo -> USB serial -> PC is all that is measured."""
    mon = Monitor(args.nucleo, verbose=False)
    mon.start()
    time.sleep(1.5)
    res = []
    with serial.Serial(args.can, SERIAL_BAUD) as s:
        for k in range(n):
            n0 = len(mon.events)
            t = time.perf_counter()
            s.write(encode(0x7FF, bytes([k] * 8)))
            s.flush()
            while time.perf_counter() - t < 1.0:
                hit = [tt for tt, ev in mon.events[n0:] if ev.get("type") == "alert"]
                if hit:
                    res.append((hit[0] - t) * 1000)
                    break
                time.sleep(0.0005)
            time.sleep(1.3)             # let the incident close before the next one
    mon.close()
    r = np.array(res)
    print(f"\nTransport delay over {len(r)}/{n} frames: median {np.median(r):.1f} ms, "
          f"min {r.min():.1f} ms, max {r.max():.1f} ms")
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("recording", nargs="?")
    ap.add_argument("--full", action="store_true", help="replay the whole recording, not just around the attack")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--all-test", action="store_true",
                    help="every test-split recording (attacks + clean drives, ~35 min), then a table")
    ap.add_argument("--latency", action="store_true", help="measure the transport delay alone (unknown-ID frames)")
    ap.add_argument("--dataset", choices=["road", "mirgu"], default="road",
                    help="which recordings (the Nucleo must run the matching firmware)")
    ap.add_argument("--clean-minutes", type=float, default=None,
                    help="--all-test: replay only the first N minutes of each clean drive "
                         "(CAN-MIRGU's clean test day is long; the offline test covers all of it)")
    ap.add_argument("--can", default="/dev/ttyUSB0", help="USB-CAN adapter")
    ap.add_argument("--nucleo", default="/dev/ttyACM0", help="Nucleo serial port")
    args = ap.parse_args()
    use_dataset(args.dataset)

    if args.list:
        for n in all_captures():
            print(("test  " if is_test(n) else "      ") + n)
        return
    if args.latency:
        latency(args)
        return
    if args.all_test:
        clean = clean_test_drives()                                      # clean test drives (false alarms)
        names = [n for n in all_captures() if is_test(n) and "accelerator" not in n and n not in clean]
        rows = [run_one(n, True, args, verbose=False) for n in names]
        rows += [run_one(n, True, args, verbose=False, max_minutes=args.clean_minutes) for n in clean]
        out = DATASET["results"] / "live_replay_test.json"
        out.write_text(json.dumps(rows, indent=2))
        print(f"\n{'recording':42s} {'detected':>8s} {'delay ms':>8s} {'false A/W':>9s} {'CPU %':>6s} {'overflow':>8s}")
        for r in rows:
            print(f"{r['recording']:42s} {str(r['detected']):>8s} {str(r['delay_ms']):>8s} "
                  f"{r['false_alert_incidents']:>4d}/{r['false_warning_incidents']:<4d} {r['nucleo_cpu_pct_max']:6.1f} "
                  f"{r['nucleo_overflow']:8d}")
        print(f"saved {out}")
        return
    if not args.recording:
        ap.error("give a recording name (see --list), or --all-test")
    run_one(args.recording, args.full, args)


if __name__ == "__main__":
    main()
