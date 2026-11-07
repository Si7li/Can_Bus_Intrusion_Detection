"""Live attacks that ROAD does not contain: DoS flooding and fuzzing on real IDs.

    python pc/live_attacks.py --list
    python pc/live_attacks.py dos_unknown_id
    python pc/live_attacks.py --all          # every attack below, then a table (~2 min)

The PC plays both the car and the attacker. Each test takes 14 s of a clean
test-split drive (ambient_dyno_drive_basic_short, which gave no alert at all
when replayed live) and builds an attack into seconds 5 to 8:

  dos_unknown_id    flood of ID 0x000 (highest priority, not a car ID), as fast as
                    the bus allows. 0x000 wins every arbitration, so during a real
                    flood the car's own frames cannot get on the bus: they are
                    left out of the attack window here too.
  dos_known_id      the same flood with the car's own highest-priority ID (0x006,
                    normally once per second) and its real data: only the rate is wrong.
  fuzz_known_ids    1 frame per ms with random data on random car IDs (from the
                    whitelist), on top of the normal traffic.
  fuzz_masquerade   the frames of one car ID (0x00E, every 10 ms, never attacked in
                    ROAD) carry random data instead of the real data; timing unchanged.

Ground truth = the injected frames (label 1). Same report as live_demo.py:
detected or not, delay, false incidents outside the attack, Nucleo load.
Random data uses a fixed seed, so every run sends the same frames.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_demo import BYTES, RESULTS, Monitor, load, print_summary, replay, summarize  # noqa: E402

BASE = "ambient_dyno_drive_basic_short"
BASE_START = 60.0                   # seconds into the drive
BEFORE, ATTACK, AFTER = 5.0, 3.0, 6.0
FLOOD_FPS = 3800                    # ~100% of a 500 kbit/s bus for 8-byte frames
FUZZ_PERIOD = 0.001
DOS_KNOWN_ID = 0x006
MASQ_ID = 0x00E
PROFILE = RESULTS / "road_profile.json"


def base_segment() -> pd.DataFrame:
    df = load(BASE)
    t0 = df["t"].iloc[0] + BASE_START
    seg = df[(df["t"] >= t0) & (df["t"] < t0 + BEFORE + ATTACK + AFTER)].copy()
    seg["t"] -= t0
    seg["label"] = 0
    return seg.reset_index(drop=True)


def frames(t: np.ndarray, ids, data: np.ndarray) -> pd.DataFrame:
    out = pd.DataFrame({"t": t, "id": ids, "label": 1})
    out[BYTES] = data
    return out


def merge(seg: pd.DataFrame, extra: pd.DataFrame) -> pd.DataFrame:
    df = pd.concat([seg, extra], ignore_index=True).sort_values("t", kind="stable")
    df[BYTES] = df[BYTES].astype(np.uint8)
    return df.reset_index(drop=True)


def in_attack(seg: pd.DataFrame) -> pd.Series:
    return (seg["t"] >= BEFORE) & (seg["t"] < BEFORE + ATTACK)


def flood(seg: pd.DataFrame, can_id: int, payload: bytes) -> pd.DataFrame:
    t = BEFORE + np.arange(int(ATTACK * FLOOD_FPS)) / FLOOD_FPS
    data = np.tile(np.frombuffer(payload, np.uint8), (len(t), 1))
    return merge(seg[~in_attack(seg)], frames(t, can_id, data))


def dos_unknown_id(seg, rng):
    return flood(seg, 0x000, bytes(8))


def dos_known_id(seg, rng):
    last = seg[(seg["id"] == DOS_KNOWN_ID) & (seg["t"] < BEFORE)].iloc[-1]
    return flood(seg, DOS_KNOWN_ID, bytes(last[BYTES].to_numpy(np.uint8)))


def fuzz_known_ids(seg, rng):
    ids = np.array(sorted(int(k) for k in json.loads(PROFILE.read_text())["ids"]))
    t = BEFORE + np.arange(int(ATTACK / FUZZ_PERIOD)) * FUZZ_PERIOD
    return merge(seg, frames(t, rng.choice(ids, len(t)), rng.integers(0, 256, (len(t), 8))))


def fuzz_masquerade(seg, rng):
    df = seg.copy()
    m = in_attack(df) & (df["id"] == MASQ_ID)
    df.loc[m, BYTES] = rng.integers(0, 256, (int(m.sum()), 8))
    df.loc[m, "label"] = 1
    df[BYTES] = df[BYTES].astype(np.uint8)
    return df


ATTACKS = {f.__name__: f for f in (dos_unknown_id, dos_known_id, fuzz_known_ids, fuzz_masquerade)}


def run(name: str, args) -> dict:
    df = ATTACKS[name](base_segment(), np.random.default_rng(1))
    mon = Monitor(args.nucleo, verbose=True)
    mon.start()
    time.sleep(1.5)                     # bus idle > 1 s: fresh detector history
    mon.t0 = time.perf_counter()
    print(f"Attack {name}: {len(df):,} frames in {df['t'].iloc[-1]:.1f} s, "
          f"{int(df['label'].sum()):,} injected/forged between {BEFORE:.0f} s and {BEFORE + ATTACK:.0f} s")
    rp = replay(df, args.can)
    time.sleep(2.0)
    mon.close()
    r = summarize(name, df, rp, mon.events)
    r["signed_lines"] = dict(mon.verifier.counts)
    print_summary(r)
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attack", nargs="?", choices=list(ATTACKS))
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--can", default="/dev/ttyUSB0")
    ap.add_argument("--nucleo", default="/dev/ttyACM0")
    args = ap.parse_args()
    if args.list:
        print("\n".join(ATTACKS))
        return
    if not (args.all or args.attack):
        ap.error("give an attack name (see --list) or --all")
    rows = [run(n, args) for n in (ATTACKS if args.all else [args.attack])]
    if args.all:
        out = RESULTS / "live_attacks.json"
        out.write_text(json.dumps(rows, indent=2))
        print(f"\n{'attack':18s} {'detected':>8s} {'delay ms':>8s} {'false A/W':>9s} {'bus fps':>7s} "
              f"{'CPU %':>6s} {'queue':>5s} {'overflow':>8s}")
        for r in rows:
            print(f"{r['recording']:18s} {str(r['detected']):>8s} {str(r['delay_ms']):>8s} "
                  f"{r['false_alert_incidents']:>4d}/{r['false_warning_incidents']:<4d} {r['nucleo_fps_max']:7d} "
                  f"{r['nucleo_cpu_pct_max']:6.1f} {r['nucleo_queue_max']:5d} {r['nucleo_overflow']:8d}")
        print(f"saved {out}")


if __name__ == "__main__":
    main()
