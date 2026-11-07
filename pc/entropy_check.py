"""Measure the on-chip entropy source (LSI jitter vs the crystal, see firmware ids_entropy.h).

    python pc/entropy_check.py               # 32,768 raw samples for 1, 2, 4 and 8 LSI periods per sample
    python pc/entropy_check.py --periods 8

For each setting the Nucleo dumps raw samples (measured periods, in 90 MHz ticks); this
script estimates the min-entropy per sample with the "most common value" estimator of
NIST SP 800-90B (section 6.3.1): H = -log2(p_upper), p_upper = the 99% upper bound of
the most frequent value's probability. It is applied to the full value, its low 8 bits
and its low 4 bits. A lag-1 correlation shows whether consecutive samples depend on each
other (slow drift of the oscillator). This is one estimator, not the full 90B battery
(which takes the minimum of ten estimators on 1,000,000 samples): it gives an honest
order of magnitude, not a certification.

Results: results/entropy_check.json and results/entropy_check.txt.
"""

import argparse
import json
import math
import time
from pathlib import Path

import numpy as np
import serial

from signed_link import Verifier

ROOT = Path(__file__).resolve().parents[1]


def mcv_min_entropy(x: np.ndarray) -> float:
    n = len(x)
    p = np.unique(x, return_counts=True)[1].max() / n
    pu = min(1.0, p + 2.576 * math.sqrt(p * (1 - p) / (n - 1)))
    return -math.log2(pu)


def predictor_min_entropy(x: np.ndarray) -> float:
    """Guess each sample as the value that most often followed the previous one (fitted on
    the first half, scored on the second half): -log2 of the 99% upper bound of the guess
    rate. Unlike MCV, this accounts for the dependence between consecutive samples."""
    half = len(x) // 2
    best = {}
    for prev, nxt in zip(x[:half - 1], x[1:half]):
        best.setdefault(prev, {}).setdefault(nxt, 0)
        best[prev][nxt] += 1
    guess = {k: max(v, key=v.get) for k, v in best.items()}
    common = np.unique(x[:half], return_counts=True)
    fallback = common[0][common[1].argmax()]
    hits = sum(guess.get(prev, fallback) == nxt for prev, nxt in zip(x[half:-1], x[half + 1:]))
    n = len(x) - half - 1
    p = hits / n
    pu = min(1.0, p + 2.576 * math.sqrt(max(p * (1 - p), 1e-12) / (n - 1)))
    return -math.log2(pu)


def max_run(x: np.ndarray) -> int:
    run = best = 1
    for a, b in zip(x[:-1], x[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best


def max_window_share(x: np.ndarray, w: int = 512) -> int:
    return max(int(np.unique(x[i:i + w] & 0xFF, return_counts=True)[1].max()) for i in range(0, len(x) - w + 1, w))


def dump(s: serial.Serial, periods: int, v: Verifier) -> np.ndarray:
    s.reset_input_buffer()
    s.write(f"E{periods}\n".encode())
    s.flush()
    rows, buf, verdicts, end = {}, b"", {}, time.perf_counter() + 30
    while time.perf_counter() < end:
        buf += s.read(65536)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode(errors="replace").strip()
            if '"entropy_raw"' in text:
                verdict = v.check(text)
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
                ev = json.loads(text)
                d = ev["d"]
                rows[ev["i"]] = [int(d[k:k + 4], 16) for k in range(0, len(d), 4)]
            elif '"entropy_done"' in text:
                if set(verdicts) - {"ok"}:
                    print(f"  warning: line signatures {verdicts}")
                return np.array([x for i in sorted(rows) for x in rows[i]], dtype=np.int64)
    raise SystemExit(f"no complete dump for periods={periods} (got {len(rows)} of 512 lines)")


def analyse(x: np.ndarray, periods: int) -> dict:
    d = np.diff(x)
    lag1 = float(np.corrcoef(x[:-1], x[1:])[0, 1])
    return {
        "periods_per_sample": periods,
        "samples": int(len(x)),
        "mean_ticks": round(float(x.mean()), 1),
        "lsi_khz": round(90e6 * periods / float(x.mean()) / 1e3, 2),
        "std_ticks": round(float(x.std()), 2),
        "distinct_values": int(len(np.unique(x))),
        "lag1_correlation": round(lag1, 3),
        "min_entropy_bits": {
            "full_value": round(mcv_min_entropy(x), 2),
            "low_8_bits": round(mcv_min_entropy(x & 0xFF), 2),
            "low_4_bits": round(mcv_min_entropy(x & 0xF), 2),
            "first_difference": round(mcv_min_entropy(d), 2),
            "predictor_from_previous": round(predictor_min_entropy(x), 2),
        },
        "longest_run_identical": max_run(x),
        "max_same_low_byte_per_512": max_window_share(x),
        "samples_per_second": round(90e6 / float(x.mean()), 0),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--periods", type=int, choices=[1, 2, 4, 8], nargs="*", default=[1, 2, 4, 8])
    ap.add_argument("--nucleo", default="/dev/ttyACM0")
    args = ap.parse_args()
    out, lines = [], []
    with serial.Serial(args.nucleo, 921600, timeout=0.05) as s:
        time.sleep(0.5)
        for p in args.periods:
            v = Verifier()
            x = dump(s, p, v)
            r = analyse(x, p)
            out.append(r)
            e = r["min_entropy_bits"]
            line = (f"{p} LSI period(s)/sample: {r['samples']} samples, mean {r['mean_ticks']} ticks "
                    f"(LSI {r['lsi_khz']} kHz), std {r['std_ticks']} ticks, {r['distinct_values']} distinct, "
                    f"lag-1 corr {r['lag1_correlation']:+.3f} | min-entropy per sample (MCV): full {e['full_value']} bits, "
                    f"low 8 bits {e['low_8_bits']}, low 4 bits {e['low_4_bits']}, first difference {e['first_difference']}, "
                    f"predicted from previous {e['predictor_from_previous']} | longest run {r['longest_run_identical']}, "
                    f"max same low byte /512 {r['max_same_low_byte_per_512']}")
            print(line)
            lines.append(line)
    (ROOT / "results" / "entropy_check.json").write_text(json.dumps(out, indent=2))
    (ROOT / "results" / "entropy_check.txt").write_text("\n".join(lines) + "\n")
    print("written results/entropy_check.json, results/entropy_check.txt")


if __name__ == "__main__":
    main()
