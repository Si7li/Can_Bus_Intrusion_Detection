"""Evaluation for ROAD detectors (rules, AI, rules + AI).

Reported per (attack family, variant):
- recall           : share of forged frames flagged
- detected         : was the attack flagged at all in each capture
- delay_ms         : time from the first forged frame to the first flagged forged frame
Reported on benign traffic:
- fpr              : share of benign frames flagged (all captures, incl. real frames during attacks)
- fpr_clean_drives : share of frames flagged on the clean ambient drives
- false_alarms_min : flagged frames per minute on the clean ambient drives only
"""

import json

import numpy as np
import pandas as pd

from common import RESULTS_DIR


def smooth_flags(df: pd.DataFrame, flags: np.ndarray, k: int, n: int) -> np.ndarray:
    """k-of-n smoothing: a frame raises an alert only if at least k of the last n
    frames with the same ID (this one included) are suspicious. On the STM32: a
    10-bit shift register per ID + popcount."""
    if k <= 1:
        return np.asarray(flags, dtype=bool)
    s = pd.Series(np.asarray(flags, dtype=np.int8), index=df.index)
    roll = s.groupby([df["capture"], df["id"]], observed=True).transform(lambda v: v.rolling(n, min_periods=1).sum())
    return (roll >= k).to_numpy()


def evaluate(df: pd.DataFrame, flagged: np.ndarray) -> dict:
    df = df.assign(flag=np.asarray(flagged, dtype=bool))
    attack = df["label"] == 1

    per_attack = {}
    for (family, variant), g in df[attack].groupby(["attack", "variant"], observed=True):
        delays, detected = [], 0
        for _, c in g.groupby("capture", observed=True):
            hit = c[c["flag"]]
            if len(hit):
                detected += 1
                delays.append(1000 * (hit["t"].iloc[0] - c["t"].iloc[0]))
        per_attack[f"{family} / {variant}"] = {
            "attack_frames": int(len(g)),
            "recall": round(float(g["flag"].mean()), 4),
            "captures_detected": f"{detected}/{g['capture'].nunique()}",
            "median_delay_ms": round(float(np.median(delays)), 1) if delays else None,
        }

    benign = df[~attack]
    amb = df[df["variant"] == "ambient"]
    amb_minutes = sum(g["t"].iloc[-1] - g["t"].iloc[0] for _, g in amb.groupby("capture", observed=True)) / 60
    return {
        "per_attack": per_attack,
        "recall_all_attacks": round(float(df.loc[attack, "flag"].mean()), 4) if attack.any() else None,
        "fpr": float(benign["flag"].mean()),
        "fpr_clean_drives": float(amb["flag"].mean()) if len(amb) else None,
        "benign_flagged_in_attack_captures": int(benign.loc[benign["variant"] != "ambient", "flag"].sum()),
        "false_alarms_per_min_ambient": round(float(amb["flag"].sum() / amb_minutes), 2) if amb_minutes else None,
        "ambient_minutes": round(float(amb_minutes), 1),
        "benign_frames": int(len(benign)),
    }


def print_eval(m: dict, title: str):
    print(f"\n=== {title} ===")
    print(f"{'attack / variant':42s} {'frames':>7s} {'recall':>7s} {'detected':>9s} {'delay ms':>9s}")
    for k, v in m["per_attack"].items():
        delay = "-" if v["median_delay_ms"] is None else f"{v['median_delay_ms']:.0f}"
        print(f"{k:42s} {v['attack_frames']:7,} {v['recall']:7.3f} {v['captures_detected']:>9s} {delay:>9s}")
    print(f"\nall attack frames recall : {m['recall_all_attacks']}")
    print(f"false alarms / minute    : {m['false_alarms_per_min_ambient']} "
          f"(clean drives, {m['ambient_minutes']} min)")
    print(f"false-pos rate, clean    : {100 * m['fpr_clean_drives']:.4f} % of frames on clean drives")
    print(f"benign frames flagged inside attack recordings: {m['benign_flagged_in_attack_captures']:,} "
          f"(real ECU frames caught by the alert window while an attack is going on)")


def save_eval(m: dict, name: str):
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / f"{name}.json").write_text(json.dumps(m, indent=2))
