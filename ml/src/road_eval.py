"""Evaluation for ROAD detectors (rules, AI, rules + AI).

Reported per (attack family, variant):
- recall           : share of forged frames flagged
- detected         : was the attack flagged at all in each capture
- delay_ms         : time from the first forged frame to the first flagged forged frame
Reported on benign traffic:
- events           : flagged frames less than 1 s apart count as one event (incident)
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


EVENT_GAP_S = 1.0


def count_events(df: pd.DataFrame, flags: np.ndarray, gap: float = EVENT_GAP_S) -> int:
    """Alert events: flagged frames closer than `gap` seconds belong to the same
    event (the dashboard shows one incident, not hundreds of frames)."""
    n = 0
    f = np.asarray(flags, dtype=bool)
    for _, t in df.loc[f, ["capture", "t"]].groupby("capture", observed=True)["t"]:
        t = np.sort(t.to_numpy())
        n += 1 + int((np.diff(t) > gap).sum())
    return n


def evaluate_levels(df: pd.DataFrame, alert: np.ndarray, warning: np.ndarray) -> dict:
    alert = np.asarray(alert, bool)
    warning = np.asarray(warning, bool) & ~alert
    amb = (df["variant"] == "ambient").to_numpy()
    d_amb = df[amb]
    hours = sum(g["t"].iloc[-1] - g["t"].iloc[0] for _, g in d_amb.groupby("capture", observed=True)) / 3600
    return {
        "alert": evaluate(df, alert),
        "alert_or_warning": evaluate(df, alert | warning),
        "clean_drives": {
            "hours": round(hours, 3),
            "alert_events": count_events(d_amb, alert[amb]),
            "warning_events": count_events(d_amb, warning[amb]),
            "alert_events_per_hour": round(count_events(d_amb, alert[amb]) / hours, 2) if hours else None,
            "warning_events_per_hour": round(count_events(d_amb, warning[amb]) / hours, 2) if hours else None,
            "alert_frames_per_min": round(float(alert[amb].sum()) / (60 * hours), 2) if hours else None,
            "warning_frames_per_min": round(float(warning[amb].sum()) / (60 * hours), 2) if hours else None,
            "warning_frames_by_capture": {str(k): int(v) for k, v in
                                          d_amb.loc[warning[amb], "capture"].astype(str).value_counts().items()},
            "alert_frames_by_capture": {str(k): int(v) for k, v in
                                        d_amb.loc[alert[amb], "capture"].astype(str).value_counts().items()},
        },
    }


def print_levels(m: dict, title: str):
    a, aw, c = m["alert"], m["alert_or_warning"], m["clean_drives"]
    print(f"\n=== {title} ===")
    print(f"{'attack / variant':42s} {'frames':>7s} {'ALERT':>7s} {'A or W':>7s} {'detected':>9s} {'delay ms':>9s}")
    for k, v in a["per_attack"].items():
        delay = "-" if v["median_delay_ms"] is None else f"{v['median_delay_ms']:.0f}"
        print(f"{k:42s} {v['attack_frames']:7,} {v['recall']:7.3f} {aw['per_attack'][k]['recall']:7.3f} "
              f"{v['captures_detected']:>9s} {delay:>9s}")
    print(f"\nall attack frames caught : ALERT {a['recall_all_attacks']} | ALERT or WARNING {aw['recall_all_attacks']}")
    print(f"clean drives ({60 * c['hours']:.1f} min):")
    print(f"  ALERT   : {c['alert_events']} events ({c['alert_events_per_hour']}/h), {c['alert_frames_per_min']} frames/min"
          f"  {c['alert_frames_by_capture'] or ''}")
    print(f"  WARNING : {c['warning_events']} events ({c['warning_events_per_hour']}/h), {c['warning_frames_per_min']} frames/min"
          f"  {c['warning_frames_by_capture'] or ''}")
