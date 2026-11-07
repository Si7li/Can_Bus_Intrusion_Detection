"""CAN-MIRGU: three detectors side by side on the same frames.

    IDS_DATASET=mirgu python ml/src/mirgu_eval.py            # val only
    IDS_DATASET=mirgu python ml/src/mirgu_eval.py --final    # + test split

1. rules only        : unknown ID + rate rule (no AI)
2. ROAD v2, cross-car: the network trained on ROAD (results/models/road_mlp_v2_int8.tflite),
                       weights, threshold and smoothing unchanged; only the profile
                       (whitelist, timing, seen values, signal pairs) is learned from
                       MIRGU's training days. Tests whether the features carry over
                       to another car without retraining the network.
3. MIRGU model       : same network and features, trained on MIRGU
                       (IDS_DATASET=mirgu python ml/src/road_train_mlp.py)

All three use the same MIRGU profile (Day 1-4) and the same severity rule.
Every split includes its synthetic random-data attacks (same recipe as ROAD v2).

Clean-drive false alarms are measured on the held-out days only (val = Day 5,
test = Day 6): Day 1-4 built the profile, so they are not "never seen" driving.

Suspension recordings (an ID goes silent, nothing is injected): the detector has
no rule for missing frames, so they are expected to be missed. Reported: incidents
inside the suspension window vs outside it.
"""

import argparse
import json
import os

os.environ.setdefault("IDS_DATASET", "mirgu")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import DATASET, MLP_NAME, PROJECT_ROOT, RESULTS_DIR  # noqa: E402
from road_eval import count_events, evaluate_levels, print_levels  # noqa: E402
from road_eval import smooth_flags  # noqa: E402
from road_features import load_split  # noqa: E402
from road_profile import get_profile  # noqa: E402
from road_train_mlp import detector, predict_int8, split_arrays, with_synthetic  # noqa: E402

if DATASET != "mirgu":
    raise SystemExit("run with IDS_DATASET=mirgu")

ROAD_RESULTS = PROJECT_ROOT / "results"
ROAD_MODEL = ROAD_RESULTS / "models" / "road_mlp_v2_int8.tflite"
ROAD_CONFIG = json.loads((ROAD_RESULTS / "road_mlp_v2_config.json").read_text())
REPORT = json.loads((RESULTS_DIR / "mirgu_report.json").read_text())


def suspension_report(df: pd.DataFrame, alert: np.ndarray, warning: np.ndarray) -> dict:
    out = {}
    for cap, v in REPORT.items():
        if v["variant"] != "suspension":
            continue
        m = (df["capture"] == cap).to_numpy()
        if not m.any():
            continue
        d = df[m]
        lo, hi = v["suspension_window_s"]
        inside = d["t"].between(lo, hi + 1.0).to_numpy()
        a, w = alert[m], warning[m] & ~alert[m]
        out[cap] = {"suspended_id": v["suspended_id"], "window_s": round(hi - lo, 1),
                    "alert_incidents_inside": count_events(d[inside], a[inside]),
                    "warning_incidents_inside": count_events(d[inside], w[inside]),
                    "alert_incidents_outside": count_events(d[~inside], a[~inside]),
                    "warning_incidents_outside": count_events(d[~inside], w[~inside])}
    return out


def outside_attack_report(df: pd.DataFrame, alert: np.ndarray, warning: np.ndarray) -> dict:
    """False alarms on the NORMAL frames of the attack recordings, outside the attack
    window (first forged frame .. last forged frame + 1 s; suspensions: their window).
    The live replay counts these as false incidents."""
    a_ev = w_ev = a_fr = n_fr = 0
    minutes = 0.0
    for cap, d in df[(df["variant"] != "ambient").to_numpy()].groupby("capture", observed=True):
        m = (df["capture"] == cap).to_numpy()
        if cap in REPORT and REPORT[cap]["variant"] == "suspension":
            lo, hi = REPORT[cap]["suspension_window_s"]
        else:
            t = d.loc[d["label"] == 1, "t"]
            if t.empty:
                continue
            lo, hi = t.min(), t.max()
        out = ~d["t"].between(lo, hi + 1.0).to_numpy()
        a, w = alert[m] & out, warning[m] & ~alert[m] & out
        a_ev += count_events(d, a)
        w_ev += count_events(d, w)
        a_fr += int(a.sum())
        n_fr += int(out.sum())
        minutes += (d["t"].iloc[-1] - d["t"].iloc[0]) / 60 * out.mean()
    return {"minutes": round(minutes, 1), "normal_frames": n_fr, "alert_frames": a_fr,
            "alert_incidents": a_ev, "warning_incidents": w_ev}


def print_suspension(s: dict):
    if not s:
        return
    print(f"  suspension recordings (no frame injected; incidents inside / outside the window):")
    for cap, v in s.items():
        print(f"    {cap:28s} ID {v['suspended_id']} silent {v['window_s']:5.0f} s: "
              f"inside ALERT {v['alert_incidents_inside']} WARNING {v['warning_incidents_inside']} | "
              f"outside ALERT {v['alert_incidents_outside']} WARNING {v['warning_incidents_outside']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--final", action="store_true", help="also score the test split")
    args = ap.parse_args()
    profile = get_profile()
    road_tfl = ROAD_MODEL.read_bytes()
    mirgu_cfg_path = RESULTS_DIR / f"{MLP_NAME}_config.json"
    mirgu_cfg = json.loads(mirgu_cfg_path.read_text()) if mirgu_cfg_path.exists() else None
    mirgu_tfl = (RESULTS_DIR / "models" / f"{MLP_NAME}_int8.tflite").read_bytes() if mirgu_cfg else None
    if mirgu_cfg is None:
        print("(MIRGU model not trained yet: rules and cross-car only)")

    summary = {}
    for split in (["val", "test"] if args.final else ["val"]):
        rate_k = ROAD_CONFIG["rate_k"]
        df, unk, fast, strong, x, _ = split_arrays(with_synthetic(load_split(split), split, profile), profile, rate_k)
        k, n = ROAD_CONFIG["smooth"]
        runs = {"rules_only": (unk | smooth_flags(df, fast, k, n), np.zeros(len(df), bool)),
                "road_v2_cross_car": detector(df, unk, fast, strong, predict_int8(road_tfl, x),
                                              ROAD_CONFIG["threshold"], k, n)}
        if mirgu_cfg:
            assert mirgu_cfg["rate_k"] == rate_k
            runs["mirgu_model"] = detector(df, unk, fast, strong, predict_int8(mirgu_tfl, x),
                                           mirgu_cfg["threshold"], *mirgu_cfg["smooth"])
        for name, (alert, warning) in runs.items():
            m = evaluate_levels(df, alert, warning)
            m["suspension"] = suspension_report(df, alert, warning)
            m["attack_recordings_outside_window"] = o = outside_attack_report(df, alert, warning)
            print_levels(m, f"CAN-MIRGU {split} - {name}")
            print(f"  attack recordings, normal part outside the attack window ({o['minutes']} min): "
                  f"ALERT {o['alert_incidents']} incidents ({o['alert_frames']:,} frames), "
                  f"WARNING {o['warning_incidents']} incidents")
            print_suspension(m["suspension"])
            (RESULTS_DIR / f"mirgu_eval_{name}_{split}.json").write_text(json.dumps(m, indent=2))
            summary[f"{split}/{name}"] = m
        del df, x

    # side-by-side table (ALERT recall per attack type, clean-drive incidents per hour)
    lines = ["# CAN-MIRGU: rules only vs ROAD v2 (cross-car) vs MIRGU model", "",
             "Generated by `ml/src/mirgu_eval.py`. Recall = share of forged frames at ALERT "
             "(ALERT or WARNING in brackets); detected = recordings with at least one ALERT on a forged frame.", ""]
    for split in ("val", "test"):
        names = [k.split("/")[1] for k in summary if k.startswith(split + "/")]
        if not names:
            continue
        lines += [f"## {split}", "", "| attack / variant | frames | " + " | ".join(names) + " |",
                  "|---|---:|" + "---|" * len(names)]
        keys = summary[f"{split}/{names[0]}"]["alert"]["per_attack"].keys()
        for key in keys:
            row = [key, f"{summary[f'{split}/{names[0]}']['alert']['per_attack'][key]['attack_frames']:,}"]
            for nm in names:
                a = summary[f"{split}/{nm}"]["alert"]["per_attack"][key]
                aw = summary[f"{split}/{nm}"]["alert_or_warning"]["per_attack"][key]
                row.append(f"{a['recall']:.3f} ({aw['recall']:.3f}), {a['captures_detected']}")
            lines.append("| " + " | ".join(row) + " |")
        c0 = summary[f"{split}/{names[0]}"]["clean_drives"]
        lines.append(f"| **clean {split} day, {c0['hours']:.2f} h: ALERT / WARNING incidents per hour** | | "
                     + " | ".join(f"{summary[f'{split}/{nm}']['clean_drives']['alert_events_per_hour']} / "
                                  f"{summary[f'{split}/{nm}']['clean_drives']['warning_events_per_hour']}"
                                  for nm in names) + " |")
        o0 = summary[f"{split}/{names[0]}"]["attack_recordings_outside_window"]
        lines.append(f"| **attack recordings outside the attack window, {o0['minutes']} min: ALERT / WARNING incidents** | | "
                     + " | ".join(f"{summary[f'{split}/{nm}']['attack_recordings_outside_window']['alert_incidents']} / "
                                  f"{summary[f'{split}/{nm}']['attack_recordings_outside_window']['warning_incidents']}"
                                  for nm in names) + " |")
        lines.append("")
    (RESULTS_DIR / "mirgu_comparison.md").write_text("\n".join(lines) + "\n")
    print(f"\nwritten {(RESULTS_DIR / 'mirgu_comparison.md').relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
