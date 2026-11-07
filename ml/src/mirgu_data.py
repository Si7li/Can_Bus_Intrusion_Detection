"""Convert the CAN-MIRGU candump logs into per-frame tables (same format as ROAD).

    python ml/src/mirgu_data.py

Input : data/raw/mirgu/drive/CAN-MIRGU/{Benign/Day_*,Attack/*}/*.log
        (+ Attacks_metadata.json), from the authors' Google Drive folder
Output: data/processed/mirgu/{ambient,attacks}/<capture>.parquet
        results/mirgu/mirgu_report.md + .json

CAN-MIRGU (Rajapaksha et al., VehicleSec 2024, CC BY 4.0, doi 10.24432/C5H911):
a 2016 electric car, 500 kbit/s. 17 h of normal driving on UK public roads over
6 days, and 36 attack recordings made on a proving ground (<= 30 mph).

Unlike ROAD, every log line carries its own label (last column, 0/1), so the
labels are used as given. One row per frame: t (s since capture start), id,
dlc, b0..b7 (missing bytes = 0, like the STM32), label, attack, variant.

variant: fabrication = frames injected next to the real ones (real attacks),
masquerade = the real frames were replaced (synthetic, made by the authors from
the real recordings), suspension = an ID goes silent (synthetic). In the
suspension recordings the authors label EVERY frame of the window 1, but no
frame is forged (an ID simply stops): those frames are stored with label 0 and
the window (s since capture start) is kept in results/mirgu/mirgu_report.json
("suspension_window_s"); the evaluation reports separately whether anything was
raised inside the window.
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from common import MIRGU_PROCESSED_DIR, MIRGU_RAW_DIR, PROJECT_ROOT, RESULTS_DIR

BYTES = [f"b{i}" for i in range(8)]
OUT = PROJECT_ROOT / "results" / "mirgu"
MAX_GAP_S = 1.0     # = the firmware's IDLE_RESET_US: a longer silence starts a new capture


def parse_log(path: Path) -> pd.DataFrame:
    """'(1698319517.908320) can0 500#01 0' -> t, id, dlc, b0..b7, label."""
    raw = pd.read_csv(path, sep=" ", header=None, names=["t", "ch", "frame", "label"],
                      dtype={"t": str, "ch": str, "frame": str, "label": np.int8}, engine="c")
    t = raw["t"].str.slice(1, -1).astype(np.float64)
    parts = raw["frame"].str.split("#", n=1, expand=True, regex=False)
    data_hex = parts[1].fillna("").str.upper()
    if (parts[0].str.len() != 3).any():
        raise ValueError(f"{path.name}: extended (29-bit) IDs found; the detector handles 11-bit IDs only")
    if (data_hex.str.len() > 16).any() or (data_hex.str.len() % 2).any():
        raise ValueError(f"{path.name}: malformed payload")
    df = pd.DataFrame({"t": t - t.iloc[0],
                       "id": parts[0].map(lambda s: int(s, 16)).astype(np.uint16),
                       "dlc": (data_hex.str.len() // 2).astype(np.uint8)})
    payload = np.frombuffer(bytes.fromhex("".join(data_hex.str.ljust(16, "0"))), np.uint8).reshape(-1, 8)
    for i, col in enumerate(BYTES):
        df[col] = payload[:, i]
    df["label"] = raw["label"].to_numpy(np.uint8)
    df.attrs["t0"] = float(t.iloc[0])
    return df


def load_metadata(path: Path) -> dict:
    """The file has trailing commas (not strict JSON): remove them before parsing."""
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", path.read_text()))


def capture_info(path: Path) -> tuple[str, str, str]:
    """-> (capture name, attack family, variant). Real and masquerade copies of the
    same attack get the same family (they must share a split)."""
    name = path.stem.lower()
    folder = path.parent.name
    if folder.startswith("Day_"):
        return name, "benign", "ambient"
    if folder == "Suspension_attacks":
        return name, re.sub(r"_attack$", "", name), "suspension"
    family = "multiple_attacks" if name.startswith("multiple_attacks") else \
        re.sub(r"(_masquerade)?_attack(_\d+)?$", "", name)
    return name, family, "masquerade" if folder == "Masquerade_attacks" else "fabrication"


# metadata keys that differ from the file names
META_NAME = {"steering_angle_replay": "Steering_angle_replay_attack",
             "fuzzing_valid_ids_dos": "Fuzzing_valid_IDs_and_DoS_attack",
             "reverse_speedometer_fuzzing_attack": "Reverse_speedometer_and_fuzzing_attack"}


def meta_for(name: str, meta: dict) -> dict | None:
    key = META_NAME.get(name)
    if key is None:
        key = next((k for k in meta if k.lower() == name), None)
    return meta.get(key)


def intervals(m: dict) -> list[tuple[float, float]]:
    return [tuple(v) for k, v in m.items() if k.endswith("_interval") or re.search(r"_interval_\d$", k)]


def main():
    root = MIRGU_RAW_DIR
    logs = sorted(root.glob("Benign/Day_*/*.log")) + sorted(root.glob("Attack/*/*.log"))
    if not logs:
        raise SystemExit(f"No logs under {root}: download CAN-MIRGU first (see README)")
    meta = load_metadata(root / "Attack" / "Attacks_metadata.json")
    for sub in ("ambient", "attacks"):
        (MIRGU_PROCESSED_DIR / sub).mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    report = {}
    for path in logs:
        name, family, variant = capture_info(path)
        sub = "ambient" if variant == "ambient" else "attacks"
        out = MIRGU_PROCESSED_DIR / sub / f"{name}.parquet"
        df = parse_log(path)
        t0 = df.attrs["t0"]
        gaps = np.diff(df["t"].to_numpy())
        df["attack"] = family
        df["variant"] = variant
        lab = df["label"] == 1
        r = {"folder": path.parent.name, "variant": variant, "family": family,
             "frames": int(len(df)), "minutes": round(float(df["t"].iloc[-1]) / 60, 2),
             "start_epoch": t0, "end_epoch": t0 + float(df["t"].iloc[-1]),
             "label1": int(lab.sum()), "ids": int(df["id"].nunique()),
             "label1_ids": sorted(f"{i:03X}" for i in df.loc[lab, "id"].unique())[:20],
             "max_gap_s": round(float(gaps.max()), 3), "backwards": int((gaps < 0).sum())}
        m = meta_for(name, meta) if variant != "ambient" else None
        if m is not None:
            iv = intervals(m)
            r["meta_intervals"] = len(iv)
            r["meta_technique"] = m.get("attack_technique") or "/".join(
                str(m[k]) for k in sorted(m) if k.startswith("attack_technique_"))
            if lab.any() and iv:
                tl = df.loc[lab, "t"].to_numpy() + t0
                inside = np.zeros(len(tl), bool)
                for a, b in iv:
                    inside |= (tl >= a - 1e-3) & (tl <= b + 1e-3)
                r["label1_inside_meta_interval"] = round(float(inside.mean()), 4)
        elif variant != "ambient":
            r["meta_intervals"] = 0
        if variant == "suspension":     # no forged frame: label 0, keep the window
            r["suspension_window_s"] = [float(df.loc[lab, "t"].min()), float(df.loc[lab, "t"].max())]
            r["suspended_id"] = name.split("_")[1].upper()
            df["label"] = np.uint8(0)
        if r["backwards"]:
            raise ValueError(f"{name}: timestamps go backwards")
        cuts = np.flatnonzero(gaps > MAX_GAP_S) + 1
        if len(cuts) and variant != "ambient":
            raise ValueError(f"{name}: attack recording with a silence > {MAX_GAP_S} s")
        for old in MIRGU_PROCESSED_DIR.glob(f"{sub}/{name}*.parquet"):     # stale whole file / parts
            if old.stem == name or old.stem.startswith(name + "_part"):
                old.unlink()
        if len(cuts):       # the chip forgets its history after 1 s of silence: one capture per piece
            pieces = np.split(np.arange(len(df)), cuts)
            r["parts"] = len(pieces)
            r["silent_minutes"] = round(float(gaps[cuts - 1].sum()) / 60, 2)
            for k, idx in enumerate(pieces, 1):
                part = df.iloc[idx].copy()
                part["t"] -= part["t"].iloc[0]
                part.to_parquet(MIRGU_PROCESSED_DIR / sub / f"{name}_part{k}.parquet", index=False)
            print(f"  {name}: {len(cuts)} silence(s) > {MAX_GAP_S} s ({r['silent_minutes']} min) -> {len(pieces)} captures")
        else:
            r["parts"], r["silent_minutes"] = 1, 0.0
            df.to_parquet(out, index=False)
        r["driving_minutes"] = round(r["minutes"] - r["silent_minutes"], 2)
        report[name] = r
        print(f"{name:42s} {variant:11s} {len(df):>10,} frames {r['minutes']:7.1f} min  label1 {r['label1']:>8,}",
              flush=True)
    write_report(report)


def write_report(report: dict):
    amb = {k: v for k, v in report.items() if v["variant"] == "ambient"}
    att = {k: v for k, v in report.items() if v["variant"] != "ambient"}
    lines = ["# CAN-MIRGU data report", "",
             "Generated by `ml/src/mirgu_data.py`. Labels are the dataset's own per-frame labels.", "",
             f"Normal driving: {len(amb)} files, {sum(v['frames'] for v in amb.values()):,} frames, "
             f"{sum(v['driving_minutes'] for v in amb.values()) / 60:.2f} h with traffic on the bus "
             f"({sum(v['silent_minutes'] for v in amb.values()):.0f} silent minutes removed).", "",
             f"A file with a silence > {MAX_GAP_S} s (car parked, bus off) is split into captures "
             "`<file>_partN` at each silence: the STM32 forgets its per-ID history after 1 s without frames.", "",
             "| file | day | frames | minutes with traffic | silent minutes | captures | IDs |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for k, v in amb.items():
        lines.append(f"| {k} | {v['folder']} | {v['frames']:,} | {v['driving_minutes']} | {v['silent_minutes']} | "
                     f"{v['parts']} | {v['ids']} |")
    lines += ["", f"Attack recordings: {len(att)}", "",
              "| recording | variant | family | frames | minutes | label 1 | label-1 IDs | label 1 inside metadata interval |",
              "|---|---|---|---:|---:|---:|---|---:|"]
    for k, v in att.items():
        ids = ", ".join(v["label1_ids"][:6]) + (" ..." if len(v["label1_ids"]) > 6 else "")
        lines.append(f"| {k} | {v['variant']} | {v['family']} | {v['frames']:,} | {v['minutes']} | {v['label1']:,} | "
                     f"{ids} | {v.get('label1_inside_meta_interval', '-')} |")
    (OUT / "mirgu_report.json").write_text(json.dumps(report, indent=2))
    (OUT / "mirgu_report.md").write_text("\n".join(lines) + "\n")
    print(f"\nReport: {(OUT / 'mirgu_report.md').relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
