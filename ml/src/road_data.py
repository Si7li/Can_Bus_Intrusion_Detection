"""Convert the ROAD candump logs into labelled per-frame tables.

    python ml/src/road_data.py

Input : data/raw/road/road/{ambient,attacks}/*.log + capture_metadata.json
Output: data/processed/road/{ambient,attacks}/<capture>.parquet
        results/road_report.md + .json

One row per CAN frame: t (s since capture start), id, dlc, b0..b7, label, attack.

ROAD gives no per-frame labels, only per-capture metadata: target ID, the
injected payload ('X' = byte not altered) and the injection interval. A frame
is labelled as an attack when it has the target ID, lies inside the interval
AND matches the injected payload. In fabrication captures the real ECU frames
are still there inside the interval and stay benign; in masquerade captures
they were removed, so every target-ID frame inside the interval is injected.

The 4 accelerator captures contain no injected frames (the exploit was applied
before recording), so no frame can be labelled: they are skipped.
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from common import PROJECT_ROOT, RESULTS_DIR, ROAD_PROCESSED_DIR, ROAD_RAW_DIR

BYTES = [f"b{i}" for i in range(8)]
EDGE_TOL = 1e-3  # s; the interval is defined by the first/last injected frame


def parse_log(path: Path) -> pd.DataFrame:
    """Parse '(1110000000.000001) can0 5E1#893FE00B0A000080' lines."""
    raw = pd.read_csv(path, sep=r"\s+", header=None, names=["t", "ch", "frame"], dtype=str, engine="c")
    t = raw["t"].str.strip("()").astype(np.float64)
    parts = raw["frame"].str.split("#", n=1, expand=True, regex=False)
    id_hex = parts[0]
    data_hex = parts[1].fillna("").str.upper()

    df = pd.DataFrame({"t": t - t.iloc[0],
                       "id": id_hex.map(lambda s: int(s, 16)).astype(np.uint16),
                       "dlc": (data_hex.str.len() // 2).astype(np.uint8)})
    # All 8 bytes at once: pad to 16 hex chars, decode in one go, reshape.
    payload = np.frombuffer(bytes.fromhex("".join(data_hex.str.ljust(16, "0"))), dtype=np.uint8).reshape(-1, 8)
    for i, col in enumerate(BYTES):
        df[col] = payload[:, i]
    return df


def payload_match(df: pd.DataFrame, pattern: str) -> pd.Series:
    """True where every non-'X' byte of the 16-char pattern equals the frame's byte."""
    ok = pd.Series(True, index=df.index)
    for i in range(8):
        byte = pattern[2 * i:2 * i + 2]
        if "X" not in byte.upper():
            ok &= df[BYTES[i]] == int(byte, 16)
    return ok


def attack_family(name: str) -> str:
    """'max_speedometer_attack_2_masquerade' -> 'max_speedometer'"""
    return re.sub(r"_attack(_\d+)?(_masquerade)?$", "", name)


def label_attack(df: pd.DataFrame, meta: dict) -> pd.Series:
    start, end = meta["injection_interval"]
    inside = df["t"].between(start - EDGE_TOL, end + EDGE_TOL)
    match = payload_match(df, meta["injection_data_str"])
    target = meta["injection_id"]
    if target in (None, "XXX"):          # fuzzing: any ID, payload all 0xFF
        return inside & match
    return inside & match & (df["id"] == int(target, 16))


def main():
    for sub in ("ambient", "attacks"):
        if not (ROAD_RAW_DIR / sub / "capture_metadata.json").exists():
            raise SystemExit(f"{ROAD_RAW_DIR / sub} not found: extract road.zip into data/raw/road/ (see README).")
        (ROAD_PROCESSED_DIR / sub).mkdir(parents=True, exist_ok=True)

    report = {"ambient": {}, "attacks": {}, "skipped": []}

    # ---------- ambient (all benign) ----------
    ambient_meta = json.loads((ROAD_RAW_DIR / "ambient" / "capture_metadata.json").read_text())
    ambient_ids = set()
    for name, meta in ambient_meta.items():
        df = parse_log(ROAD_RAW_DIR / "ambient" / f"{name}.log")
        df["label"] = np.uint8(0)
        df["attack"] = "none"
        df.to_parquet(ROAD_PROCESSED_DIR / "ambient" / f"{name}.parquet", index=False)
        ids = set(df["id"].unique().tolist())
        ambient_ids |= ids
        report["ambient"][name] = {"frames": len(df), "seconds": round(float(df["t"].iloc[-1]), 1),
                                   "fps": round(len(df) / df["t"].iloc[-1]), "ids": len(ids),
                                   "on_dyno": bool(meta.get("on_dyno")),
                                   "dlc_not_8": int((df["dlc"] != 8).sum()),
                                   "all_ff_frames": int((df[BYTES] == 255).all(axis=1).sum())}
        print(f"  ambient {name:45s} {len(df):>10,} frames {len(ids):4d} IDs")

    # ---------- attacks ----------
    attack_meta = json.loads((ROAD_RAW_DIR / "attacks" / "capture_metadata.json").read_text())
    for name, meta in attack_meta.items():
        if meta.get("injection_interval") is None:
            report["skipped"].append({"capture": name, "reason": "no injected frames (accelerator attack)"})
            print(f"  attack  {name:45s} SKIPPED (no injected frames)")
            continue
        df = parse_log(ROAD_RAW_DIR / "attacks" / f"{name}.log")
        is_attack = label_attack(df, meta)
        family = attack_family(name)
        df["label"] = is_attack.astype(np.uint8)
        df["attack"] = np.where(is_attack, family, "none")
        df.to_parquet(ROAD_PROCESSED_DIR / "attacks" / f"{name}.parquet", index=False)

        start, end = meta["injection_interval"]
        inside = df["t"].between(start - EDGE_TOL, end + EDGE_TOL)
        entry = {"family": family, "masquerade": name.endswith("_masquerade"),
                 "frames": len(df), "attack_frames": int(is_attack.sum()),
                 "ids": int(df["id"].nunique()),
                 "ids_not_in_ambient": int(len(set(df["id"].unique().tolist()) - ambient_ids)),
                 "injection_id": meta["injection_id"], "payload": meta["injection_data_str"],
                 "interval_s": [round(start, 3), round(end, 3)],
                 "payload_matches_outside_interval": int((payload_match(df, meta["injection_data_str"]) & ~inside
                                                          & ((df["id"] == int(meta["injection_id"], 16))
                                                             if meta["injection_id"] not in (None, "XXX") else True)).sum())}
        if meta["injection_id"] not in (None, "XXX"):
            tgt_inside = (df["id"] == int(meta["injection_id"], 16)) & inside
            entry["target_frames_in_interval"] = int(tgt_inside.sum())
        report["attacks"][name] = entry
        print(f"  attack  {name:45s} {len(df):>10,} frames {entry['attack_frames']:>7,} attack")

    report["ambient_ids"] = sorted(ambient_ids)
    write_report(report)


def write_report(report: dict):
    amb = report["ambient"]
    att = report["attacks"]
    lines = ["# ROAD data report", "",
             f"Ambient: **{len(amb)}** captures, **{sum(a['frames'] for a in amb.values()):,}** frames, "
             f"**{sum(a['seconds'] for a in amb.values()) / 3600:.2f} h**, "
             f"**{len(report['ambient_ids'])}** distinct IDs", "",
             "| Ambient capture | Frames | Seconds | Frames/s | IDs | Dyno | DLC≠8 | all-0xFF frames |",
             "|---|---:|---:|---:|---:|---|---:|---:|"]
    for n, a in amb.items():
        lines.append(f"| {n} | {a['frames']:,} | {a['seconds']} | {a['fps']} | {a['ids']} | "
                     f"{'yes' if a['on_dyno'] else 'road'} | {a['dlc_not_8']:,} | {a['all_ff_frames']:,} |")

    lines += ["", "| Attack capture | Target ID | Payload | Frames | Attack frames | Target frames in interval | "
                  "Payload matches outside interval | IDs not in ambient |",
              "|---|---|---|---:|---:|---:|---:|---:|"]
    for n, a in att.items():
        lines.append(f"| {n} | {a['injection_id']} | `{a['payload']}` | {a['frames']:,} | {a['attack_frames']:,} | "
                     f"{a.get('target_frames_in_interval', '-')} | {a['payload_matches_outside_interval']:,} | "
                     f"{a['ids_not_in_ambient']} |")

    lines += ["", "**Attack frames per family**", "",
              "| Family | Fabrication | Masquerade |", "|---|---:|---:|"]
    families = sorted({a["family"] for a in att.values()})
    for f in families:
        fab = sum(a["attack_frames"] for a in att.values() if a["family"] == f and not a["masquerade"])
        mas = sum(a["attack_frames"] for a in att.values() if a["family"] == f and a["masquerade"])
        lines.append(f"| {f} | {fab:,} | {mas:,} |")

    lines += ["", "Skipped:"] + [f"- {s['capture']}: {s['reason']}" for s in report["skipped"]]
    lines += ["", "Notes:",
              "- *Payload matches outside interval*: frames with the target ID that already carry the injected value "
              "in normal operation. High values (reverse_light_off) mean the forged value is normal in other contexts: "
              "it can't be detected from the value alone.",
              "- Each `_masquerade` capture is its fabrication capture with the real target-ID frames removed: keep "
              "both in the same split."]

    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "road_report.json").write_text(json.dumps(report, indent=2))
    (RESULTS_DIR / "road_report.md").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))
    print(f"\nTables written to {ROAD_PROCESSED_DIR.relative_to(PROJECT_ROOT)}/")


if __name__ == "__main__":
    main()
