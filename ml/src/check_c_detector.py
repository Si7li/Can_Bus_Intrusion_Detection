"""Check that the C detector (firmware/can_ids_fw/Core/Src/ids_detector.c) gives
exactly the same answers as the Python pipeline, frame by frame.

    python ml/src/check_c_detector.py            # val + test splits (+ synthetic attacks for model v2)

The C file is compiled for the PC (gcc) and fed every frame of the split.
Compared per frame: the 27 quantized model inputs, the int8 model output, and
the final ALERT / WARNING level.

Timestamps: the candump logs store epoch times (~1.1e9 s) as text; Python parses
them into float64, which adds up to ~0.2 us of rounding noise to each gap. The
chip uses exact integer microseconds. For the bit-exact check, Python gets the
same exact microseconds. The test split is then also re-scored with the C
detector's own answers (no tuning: same detector, same threshold), to show the
published results hold for the C version.
"""

import subprocess
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from common import PROJECT_ROOT
from export_c import python_reference
from mcu_model import load_params
from road_eval import evaluate_levels, print_levels
from road_features import BYTES, add_gaps, chunks, load_split
from road_profile import get_profile
from road_train_mlp import SLIM, with_synthetic

FW = PROJECT_ROOT / "firmware"
IN_DT = np.dtype([("t_us", "<u4"), ("id", "<u2"), ("dlc", "u1"), ("reset", "u1"), ("data", "u1", 8)])
OUT_DT = np.dtype([("feat", "i1", 27), ("score", "i1"), ("level", "u1"), ("reasons", "u1"),
                   ("novel", "u1"), ("pair", "u1")])


def build(out_dir: Path) -> Path:
    exe = out_dir / "ids_host"
    subprocess.run(["gcc", "-O2", "-std=c11", "-Wall", "-Wextra", "-ffp-contract=off",
                    "-I", str(FW / "can_ids_fw/Core/Inc"), str(FW / "host_test/ids_host.c"),
                    str(FW / "can_ids_fw/Core/Src/ids_detector.c"), "-o", str(exe)], check=True)
    return exe


def run_c(exe: Path, df) -> np.ndarray:
    rec = np.zeros(len(df), IN_DT)
    rec["t_us"] = np.round(df["t"].to_numpy() * 1e6).astype(np.int64)
    rec["id"] = df["id"].to_numpy()
    rec["dlc"] = df["dlc"].to_numpy()
    cap = df["capture"].astype(str).to_numpy()
    rec["reset"] = np.r_[True, cap[1:] != cap[:-1]]
    rec["data"] = df[BYTES].to_numpy()
    out = subprocess.run([str(exe)], input=rec.tobytes(), capture_output=True, check=True).stdout
    return np.frombuffer(out, OUT_DT)


def main():
    profile, p = get_profile(), load_params()
    with tempfile.TemporaryDirectory() as tmp:
        exe = build(Path(tmp))
        for split in ["val", "test"]:
            df = with_synthetic(load_split(split), split, profile)      # v2: + synthetic random-data attacks
            df["t"] = np.round(df["t"] * 1e6) / 1e6          # exact microseconds, like the chip
            n = n_known = diff_feat = same_score = diff_level = 0
            examples, slim, levels = [], [], []
            for d in chunks(df):                              # whole captures at a time (bounded memory)
                d = add_gaps(d)
                c = run_c(exe, d)
                q, score, level, unknown = python_reference(d, profile, p)
                known = ~unknown
                same_feat = (c["feat"][known] == q[known]).all(axis=1)
                n += len(d)
                n_known += int(known.sum())
                diff_feat += int((~same_feat).sum())
                same_score += int((c["score"][known] == score[known]).sum())
                diff_level += int((c["level"] != level).sum())
                if (~same_feat).any() and len(examples) < 3:
                    for k in np.flatnonzero(known)[np.flatnonzero(~same_feat)[:3 - len(examples)]]:
                        dk = np.flatnonzero(c["feat"][k] != q[k])
                        examples.append(f"    id 0x{d['id'].iloc[k]:03X}, features {dk.tolist()}: "
                                        f"C {c['feat'][k][dk].tolist()} vs Python {q[k][dk].tolist()}")
                if split == "test":
                    slim.append(d[SLIM])
                    levels.append(c["level"])
            print(f"\n=== {split}: {n:,} frames ({n_known:,} with a known ID) ===")
            print(f"  model inputs (27 int8) identical : {100 * (1 - diff_feat / n_known):.4f}%  ({diff_feat} frames differ)")
            print(f"  model output (int8) identical    : {100 * same_score / n_known:.4f}%")
            print(f"  ALERT/WARNING level identical    : {100 * (1 - diff_level / n):.4f}%  "
                  f"({diff_level} frames differ)")
            for e in examples:
                print(e)
            if split == "test":
                d, lv = pd.concat(slim, ignore_index=True), np.concatenate(levels)
                m = evaluate_levels(d, lv == 2, lv == 1)
                print_levels(m, "C DETECTOR (exact-us timestamps) - test")


if __name__ == "__main__":
    main()
