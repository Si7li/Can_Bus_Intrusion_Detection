"""Stage 1 of the detector: rules only, no AI. Run on ROAD.

    python ml/src/road_rules.py            # builds the profile, scores the validation split
    python ml/src/road_rules.py --final    # also scores the test split (once, at the end)

Rules (what the STM32 checks before the AI):
- unknown ID : ID never seen in the training ambient traffic
- too fast   : gap since the previous frame of this ID < K x the shortest
               normal gap of that ID (its 0.1% quantile in training ambient)

This is the baseline the AI must beat: whatever the rules miss is the AI's job.
"""

import argparse

import numpy as np

from road_eval import evaluate, print_eval, save_eval
from road_features import add_gaps, load_split
from road_profile import get_profile


def rule_flags(df, profile, k: float):
    """Returns (unknown_id, too_fast) boolean arrays. df must have 'dt' (see add_gaps)."""
    known = df["id"].isin(profile["ids"].keys()).to_numpy()
    thr = df["id"].map({a: v["gap_q001"] for a, v in profile["ids"].items()}).to_numpy(dtype=float)
    too_fast = known & (df["dt"].to_numpy() < k * thr)   # NaN dt (first frame) -> False
    return ~known, too_fast


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--final", action="store_true", help="also score the test split")
    ap.add_argument("--k", type=float, default=0.5, help="too-fast threshold factor (default 0.5)")
    ap.add_argument("--rebuild-profile", action="store_true")
    args = ap.parse_args()

    profile = get_profile(args.rebuild_profile)
    for split in ["val"] + (["test"] if args.final else []):
        df = add_gaps(load_split(split))
        unknown, fast = rule_flags(df, profile, args.k)
        for name, flags in [("whitelist only", unknown), ("rate only", fast), ("whitelist + rate", unknown | fast)]:
            m = evaluate(df, flags)
            print_eval(m, f"RULES ({name}) - {split}")
        save_eval(m, f"road_rules_{split}")


if __name__ == "__main__":
    main()
