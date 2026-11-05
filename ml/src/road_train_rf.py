"""Stage 2 of the detector: AI on frame content, Random Forest baseline. ROAD.

    python ml/src/road_train_rf.py            # train on 'train', score 'val'
    python ml/src/road_train_rf.py --final    # also score 'test' (once, at the end)

The AI answers one question per frame: normal or attack? (option B: the attack
type comes afterwards from the explanation step, not from the model.)

Frames with an unknown ID never reach the AI (the whitelist rule flags them
first), so they are excluded from AI training and from the AI-only scores.
Normal traffic is subsampled for training: 24M frames are far more than a
forest needs, and the benign/attack imbalance is handled by class weights.
"""

import argparse
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from common import RESULTS_DIR, SEED
from road_eval import evaluate, print_eval, save_eval, smooth_flags
from road_features import add_gaps, load_split, make_features, training_frames
from road_profile import get_profile
from road_rules import rule_flags


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--benign", type=int, default=1_500_000, help="benign training frames to sample")
    ap.add_argument("--trees", type=int, default=50)
    ap.add_argument("--depth", type=int, default=14)
    ap.add_argument("--threshold", type=float, default=0.8, help="attack probability threshold (chosen on val)")
    ap.add_argument("--smooth", default="5/10", help="k/n: alert if k of the last n frames of an ID are suspicious")
    ap.add_argument("--k", type=float, default=0.5, help="rate rule factor (see road_rules.py)")
    args = ap.parse_args()

    profile = get_profile()

    # ---------- training set ----------
    sel = training_frames(profile, args.benign, SEED)
    x_train, cols = make_features(sel, profile)
    y_train = sel["label"].to_numpy()
    print(f"Training on {len(y_train):,} frames ({y_train.sum():,} attack) with features {cols}")

    model = RandomForestClassifier(n_estimators=args.trees, max_depth=args.depth, class_weight="balanced",
                                   min_samples_leaf=5, random_state=SEED, n_jobs=-1)
    t0 = time.perf_counter()
    model.fit(x_train, y_train)
    print(f"  trained in {time.perf_counter() - t0:.0f} s")
    importances = sorted(zip(cols, model.feature_importances_), key=lambda p: -p[1])
    print("  feature importance:", ", ".join(f"{c} {v:.2f}" for c, v in importances[:8]))

    # ---------- evaluation ----------
    for split in ["val"] + (["test"] if args.final else []):
        df = add_gaps(load_split(split))
        unknown, fast = rule_flags(df, profile, args.k)
        x, _ = make_features(df, profile)
        p_attack = model.predict_proba(x)[:, 1]
        ai = (~unknown) & (p_attack >= args.threshold)

        m_ai = evaluate(df[~unknown], ai[~unknown])
        print_eval(m_ai, f"AI only (RF), known IDs, no smoothing - {split}")
        save_eval(m_ai, f"road_rf_ai_{split}")

        # Final detector: unknown ID alerts at once; rate rule and AI go through k-of-n smoothing.
        k, n = map(int, args.smooth.split("/"))
        alert = unknown | smooth_flags(df, fast | ai, k, n)
        m_all = evaluate(df, alert)
        print_eval(m_all, f"RULES + AI (RF), threshold {args.threshold}, smoothing {k}/{n} - {split}")
        save_eval(m_all, f"road_rf_rules_ai_{split}")

    (RESULTS_DIR / "models").mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": cols}, RESULTS_DIR / "models" / "road_rf.joblib")


if __name__ == "__main__":
    main()
