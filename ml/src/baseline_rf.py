"""Random Forest baseline (handoff §6, step 5).

    python ml/src/baseline_rf.py                      # train, evaluate on the validation set
    python ml/src/baseline_rf.py --nodedup            # same on the non-deduplicated split
    python ml/src/baseline_rf.py --final              # ALSO evaluate on the test set

The test set is meant to be used once, at the very end, so it is only scored
with --final. Day-to-day comparisons use the validation set.
"""

import argparse
import time

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from common import PROCESSED_DIR, RESULTS_DIR, SEED, to_features
from evaluate import compute_metrics, print_metrics, save_metrics


def load_split(data_dir, name):
    df = pd.read_csv(data_dir / f"{name}.csv")
    return to_features(df), df["y"].to_numpy()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodedup", action="store_true", help="use data/processed_nodedup/")
    ap.add_argument("--final", action="store_true", help="also score the test set (do this once)")
    ap.add_argument("--trees", type=int, default=50)
    ap.add_argument("--depth", type=int, default=12)
    args = ap.parse_args()

    data_dir = PROCESSED_DIR.with_name("processed_nodedup") if args.nodedup else PROCESSED_DIR
    if not (data_dir / "train.csv").exists():
        raise SystemExit(f"{data_dir}/train.csv not found: run prepare_data.py"
                         + (" --no-dedup" if args.nodedup else "") + " first.")
    tag = "rf_nodedup" if args.nodedup else "rf"

    x_train, y_train = load_split(data_dir, "train")
    x_val, y_val = load_split(data_dir, "val")

    model = RandomForestClassifier(n_estimators=args.trees, max_depth=args.depth,
                                   class_weight="balanced", random_state=SEED, n_jobs=-1)
    t0 = time.perf_counter()
    model.fit(x_train, y_train)
    print(f"Trained {args.trees} trees (max depth {args.depth}) on {len(y_train):,} rows "
          f"in {time.perf_counter() - t0:.1f} s")

    m_val = compute_metrics(y_val, model.predict(x_val))
    print_metrics(m_val, f"{tag} - validation")
    save_metrics(m_val, RESULTS_DIR, f"{tag}_val")

    if args.final:
        x_test, y_test = load_split(data_dir, "test")
        m_test = compute_metrics(y_test, model.predict(x_test))
        print_metrics(m_test, f"{tag} - TEST")
        save_metrics(m_test, RESULTS_DIR, f"{tag}_test")

    models_dir = RESULTS_DIR / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, models_dir / f"{tag}.joblib")
    print(f"\nMetrics and confusion matrix written to {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
