"""Step 1 of the ML pipeline: load, clean, deduplicate and split CICIoV2024.

    python ml/src/prepare_data.py               # deduplicated split (the honest one)
    python ml/src/prepare_data.py --no-dedup    # raw split, only to show score inflation

Input : every *.csv in data/raw/decimal/ (the decimal version of the dataset)
Output: data/processed/{train,val,test}.csv  (or data/processed_nodedup/)
        results/data_report.md + .json       (row counts, duplicates, label conflicts)

Why deduplicate BEFORE splitting: ECUs repeat the same frame thousands of
times. Without dedup, the same row lands in train and test, and the model is
graded on frames it memorised, which explains the ~99.9% scores in papers.
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from common import (BYTE_COLS, CLASS_TO_INDEX, CLASSES, FEATURE_COLS, PROCESSED_DIR,
                    PROJECT_ROOT, RAW_DIR, RESULTS_DIR, SEED, normalize_class)

MIN_ROWS_WARNING = 50  # a class with fewer unique rows than this gives unreliable F1
MIN_SPLITTABLE = 10    # below this a class cannot be split 70/10/20 (see split())


def load_raw(raw_dir: Path) -> pd.DataFrame:
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        sys.exit(f"No CSV files in {raw_dir}.\n"
                 "Download CICIoV2024 and copy the files of the *decimal* folder there "
                 "(see README.md).")

    frames = []
    for f in files:
        df = pd.read_csv(f)
        df.columns = [c.strip() for c in df.columns]
        missing = [c for c in FEATURE_COLS if c not in df.columns]
        if missing:
            sys.exit(f"{f.name}: missing columns {missing}. Found: {list(df.columns)}")

        # Class: use the 'specific_class' column; fall back to the file name.
        source = df["specific_class"] if "specific_class" in df.columns else pd.Series(f.stem, index=df.index)
        df["cls"] = source.astype(str).map(normalize_class)
        df["source_file"] = f.name
        frames.append(df[FEATURE_COLS + ["cls", "source_file"]])
        print(f"  loaded {f.name:45s} {len(df):>9,} rows")

    data = pd.concat(frames, ignore_index=True)

    # Values must be plain integers in range; the hex version of the dataset would fail here.
    for c in FEATURE_COLS:
        if not pd.api.types.is_integer_dtype(data[c]):
            sys.exit(f"Column {c} is not integer ({data[c].dtype}). Use the *decimal* files.")
    bad_id = ~data["ID"].between(0, 2047)
    bad_bytes = ~data[BYTE_COLS].apply(lambda col: col.between(0, 255)).all(axis=1)
    n_bad = int((bad_id | bad_bytes).sum())
    if n_bad:
        print(f"  WARNING: dropping {n_bad} rows with ID outside 0-2047 or bytes outside 0-255")
        data = data[~(bad_id | bad_bytes)]
    return data


def find_conflicts(data: pd.DataFrame) -> pd.DataFrame:
    """Feature vectors that appear with more than one class.
    A per-frame model cannot classify these correctly; they set a ceiling on accuracy."""
    uniq = data.drop_duplicates(FEATURE_COLS + ["cls"])
    n_cls = uniq.groupby(FEATURE_COLS)["cls"].nunique()
    conflict_keys = n_cls[n_cls > 1].index
    if len(conflict_keys) == 0:
        return uniq.iloc[0:0]
    return uniq.set_index(FEATURE_COLS).loc[conflict_keys].reset_index()


def split(data: pd.DataFrame):
    """Stratified 70/10/20 split.

    A class with fewer than MIN_SPLITTABLE unique rows cannot be split (e.g. a DoS
    flood that is always the same frame). Its rows are copied into all three
    splits and the class is reported as 'memorised': its test score shows the
    model recognises those exact frames, not that it generalises.
    """
    counts = data["cls"].value_counts()
    memorised = sorted(counts[counts < MIN_SPLITTABLE].index)
    small = data[data["cls"].isin(memorised)]
    rest_data = data[~data["cls"].isin(memorised)]

    train, rest = train_test_split(rest_data, test_size=0.30, stratify=rest_data["cls"], random_state=SEED)
    # rest = 30% of the total -> val 10% / test 20%
    val, test = train_test_split(rest, test_size=2 / 3, stratify=rest["cls"], random_state=SEED)
    if memorised:
        train, val, test = (pd.concat([part, small]) for part in (train, val, test))
    return train, val, test, memorised


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    ap.add_argument("--no-dedup", action="store_true",
                    help="skip deduplication (for the 'inflated score' comparison only)")
    ap.add_argument("--drop-conflicts", action="store_true",
                    help="remove feature vectors that appear with several classes")
    args = ap.parse_args()

    print(f"Loading {args.raw_dir}")
    raw = load_raw(args.raw_dir)

    raw_counts = raw["cls"].value_counts().reindex(CLASSES, fill_value=0)
    dedup = raw.drop_duplicates(FEATURE_COLS + ["cls"])
    uniq_counts = dedup["cls"].value_counts().reindex(CLASSES, fill_value=0)
    conflicts = find_conflicts(raw)
    n_conflict_vectors = len(conflicts.drop_duplicates(FEATURE_COLS))
    conflict_pairs = (conflicts.groupby(FEATURE_COLS)["cls"]
                      .apply(lambda s: " + ".join(sorted(s))).value_counts().to_dict())

    data = raw if args.no_dedup else dedup
    if args.drop_conflicts and n_conflict_vectors:
        key = pd.MultiIndex.from_frame(conflicts[FEATURE_COLS].drop_duplicates())
        data = data[~pd.MultiIndex.from_frame(data[FEATURE_COLS]).isin(key)]

    train, val, test, memorised = split(data)

    out_dir = PROCESSED_DIR if not args.no_dedup else PROCESSED_DIR.with_name("processed_nodedup")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, part in [("train", train), ("val", val), ("test", test)]:
        part = part.assign(y=part["cls"].map(CLASS_TO_INDEX))
        part[FEATURE_COLS + ["cls", "y"]].to_csv(out_dir / f"{name}.csv", index=False)

    # ---------- report ----------
    report = {
        "files": sorted(raw["source_file"].unique().tolist()),
        "deduplicated": not args.no_dedup,
        "dropped_conflicts": bool(args.drop_conflicts),
        "rows_raw": int(len(raw)),
        "rows_unique": int(len(dedup)),
        "per_class": {
            c: {"raw": int(raw_counts[c]), "unique": int(uniq_counts[c]),
                "unique_pct": round(100 * uniq_counts[c] / raw_counts[c], 2) if raw_counts[c] else 0.0}
            for c in CLASSES
        },
        "memorised_classes": memorised,
        "label_conflicts": {"feature_vectors": n_conflict_vectors, "class_combinations": conflict_pairs},
        "split_sizes": {
            name: part["cls"].value_counts().reindex(CLASSES, fill_value=0).astype(int).to_dict()
            for name, part in [("train", train), ("val", val), ("test", test)]
        },
        "output_dir": str(out_dir.relative_to(PROJECT_ROOT)),
    }

    lines = ["# CICIoV2024 data report", "",
             f"Raw rows: **{report['rows_raw']:,}**, unique (features + class): **{report['rows_unique']:,}**", "",
             "| Class | Raw rows | Unique rows | Unique % | Train | Val | Test |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for c in CLASSES:
        pc = report["per_class"][c]
        s = report["split_sizes"]
        lines.append(f"| {c} | {pc['raw']:,} | {pc['unique']:,} | {pc['unique_pct']}% | "
                     f"{s['train'][c]:,} | {s['val'][c]:,} | {s['test'][c]:,} |")
    lines += ["", f"Split built from: **{'deduplicated' if not args.no_dedup else 'raw (NOT deduplicated)'}** data"
              + (", conflicting vectors dropped" if args.drop_conflicts else ""), "",
              f"Label conflicts (same 9 features, different class): **{n_conflict_vectors:,}** feature vectors"]
    for combo, n in conflict_pairs.items():
        lines.append(f"- {combo}: {n:,}")
    if memorised:
        lines += ["", f"MEMORISED classes (< {MIN_SPLITTABLE} unique rows, copied into train/val/test): {memorised}. "
                      "Their scores do not measure generalisation; rules (e.g. unknown ID) should catch them."]
    absent = [c for c in CLASSES if uniq_counts[c] == 0]
    if absent:
        lines += ["", f"WARNING: no rows at all for {absent}."]
    warnings = [c for c in CLASSES if 0 < uniq_counts[c] < MIN_ROWS_WARNING]
    if warnings:
        lines += ["", f"WARNING: few unique rows (< {MIN_ROWS_WARNING}) for {warnings}: per-class scores "
                      "will be unreliable; consider the binary task."]

    RESULTS_DIR.mkdir(exist_ok=True)
    suffix = "" if not args.no_dedup else "_nodedup"
    (RESULTS_DIR / f"data_report{suffix}.json").write_text(json.dumps(report, indent=2))
    (RESULTS_DIR / f"data_report{suffix}.md").write_text("\n".join(lines) + "\n")
    print()
    print("\n".join(lines))
    print(f"\nSplits written to {out_dir}")


if __name__ == "__main__":
    main()
