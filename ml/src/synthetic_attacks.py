"""Synthetic random-data attacks for model v2 (ROAD has none of these).

Why: the live tests (pc/live_attacks.py) showed that model v1 misses a real ID
carrying random data at its normal timing. v1 only learned ROAD's attacks, where
one or two bytes of an otherwise real frame are changed. v2 also trains on the
attacks generated here. This was decided AFTER the test split had been used:
v2 results are reported next to v1's, as a post-test revision.

Each synthetic capture is a 20 s piece of a normal drive with one attack on one
target ID in the middle (from 8 s, at most 8 s and 300 frames of that ID):
  random_all8       masquerade: every frame of the ID carries 8 random bytes
  random_some       masquerade: 3-5 byte positions (fixed per attack) are random
  random_injected   fabrication: extra frames between the real ones, a copy of
                    the latest real frame with 3-8 random byte positions

At least 3 random bytes: a first try with 2 (val only) taught the model that
2 new values are an attack, but normal driving also produces frames with 1-2
new values (1,902 of 1.72M clean val frames) and almost never 3 or more (4
frames): WARNINGs on the clean val drive went from 23.5 to 147 frames/min.

v2 was first evaluated with an extra severity rule, "3+ never-seen bytes in one
frame = strong evidence (ALERT)", calibrated on the val drives. On the test drives
it gave 36 false ALERT incidents (v1: 1): the "benign anomaly" drive has 1,232
such frames. The rule was removed AFTER that test run (results kept in
results/road_mlp_v2_with_3byte_rule_*); v2 uses v1's severity rule.

Nothing leaks between splits:
- training attacks are cut from training drives, val from val drives, test from
  test drives (same drive split as road_features.AMBIENT_SPLIT);
- target IDs are split too: 70% of the whitelist for training, 15% val, 15% test.
  0x00E (the ID attacked in the live test) is always in the test group, so the
  live test measures an ID the model never saw attacked.
"""

import numpy as np
import pandas as pd

from common import DATASET, DATASET_PROCESSED_DIR, SEED
from road_features import AMBIENT_SPLIT, BYTES

SEGMENT_S, ATTACK_START_S, ATTACK_MAX_S, ATTACK_MAX_FRAMES = 20.0, 8.0, 8.0, 300
N_ATTACKS = {"train": 150, "val": 40, "test": 40}
if DATASET == "mirgu":          # CAN-MIRGU: same recipe, drives = the split's days
    from mirgu_split import LIVE_TEST_ID
else:
    LIVE_TEST_ID = 0x00E
MAX_CACHED_DRIVES = 3           # MIRGU drives are ~10M frames each: keep only a few in memory
TYPES = ["random_all8", "random_some", "random_injected"]


def id_groups(profile: dict) -> dict:
    """{id: 'train' | 'val' | 'test'}: which split may use the ID as attack target."""
    ids = sorted(int(a) for a in profile["ids"] if int(a) != LIVE_TEST_ID)
    rng = np.random.default_rng(SEED)
    ids = list(rng.permutation(ids))
    n_tr, n_va = round(0.70 * len(ids)), round(0.15 * len(ids))
    groups = {int(a): "train" for a in ids[:n_tr]}
    groups |= {int(a): "val" for a in ids[n_tr:n_tr + n_va]}
    groups |= {int(a): "test" for a in ids[n_tr + n_va:]}
    groups[LIVE_TEST_ID] = "test"
    return groups


def _segment(drive: pd.DataFrame, rng) -> pd.DataFrame:
    t0, t1 = drive["t"].iloc[0], drive["t"].iloc[-1] - SEGMENT_S
    s = rng.uniform(t0, t1)
    lo, hi = np.searchsorted(drive["t"].to_numpy(), [s, s + SEGMENT_S])
    seg = drive.iloc[lo:hi].copy()
    seg["t"] -= s
    return seg.reset_index(drop=True)


def _attack(seg: pd.DataFrame, target: int, kind: str, rng) -> pd.DataFrame:
    seg = seg.copy()
    seg["label"] = 0
    is_t = (seg["id"] == target).to_numpy()
    in_win = (seg["t"] >= ATTACK_START_S).to_numpy() & (seg["t"] < ATTACK_START_S + ATTACK_MAX_S).to_numpy()
    rows = np.flatnonzero(is_t & in_win)[:ATTACK_MAX_FRAMES]
    if kind in ("random_all8", "random_some"):
        cols = list(range(8)) if kind == "random_all8" else sorted(rng.choice(8, rng.integers(3, 6), replace=False))
        vals = seg[BYTES].to_numpy(np.uint8).copy()
        vals[np.ix_(rows, cols)] = rng.integers(0, 256, (len(rows), len(cols)), dtype=np.uint8)
        seg[BYTES] = vals
        seg.loc[rows, "label"] = 1
        return seg
    # random_injected: one extra frame halfway between consecutive real frames of the target
    t = seg["t"].to_numpy()
    all_t = np.flatnonzero(is_t)
    extra = []
    for r in rows:
        nxt = all_t[all_t > r]
        if not len(nxt):
            break
        row = seg.iloc[r].copy()
        row["t"] = (t[r] + t[nxt[0]]) / 2
        cols = rng.choice(8, rng.integers(3, 9), replace=False)
        for c in cols:
            row[BYTES[c]] = rng.integers(0, 256)
        row["label"] = 1
        extra.append(row)
    out = pd.concat([seg, pd.DataFrame(extra)], ignore_index=True).sort_values("t", kind="stable")
    out[BYTES] = out[BYTES].astype(np.uint8)
    return out.reset_index(drop=True)


def make_synthetic(split: str, profile: dict, n_attacks: int | None = None) -> tuple[pd.DataFrame, dict]:
    """Synthetic attack captures for one split, in load_split()'s format.
    Returns (frames, {capture name: source drive})."""
    n_attacks = N_ATTACKS[split] if n_attacks is None else n_attacks
    rng = np.random.default_rng({"train": SEED, "val": SEED + 1, "test": SEED + 2}[split])
    groups = id_groups(profile)
    targets = {a for a, s in groups.items() if s == split}
    names = [n for n, s in AMBIENT_SPLIT.items() if s == split]
    path = {n: DATASET_PROCESSED_DIR / "ambient" / f"{n}.parquet" for n in names}
    minutes = []
    for n in names:
        t = pd.read_parquet(path[n], columns=["t"])["t"]
        minutes.append(t.iloc[-1] - t.iloc[0])
    minutes = np.array(minutes)
    cache = {}

    def drive(n):
        if n not in cache:
            if len(cache) >= MAX_CACHED_DRIVES:
                cache.pop(next(iter(cache)))
            cache[n] = pd.read_parquet(path[n])
        return cache[n]

    parts, source = [], {}
    for i in range(n_attacks):
        name = str(rng.choice(names, p=minutes / minutes.sum()))
        seg = _segment(drive(name), rng)
        present = sorted(targets & set(seg.loc[seg["t"] >= ATTACK_START_S, "id"].astype(int).unique()))
        target = int(rng.choice(present))
        kind = TYPES[i % len(TYPES)]
        df = _attack(seg, target, kind, rng)
        cap = f"synth_{split}_{i:03d}_{kind}_{target:03X}"
        df["capture"], df["attack"] = cap, kind
        df["variant"] = "fabrication" if kind == "random_injected" else "masquerade"
        parts.append(df)
        source[cap] = name
    out = pd.concat(parts, ignore_index=True)
    out["label"] = out["label"].astype(np.int8)
    return out, source


if __name__ == "__main__":
    from road_profile import get_profile
    prof = get_profile()
    g = id_groups(prof)
    print({s: sum(v == s for v in g.values()) for s in ("train", "val", "test")}, "IDs per group")
    for split in ("val", "test"):
        df, src = make_synthetic(split, prof)
        lab = df[df["label"] == 1]
        print(f"{split}: {df['capture'].nunique()} attacks, {len(lab):,} forged frames, "
              f"{lab.groupby('attack', observed=True).size().to_dict()}, targets {sorted(lab['id'].unique())[:12]}...")
