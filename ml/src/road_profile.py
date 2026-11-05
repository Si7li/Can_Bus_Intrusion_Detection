"""Build the normal-traffic profile used by the rules and the AI features (ROAD).

    python ml/src/road_profile.py

Learned from the TRAINING ambient captures only (never from attacks), then
checked on the validation ambient captures. Everything in it becomes a small
lookup table in the STM32 firmware:

Pairs are cross-validated inside the training data: searched on each half of
the training drives, kept only if found in both halves and quiet (<= 1
surprising frame/min) on the other half.

1. whitelist        : the IDs seen in normal traffic
2. timing           : per ID, nominal period and shortest normal gap (rate rule)
3. seen values      : per ID and byte position, which of the 256 values ever
                      occur (256-bit mask; 106 IDs x 8 bytes x 32 B = 27 KB)
4. signal pairs     : for each state-like byte (2..16 distinct values: gear,
                      lights, flags...), the byte of ANOTHER ID that predicts it
                      best, and the table P(value | partner value). A frame whose
                      byte is very unlikely given its partner's latest value
                      contradicts the rest of the car (e.g. reverse light on
                      while the gear signal says Drive).

Pairs are found automatically by a search over all byte pairs, not chosen by
hand, so the method is not tuned to the attacks in the dataset.
"""

import json
import time

import numpy as np
import pandas as pd

from common import RESULTS_DIR, SEED
from road_features import BYTES, add_gaps, load_split

PROFILE_PATH = RESULTS_DIR / "road_profile.json"

MIN_VALUES, MAX_VALUES = 2, 16      # state-like bytes
MIN_ENTROPY_BITS = 0.05             # skip bytes that are almost constant
MIN_UNCERTAINTY_COEF = 0.8          # partner must explain >= 80% of the byte's entropy
QUERY_FRAMES_PER_ID = 8_000         # per capture, for the pair search (7 captures -> up to 56k per ID)
SMOOTHING = 0.5                     # Laplace smoothing of P(value | partner)


def entropy(counts: np.ndarray) -> float:
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def latest_values(queries: pd.DataFrame, cap_frames: pd.DataFrame, partner_cols: dict) -> pd.DataFrame:
    """For each query frame, the latest value of every partner byte (ID B, byte j)
    seen before it in the same capture: what the STM32 keeps in RAM."""
    out = queries[["t", "id"] + BYTES].sort_values("t").reset_index(drop=True)
    left = out[["t"]]
    cols = {}
    for aid, byte_list in partner_cols.items():
        src = cap_frames.loc[cap_frames["id"] == aid, ["t"] + byte_list].sort_values("t")
        m = pd.merge_asof(left, src, on="t", direction="backward", allow_exact_matches=False)
        for b in byte_list:   # int16 with -1 = partner not seen yet (keeps memory small)
            cols[f"{aid}:{b}"] = m[b].fillna(-1).to_numpy(np.int16)
    return pd.concat([out, pd.DataFrame(cols)], axis=1)


def build_states(amb: pd.DataFrame, candidates: dict) -> pd.DataFrame:
    """Sampled query frames + latest value of every candidate partner byte."""
    rng = np.random.default_rng(SEED)
    partner_cols = {}
    for (aid, b) in candidates:
        partner_cols.setdefault(aid, []).append(b)
    tables = []
    for cap, g in amb.groupby("capture", observed=True):
        q = []
        for aid in partner_cols:
            idx = np.flatnonzero(g["id"].to_numpy() == aid)
            if len(idx) > QUERY_FRAMES_PER_ID:
                idx = rng.choice(idx, QUERY_FRAMES_PER_ID, replace=False)
            q.append(g.iloc[idx])
        tables.append(latest_values(pd.concat(q), g, partner_cols).assign(capture=str(cap)))
    return pd.concat(tables, ignore_index=True)


def joint_counts(rows: pd.DataFrame, b: str, pid: int, pb: str):
    col = rows[f"{pid}:{pb}"].to_numpy()
    ok = col >= 0
    if ok.sum() < 100:
        return None
    return np.bincount(rows[b].to_numpy()[ok].astype(np.int64) * 256 + col[ok].astype(np.int64),
                       minlength=65536).reshape(256, 256)                    # [a, b]


def uncertainty_coef(joint: np.ndarray) -> float:
    """Share of the byte's entropy explained by the partner (0 = nothing, 1 = fully)."""
    n_b = joint.sum(axis=0)
    h_a = entropy(joint.sum(axis=1))
    if h_a == 0:
        return 0.0
    h_a_given_b = sum(n_b[v] / n_b.sum() * entropy(joint[:, v]) for v in np.flatnonzero(n_b))
    return 1 - h_a_given_b / h_a


def search_pairs(states: pd.DataFrame, candidates: dict) -> dict:
    """For each state-like byte, the best partner byte in another ID, if U >= threshold."""
    found = {}
    for (aid, b) in candidates:
        rows = states[states["id"] == aid]
        if entropy(np.bincount(rows[b].to_numpy(), minlength=256)) < MIN_ENTROPY_BITS:
            continue
        best = (0.0, None)
        for (pid, pb) in candidates:
            if pid == aid:
                continue
            joint = joint_counts(rows, b, pid, pb)
            if joint is not None:
                u = uncertainty_coef(joint)
                if u > best[0]:
                    best = (u, (pid, pb))
        if best[0] >= MIN_UNCERTAINTY_COEF:
            found[(aid, b, *best[1])] = best[0]
    return found


def fit_table(states: pd.DataFrame, key) -> dict:
    aid, b, pid, pb = key
    joint = joint_counts(states[states["id"] == aid], b, pid, pb)
    a_list = sorted(np.flatnonzero(joint.sum(axis=1)).tolist())
    b_list = sorted(np.flatnonzero(joint.sum(axis=0)).tolist())
    sub = joint[np.ix_(a_list, b_list)].astype(float) + SMOOTHING
    p = sub / sub.sum(axis=0, keepdims=True)                                  # P(a | b)
    return {"id": int(aid), "byte": int(b[1]), "partner_id": int(pid), "partner_byte": int(pb[1]),
            "u": round(uncertainty_coef(joint), 4), "a_values": a_list, "b_values": b_list,
            "surprise": np.round(-np.log2(p), 2).tolist(),                     # [a][b] in bits
            "frames": int(joint.sum())}


def surprising_per_minute(pair: dict, states: pd.DataFrame, id_frames_per_min: float) -> float:
    """Frames per minute whose surprise exceeds 8 bits, on held-out states."""
    rows = states[states["id"] == pair["id"]]
    a = rows[f"b{pair['byte']}"].map({v: i for i, v in enumerate(pair["a_values"])})
    bv = rows[f"{pair['partner_id']}:b{pair['partner_byte']}"].map({v: i for i, v in enumerate(pair["b_values"])})
    table = np.asarray(pair["surprise"])
    known_b = bv.notna().to_numpy()
    s = np.where(a.isna().to_numpy(), table.max(), 0.0)
    ok = known_b & a.notna().to_numpy()
    s[ok] = table[a[ok].astype(int), bv[ok].astype(int)]
    s[~known_b] = 0.0
    return float((s > 8).mean() * id_frames_per_min) if len(s) else 0.0


# Two halves of the training ambient captures, used to keep only pairs that
# hold on drives they were not learned from (validation captures stay untouched).
FOLDS = [
    ["ambient_dyno_drive_basic_long", "ambient_dyno_exercise_all_bits", "ambient_dyno_drive_winter",
     "ambient_dyno_reverse"],
    ["ambient_dyno_drive_extended_long", "ambient_dyno_idle_radio_infotainment",
     "ambient_highway_street_driving_long"],
]
MAX_SURPRISING_PER_MIN = 1.0


def select_pairs(amb: pd.DataFrame, states: pd.DataFrame, candidates: dict) -> list[dict]:
    fold_states = [states[states["capture"].isin(f)] for f in FOLDS]
    fold_amb = [amb[amb["capture"].isin(f)] for f in FOLDS]
    minutes = [sum(g["t"].iloc[-1] - g["t"].iloc[0] for _, g in a.groupby("capture", observed=True)) / 60
               for a in fold_amb]
    found = []
    for i in range(2):
        found.append(search_pairs(fold_states[i], candidates))
        print(f"  fold {i + 1}: {len(found[i])} pairs found", flush=True)

    kept, rejected = [], {"not found in both halves": 0, "noisy on the other half": 0}
    for key in sorted(set(found[0]) | set(found[1])):
        if key not in found[0] or key not in found[1]:
            rejected["not found in both halves"] += 1
            continue
        noisy = False
        for i, j in [(0, 1), (1, 0)]:
            pair = fit_table(fold_states[i], key)
            per_min = (fold_amb[j]["id"] == key[0]).sum() / minutes[j]
            if surprising_per_minute(pair, fold_states[j], per_min) > MAX_SURPRISING_PER_MIN:
                noisy = True
        if noisy:
            rejected["noisy on the other half"] += 1
        else:
            kept.append(fit_table(states, key))      # final table: all training captures
    print(f"  kept {len(kept)} pairs; rejected: {rejected}")
    return kept


def build_profile() -> dict:
    t0 = time.perf_counter()
    train = load_split("train")
    amb = add_gaps(train[train["variant"] == "ambient"].copy())

    ids = {}
    seen = {}
    candidates = {}
    for aid, g in amb.groupby("id", observed=True):
        aid = int(aid)
        gaps = g["dt"].dropna().to_numpy()
        ids[aid] = {"period": float(np.median(gaps)), "gap_q001": float(np.quantile(gaps, 0.001)),
                    "frames": int(len(g))}
        masks = []
        for b in BYTES:
            vals = np.unique(g[b].to_numpy())
            mask = np.zeros(256, bool)
            mask[vals] = True
            masks.append(np.packbits(mask).tobytes().hex())
            if MIN_VALUES <= len(vals) <= MAX_VALUES:
                candidates[(aid, b)] = vals.tolist()
        seen[aid] = masks
    print(f"  {len(ids)} IDs, {len(candidates)} state-like bytes; searching signal pairs...", flush=True)
    states = build_states(amb, candidates)
    pairs = select_pairs(amb, states, candidates)
    print(f"  done in {time.perf_counter() - t0:.0f} s")
    return {"ids": ids, "seen": seen, "pairs": pairs}


def save_profile(profile: dict):
    RESULTS_DIR.mkdir(exist_ok=True)
    PROFILE_PATH.write_text(json.dumps(profile))


def load_profile() -> dict:
    p = json.loads(PROFILE_PATH.read_text())
    p["ids"] = {int(k): v for k, v in p["ids"].items()}
    p["seen"] = {int(k): v for k, v in p["seen"].items()}
    return p


def get_profile(rebuild: bool = False) -> dict:
    if PROFILE_PATH.exists() and not rebuild:
        p = load_profile()
        if "pairs" in p:
            return p
    print("Building normal-traffic profile from the training ambient captures...", flush=True)
    p = build_profile()
    save_profile(p)
    return load_profile()


def main():
    from road_features import context_surprise
    profile = get_profile(rebuild=True)
    val = load_split("val")
    amb = val[val["variant"] == "ambient"]
    surprises = context_surprise(amb, profile, per_pair=True)
    rows = []
    for pair, s in zip(profile["pairs"], surprises):
        name = f"0x{pair['id']:03X}.b{pair['byte']} <- 0x{pair['partner_id']:03X}.b{pair['partner_byte']}"
        rows.append((name, pair["u"], len(pair["a_values"]), int((s > 8).sum()), len(s)))
    rows.sort(key=lambda r: -r[3])
    total = sum(r[3] for r in rows)
    minutes = sum(g["t"].iloc[-1] - g["t"].iloc[0] for _, g in amb.groupby("capture", observed=True)) / 60
    print(f"\nCheck on VAL ambient ({minutes:.1f} min of normal driving never used to build the profile):")
    print(f"frames with a pair surprise > 8 bits (P < 1/256): {total:,} = {total / minutes:.1f} per minute")
    print(f"\n{'pair (byte <- partner)':30s} {'U':>5s} {'values':>6s} {'>8 bits':>8s} {'of frames':>10s}")
    for r in rows[:12]:
        print(f"{r[0]:30s} {r[1]:5.2f} {r[2]:6d} {r[3]:8,} {r[4]:10,}")
    print("...")
    print(f"pairs with zero surprising frames on val: {sum(r[3] == 0 for r in rows)} / {len(rows)}")
    print(f"\nProfile written to {PROFILE_PATH}")


if __name__ == "__main__":
    main()
