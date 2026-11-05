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
                      occur (256-bit mask; 106 IDs x 8 bytes x 32 B = 27 KB),
                      the min..max range, and which check is reliable for that
                      byte (exact set / range / none), cross-validated like the pairs
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


MAX_NOVEL_PER_MIN = 1.0
RANGE_MARGIN = 0.5      # range check flags values beyond min/max by > 50% of the range width


def range_bounds(lo: int, hi: int) -> tuple[int, int]:
    """Seen range widened by a margin: new drives go a little beyond the training
    range (e.g. a higher speed), attacks typically go far beyond it (0xFF)."""
    m = max(4, int(RANGE_MARGIN * (hi - lo)))
    return lo - m, hi + m


def novelty_modes(amb: pd.DataFrame) -> dict:
    """Per ID and byte, the strictest 'never seen' check that stays quiet on drives
    it was not learned from: 1 = exact set of seen values, 2 = outside the seen
    min..max range widened by a margin (see range_bounds), 0 = neither (byte ignored, e.g. values that change from drive
    to drive). Cross-validated on the two halves of the training drives."""
    fold_amb = [amb[amb["capture"].isin(f)] for f in FOLDS]
    minutes = [sum(g["t"].iloc[-1] - g["t"].iloc[0] for _, g in a.groupby("capture", observed=True)) / 60
               for a in fold_amb]
    stats = []   # per fold: {(id, byte): (set of values, min, max)}
    for a in fold_amb:
        d = {}
        for aid, g in a.groupby("id", observed=True):
            for b in BYTES:
                v = g[b].to_numpy()
                d[(int(aid), b)] = (np.unique(v), int(v.min()), int(v.max()))
        stats.append(d)
    modes = {}
    for aid in sorted(amb["id"].unique().tolist()):
        row = []
        for b in BYTES:
            set_ok = range_ok = True
            for i, j in [(0, 1), (1, 0)]:
                if (aid, b) not in stats[i]:
                    set_ok = range_ok = False
                    continue
                vals, lo, hi = stats[i][(aid, b)]
                other = fold_amb[j].loc[fold_amb[j]["id"] == aid, b].to_numpy().astype(np.int16)
                set_ok &= (~np.isin(other, vals)).sum() / minutes[j] <= MAX_NOVEL_PER_MIN
                lo_x, hi_x = range_bounds(lo, hi)
                range_ok &= ((other < lo_x) | (other > hi_x)).sum() / minutes[j] <= MAX_NOVEL_PER_MIN
            row.append(1 if set_ok else 2 if range_ok else 0)
        modes[int(aid)] = row
    return modes


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
        ids[aid]["min"] = [int(g[b].min()) for b in BYTES]
        ids[aid]["max"] = [int(g[b].max()) for b in BYTES]
        bounds = [range_bounds(lo, hi) for lo, hi in zip(ids[aid]["min"], ids[aid]["max"])]
        ids[aid]["range_lo"] = [b[0] for b in bounds]
        ids[aid]["range_hi"] = [b[1] for b in bounds]
        for b in BYTES:
            vals = np.unique(g[b].to_numpy())
            mask = np.zeros(256, bool)
            mask[vals] = True
            masks.append(np.packbits(mask).tobytes().hex())
            if MIN_VALUES <= len(vals) <= MAX_VALUES:
                candidates[(aid, b)] = vals.tolist()
        seen[aid] = masks
    print(f"  {len(ids)} IDs, {len(candidates)} state-like bytes; searching signal pairs...", flush=True)
    modes = novelty_modes(amb)
    flat = [m for row in modes.values() for m in row]
    print(f"  novelty check per byte: exact set {flat.count(1)}, range {flat.count(2)}, "
          f"ignored {flat.count(0)} (of {len(flat)})", flush=True)
    states = build_states(amb, candidates)
    pairs = select_pairs(amb, states, candidates)
    print(f"  done in {time.perf_counter() - t0:.0f} s")
    return {"ids": ids, "seen": seen, "novelty_mode": modes, "pairs": pairs}


def fold_profile(amb_subset: pd.DataFrame, base: dict) -> dict:
    """Same structure as the full profile (same checks, same signal pairs) but the
    value tables are learned from a subset of the training drives only.

    Used for out-of-fold training features: normal training frames are scored
    against a profile that did NOT see them, so the model learns that normal
    driving sometimes produces new values (otherwise new values would be 0 for
    every normal training frame and the model would treat any new value as an attack)."""
    ids = {a: dict(v) for a, v in base["ids"].items()}
    seen = dict(base["seen"])
    for aid, g in amb_subset.groupby("id", observed=True):
        aid = int(aid)
        lo = [int(g[b].min()) for b in BYTES]
        hi = [int(g[b].max()) for b in BYTES]
        bounds = [range_bounds(a, b) for a, b in zip(lo, hi)]
        ids[aid].update(min=lo, max=hi, range_lo=[b[0] for b in bounds], range_hi=[b[1] for b in bounds])
        masks = []
        for b in BYTES:
            mask = np.zeros(256, bool)
            mask[np.unique(g[b].to_numpy())] = True
            masks.append(np.packbits(mask).tobytes().hex())
        seen[aid] = masks
    keys = [(p["id"], f"b{p['byte']}", p["partner_id"], f"b{p['partner_byte']}") for p in base["pairs"]]
    cands = {(k[0], k[1]): None for k in keys} | {(k[2], k[3]): None for k in keys}
    states = build_states(amb_subset, cands)
    pairs = [fit_table(states, k) for k in keys]
    return {"ids": ids, "seen": seen, "novelty_mode": base["novelty_mode"], "pairs": pairs}


def fold_profiles(base: dict) -> list[dict]:
    """[profile learned on FOLDS[0], profile learned on FOLDS[1]], cached."""
    out = []
    train = None
    for i in range(2):
        path = RESULTS_DIR / f"road_profile_fold{i + 1}.json"
        if path.exists() and path.stat().st_mtime >= PROFILE_PATH.stat().st_mtime:
            p = json.loads(path.read_text())
        else:
            if train is None:
                train = load_split("train")
                train = train[train["variant"] == "ambient"]
            p = fold_profile(train[train["capture"].isin(FOLDS[i])], base)
            path.write_text(json.dumps(p))
            p = json.loads(path.read_text())
        p["ids"] = {int(k): v for k, v in p["ids"].items()}
        p["seen"] = {int(k): v for k, v in p["seen"].items()}
        p["novelty_mode"] = {int(k): v for k, v in p["novelty_mode"].items()}
        out.append(p)
    return out


def save_profile(profile: dict):
    RESULTS_DIR.mkdir(exist_ok=True)
    PROFILE_PATH.write_text(json.dumps(profile))


def load_profile() -> dict:
    p = json.loads(PROFILE_PATH.read_text())
    p["ids"] = {int(k): v for k, v in p["ids"].items()}
    p["seen"] = {int(k): v for k, v in p["seen"].items()}
    p["novelty_mode"] = {int(k): v for k, v in p.get("novelty_mode", {}).items()}
    return p


def get_profile(rebuild: bool = False) -> dict:
    if PROFILE_PATH.exists() and not rebuild:
        p = load_profile()
        if "pairs" in p and p["novelty_mode"]:
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
