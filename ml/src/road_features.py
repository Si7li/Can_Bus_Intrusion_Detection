"""ROAD: train/val/test split and per-frame features (profile: see road_profile.py).

Everything here must be reproducible on the STM32 in a single pass over the
bus, keeping only small per-ID state (previous bytes, previous timestamp).

Split: whole captures, never frames. Random frame splits would put
neighbouring, nearly identical frames in train and test. Each `_masquerade`
capture is a copy of its fabrication capture, so both always share a split.
- attacks: instance 3 -> train, 2 -> val, 1 -> test
- max_engine_coolant_temp has one instance only: test only, so it doubles as
  an attack the model never saw during training.
- ambient: one road drive and two dyno drives are held out for val/test, so the
  false-alarm rate is measured on drives the model never saw.
"""

import re

import numpy as np
import pandas as pd
from pandas.api.types import union_categoricals

from common import DATASET, DATASET_PROCESSED_DIR, RANGE_STRONG_ALL_CHECKED

BYTES = [f"b{i}" for i in range(8)]
DELTAS = [f"d{i}" for i in range(8)]

AMBIENT_SPLIT = {
    "ambient_dyno_drive_basic_long": "train",
    "ambient_dyno_drive_extended_long": "train",
    "ambient_dyno_exercise_all_bits": "train",
    "ambient_dyno_idle_radio_infotainment": "train",
    "ambient_dyno_drive_winter": "train",
    "ambient_dyno_reverse": "train",             # only ambient capture in reverse: needed in train
    "ambient_highway_street_driving_long": "train",
    "ambient_dyno_drive_extended_short": "val",
    "ambient_dyno_drive_radio_infotainment": "val",
    "ambient_dyno_drive_basic_short": "test",
    "ambient_dyno_drive_benign_anomaly": "test",
    "ambient_highway_street_driving_diagnostics": "test",
}
INSTANCE_SPLIT = {"3": "train", "2": "val", "1": "test"}


def attack_split(name: str) -> str:
    if name.startswith("max_engine_coolant_temp"):
        return "test"
    m = re.search(r"_attack_(\d)", name)
    return INSTANCE_SPLIT[m.group(1)]


if DATASET == "mirgu":          # CAN-MIRGU: split fixed in mirgu_split.py
    import mirgu_split
    AMBIENT_SPLIT = {p.stem: mirgu_split.ambient_split(p.stem)
                     for p in sorted((DATASET_PROCESSED_DIR / "ambient").glob("*.parquet"))}
    attack_split = mirgu_split.attack_split  # noqa: F811


def captures(split: str) -> list[tuple[str, str]]:
    """[(subfolder, capture_name)] for one split."""
    out = [("ambient", n) for n, s in AMBIENT_SPLIT.items() if s == split]
    for p in sorted((DATASET_PROCESSED_DIR / "attacks").glob("*.parquet")):
        if attack_split(p.stem) == split:
            out.append(("attacks", p.stem))
    return out


def load_split(split: str) -> pd.DataFrame:
    parts = []
    for sub, name in captures(split):
        df = pd.read_parquet(DATASET_PROCESSED_DIR / sub / f"{name}.parquet")
        df["capture"] = pd.Categorical.from_codes(np.zeros(len(df), np.int8), [name])
        if "variant" not in df.columns:     # ROAD: from the name (MIRGU stores it)
            df["variant"] = ("ambient" if sub == "ambient"
                             else "masquerade" if name.endswith("_masquerade") else "fabrication")
        for c in ("attack", "variant"):
            df[c] = df[c].astype("category")
        parts.append(df)
    # categories sorted by name, as astype("category") on strings would do (keeps ROAD's row order)
    cats = {c: union_categoricals([p[c] for p in parts], sort_categories=True)
            for c in ("capture", "attack", "variant")}
    df = pd.concat([p.drop(columns=list(cats)) for p in parts], ignore_index=True)
    for c, v in cats.items():
        df[c] = v
    return df


# ---------------------------------------------------------------- features
def add_gaps(df: pd.DataFrame, deltas: bool = True) -> pd.DataFrame:
    """dt = seconds since the previous frame with the same ID in the same capture,
    d0..d7 = byte change since that frame (NaN for the first frame of an ID).
    d is float32 (whole numbers -255..255, exact); deltas=False skips it (profile)."""
    df = df.sort_values(["capture", "t"], kind="stable")
    g = df.groupby(["capture", "id"], observed=True, sort=False)
    df["dt"] = g["t"].diff()
    if deltas:
        for b, d in zip(BYTES, DELTAS):
            df[d] = (df[b].astype(np.float32) - g[b].shift(1).astype(np.float32)).astype(np.float32)
    return df


def chunks(df: pd.DataFrame, max_frames: int = 3_000_000):
    """Split df into groups of whole captures (in add_gaps order), at most ~max_frames
    each, to bound memory. Exact: every per-frame value (gaps, features, rules,
    smoothing) depends only on the frame's own capture."""
    groups = [g for _, g in df.groupby("capture", observed=True, sort=True)]
    cur, n = [], 0
    for g in groups:
        if cur and n + len(g) > max_frames:
            yield pd.concat(cur)
            cur, n = [], 0
        cur.append(g)
        n += len(g)
    if cur:
        yield pd.concat(cur)


def novelty(df: pd.DataFrame, profile: dict, modes: tuple = (1, 2)) -> np.ndarray:
    """(n, 8) bool: byte value not normal for this ID, using the check chosen per
    byte in the profile (1 = never seen exactly, 2 = outside the seen range + margin,
    0 = byte ignored because new values are common in normal driving)."""
    ids = sorted(profile["seen"])
    n_ids = len(ids)
    seen = np.zeros((n_ids + 1, 8, 256), bool)       # last row = unknown ID
    mode = np.zeros((n_ids + 1, 8), np.int8)
    lo = np.zeros((n_ids + 1, 8), np.int16)
    hi = np.full((n_ids + 1, 8), 255, np.int16)
    for i, aid in enumerate(ids):
        for j, h in enumerate(profile["seen"][aid]):
            seen[i, j] = np.unpackbits(np.frombuffer(bytes.fromhex(h), dtype=np.uint8)).astype(bool)
        mode[i] = profile["novelty_mode"][aid]
        lo[i], hi[i] = profile["ids"][aid]["range_lo"], profile["ids"][aid]["range_hi"]
    idx = df["id"].map({a: i for i, a in enumerate(ids)}).fillna(n_ids).astype(int).to_numpy()
    out = np.zeros((len(df), 8), bool)
    for j, b in enumerate(BYTES):
        v = df[b].to_numpy().astype(np.int16)
        m = mode[idx, j]
        exact = (m == 1) & ~seen[idx, j, v]
        outside = (m == 2) & ((v < lo[idx, j]) | (v > hi[idx, j]))
        out[:, j] = (exact if 1 in modes else False) | (outside if 2 in modes else False)
    return out


def context_surprise(df: pd.DataFrame, profile: dict, per_pair: bool = False):
    """Signal-pair check: how unlikely each byte is, given the latest value of its
    partner byte in another ID (bits; 0 = no partner or no information).

    Returns (n, 8) float32, the surprise per byte position; with per_pair=True,
    a list with, for each pair, the surprises of the frames of its ID.
    """
    df = df[["capture", "t", "id"] + BYTES].copy()
    df["capture"] = df["capture"].astype(str)
    df["row"] = np.arange(len(df))
    df = df.sort_values("t", kind="stable")
    out = np.zeros((len(df), 8), np.float32)
    pair_out = []
    for pr in profile["pairs"]:
        a, ab = pr["id"], f"b{pr['byte']}"
        p, pb = pr["partner_id"], f"b{pr['partner_byte']}"
        tgt = df.loc[df["id"] == a, ["capture", "t", "row", ab]]
        src = df.loc[df["id"] == p, ["capture", "t", pb]].rename(columns={pb: "partner"})
        m = pd.merge_asof(tgt, src, on="t", by="capture", direction="backward", allow_exact_matches=False)
        table = np.asarray(pr["surprise"], dtype=np.float32)              # [a_index][b_index]
        a_idx = m[ab].map({v: i for i, v in enumerate(pr["a_values"])})
        b_idx = m["partner"].map({v: i for i, v in enumerate(pr["b_values"])})
        s = np.zeros(len(m), np.float32)
        ok = a_idx.notna().to_numpy() & b_idx.notna().to_numpy()
        s[ok] = table[a_idx[ok].astype(int), b_idx[ok].astype(int)]
        # value never seen with ANY partner value: maximal surprise for this table
        s[a_idx.isna().to_numpy() & b_idx.notna().to_numpy()] = table.max()
        rows = m["row"].to_numpy()
        out[rows, pr["byte"]] = np.maximum(out[rows, pr["byte"]], s)
        if per_pair:
            pair_out.append(s)
    return pair_out if per_pair else out


def make_features(df: pd.DataFrame, profile: dict) -> tuple[np.ndarray, list[str]]:
    """Per-frame feature vector for the AI model. df must come from add_gaps().

    - id_index  : position of the ID in the whitelist (unknown IDs never reach the AI)
    - nov0..7   : byte value never seen for this ID in normal traffic (0/1), nov_count
    - s0..7     : signal-pair surprise per byte (bits / 16), s_max
    - d0..7     : byte change since the previous frame of this ID / 255
    - dt_norm   : gap since the previous frame of this ID / nominal period of the ID

    Raw byte values are NOT features: they describe what the car is doing (speed,
    pedal...), and a model trained on them learns the driving situation of the
    attack recordings instead of the attacks (measured: ~1,100 false alarms/min).
    """
    ids = sorted(profile["ids"])
    period = df["id"].map({a: v["period"] for a, v in profile["ids"].items()})
    nov = novelty(df, profile)
    sur = context_surprise(df, profile)

    cols = {"id_index": df["id"].map({a: i for i, a in enumerate(ids)}).fillna(-1).to_numpy(np.float32)}
    for j in range(8):
        cols[f"nov{j}"] = nov[:, j].astype(np.float32)
    cols["nov_count"] = nov.sum(axis=1).astype(np.float32)
    for j in range(8):
        cols[f"s{j}"] = np.minimum(sur[:, j], 16) / 16
    cols["s_max"] = np.minimum(sur.max(axis=1), 16) / 16
    for d in DELTAS:
        cols[d] = df[d].fillna(0).to_numpy(np.float32) / 255.0
    cols["dt_norm"] = (df["dt"] / period).fillna(1.0).clip(0, 4).to_numpy(np.float32)
    return np.column_stack(list(cols.values())).astype(np.float32), list(cols)


def training_frames(profile: dict, n_benign: int, seed: int) -> pd.DataFrame:
    """Training split, known IDs only: every attack frame + a random sample of
    benign frames (24M benign frames are far more than needed). Shared by the
    RF and the MLP so both see exactly the same data.
    CAN-MIRGU (~95M training frames): sampled capture by capture, each capture
    contributing in proportion to its benign frames (same result in expectation,
    bounded memory)."""
    train = load_split("train")
    if DATASET == "road":
        train = add_gaps(train)
        train = train[train["id"].isin(profile["ids"].keys())]
        lab = train["label"].to_numpy()
        rng = np.random.default_rng(seed)
        benign = np.flatnonzero(lab == 0)
        benign = rng.choice(benign, size=min(n_benign, len(benign)), replace=False)
        return train.iloc[np.sort(np.concatenate([np.flatnonzero(lab == 1), benign]))]
    known = train["id"].isin(profile["ids"].keys()).to_numpy()
    rate = min(1.0, n_benign / max(1, int((known & (train["label"].to_numpy() == 0)).sum())))
    rng = np.random.default_rng(seed)
    parts = []
    for c in chunks(train):
        c = add_gaps(c)
        c = c[c["id"].isin(profile["ids"].keys())]
        keep = (c["label"].to_numpy() == 1) | (rng.random(len(c)) < rate)
        parts.append(c[keep])
    return pd.concat(parts)


def training_features(sel: pd.DataFrame, profile: dict, folds: list[dict], fold_captures: list[list[str]]):
    """Out-of-fold features for training: normal frames from the ambient drives of
    fold i are scored with the profile learned on the OTHER fold; frames from the
    attack recordings (never used to build any profile) use the full profile."""
    cap = sel["capture"].astype(str).to_numpy()
    parts = {}
    for i in range(2):
        m = np.isin(cap, fold_captures[i])
        if m.any():
            parts[i] = (m, folds[1 - i])
    rest = ~np.logical_or.reduce([m for m, _ in parts.values()]) if parts else np.ones(len(sel), bool)
    x, cols = None, None
    for m, prof in list(parts.values()) + [(rest, profile)]:
        if not m.any():
            continue
        xi, cols = make_features(sel[m], prof)
        if x is None:
            x = np.zeros((len(sel), xi.shape[1]), np.float32)
        x[m] = xi
    return x, cols


STRONG_SURPRISE_BITS = 8.0


def strong_evidence(df: pd.DataFrame, profile: dict) -> np.ndarray:
    """Per frame: is there evidence beyond 'a value never seen before'?
    - a byte outside its normal range + margin (an impossible value, e.g. speed 0xFF);
      ROAD: only bytes checked by range; CAN-MIRGU: every checked byte
      (common.RANGE_STRONG_ALL_CHECKED)
    - a broken signal pair (byte very unlikely given its partner, > 8 bits)
    Model alerts backed by this evidence are ALERTs; the others are WARNINGs
    (possibly a normal car state that the training drives never contained)."""
    outside = outside_range(df, profile) if RANGE_STRONG_ALL_CHECKED else novelty(df, profile, modes=(2,)).any(axis=1)
    broken_pair = context_surprise(df, profile).max(axis=1) > STRONG_SURPRISE_BITS
    return outside | broken_pair


def outside_range(df: pd.DataFrame, profile: dict) -> np.ndarray:
    """Per frame: a byte with a novelty check (exact set or range) is beyond the
    seen range + margin of its ID (unknown IDs: False)."""
    ids = sorted(profile["ids"])
    mode = np.array([profile["novelty_mode"][a] for a in ids], np.int8)
    lo = np.array([profile["ids"][a]["range_lo"] for a in ids], np.int16)
    hi = np.array([profile["ids"][a]["range_hi"] for a in ids], np.int16)
    k = df["id"].map({a: i for i, a in enumerate(ids)})
    known = k.notna().to_numpy()
    k = k.fillna(0).astype(int).to_numpy()
    v = df[BYTES].to_numpy().astype(np.int16)
    return ((mode[k] >= 1) & ((v < lo[k]) | (v > hi[k]))).any(axis=1) & known
