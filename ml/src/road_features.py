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

from common import ROAD_PROCESSED_DIR

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


def captures(split: str) -> list[tuple[str, str]]:
    """[(subfolder, capture_name)] for one split."""
    out = [("ambient", n) for n, s in AMBIENT_SPLIT.items() if s == split]
    for p in sorted((ROAD_PROCESSED_DIR / "attacks").glob("*.parquet")):
        if attack_split(p.stem) == split:
            out.append(("attacks", p.stem))
    return out


def load_split(split: str) -> pd.DataFrame:
    parts = []
    for sub, name in captures(split):
        df = pd.read_parquet(ROAD_PROCESSED_DIR / sub / f"{name}.parquet")
        df["capture"] = name
        df["variant"] = ("ambient" if sub == "ambient"
                         else "masquerade" if name.endswith("_masquerade") else "fabrication")
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    df["capture"] = df["capture"].astype("category")
    df["attack"] = df["attack"].astype("category")
    return df


# ---------------------------------------------------------------- features
def add_gaps(df: pd.DataFrame) -> pd.DataFrame:
    """dt = seconds since the previous frame with the same ID in the same capture,
    d0..d7 = byte change since that frame (NaN for the first frame of an ID)."""
    df = df.sort_values(["capture", "t"], kind="stable")
    g = df.groupby(["capture", "id"], observed=True, sort=False)
    df["dt"] = g["t"].diff()
    prev = g[BYTES].shift(1)
    for b, d in zip(BYTES, DELTAS):
        df[d] = df[b].astype(np.int16) - prev[b]   # float, NaN on first frame
    return df


def novelty(df: pd.DataFrame, profile: dict) -> np.ndarray:
    """(n, 8) bool: byte value never seen for this ID in normal training traffic."""
    ids = sorted(profile["seen"])
    seen = np.zeros((len(ids) + 1, 8, 256), bool)      # last row = unknown ID -> nothing seen
    for i, aid in enumerate(ids):
        for j, h in enumerate(profile["seen"][aid]):
            seen[i, j] = np.unpackbits(np.frombuffer(bytes.fromhex(h), dtype=np.uint8)).astype(bool)
    idx = df["id"].map({a: i for i, a in enumerate(ids)}).fillna(len(ids)).astype(int).to_numpy()
    return np.stack([~seen[idx, j, df[b].to_numpy()] for j, b in enumerate(BYTES)], axis=1)


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
    RF and the MLP so both see exactly the same data."""
    train = add_gaps(load_split("train"))
    train = train[train["id"].isin(profile["ids"].keys())]
    lab = train["label"].to_numpy()
    rng = np.random.default_rng(seed)
    benign = np.flatnonzero(lab == 0)
    benign = rng.choice(benign, size=min(n_benign, len(benign)), replace=False)
    return train.iloc[np.sort(np.concatenate([np.flatnonzero(lab == 1), benign]))]
