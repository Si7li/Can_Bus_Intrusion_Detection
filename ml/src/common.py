"""Definitions shared by every ML script.

Anything here must match what the STM32 firmware does, so change it in one
place only. The device sees, per CAN frame, an 11-bit ID and 8 data bytes;
the features are exactly those values scaled to [0, 1].
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "decimal"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

ROAD_RAW_DIR = PROJECT_ROOT / "data" / "raw" / "road" / "road"   # extracted road.zip
ROAD_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "road"
MIRGU_RAW_DIR = PROJECT_ROOT / "data" / "raw" / "mirgu" / "drive" / "CAN-MIRGU"
MIRGU_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "mirgu"

SEED = 42

# Which car the road_* scripts (profile, training, export, C check) work on:
#   IDS_DATASET=road  (default) ROAD; results in results/
#   IDS_DATASET=mirgu           CAN-MIRGU; same code, results in results/mirgu/
DATASET = os.environ.get("IDS_DATASET", "road").lower()
if DATASET not in ("road", "mirgu"):
    raise ValueError(f"IDS_DATASET must be 'road' or 'mirgu', not {DATASET!r}")
RESULTS_DIR = PROJECT_ROOT / "results" if DATASET == "road" else PROJECT_ROOT / "results" / "mirgu"
DATASET_PROCESSED_DIR = ROAD_PROCESSED_DIR if DATASET == "road" else MIRGU_PROCESSED_DIR

# Severity rule, "impossible value" part: a byte beyond its normal range + margin.
#   False (ROAD, as published): checked only on bytes whose novelty check is the range.
#   True  (CAN-MIRGU): on every checked byte (exact-set bytes too). Chosen on MIRGU's
#   val split: MIRGU's profile uses the exact set on 415 of 448 bytes, so with False
#   no model detection could ever become an ALERT. Model inputs are unchanged.
RANGE_STRONG_ALL_CHECKED = DATASET == "mirgu"

# Which ROAD MLP the export / check scripts use, and the file names it is saved under.
# v1 = the model evaluated before the live tests (results/road_mlp_*).
# v2 = v1's data + synthetic random-data attacks (synthetic_attacks.py), trained after
#      the live tests found that v1 misses random data on a real ID (post-test revision).
# CAN-MIRGU: one model, trained like v2 (results/mirgu/mirgu_mlp_*).
MODEL_VERSION = "v2"
if DATASET == "mirgu":
    MLP_NAME = "mirgu_mlp"
else:
    MLP_NAME = "road_mlp" if MODEL_VERSION == "v1" else f"road_mlp_{MODEL_VERSION}"

BYTE_COLS = [f"DATA_{i}" for i in range(8)]
FEATURE_COLS = ["ID"] + BYTE_COLS  # 9 features

# Fixed class order = the model's output index. The firmware uses the same order.
CLASSES = ["benign", "dos", "spoof_gas", "spoof_rpm", "spoof_speed", "spoof_steering"]
CLASS_TO_INDEX = {name: i for i, name in enumerate(CLASSES)}


def to_features(df: pd.DataFrame) -> np.ndarray:
    """ID / 2047 and each byte / 255, as float32 (what the MCU computes per frame)."""
    x = df[FEATURE_COLS].to_numpy(dtype=np.float32)
    x[:, 0] /= 2047.0
    x[:, 1:] /= 255.0
    return x


def normalize_class(raw: str) -> str:
    """Map the dataset's class names (e.g. 'SPEED', 'STEERING_WHEEL', 'DoS ')
    to the short names in CLASSES. Raises on anything unexpected."""
    s = str(raw).strip().upper().replace("-", "_").replace(" ", "_")
    if "BENIGN" in s:
        return "benign"
    if "DOS" in s:
        return "dos"
    if "GAS" in s:
        return "spoof_gas"
    if "RPM" in s:
        return "spoof_rpm"
    if "SPEED" in s:
        return "spoof_speed"
    if "STEER" in s:
        return "spoof_steering"
    raise ValueError(f"Unknown class name in dataset: {raw!r}")
