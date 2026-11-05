"""Definitions shared by every ML script.

Anything here must match what the STM32 firmware does, so change it in one
place only. The device sees, per CAN frame, an 11-bit ID and 8 data bytes;
the features are exactly those values scaled to [0, 1].
"""

from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "decimal"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
RESULTS_DIR = PROJECT_ROOT / "results"

ROAD_RAW_DIR = PROJECT_ROOT / "data" / "raw" / "road" / "road"   # extracted road.zip
ROAD_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "road"

SEED = 42

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
