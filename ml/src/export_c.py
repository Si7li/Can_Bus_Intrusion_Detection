"""Export the detector (rules + features + int8 MLP) to C headers for the STM32.

    python ml/src/export_c.py

Writes firmware/can_ids_fw/Core/Inc/ids_model.h (all tables and weights, ~40 KB
of flash) and ids_selftest_data.h (real frames + the answers Python gives
for them, checked by the firmware at boot).

IDS_DATASET=mirgu exports the CAN-MIRGU detector instead (same firmware code,
other tables and weights); IDS_DATASET=road (default) puts the ROAD one back.

Design: everything the chip would otherwise compute in floating point and that
depends on a small set of inputs is precomputed here as int8 values with exactly
the numpy expressions the Python pipeline uses (byte-change features, signal-pair
surprise, novelty counts, sigmoid). The chip only does table lookups, the
time-gap feature, and the int8 network (see mcu_model.py for its arithmetic).
"""

import json

import numpy as np
import pandas as pd

from mcu_model import F32, forward, load_params, quantize_input
from road_features import BYTES, STRONG_SURPRISE_BITS, add_gaps, make_features, strong_evidence
from road_profile import PROFILE_PATH, get_profile
from road_rules import rule_flags
from road_train_mlp import detector, drop_id
from common import DATASET, DATASET_PROCESSED_DIR, MLP_NAME, PROJECT_ROOT, RANGE_STRONG_ALL_CHECKED, RESULTS_DIR

FW_INC = PROJECT_ROOT / "firmware" / "can_ids_fw" / "Core" / "Inc"
CONFIG = json.loads((RESULTS_DIR / f"{MLP_NAME}_config.json").read_text())
N_FEATURES = len(CONFIG["features"])

# Self-test windows (validation captures, so the test split is not touched again):
# (capture, seconds before the first forged frame, number of frames)
SELFTEST = [("max_speedometer_attack_2_masquerade", 0.3, 1500),
            ("reverse_light_on_attack_2_masquerade", 0.3, 1500),
            ("fuzzing_attack_2", 0.05, 600)]
if DATASET == "mirgu":
    SELFTEST = [("ems_attack", 0.3, 1500),
                ("door_open_warning_attack", 0.05, 1500),
                ("fuzzing_valid_ids_dos", 0.05, 600)]


# ------------------------------------------------------------------ helpers
def c_float(x) -> str:
    return float.hex(float(F32(x))) + "f"


def c_double(x) -> str:
    return float.hex(float(x))


def c_array(ctype: str, name: str, a, fmt=str, per_line: int = 16) -> str:
    a = np.asarray(a)
    dims = "".join(f"[{d}]" for d in a.shape)

    def body(v, indent):
        flat = [fmt(x) for x in v]
        lines = [", ".join(flat[i:i + per_line]) for i in range(0, len(flat), per_line)]
        return (",\n" + indent).join(lines)

    if a.ndim == 1:
        return f"static const {ctype} {name}{dims} = {{\n    " + body(a, "    ") + "\n};\n"
    rows = ["{" + body(r, "     ") + "}" for r in a.reshape(a.shape[0], -1)]   # 2-D: one {...} per row
    return f"static const {ctype} {name}{dims} = {{\n    " + ",\n    ".join(rows) + "\n};\n"


def q_feature(x, p) -> np.ndarray:
    return quantize_input(np.atleast_1d(np.asarray(x, dtype=F32)).reshape(-1, 1), p).reshape(-1)


# ------------------------------------------------------------------ tables
def build(profile: dict, p: dict) -> str:
    ids = sorted(profile["ids"], key=int)
    n = len(ids)
    out = []
    w = out.append

    # --- quantized constants (same numpy expressions as make_features) ---
    q0, q1 = q_feature(0.0, p)[0], q_feature(1.0, p)[0]
    q_count = q_feature(np.arange(9, dtype=F32), p)
    q_delta = q_feature(np.arange(-255, 256).astype(F32) / 255.0, p)
    prob = (np.arange(-128, 128).astype(F32) - p["out_zero"]) * p["out_scale"]
    thr_q = int(np.flatnonzero(prob >= CONFIG["threshold"])[0]) - 128
    k_s, n_s = CONFIG["smooth"]

    w(f"#define IDS_N_IDS        {n}\n#define IDS_N_FEATURES   {N_FEATURES}\n"
      f"#define IDS_N_PAIRS      {len(profile['pairs'])}\n"
      f"#define IDS_SMOOTH_K     {k_s}     /* alert if >= K of the last N frames of an ID are suspicious */\n"
      f"#define IDS_SMOOTH_N     {n_s}\n"
      f"#define IDS_THRESHOLD    {CONFIG['threshold']}f\n"
      f"#define IDS_THRESHOLD_Q  {thr_q}    /* model output int8 >= this  <=>  probability >= threshold */\n"
      f"#define IDS_RANGE_ALL_CHECKED {int(RANGE_STRONG_ALL_CHECKED)}  /* 1: out of range on any checked byte = strong evidence */\n"
      f"#define IDS_OUT_SCALE    {c_float(p['out_scale'])}\n#define IDS_OUT_ZERO     {p['out_zero']}\n"
      f"#define IDS_IN_SCALE     {c_float(p['in_scale'])}  /* input quantization: q = round(x / scale) + zero */\n"
      f"#define IDS_IN_ZERO      {p['in_zero']}\n"
      f"#define IDS_Q_ZERO       {q0}   /* quantized 0.0 */\n#define IDS_Q_ONE        {q1}   /* quantized 1.0 */\n\n")

    # --- whitelist + rate rule ---
    index_of = np.full(4096, 0xFF, np.uint8)   # 12 bit: ROAD has ID 0xFFF
    for i, a in enumerate(ids):
        index_of[int(a)] = i
    rate_k = CONFIG["rate_k"]
    fast_us = [int(np.ceil(rate_k * profile["ids"][a]["gap_q001"] * 1e6)) for a in ids]
    w("/* Whitelist: CAN ID (12 bit, ROAD contains 0xFFF) -> index, 0xFF = unknown ID */\n")
    w(c_array("uint8_t", "ids_index_of", index_of, per_line=32))
    w(c_array("uint16_t", "ids_can_id", [int(a) for a in ids], lambda v: f"0x{v:03X}"))
    w("/* Nominal period of each ID (us), for the time-gap feature */\n")
    w(c_array("double", "ids_period_us", [profile["ids"][a]["period"] * 1e6 for a in ids], c_double, 4))
    w(f"/* Rate rule: too fast if the gap since the previous frame < this (= {rate_k} x shortest normal gap) */\n")
    w(c_array("uint32_t", "ids_fast_us", fast_us))

    # --- novelty ---
    mode = np.array([profile["novelty_mode"][a] for a in ids], np.uint8)
    seen_rows, seen_index = [], np.zeros((n, 8), np.uint16)
    for i, a in enumerate(ids):
        for j in range(8):
            if mode[i, j] == 1:
                seen_index[i, j] = len(seen_rows)
                seen_rows.append(np.frombuffer(bytes.fromhex(profile["seen"][a][j]), np.uint8))
    lo = np.array([profile["ids"][a]["range_lo"] for a in ids], np.int16)
    hi = np.array([profile["ids"][a]["range_hi"] for a in ids], np.int16)
    w("/* Novelty check per ID and byte: 0 = ignored, 1 = value never seen (bitmap), 2 = outside [lo, hi] */\n")
    w(c_array("uint8_t", "ids_nov_mode", mode, per_line=8))
    w(c_array("uint16_t", "ids_seen_row", seen_index, per_line=8))
    w("/* Seen bitmaps: bit (7 - v % 8) of byte v / 8 is set if value v was seen in normal traffic */\n")
    w(c_array("uint8_t", "ids_seen", np.array(seen_rows), lambda v: f"0x{v:02X}", 16))
    w(c_array("int16_t", "ids_range_lo", lo, per_line=8))
    w(c_array("int16_t", "ids_range_hi", hi, per_line=8))
    w(c_array("int8_t", "ids_q_nov_count", q_count))
    w("/* Byte change since the previous frame of the ID, d = -255..255 -> quantized d / 255 */\n")
    w(c_array("int8_t", "ids_q_delta", q_delta))

    # --- signal pairs ---
    w("\n/* Signal pairs: byte `byte` of ID `id` is checked against the latest value of byte\n"
      "   `partner_byte` of ID `partner`. Cells hold the quantized surprise min(bits, 16) / 16\n"
      f"   and whether it is strong evidence (> {STRONG_SURPRISE_BITS:g} bits). */\n")
    w("typedef struct {\n    uint8_t id, byte, partner, partner_byte;  /* id/partner = whitelist index */\n"
      "    uint8_t n_b;          /* number of known partner values (cell = a_slot * n_b + b_slot) */\n"
      "    uint16_t cell0;       /* first cell of this pair in ids_pair_q / ids_pair_strong */\n"
      "    int8_t q_unseen;      /* byte value never seen with any partner value */\n"
      "    uint8_t strong_unseen;\n} ids_pair_def_t;\n")
    pdefs, a_slot, b_slot, cells_q, cells_s = [], [], [], [], []
    index = {int(a): i for i, a in enumerate(ids)}
    for pr in profile["pairs"]:
        table = np.asarray(pr["surprise"], dtype=F32)
        q_cells = q_feature(np.minimum(table, 16) / 16, p)
        unseen = table.max()
        sa = np.full(256, 0xFF, np.uint8)
        sa[pr["a_values"]] = np.arange(len(pr["a_values"]))
        sb = np.full(256, 0xFF, np.uint8)
        sb[pr["b_values"]] = np.arange(len(pr["b_values"]))
        a_slot.append(sa)
        b_slot.append(sb)
        pdefs.append(f"{{{index[int(pr['id'])]}, {pr['byte']}, {index[int(pr['partner_id'])]}, {pr['partner_byte']}, "
                     f"{len(pr['b_values'])}, {len(cells_q)}, {q_feature(np.minimum(unseen, 16) / 16, p)[0]}, "
                     f"{int(unseen > STRONG_SURPRISE_BITS)}}},  /* 0x{pr['id']:03X}.b{pr['byte']} <- "
                     f"0x{pr['partner_id']:03X}.b{pr['partner_byte']} */")
        cells_q.extend(q_cells)
        cells_s.extend((table.reshape(-1) > STRONG_SURPRISE_BITS).astype(np.uint8))
    w("static const ids_pair_def_t ids_pairs[IDS_N_PAIRS] = {\n    " + "\n    ".join(pdefs) + "\n};\n")
    w("/* value -> slot in the pair table, 0xFF = value not in the table */\n")
    w(c_array("uint8_t", "ids_pair_a_slot", np.array(a_slot), per_line=32))
    w(c_array("uint8_t", "ids_pair_b_slot", np.array(b_slot), per_line=32))
    w(c_array("int8_t", "ids_pair_q", cells_q))
    w(c_array("uint8_t", "ids_pair_strong", cells_s))

    # --- int8 network ---
    w("\n/* int8 MLP: 27 -> 32 -> 16 -> 1. Per layer: W[out][in], bias, requantization scale\n"
      "   (in_scale * w_scale / out_scale), input and output zero points. */\n")
    for k, L in enumerate(p["layers"], 1):
        w(c_array("int8_t", f"ids_w{k}", L["W"], per_line=L["W"].shape[1]))
        w(c_array("int32_t", f"ids_b{k}", L["b"], per_line=8))
        w(c_array("float", f"ids_s{k}", L["scale"], c_float, 4))
        w(f"#define IDS_X{k}_ZERO {L['x_zero']}\n#define IDS_Y{k}_ZERO {L['y_zero']}\n")
    w("/* int8 sigmoid, indexed by logit + 128 */\n")
    w(c_array("int8_t", "ids_sigmoid", p["sigmoid_lut"]))

    sizes = {"seen bitmaps": 32 * len(seen_rows), "whitelist": 4096 + 2 * n,
             "weights": sum(L["W"].size + 8 * len(L["b"]) for L in p["layers"])}
    return "".join(out), sizes


# ------------------------------------------------------------------ self-test
def python_reference(df, profile: dict, p: dict):
    """What the Python pipeline answers for each frame of df (df must come from add_gaps).
    Returns the quantized features, the int8 model output and the ALERT/WARNING levels."""
    unknown, fast = rule_flags(df, profile, CONFIG["rate_k"])
    strong = strong_evidence(df, profile)
    x, _ = drop_id(*make_features(df, profile))
    q = quantize_input(x, p)
    _, score = forward(q, p)
    probs = (score.astype(F32) - p["out_zero"]) * p["out_scale"]
    alert, warning = detector(df, unknown, fast, strong, probs, CONFIG["threshold"], *CONFIG["smooth"])
    level = np.where(alert, 2, np.where(warning, 1, 0)).astype(np.uint8)
    return q, score, level, unknown


def selftest(profile: dict, p: dict) -> str:
    rows, expect, labels = [], [], []
    for cap, before, count in SELFTEST:
        df = pd.read_parquet(DATASET_PROCESSED_DIR / "attacks" / f"{cap}.parquet")
        t0 = df.loc[df["label"] == 1, "t"].iloc[0] - before
        df = df[df["t"] >= t0].iloc[:count].copy()
        df["t"] = np.round((df["t"] - df["t"].iloc[0]) * 1e6) / 1e6     # exact microseconds, like the chip
        df["capture"] = cap
        df["capture"] = df["capture"].astype("category")
        df = add_gaps(df)
        q, score, level, unknown = python_reference(df, profile, p)
        score = np.where(unknown, -128, score)
        t_us = np.round(df["t"].to_numpy() * 1e6).astype(np.int64)
        for k, (t, cid, *data) in enumerate(zip(t_us, df["id"], *(df[b] for b in BYTES))):
            rows.append(f"{{{t}u, 0x{cid:03X}, {int(k == 0)}, {{{', '.join(map(str, data))}}}}}")
        expect.extend(f"{{{s}, {lv}}}" for s, lv in zip(score, level))
        labels.extend(df["label"].tolist())
        print(f"  self-test window {cap}: {len(df)} frames, {int(df['label'].sum())} forged, "
              f"{int((level == 2).sum())} ALERT / {int((level == 1).sum())} WARNING frames (Python)")
    n = len(rows)
    lab = np.packbits(np.array(labels, np.uint8), bitorder="little")
    return (f"/* Generated by ml/src/export_c.py: {n} real {DATASET.upper()} frames ({', '.join(c for c, _, _ in SELFTEST)})\n"
            f"   and the answers of the Python pipeline for each of them. */\n"
            f"#define IDS_SELFTEST_N {n}\n"
            f"#define IDS_DATASET_NAME \"{'CAN-MIRGU' if DATASET == 'mirgu' else 'ROAD'}\"\n"
            "typedef struct { uint32_t t_us; uint16_t can_id; uint8_t reset; uint8_t data[8]; } ids_selftest_frame_t;\n"
            "typedef struct { int8_t score_q; uint8_t level; } ids_selftest_expect_t;\n"
            f"static const ids_selftest_frame_t ids_selftest_frames[{n}] = {{\n    " + ",\n    ".join(rows) + "\n};\n"
            f"static const ids_selftest_expect_t ids_selftest_expect[{n}] = {{\n    "
            + ",\n    ".join(", ".join(expect[i:i + 8]) for i in range(0, n, 8)) + "\n};\n"
            "/* 1 bit per frame (LSB first): forged frame */\n"
            + c_array("uint8_t", "ids_selftest_forged", lab, lambda v: f"0x{v:02X}"))


def main():
    profile = get_profile()
    p = load_params()
    body, sizes = build(profile, p)
    guard = f"/* Generated by ml/src/export_c.py from {PROFILE_PATH.relative_to(PROJECT_ROOT)}, " \
            f"{(RESULTS_DIR / 'models').relative_to(PROJECT_ROOT)}/{MLP_NAME}_int8.tflite\n" \
            f"   and {RESULTS_DIR.relative_to(PROJECT_ROOT)}/{MLP_NAME}_config.json. Do not edit by hand. Included by ids_detector.c only. */\n" \
            "#ifndef IDS_MODEL_H\n#define IDS_MODEL_H\n#include <stdint.h>\n\n"
    (FW_INC / "ids_model.h").write_text(guard + body + "\n#endif\n")
    print(f"wrote {FW_INC / 'ids_model.h'}  ({', '.join(f'{k} {v:,} B' for k, v in sizes.items())})")
    st = selftest(profile, p)
    (FW_INC / "ids_selftest_data.h").write_text("#ifndef IDS_SELFTEST_DATA_H\n#define IDS_SELFTEST_DATA_H\n"
                                                "#include <stdint.h>\n\n" + st + "\n#endif\n")
    print(f"wrote {FW_INC / 'ids_selftest_data.h'}")


if __name__ == "__main__":
    main()
