"""The model that runs on the STM32: a small MLP, float32 then full-int8. ROAD.

    python ml/src/road_train_mlp.py            # train, quantize, pick the threshold on val
    python ml/src/road_train_mlp.py --final    # also score the test split (do this ONCE)

Network: 27 features -> 32 -> 16 -> 1 (ReLU, sigmoid) = 1,441 parameters.
Output: probability that the frame is forged (option B: normal vs attack; the
attack type comes from the explanation step, not from the model).

Protocol:
1. Train on the 'train' split (same frames as the RF), early stopping on 'val'.
   Training features are out-of-fold (see road_features.training_features).
2. Post-training full-int8 quantization (TFLite), calibrated on training frames.
3. On 'val': choose the threshold = highest masquerade recall at ALERT level with
   at most MAX_FA_PER_MIN ALERT frames per minute on clean drives (after k-of-n
   smoothing). It is saved and reused unchanged on 'test' with --final.
4. Two severity levels (see detector()): ALERT and WARNING.

Model v2 (common.MODEL_VERSION = "v2"): every split also gets the synthetic
random-data attacks of synthetic_attacks.py (train attacks on train drives and
train IDs, val on val, test on test). Files are saved as road_mlp_v2_*; v1's
files (road_mlp_*) are left as they were.
"""

import argparse
import json
import time

import numpy as np
import pandas as pd

from common import MLP_NAME, MODEL_VERSION, RESULTS_DIR, SEED
from road_eval import evaluate_levels, print_levels, save_eval, smooth_flags
from road_features import (add_gaps, chunks, load_split, make_features, strong_evidence, training_features,
                           training_frames)
from road_profile import FOLDS, fold_profiles, get_profile
from road_rules import rule_flags
from synthetic_attacks import make_synthetic

MODELS = RESULTS_DIR / "models"
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98]
MAX_FA_PER_MIN = 0.5


def drop_id(x: np.ndarray, cols: list[str]):
    keep = [i for i, c in enumerate(cols) if c != "id_index"]
    return x[:, keep], [cols[i] for i in keep]


def build_model(n_inputs: int):
    import tensorflow as tf
    return tf.keras.Sequential([
        tf.keras.Input(shape=(n_inputs,)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])


def quantize(model, x_calib: np.ndarray) -> bytes:
    import tensorflow as tf
    conv = tf.lite.TFLiteConverter.from_keras_model(model)
    conv.optimizations = [tf.lite.Optimize.DEFAULT]
    conv.representative_dataset = lambda: ([row[None, :]] for row in x_calib)
    conv.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
    conv.inference_input_type = tf.int8
    conv.inference_output_type = tf.int8
    return conv.convert()


def predict_int8(tflite_model: bytes, x: np.ndarray, batch: int = 16384) -> np.ndarray:
    """Run the int8 model exactly as the MCU will: quantize inputs, int8 inference, dequantize."""
    import tensorflow as tf
    interp = tf.lite.Interpreter(model_content=tflite_model)
    inp, out = interp.get_input_details()[0], interp.get_output_details()[0]
    in_scale, in_zero = inp["quantization"]
    out_scale, out_zero = out["quantization"]
    interp.resize_tensor_input(inp["index"], [batch, x.shape[1]])
    interp.allocate_tensors()
    probs = np.empty(len(x), np.float32)
    for start in range(0, len(x), batch):
        chunk = x[start:start + batch]
        q = np.clip(np.round(chunk / in_scale + in_zero), -128, 127).astype(np.int8)
        if len(q) < batch:
            q = np.vstack([q, np.zeros((batch - len(q), x.shape[1]), np.int8)])
        interp.set_tensor(inp["index"], q)
        interp.invoke()
        y = interp.get_tensor(out["index"])[:len(chunk), 0]
        probs[start:start + len(chunk)] = (y.astype(np.float32) - out_zero) * out_scale
    return probs


def with_synthetic(df: pd.DataFrame, split: str, profile: dict) -> pd.DataFrame:
    """v2: append the split's synthetic attack captures (v1: unchanged)."""
    if MODEL_VERSION == "v1":
        return df
    synth, _ = make_synthetic(split, profile)
    df = pd.concat([df, synth], ignore_index=True)
    for c in ("capture", "attack", "variant"):
        df[c] = df[c].astype(str).astype("category")
    return df


SLIM = ["capture", "t", "id", "label", "attack", "variant"]


def split_arrays(df: pd.DataFrame, profile: dict, k_rate: float):
    """add_gaps + rule flags + strong evidence + model features, computed capture
    chunk by chunk to bound memory (CAN-MIRGU's test split is ~20M frames). Same
    values and same frame order as add_gaps / make_features on the whole split.
    Returns (frames with the SLIM columns, unknown, too_fast, strong, x, feature names)."""
    out = {"slim": [], "unk": [], "fast": [], "strong": [], "x": []}
    cols = None
    for c in chunks(df):
        c = add_gaps(c)
        u, f = rule_flags(c, profile, k_rate)
        x, cols = drop_id(*make_features(c, profile))
        for key, v in zip(out, (c[SLIM], u, f, strong_evidence(c, profile), x)):
            out[key].append(v)
    return (pd.concat(out["slim"], ignore_index=True), *(np.concatenate(out[k]) for k in ("unk", "fast", "strong", "x")),
            cols)


def detector(df, unknown, fast, strong, probs, threshold, k, n):
    """Two severity levels, as shown on the dashboard.
    ALERT   = unknown ID (at once) OR k-of-n smoothed (rate rule OR model backed by
              strong evidence: impossible value or broken signal pair)
    WARNING = k-of-n smoothed model flags whose only evidence is a value never seen
              before (possibly a normal car state missing from the training drives)."""
    ai = (~unknown) & (probs >= threshold)
    alert = unknown | smooth_flags(df, fast | (ai & strong), k, n)
    warning = smooth_flags(df, ai, k, n) & ~alert
    return alert, warning


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--final", action="store_true", help="also score the test split (once)")
    ap.add_argument("--benign", type=int, default=1_500_000)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--smooth", default="5/10")
    ap.add_argument("--k", type=float, default=0.5, help="rate rule factor")
    args = ap.parse_args()
    k_s, n_s = map(int, args.smooth.split("/"))

    import tensorflow as tf
    tf.keras.utils.set_random_seed(SEED)
    profile = get_profile()
    MODELS.mkdir(parents=True, exist_ok=True)

    # ---------- data ----------
    sel = training_frames(profile, args.benign, SEED)
    folds = [list(f) for f in FOLDS]
    if MODEL_VERSION != "v1":
        synth, source = make_synthetic("train", profile)
        synth = add_gaps(synth)
        keep = (synth["label"] == 1).to_numpy() | (np.random.default_rng(SEED).random(len(synth)) < 0.05)
        sel = pd.concat([sel, synth[keep]], ignore_index=True)
        sel["capture"] = sel["capture"].astype(str)
        for i, f in enumerate(FOLDS):      # synthetic frames are scored like the drive they come from
            folds[i] += [c for c, src in source.items() if src in f]
        print(f"model {MODEL_VERSION}: + {int(synth['label'].sum()):,} synthetic attack frames "
              f"({synth['capture'].nunique()} attacks) and {int((keep & (synth['label'] == 0).to_numpy()).sum()):,} "
              f"benign frames around them")
    x_train, cols = drop_id(*training_features(sel, profile, fold_profiles(profile), folds))
    y_train = sel["label"].to_numpy().astype(np.float32)

    val, unknown_v, fast_v, strong_v, x_val, _ = split_arrays(with_synthetic(load_split("val"), "val", profile),
                                                              profile, args.k)
    known_v = ~unknown_v
    y_val = val["label"].to_numpy().astype(np.float32)
    print(f"Train {len(y_train):,} frames ({int(y_train.sum()):,} attack), val {len(y_val):,} frames; "
          f"{len(cols)} features: {cols}")

    # ---------- train (float32) ----------
    model = build_model(len(cols))
    model.compile(optimizer=tf.keras.optimizers.Adam(1e-3), loss="binary_crossentropy",
                  metrics=[tf.keras.metrics.AUC(name="auc")])
    n_pos = y_train.sum()
    class_weight = {0: len(y_train) / (2 * (len(y_train) - n_pos)), 1: len(y_train) / (2 * n_pos)}
    rng = np.random.default_rng(SEED)
    v_idx = np.flatnonzero(known_v & ((y_val == 1) | (rng.random(len(y_val)) < 0.1)))   # 10% of benign
    t0 = time.perf_counter()
    model.fit(x_train, y_train, epochs=args.epochs, batch_size=1024, class_weight=class_weight,
              validation_data=(x_val[v_idx], y_val[v_idx]), verbose=2,
              callbacks=[tf.keras.callbacks.EarlyStopping(patience=4, restore_best_weights=True)])
    print(f"Trained in {time.perf_counter() - t0:.0f} s, {model.count_params():,} parameters")
    model.save(MODELS / f"{MLP_NAME}.keras")

    # ---------- int8 ----------
    calib = np.concatenate([rng.choice(np.flatnonzero(y_train == 0), 1500, replace=False),
                            rng.choice(np.flatnonzero(y_train == 1), 500, replace=False)])
    tflite = quantize(model, x_train[calib])
    (MODELS / f"{MLP_NAME}_int8.tflite").write_bytes(tflite)
    print(f"int8 TFLite model: {len(tflite):,} bytes")

    # ---------- choose the threshold on val ----------
    p_float = model.predict(x_val, batch_size=65536, verbose=0)[:, 0]
    p_int8 = predict_int8(tflite, x_val)
    agree = np.mean((p_float >= 0.5) == (p_int8 >= 0.5))
    print(f"float vs int8: max |diff| {np.abs(p_float - p_int8).max():.3f}, same decision on {100 * agree:.3f}% of frames")

    masq = ((val["label"] == 1) & (val["variant"] == "masquerade")).to_numpy()
    sweep, best = [], None
    print(f"\nThreshold sweep on val (int8 model, rules + model, smoothing {k_s}/{n_s}), ALERT level:")
    print(f"{'thr':>5s} {'recall all':>10s} {'recall masq':>11s} {'ALERT fr/min':>12s} {'WARN fr/min':>11s}")
    for thr in THRESHOLDS:
        alert, warning = detector(val, unknown_v, fast_v, strong_v, p_int8, thr, k_s, n_s)
        m = evaluate_levels(val, alert, warning)
        masq_flag = float(alert[masq].mean())
        c = m["clean_drives"]
        sweep.append({"threshold": thr, "recall_all": m["alert"]["recall_all_attacks"], "recall_masq": masq_flag,
                      "alert_frames_per_min": c["alert_frames_per_min"],
                      "warning_frames_per_min": c["warning_frames_per_min"]})
        print(f"{thr:5.2f} {m['alert']['recall_all_attacks']:10.3f} {masq_flag:11.3f} "
              f"{c['alert_frames_per_min']:12.2f} {c['warning_frames_per_min']:11.2f}")
        if c["alert_frames_per_min"] <= MAX_FA_PER_MIN and (best is None or masq_flag > best[1]):
            best = (thr, masq_flag)
    threshold = best[0] if best else max(THRESHOLDS)
    print(f"-> chosen threshold {threshold} (max masquerade ALERT recall with <= {MAX_FA_PER_MIN} "
          f"ALERT frames/min on clean drives)")

    config = {"model_version": MODEL_VERSION, "threshold": threshold, "smooth": [k_s, n_s], "rate_k": args.k, "features": cols,
              "parameters": int(model.count_params()), "tflite_bytes": len(tflite),
              "float_int8_decision_agreement": float(agree), "val_sweep": sweep}
    (RESULTS_DIR / f"{MLP_NAME}_config.json").write_text(json.dumps(config, indent=2))

    # ---------- report ----------
    splits = [("val", val, x_val, unknown_v, fast_v, strong_v)]
    if args.final:
        test, u_t, f_t, s_t, x_t, _ = split_arrays(with_synthetic(load_split("test"), "test", profile), profile, args.k)
        splits.append(("test", test, x_t, u_t, f_t, s_t))
    for split, df, x, unk, fast, strong in splits:
        for name, probs in [("float32", model.predict(x, batch_size=65536, verbose=0)[:, 0]),
                            ("int8", predict_int8(tflite, x))]:
            m = evaluate_levels(df, *detector(df, unk, fast, strong, probs, threshold, k_s, n_s))
            print_levels(m, f"RULES + MLP {name}, threshold {threshold}, smoothing {k_s}/{n_s} - {split}")
            save_eval(m, f"{MLP_NAME}_{name}_{split}")


if __name__ == "__main__":
    main()
