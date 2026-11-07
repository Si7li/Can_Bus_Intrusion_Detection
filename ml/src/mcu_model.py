"""The int8 MLP exactly as the STM32 computes it (numpy reference of the C code).

TFLite (with its default XNNPACK backend, which produced every published result)
computes each int8 fully connected layer as:
    acc  = bias[o] + sum_i (x[i] - x_zero) * W[o][i]          (exact, int32)
    y    = acc * scale[o]          in float32, scale[o] = in_scale * w_scale[o] / out_scale
    y    = clamp(y, -128 - out_zero, 127 - out_zero)
    q[o] = round_half_to_even(y) + out_zero
and the int8 sigmoid as a 256-entry lookup table. The C code does the same, so
both give identical int8 outputs (checked by `python ml/src/mcu_model.py`).
"""

from pathlib import Path

import numpy as np

from common import MLP_NAME, RESULTS_DIR

TFLITE_PATH = RESULTS_DIR / "models" / f"{MLP_NAME}_int8.tflite"
F32 = np.float32


def load_params(path: Path = TFLITE_PATH) -> dict:
    """Weights, biases and quantization parameters of the 3 layers + sigmoid."""
    import tensorflow as tf
    it = tf.lite.Interpreter(model_path=str(path))
    it.allocate_tensors()
    tensors = {t["index"]: t for t in it.get_tensor_details()}
    ops = [o for o in it._get_ops_details() if o["op_name"] != "DELEGATE"]
    assert [o["op_name"] for o in ops] == ["FULLY_CONNECTED"] * 3 + ["LOGISTIC"], ops

    def q(idx):
        p = tensors[idx]["quantization_parameters"]
        return p["scales"].astype(F32), p["zero_points"].astype(np.int32)

    layers = []
    for op in ops[:3]:
        x_idx, w_idx, b_idx = op["inputs"]
        (x_s,), (x_z,) = q(x_idx)
        w_s, _ = q(w_idx)
        (y_s,), (y_z,) = q(op["outputs"][0])
        layers.append({
            "W": it.get_tensor(w_idx).astype(np.int8),           # [out, in]
            "b": it.get_tensor(b_idx).astype(np.int32),
            "x_zero": int(x_z), "y_zero": int(y_z),
            "scale": (F32(x_s) * w_s / F32(y_s)).astype(F32),     # float32, same order as XNNPACK
        })
    (in_s,), (in_z,) = q(ops[0]["inputs"][0])
    (lg_s,), (lg_z,) = q(ops[3]["inputs"][0])
    (out_s,), (out_z,) = q(ops[3]["outputs"][0])
    return {"layers": layers, "in_scale": float(in_s), "in_zero": int(in_z),
            "sigmoid_lut": sigmoid_lut(float(lg_s), int(lg_z), float(out_s), int(out_z)),
            "out_scale": float(out_s), "out_zero": int(out_z)}


def sigmoid_lut(in_scale: float, in_zero: int, out_scale: float, out_zero: int) -> np.ndarray:
    """int8 sigmoid table, indexed by (input + 128)."""
    x = (np.arange(-128, 128) - in_zero) * F32(in_scale)
    y = np.rint((1 / (1 + np.exp(-x.astype(np.float64)))) / out_scale) + out_zero
    return np.clip(y, -128, 127).astype(np.int8)


def quantize_input(x: np.ndarray, p: dict) -> np.ndarray:
    """Same expression as road_train_mlp.predict_int8 (float32 arithmetic)."""
    return np.clip(np.round(x.astype(F32) / p["in_scale"] + p["in_zero"]), -128, 127).astype(np.int8)


def forward(q_in: np.ndarray, p: dict) -> tuple[np.ndarray, np.ndarray]:
    """(n, 27) int8 -> (logit int8, sigmoid output int8), exactly like the C code."""
    h = q_in.astype(np.int32)
    for L in p["layers"]:
        acc = (h - L["x_zero"]) @ L["W"].T.astype(np.int32) + L["b"]
        y = acc.astype(F32) * L["scale"]
        y = np.clip(y, F32(-128 - L["y_zero"]), F32(127 - L["y_zero"]))
        h = np.rint(y).astype(np.int32) + L["y_zero"]          # rint = round half to even
    logit = h[:, 0].astype(np.int8)
    return logit, p["sigmoid_lut"][logit.astype(np.int32) + 128]


def tflite_int8(q_in: np.ndarray, reference_kernels: bool = False) -> np.ndarray:
    """int8 output of the real TFLite interpreter for int8 inputs."""
    import tensorflow as tf
    kw = {"experimental_op_resolver_type": tf.lite.experimental.OpResolverType.BUILTIN_REF} if reference_kernels else {}
    it = tf.lite.Interpreter(model_path=str(TFLITE_PATH), **kw)
    inp, out = it.get_input_details()[0], it.get_output_details()[0]
    batch = 16384
    it.resize_tensor_input(inp["index"], [batch, q_in.shape[1]])
    it.allocate_tensors()
    res = np.empty(len(q_in), np.int8)
    for s in range(0, len(q_in), batch):
        c = q_in[s:s + batch]
        it.set_tensor(inp["index"], np.vstack([c, np.zeros((batch - len(c), c.shape[1]), np.int8)]))
        it.invoke()
        res[s:s + len(c)] = it.get_tensor(out["index"])[:len(c), 0]
    return res


def main():
    """Check the numpy reference against TFLite on the val features."""
    from road_features import add_gaps, load_split, make_features
    from road_profile import get_profile
    from road_train_mlp import drop_id

    p = load_params()
    profile = get_profile()
    val = add_gaps(load_split("val"))
    val = val[val["id"].isin(profile["ids"].keys())]
    x, _ = drop_id(*make_features(val, profile))
    q = quantize_input(x, p)
    # every distinct input vector once (most frames repeat), plus random int8 inputs
    q = np.unique(q, axis=0)
    rnd = np.random.default_rng(0).integers(-128, 128, size=(200_000, q.shape[1]), dtype=np.int16).astype(np.int8)
    for name, data in [(f"val ({len(q):,} distinct input vectors)", q), ("random int8 inputs (200,000)", rnd)]:
        _, ours = forward(data, p)
        for kernels, ref in [("TFLite default (XNNPACK)", False), ("TFLite reference kernels", True)]:
            theirs = tflite_int8(data, ref)
            print(f"{name:40s} vs {kernels:26s}: identical on {np.mean(ours == theirs) * 100:.4f}%, "
                  f"max diff {np.abs(ours.astype(int) - theirs).max()}")


if __name__ == "__main__":
    main()
