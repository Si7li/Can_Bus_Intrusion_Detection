"""Metrics shared by every model (RF baseline, float MLP, int8 MLP).

Accuracy is NOT reported as a headline: with 87% benign traffic, a model that
always says "benign" gets 87% accuracy. We report per-class F1, macro-F1,
the confusion matrix and the benign false-positive rate.
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # no window needed, just write PNG files
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from common import CLASSES

BENIGN = CLASSES.index("benign")


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    labels = list(range(len(CLASSES)))
    report = classification_report(y_true, y_pred, labels=labels, target_names=CLASSES,
                                   output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    benign_mask = y_true == BENIGN
    # Share of benign frames flagged as any attack: drives the false alarms per minute.
    benign_fpr = float((y_pred[benign_mask] != BENIGN).mean()) if benign_mask.any() else float("nan")

    # Binary view (benign vs attack): does the model at least detect *that* something is wrong?
    bin_true = (y_true != BENIGN).astype(int)
    bin_pred = (y_pred != BENIGN).astype(int)

    return {
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "per_class": {c: {k: round(float(report[c][k]), 4) for k in ("precision", "recall", "f1-score", "support")}
                      for c in CLASSES},
        "benign_fpr": benign_fpr,
        "binary_f1_attack": float(f1_score(bin_true, bin_pred, zero_division=0)),
        "confusion_matrix": cm.tolist(),
        "n_samples": int(len(y_true)),
    }


def print_metrics(m: dict, title: str):
    print(f"\n=== {title} ({m['n_samples']:,} frames) ===")
    print(f"{'class':16s} {'precision':>9s} {'recall':>8s} {'F1':>8s} {'support':>9s}")
    for c in CLASSES:
        pc = m["per_class"][c]
        print(f"{c:16s} {pc['precision']:9.4f} {pc['recall']:8.4f} {pc['f1-score']:8.4f} {int(pc['support']):9,}")
    print(f"\nmacro-F1             : {m['macro_f1']:.4f}")
    print(f"benign false-pos rate: {100 * m['benign_fpr']:.3f} %")
    print(f"binary F1 (attack)   : {m['binary_f1_attack']:.4f}")


def save_metrics(m: dict, out_dir: Path, name: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}_metrics.json").write_text(json.dumps(m, indent=2))

    cm = np.array(m["confusion_matrix"], dtype=float)
    # Row-normalised: each row shows where the frames of one true class ended up.
    row_sum = cm.sum(axis=1, keepdims=True)
    cm_norm = np.divide(cm, row_sum, out=np.zeros_like(cm), where=row_sum > 0)

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=40, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title(f"{name}: confusion matrix (row-normalised)\nmacro-F1 = {m['macro_f1']:.3f}")
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            if cm[i, j]:
                ax.text(j, i, f"{cm_norm[i, j]:.2f}\n({int(cm[i, j])})", ha="center", va="center", fontsize=7,
                        color="white" if cm_norm[i, j] > 0.5 else "black")
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_confusion.png", dpi=150)
    plt.close(fig)
