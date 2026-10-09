"""Train the Layer 2 scorer on synthetic senders and write ``data/scorer_weights.json``.

Pure-Python logistic regression (gradient descent, L2 penalty) so the package stays
dependency-free. The protected set used for training is generic — the features are
relative to *whatever* protected set the scorer is instantiated with, so the weights
transfer across brands.

    python -m impersonation_detector.train [--n 6000] [--seed 7] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

from .features import FEATURE_NAMES, FeatureExtractor
from .synth import SenderSynth

# Several brands so the model never learns one name's quirks.
TRAIN_PROTECTED = [
    ["handshake.com", "joinhandshake.com", "Handshake", "Handshake Support"],
    ["paypal.com", "PayPal", "PayPal Support"],
    ["microsoft.com", "Microsoft", "Microsoft Security"],
    ["coinbase.com", "Coinbase", "Coinbase Support"],
    ["indeed.com", "Indeed", "Indeed Recruiting"],
    ["linkedin.com", "LinkedIn", "LinkedIn Talent"],
    ["chase.com", "Chase", "Chase Alerts"],
    ["dropbox.com", "Dropbox", "Dropbox Team"],
]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def build(n_per_brand: int, seed: int) -> tuple[list[list[float]], list[int], list[str]]:
    X: list[list[float]] = []
    y: list[int] = []
    techniques: list[str] = []
    for i, protected in enumerate(TRAIN_PROTECTED):
        fx = FeatureExtractor(protected)
        synth = SenderSynth(protected, seed=seed + i)
        for ex in synth.dataset(n_per_brand // 2, n_per_brand // 2):
            f = fx.extract(ex.sender)
            X.append([f[k] for k in FEATURE_NAMES])
            y.append(ex.label)
            techniques.append(ex.technique)
    return X, y, techniques


def fit(X: list[list[float]], y: list[int], epochs: int = 600, lr: float = 1.0,
        l2: float = 1e-4) -> tuple[list[float], float]:
    n, d = len(X), len(X[0])
    w = [0.0] * d
    b = 0.0
    for _ in range(epochs):
        gw = [0.0] * d
        gb = 0.0
        for xi, yi in zip(X, y):
            p = _sigmoid(b + sum(wj * xj for wj, xj in zip(w, xi)))
            err = p - yi
            for j in range(d):
                if xi[j]:
                    gw[j] += err * xi[j]
            gb += err
        for j in range(d):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * gb / n
    return w, b


def evaluate(X, y, w, b, threshold: float = 0.5) -> dict[str, float]:
    tp = fp = fn = tn = 0
    scores = []
    for xi, yi in zip(X, y):
        p = _sigmoid(b + sum(wj * xj for wj, xj in zip(w, xi)))
        scores.append((p, yi))
        pred = p >= threshold
        if pred and yi:
            tp += 1
        elif pred and not yi:
            fp += 1
        elif not pred and yi:
            fn += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    # AUC via rank statistic
    pos = [s for s, lab in scores if lab]
    neg = [s for s, lab in scores if not lab]
    auc = 0.0
    if pos and neg:
        wins = sum(1.0 if p > q else 0.5 if p == q else 0.0 for p in pos for q in neg)
        auc = wins / (len(pos) * len(neg))
    return {"precision": prec, "recall": rec, "f1": f1, "auc": auc,
            "accuracy": (tp + tn) / len(y), "n": len(y)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--n", type=int, default=800, help="examples per brand (half positive)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--epochs", type=int, default=600)
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "data" / "scorer_weights.json")
    args = ap.parse_args(argv)

    X, y, tech = build(args.n, args.seed)
    idx = list(range(len(X)))
    random.Random(args.seed).shuffle(idx)
    cut = int(len(idx) * 0.8)
    tr, ho = idx[:cut], idx[cut:]
    w, b = fit([X[i] for i in tr], [y[i] for i in tr], epochs=args.epochs)
    train_m = evaluate([X[i] for i in tr], [y[i] for i in tr], w, b)
    hold_m = evaluate([X[i] for i in ho], [y[i] for i in ho], w, b)

    # per-technique holdout recall / specificity
    by_tech: dict[str, list[int]] = {}
    for i in ho:
        p = _sigmoid(b + sum(wj * xj for wj, xj in zip(w, X[i])))
        by_tech.setdefault(tech[i], []).append(int((p >= 0.5) == bool(y[i])))
    per_tech = {t: sum(v) / len(v) for t, v in sorted(by_tech.items())}

    payload = {
        "model": "logistic_regression",
        "features": list(FEATURE_NAMES),
        "weights": {**{k: round(v, 4) for k, v in zip(FEATURE_NAMES, w)}, "bias": round(b, 4)},
        "training": {"n_per_brand": args.n, "brands": len(TRAIN_PROTECTED), "seed": args.seed,
                     "epochs": args.epochs, "train": train_m, "holdout": hold_m,
                     "holdout_accuracy_by_technique": per_tech},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    print("holdout:", {k: round(v, 3) if isinstance(v, float) else v for k, v in hold_m.items()})
    for t, acc in per_tech.items():
        print(f"  {t:28s} {acc:.3f}")
    print("weights:")
    for k, v in sorted(zip(FEATURE_NAMES, w), key=lambda kv: -abs(kv[1])):
        print(f"  {k:34s} {v:+.3f}")
    print(f"  {'bias':34s} {b:+.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
