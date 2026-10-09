"""Ablation for the paper: Layer 3 (rule backend) with de-obfuscation disabled.

Disables (a) confusable folding inside intent._normalize and (b) the leet/de-spacing
text views, then re-runs the benchmark for the L3 configuration on the variants those
defences target. Writes paper/ablation.json. Run from the repo root:

    .venv/bin/python paper/ablation.py
"""
from __future__ import annotations

import json
from pathlib import Path

from impersonation_detector import intent
from impersonation_detector.bench.run import run_benchmark

PROTECTED = ["handshake.com", "Handshake", "Handshake Support"]
VARIANTS = ["clean", "homoglyph", "zero_width", "leet", "spaced", "synonym"]


def cells(report):
    return {v: {k: s[k] for k in ("recall", "fpr", "per_class_recall")}
            for v, s in report.results["L3"].items()}


def main() -> None:
    out = {}
    out["full"] = cells(run_benchmark(PROTECTED, variants=VARIANTS, configs=["L3"]))

    orig_fold, orig_views = intent.confusable_fold, intent.text_views
    try:
        intent.confusable_fold = lambda t: t
        out["no_confusable_fold"] = cells(run_benchmark(PROTECTED, variants=VARIANTS, configs=["L3"]))
        intent.confusable_fold = orig_fold
        intent.text_views = lambda t: (t,)
        out["no_leet_despace_views"] = cells(run_benchmark(PROTECTED, variants=VARIANTS, configs=["L3"]))
        intent.confusable_fold = lambda t: t
        out["neither"] = cells(run_benchmark(PROTECTED, variants=VARIANTS, configs=["L3"]))
    finally:
        intent.confusable_fold, intent.text_views = orig_fold, orig_views

    Path(__file__).with_name("ablation.json").write_text(json.dumps(out, indent=2) + "\n")
    for cfg, by_v in out.items():
        print(f"{cfg:24s}", "  ".join(f"{v}={by_v[v]['recall']:.3f}/{by_v[v]['fpr']:.3f}" for v in VARIANTS))


if __name__ == "__main__":
    main()
