"""Run the benchmark: every layer configuration × every variant, with per-class recall,
false-positive rate, injection hijack rate, and latency. Writes JSON and Markdown."""

from __future__ import annotations

import json
import platform
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..domains import brand_tokens
from ..intent import LLMIntentClassifier, RuleIntentClassifier
from ..pipeline import Detector, Verdict
from .seed import SeedItem, load_seed
from .variants import VARIANTS, apply_variant

LAYER_CONFIGS: dict[str, frozenset[int]] = {
    "L1": frozenset({1}),
    "L2": frozenset({2}),
    "L3": frozenset({3}),
    "L1+L2": frozenset({1, 2}),
    "L1+L2+L3": frozenset({1, 2, 3}),
}


@dataclass
class Cell:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    unknown: int = 0
    hijacked: int = 0            # malicious messages the L3 label called benign under injection
    per_class_tp: dict[str, int] = field(default_factory=dict)
    per_class_n: dict[str, int] = field(default_factory=dict)
    latency_ms: list[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def summary(self) -> dict:
        lat = sorted(self.latency_ms)
        p50 = lat[len(lat) // 2] if lat else 0.0
        return {
            "n": self.tp + self.fp + self.fn + self.tn,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "f1": round(self.f1, 3), "fpr": round(self.fpr, 3), "unknown": self.unknown,
            "hijacked": self.hijacked,
            "per_class_recall": {c: round(self.per_class_tp.get(c, 0) / n, 3)
                                 for c, n in sorted(self.per_class_n.items())},
            "latency_ms_p50": round(p50, 2),
        }


@dataclass
class Report:
    protected: list[str]
    intent_backend: str
    version: str
    generated_at: str
    machine: str
    n_seed: int
    label_counts: dict[str, int]
    results: dict[str, dict[str, dict]]  # layer config -> variant -> summary
    threshold_note: str = "flagged = any L1 match | max L2 score >= 0.5 | L3 label malicious or unknown | pipeline action != allow"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def to_markdown(self) -> str:
        lines = [f"# impersonation-detector benchmark v{self.version}", "",
                 f"Generated {self.generated_at} on {self.machine}. Intent backend: `{self.intent_backend}`. "
                 f"Seed corpus: {self.n_seed} messages ("
                 + ", ".join(f"{k} {v}" for k, v in self.label_counts.items()) + ").", "",
                 "Flagged means: " + self.threshold_note + ".", ""]
        variants = list(VARIANTS)
        lines.append("## Recall / FPR by layer configuration and variant")
        lines.append("")
        lines.append("| Config | " + " | ".join(variants) + " |")
        lines.append("|---|" + "---|" * len(variants))
        for cfg, by_var in self.results.items():
            cells = []
            for v in variants:
                s = by_var.get(v)
                if s is None:
                    cells.append("–")
                elif VARIANTS[v].malicious_only:
                    cells.append(f"R {s['recall']:.2f}")
                else:
                    cells.append(f"R {s['recall']:.2f} / FPR {s['fpr']:.2f}")
            lines.append(f"| {cfg} | " + " | ".join(cells) + " |")
        lines.append("")
        lines.append("## Per-class recall (clean) and injection hijack")
        lines.append("")
        classes = sorted({c for by_var in self.results.values() for s in by_var.values()
                          for c in s["per_class_recall"]})
        lines.append("| Config | " + " | ".join(classes) + " | hijacked (injection) | unknown (injection) | p50 ms |")
        lines.append("|---|" + "---|" * (len(classes) + 3))
        for cfg, by_var in self.results.items():
            clean = by_var["clean"]["per_class_recall"]
            inj = by_var.get("injection", {})
            lines.append(f"| {cfg} | " + " | ".join(f"{clean.get(c, 0):.2f}" for c in classes)
                         + f" | {inj.get('hijacked', 0)} | {inj.get('unknown', 0)} | {by_var['clean']['latency_ms_p50']} |")
        lines.append("")
        lines.append("## Variants")
        lines.append("")
        for v in VARIANTS.values():
            lines.append(f"- **{v.name}**: {v.description}" + (" (malicious only; recall)" if v.malicious_only else ""))
        return "\n".join(lines) + "\n"


def _flagged(cfg: str, v: Verdict) -> bool:
    if cfg == "L1":
        return bool(v.lookalikes)
    if cfg == "L2":
        scores = [v.sender_score.probability if v.sender_score else 0.0] + [s.probability for s in v.link_scores.values()]
        return max(scores) >= 0.5
    if cfg == "L3":
        return v.intent is not None and (v.intent.is_malicious or v.intent.label == "unknown")
    return not v.allowed


def run_benchmark(protected: list[str], intent: RuleIntentClassifier | LLMIntentClassifier | None = None,
                  variants: list[str] | None = None, configs: list[str] | None = None,
                  seed: int = 0, items: list[SeedItem] | None = None,
                  dump: list[dict] | None = None) -> Report:
    """``dump``, if given, receives one record per (config, variant, message) with the
    verdict, so operating points and false positives can be analysed offline."""
    items = items if items is not None else load_seed(protected)
    brand = min(brand_tokens(protected))
    intent = intent or RuleIntentClassifier()
    variants = variants or list(VARIANTS)
    configs = configs or list(LAYER_CONFIGS)
    results: dict[str, dict[str, dict]] = {}
    detectors = {cfg: Detector(protected, intent=intent, layers=LAYER_CONFIGS[cfg]) for cfg in configs}
    for cfg in configs:
        results[cfg] = {}
        # L3 label on the clean message, so "hijacked" means an injection flipped a
        # detection to benign rather than counting messages L3 never caught.
        clean_label: dict[str, str] = {}
        if 3 in LAYER_CONFIGS[cfg]:
            for item in items:
                v0 = detectors[cfg].analyze(item.to_message())
                clean_label[item.id] = v0.intent.label if v0.intent else "benign"
        for vname in variants:
            var = VARIANTS[vname]
            cell = Cell()
            for item in items:
                malicious = item.label != "benign"
                if var.malicious_only and not malicious:
                    continue
                mutated = apply_variant(vname, item, brand, seed)
                msg = mutated.to_message()
                t0 = time.perf_counter()
                verdict = detectors[cfg].analyze(msg)
                cell.latency_ms.append((time.perf_counter() - t0) * 1000)
                flag = _flagged(cfg, verdict)
                if dump is not None:
                    dump.append({"config": cfg, "variant": vname, "id": item.id, "label": item.label,
                                 "flagged": flag, "risk": round(verdict.risk, 4), "action": verdict.action,
                                 "intent": None if verdict.intent is None else verdict.intent.label,
                                 "confidence": None if verdict.intent is None else round(verdict.intent.confidence, 3),
                                 "signals": [] if verdict.intent is None else list(verdict.intent.signals),
                                 "rationale": "" if verdict.intent is None else verdict.intent.rationale,
                                 "sender_p": None if verdict.sender_score is None else round(verdict.sender_score.probability, 4),
                                 "reasons": verdict.reasons})
                if verdict.intent is not None and verdict.intent.label == "unknown":
                    cell.unknown += 1
                if malicious:
                    cell.per_class_n[item.label] = cell.per_class_n.get(item.label, 0) + 1
                    if flag:
                        cell.tp += 1
                        cell.per_class_tp[item.label] = cell.per_class_tp.get(item.label, 0) + 1
                    else:
                        cell.fn += 1
                    if (vname == "injection" and verdict.intent is not None
                            and verdict.intent.label == "benign"
                            and clean_label.get(item.id, "benign") not in ("benign", "unknown")):
                        cell.hijacked += 1
                else:
                    if flag:
                        cell.fp += 1
                    else:
                        cell.tn += 1
            results[cfg][vname] = cell.summary()
    return Report(
        protected=list(protected), intent_backend=getattr(intent, "name", "rule"),
        version=__version__, generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        machine=f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
        n_seed=len(items), label_counts=dict(sorted(Counter(i.label for i in items).items())),
        results=results,
    )


def write_report(report: Report, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = report.intent_backend.replace("/", "_").replace(":", "_")
    j = out_dir / f"benchmark_{tag}.json"
    m = out_dir / f"benchmark_{tag}.md"
    j.write_text(report.to_json(), encoding="utf-8")
    m.write_text(report.to_markdown(), encoding="utf-8")
    return j, m
