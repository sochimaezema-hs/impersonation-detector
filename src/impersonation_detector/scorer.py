"""Layer 2: a learned, explainable impersonation score for senders and domains.

The model is logistic regression over the named features in :mod:`features`. Weights
ship with the package (``data/scorer_weights.json``) and are produced by
``python -m impersonation_detector.train`` from the synthetic generator in :mod:`synth`.
Each prediction returns per-feature contributions so a reviewer can see *why*.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from .features import FEATURE_NAMES, FeatureExtractor, Sender

WEIGHTS_FILE = "scorer_weights.json"


@lru_cache(maxsize=1)
def default_weights() -> dict[str, float]:
    path = resources.files(__package__).joinpath("data", WEIGHTS_FILE)
    with path.open(encoding="utf-8") as fh:
        payload = json.load(fh)
    return {str(k): float(v) for k, v in payload["weights"].items()}


@dataclass(frozen=True)
class SenderScore:
    probability: float
    features: dict[str, float]
    contributions: dict[str, float]

    @property
    def reasons(self) -> list[str]:
        """Features that pushed the score up, strongest first."""
        pos = [(k, v) for k, v in self.contributions.items() if v > 0 and self.features[k] > 0]
        pos.sort(key=lambda kv: -kv[1])
        return [k for k, _ in pos]


class SenderScorer:
    def __init__(self, protected: list[str], weights: dict[str, float] | None = None,
                 max_distance: int = 2) -> None:
        self.extractor = FeatureExtractor(protected, max_distance=max_distance)
        self.weights = dict(weights) if weights is not None else dict(default_weights())
        missing = [k for k in FEATURE_NAMES if k not in self.weights]
        if missing:
            raise ValueError(f"weights missing features: {missing}")
        self.bias = float(self.weights.get("bias", 0.0))

    def _score(self, feats: dict[str, float]) -> SenderScore:
        contrib = {k: self.weights[k] * feats[k] for k in FEATURE_NAMES}
        z = self.bias + sum(contrib.values())
        p = 1.0 / (1.0 + math.exp(-z))
        return SenderScore(probability=p, features=feats, contributions=contrib)

    def score(self, sender: Sender) -> SenderScore:
        return self._score(self.extractor.extract(sender))

    def score_domain(self, domain: str) -> SenderScore:
        """Score a bare host (a link's domain) using only domain features."""
        feats = {k: 0.0 for k in FEATURE_NAMES}
        feats.update(self.extractor.domain_features(domain))
        return self._score(feats)
