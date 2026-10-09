"""impersonation-detector: layered detection of lookalike senders and support-team /
recruiter impersonation for messaging platforms.

Layer 1 — deterministic UTS #39 checks (:mod:`lookalike`).
Layer 2 — explainable learned sender score (:mod:`scorer`).
Layer 3 — message-intent classification, rule baseline or LLM (:mod:`intent`).
Layer 4 — benchmark with adversarial variants (:mod:`bench`).
:class:`Detector` combines 1–3; :class:`Middleware` wraps a send pipeline.
"""

from .features import FeatureExtractor, Sender
from .intent import (
    LABELS,
    SIGNALS,
    AnthropicBackend,
    IntentResult,
    LLMIntentClassifier,
    Message,
    OllamaBackend,
    OpenAICompatibleBackend,
    RuleIntentClassifier,
    make_backend,
)
from .lookalike import LookalikeDetector, Match
from .pipeline import Detector, Middleware, Thresholds, Verdict
from .scorer import SenderScore, SenderScorer
from .scripts import is_mixed_script, scripts_in
from .skeleton import confusable, fold_skeleton, skeleton

__all__ = [
    "LABELS",
    "SIGNALS",
    "AnthropicBackend",
    "Detector",
    "FeatureExtractor",
    "IntentResult",
    "LLMIntentClassifier",
    "LookalikeDetector",
    "Match",
    "Message",
    "Middleware",
    "OllamaBackend",
    "OpenAICompatibleBackend",
    "RuleIntentClassifier",
    "Sender",
    "SenderScore",
    "SenderScorer",
    "Thresholds",
    "Verdict",
    "confusable",
    "fold_skeleton",
    "is_mixed_script",
    "make_backend",
    "scripts_in",
    "skeleton",
]
__version__ = "0.1.0"
