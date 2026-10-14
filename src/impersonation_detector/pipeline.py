"""The detector: combine Layers 1–3 into one explainable verdict per message, and a
middleware helper for platform send pipelines.

Risk composition is noisy-OR over independent evidence (sender score, worst link score,
intent risk) with two floors: a Layer 1 confusable hit on the sender or a link, and an
injection attempt in the body. Actions are thresholds on risk and are configurable.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .domains import normalize_host, registrable
from .features import Sender
from .intent import IntentResult, LLMIntentClassifier, Message, RuleIntentClassifier
from .lookalike import LookalikeDetector, Match
from .scorer import SenderScore, SenderScorer

ACTIONS = ("allow", "warn", "hold", "block")
_URL = re.compile(r"(?:https?://|www\.)([^\s/<>\"')\]]+)", re.IGNORECASE)
_BARE_DOMAIN = re.compile(
    r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|co|app|xyz|top|site|online|click|link|info|me|us|cc"
    r"|live|help|support|careers|jobs|ly|gl|to|tv|ai|dev|sh|cloud|store|shop|work|biz|edu|gov))\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Thresholds:
    warn: float = 0.30
    hold: float = 0.60
    block: float = 0.85


@dataclass
class Verdict:
    risk: float
    action: str
    reasons: list[str]
    sender_score: SenderScore | None
    link_scores: dict[str, SenderScore]
    lookalikes: list[Match]
    intent: IntentResult | None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    def to_dict(self) -> dict:
        return {
            "risk": round(self.risk, 4),
            "action": self.action,
            "reasons": self.reasons,
            "sender": None if self.sender_score is None else {
                "probability": round(self.sender_score.probability, 4),
                "reasons": self.sender_score.reasons,
            },
            "links": {h: round(s.probability, 4) for h, s in self.link_scores.items()},
            "lookalikes": [
                {"candidate": m.candidate, "protected": m.protected, "reasons": list(m.reasons)}
                for m in self.lookalikes
            ],
            "intent": None if self.intent is None else {
                "label": self.intent.label, "confidence": round(self.intent.confidence, 3),
                "signals": list(self.intent.signals), "rationale": self.intent.rationale,
                "backend": self.intent.backend,
            },
        }


def extract_hosts(text: str, links: tuple[str, ...] = ()) -> list[str]:
    hosts: list[str] = []
    for link in links:
        m = _URL.search(link)
        hosts.append(normalize_host(m.group(1) if m else link))
    for m in _URL.finditer(text):
        hosts.append(normalize_host(m.group(1)))
    for m in _BARE_DOMAIN.finditer(text):
        hosts.append(normalize_host(m.group(1)))
    seen: list[str] = []
    for h in hosts:
        h = h.removeprefix("www.")
        if h and h not in seen:
            seen.append(h)
    return seen


class Detector:
    """Analyze messages against a protected set.

    Args:
        protected: brand names, domains, and team names to defend.
        intent: a Layer 3 classifier; defaults to the rule baseline. Pass
            ``LLMIntentClassifier(backend)`` for the model-backed version.
        thresholds: risk cut-offs for warn / hold / block.
        layers: which layers to run (``{1, 2, 3}``). Used by the benchmark to
            measure each layer alone.
    """

    def __init__(self, protected: list[str],
                 intent: RuleIntentClassifier | LLMIntentClassifier | None = None,
                 thresholds: Thresholds | None = None,
                 layers: frozenset[int] = frozenset({1, 2, 3}),
                 blocklist: set[str] | None = None) -> None:
        self.protected = protected
        self.lookalike = LookalikeDetector(protected)
        self.scorer = SenderScorer(protected)
        self.intent = intent if intent is not None else RuleIntentClassifier()
        self.thresholds = thresholds or Thresholds()
        self.layers = frozenset(layers)
        # Domains the lookalike-domain watch (domainwatch.py) has already judged: a sender
        # or link on one of them is blocked outright.
        self.blocklist = {normalize_host(d) for d in (blocklist or set())}

    def _action(self, risk: float) -> str:
        t = self.thresholds
        if risk >= t.block:
            return "block"
        if risk >= t.hold:
            return "hold"
        if risk >= t.warn:
            return "warn"
        return "allow"

    def analyze(self, msg: Message) -> Verdict:
        reasons: list[str] = []
        sender = Sender(msg.sender_name, msg.sender_address)
        _, _, sender_domain = sender.parts
        hosts = extract_hosts(f"{msg.subject}\n{msg.body}", msg.links)
        risks: list[float] = []
        floor = 0.0

        for host in [sender_domain, *hosts]:
            if host and (host in self.blocklist or registrable(host) in self.blocklist):
                floor = max(floor, 0.95)
                reasons.append(f"blocklisted domain {host!r} (lookalike-domain watch)")

        lookalikes: list[Match] = []
        if 1 in self.layers:
            candidates = [c for c in (msg.sender_name, sender_domain, *hosts) if c]
            for c in candidates:
                lookalikes.extend(self.lookalike.check(c))
            if lookalikes:
                floor = max(floor, 0.85)
                for m in lookalikes[:3]:
                    reasons.append(f"L1 lookalike of {m.protected!r}: {m.candidate!r} [{', '.join(m.reasons)}]")

        sender_score: SenderScore | None = None
        link_scores: dict[str, SenderScore] = {}
        if 2 in self.layers:
            sender_score = self.scorer.score(sender)
            risks.append(sender_score.probability)
            if sender_score.probability >= self.thresholds.warn:
                reasons.append("L2 sender " + ", ".join(sender_score.reasons[:3]) +
                               f" (p={sender_score.probability:.2f})")
            for h in hosts:
                if h == sender_domain and sender_score.probability >= 0.5:
                    continue
                s = self.scorer.score_domain(h)
                link_scores[h] = s
                risks.append(s.probability)
                if s.probability >= self.thresholds.warn:
                    reasons.append(f"L2 link {h!r} " + ", ".join(s.reasons[:3]) +
                                   f" (p={s.probability:.2f})")

        intent: IntentResult | None = None
        if 3 in self.layers:
            intent = self.intent.classify(msg)
            risks.append(intent.risk)
            if intent.is_malicious:
                reasons.append(f"L3 intent {intent.label} (conf={intent.confidence:.2f}; "
                               + ", ".join(intent.signals) + ")")
            elif intent.label == "unknown":
                reasons.append("L3 intent unknown: " + intent.rationale)
            if "injection_attempt" in intent.signals:
                floor = max(floor, 0.60)
                reasons.append("L3 prompt-injection attempt in message body")

        survive = 1.0
        for r in risks:
            survive *= 1.0 - max(0.0, min(1.0, r))
        risk = max(1.0 - survive, floor)
        return Verdict(risk, self._action(risk), reasons, sender_score, link_scores,
                       lookalikes, intent)


@dataclass
class Middleware:
    """Wrap a platform's send function: ``send = Middleware(detector).wrap(raw_send)``.

    ``on_hold`` / ``on_block`` receive (message, verdict) and decide what happens; by
    default a held message is still delivered with the verdict attached for review and
    a blocked one is dropped. ``warn`` always delivers.
    """

    detector: Detector
    on_hold: Callable[[Message, Verdict], bool] = field(default=lambda m, v: True)
    on_block: Callable[[Message, Verdict], bool] = field(default=lambda m, v: False)

    def check(self, msg: Message) -> Verdict:
        return self.detector.analyze(msg)

    def wrap(self, send: Callable[..., object]) -> Callable[..., object]:
        try:
            params = inspect.signature(send).parameters
            accepts_verdict = "verdict" in params or any(
                p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            accepts_verdict = False

        def guarded(msg: Message, *args, **kwargs):
            v = self.check(msg)
            if v.action == "block" and not self.on_block(msg, v):
                return v
            if v.action == "hold" and not self.on_hold(msg, v):
                return v
            if accepts_verdict:
                kwargs["verdict"] = v
            return send(msg, *args, **kwargs)

        return guarded
