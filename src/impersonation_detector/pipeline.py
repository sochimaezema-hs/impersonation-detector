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
from dataclasses import replace as _replace

from .domains import (
    FREE_MAIL,
    embedded_domain,
    is_institutional,
    normalize_host,
    registrable,
    sld,
    strip_invisible,
    tokenize,
)
from .features import Sender
from .intent import (
    IntentResult,
    LLMIntentClassifier,
    Message,
    RuleIntentClassifier,
    _normalize,
    detect_signals,
    text_views,
)
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
    # Evidence below this level is noise (a role word, an ordinary organisation domain) and
    # does not combine: three weak nothings must not add up to a warning.
    noise_floor: float = 0.15


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
    text = strip_invisible(text)  # a zero-width space must not split a host in two
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


def sender_facts(protected_domains: set[str], sender_domain: str, display_claims_brand: bool,
                 hosts: list[str], lookalike_hosts: set[str], lookalike_sender: bool,
                 free_mail: bool) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Structured facts about the sender and links (see ``intent.SENDER_FACTS``), plus a
    human-readable list of embedded domains, for Layer 3."""
    facts: list[str] = []
    sreg = registrable(sender_domain) if sender_domain else ""
    if not sender_domain:
        facts.append("sender:no-domain")
    elif sreg in protected_domains:
        facts.append("sender:platform-domain")
    elif lookalike_sender:
        facts.append("sender:lookalike-domain")
    elif is_institutional(sender_domain):
        facts.append("sender:institutional-domain")
    elif free_mail:
        facts.append("sender:free-webmail")
    else:
        facts.append("sender:unrelated-domain")
    if display_claims_brand:
        facts.append("display:claims-platform-brand")
    embedded: list[str] = []
    if not hosts:
        facts.append("links:none")
    else:
        off = [h for h in hosts if registrable(h) not in protected_domains]
        if not off:
            facts.append("links:platform-only")
        else:
            facts.append("links:off-platform")
            if sreg and all(registrable(h) == sreg for h in off):
                facts.append("links:same-as-sender")
        if any(h in lookalike_hosts for h in hosts):
            facts.append("links:lookalike")
        for h in hosts:
            inner = embedded_domain(h)
            if inner:
                facts.append("links:embedded-domain")
                embedded.append(f"{inner} inside {registrable(h)}")
    # dedupe, keep order
    seen: list[str] = []
    for f in facts:
        if f not in seen:
            seen.append(f)
    return tuple(seen), tuple(embedded)


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
        self.protected_domains = {registrable(p) for p in protected if "." in p and " " not in p.strip()}

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
        lookalike_hosts: set[str] = set()
        lookalike_sender = False
        if 1 in self.layers:
            for c in [c for c in (msg.sender_name, sender_domain, *hosts) if c]:
                ms = self.lookalike.check(c)
                if ms:
                    lookalikes.extend(ms)
                    if c == sender_domain:
                        lookalike_sender = True
                    if c in hosts:
                        lookalike_hosts.add(c)
            if lookalikes:
                floor = max(floor, 0.85)
                for m in lookalikes[:3]:
                    reasons.append(f"L1 lookalike of {m.protected!r}: {m.candidate!r} [{', '.join(m.reasons)}]")
            # Brand-agnostic: a link host that hides another organisation's domain inside its
            # own (orbitallabs.io.docs-share.site) is deceptive whoever the brand is.
            sender_sld = sld(sender_domain) if sender_domain else ""
            for h in hosts:
                inner = embedded_domain(h)
                if inner:
                    floor = max(floor, 0.85)
                    who = "the sender's own domain" if sender_sld and sld(inner) == sender_sld else inner
                    reasons.append(f"L1 link {h!r} embeds {who} inside {registrable(h)!r}")

        sender_score: SenderScore | None = None
        link_scores: dict[str, SenderScore] = {}
        display_claims_brand = False
        if 2 in self.layers:
            sender_score = self.scorer.score(sender)
            display_claims_brand = bool(sender_score.features.get("display_brand_token")
                                        or sender_score.features.get("display_brand_lookalike"))
            lookalike_sender = lookalike_sender or bool(
                sender_score.features.get("domain_skeleton_match") or sender_score.features.get("domain_close_typo")
                or sender_score.features.get("domain_brand_affix") or sender_score.features.get("domain_tld_swap")
                or sender_score.features.get("domain_leet_match"))
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
                if s.probability >= 0.5 and not (s.features.get("domain_free_mail")):
                    lookalike_hosts.add(h)

        intent: IntentResult | None = None
        fused = False
        if 3 in self.layers:
            facts: tuple[str, ...] = ()
            if {1, 2} & self.layers:
                # Layer 1/2 -> Layer 3 fusion: hand the classifier what the sender checks found.
                facts, embedded = sender_facts(
                    self.protected_domains, sender_domain, display_claims_brand, hosts, lookalike_hosts,
                    lookalike_sender, registrable(sender_domain) in FREE_MAIL if sender_domain else False)
                msg = _replace(msg, sender_facts=facts, embedded_domains=embedded)
                fused = True
            intent = self.intent.classify(msg)
            intent_risk = intent.risk
            if fused and intent.is_malicious:
                fset = set(facts)
                # Who is the sender? Verified institutions, or an organisation on its own domain.
                trusted = bool({"sender:platform-domain", "sender:institutional-domain"} & fset)
                own_org = "sender:unrelated-domain" in fset and not display_claims_brand
                # A peer on free webmail who asks for nothing and links nowhere is a peer.
                peer = ("sender:free-webmail" in fset and not display_claims_brand
                        and "links:none" in fset)
                # Do the links go anywhere the sender does not control?
                links_safe = not ({"links:lookalike", "links:embedded-domain"} & fset) and (
                    "links:off-platform" not in fset or "links:same-as-sender" in fset)
                # Is anything sensitive actually asked for? Judged by the deterministic cue
                # detector on the text, not by the model's self-reported signals, which a
                # small model invents ("requests sensitive documents" for a resume).
                asked: set[str] = set()
                for view in text_views(_normalize(f"{msg.subject}\n{msg.body}")):
                    asked |= detect_signals(view)
                sensitive = bool({"credential_request", "payment_request", "personal_data_request",
                                  "off_platform_move", "too_good_to_be_true"} & asked) \
                    or "injection_attempt" in intent.signals
                # The body claims the platform's authority ("Warning from <brand> Trust and
                # Safety") but the sender is not the platform: never discount that.
                body_tokens = set(tokenize(msg.body))
                claims_platform_in_body = (not trusted and "authority_claim" in asked
                                           and bool(self.scorer.extractor.brands & body_tokens))
                if (trusted or own_org or peer) and links_safe and not sensitive and not claims_platform_in_body:
                    # The classifier called it an attack, but the sender is who it says it is
                    # (or at least an organisation on its own domain), asks for nothing
                    # sensitive, and links nowhere it does not control. That is a notice or an
                    # ordinary recruiter, whatever its tone.
                    intent_risk *= 0.25
                    who = ("trusted sender" if trusted else
                           "organisation on its own domain" if own_org else "peer on webmail")
                    reasons.append(f"fusion: {who}, no sensitive request, no foreign link; "
                                   f"L3 {intent.label} discounted")
            risks.append(intent_risk)
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
            r = max(0.0, min(1.0, r))
            if r >= self.thresholds.noise_floor:
                survive *= 1.0 - r
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
