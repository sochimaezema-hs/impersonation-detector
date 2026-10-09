"""Layer 1: deterministic lookalike detection against a set of protected names.

A *protected name* is any string an attacker might imitate: a domain
(``handshake.com``), a brand (``Handshake``), a team (``Handshake Support``),
or an email local part (``support``). The detector reports *why* a candidate
matched so downstream systems can explain or weight the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .distance import osa_distance
from .scripts import is_mixed_script, scripts_in
from .skeleton import fold_skeleton


@dataclass(frozen=True)
class Match:
    candidate: str
    protected: str
    reasons: tuple[str, ...]
    distance: int

    @property
    def is_exact(self) -> bool:
        return self.candidate == self.protected


@dataclass
class LookalikeDetector:
    """Check candidates against protected names.

    Args:
        protected: names to defend (compared case-insensitively).
        max_distance: edit-distance threshold for the typo check; scaled down
            for very short names so ``a.co`` is not flagged against ``b.co``.
    """

    protected: list[str]
    max_distance: int = 2
    _skeletons: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.protected = [p.strip() for p in self.protected if p.strip()]
        self._skeletons = {p: fold_skeleton(p) for p in self.protected}

    @staticmethod
    def _decode_idn(text: str) -> str:
        """Decode ``xn--`` labels so punycode domains are judged by what they display."""
        if "xn--" not in text.casefold():
            return text
        try:
            return text.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            return text

    def _threshold(self, name: str) -> int:
        if len(name) <= 4:
            return 0
        if len(name) <= 8:
            return min(self.max_distance, 1)
        return self.max_distance

    def check(self, candidate: str) -> list[Match]:
        """Return every protected name *candidate* resembles, with reasons."""
        shown = self._decode_idn(candidate)
        folded = shown.casefold()
        cand_skel = fold_skeleton(shown)
        mixed = is_mixed_script(shown)
        matches: list[Match] = []
        for name, prot_skel in self._skeletons.items():
            if folded == name.casefold():
                continue  # the genuine name is not an impersonation
            reasons: list[str] = []
            if cand_skel == prot_skel:
                reasons.append("confusable-skeleton")
            dist = osa_distance(cand_skel, prot_skel)
            if 0 < dist <= self._threshold(name):
                reasons.append(f"edit-distance<={self._threshold(name)}")
            if reasons and mixed:
                reasons.append("mixed-script:" + "+".join(sorted(scripts_in(shown))))
            if reasons and shown != candidate:
                reasons.append("punycode")
            if reasons:
                matches.append(Match(candidate, name, tuple(reasons), dist))
        matches.sort(key=lambda m: (m.distance, m.protected))
        return matches

    def is_lookalike(self, candidate: str) -> bool:
        return bool(self.check(candidate))
