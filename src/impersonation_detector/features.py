"""Layer 2 feature extraction: turn a sender (or a bare domain) into named, explainable
signals of impersonation against a set of protected names.

Every feature is a float in [0, 1]. Most are indicators. Names are stable and appear
verbatim in the trained weights file and in ``SenderScore.contributions``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .distance import osa_distance
from .domains import (
    DOMAIN_LURE_WORDS,
    FREE_MAIL,
    ROLE_WORDS,
    brand_tokens,
    embedded_domain,
    has_invisible,
    parse_address,
    protected_domains,
    registrable,
    sld,
    subdomain_labels,
    tokenize,
    unleet,
)
from .scripts import is_mixed_script
from .skeleton import fold_skeleton as skeleton

FEATURE_NAMES: tuple[str, ...] = (
    # domain-level
    "domain_is_protected",
    "domain_skeleton_match",
    "domain_close_typo",
    "domain_mixed_script",
    "domain_punycode",
    "domain_tld_swap",
    "domain_brand_affix",
    "domain_brand_in_subdomain",
    "domain_embeds_foreign_domain",
    "domain_lure_words",
    "domain_leet_match",
    "domain_free_mail",
    "domain_missing",
    "domain_invisible_chars",
    # display-name-level
    "display_brand_token",
    "display_brand_lookalike",
    "display_role_word",
    "display_claims_brand_off_domain",
    "display_invisible_chars",
    "display_mixed_script",
    # local-part / handle
    "local_brand_token",
    "local_role_word",
    "local_brand_lookalike",
)


@dataclass(frozen=True)
class Sender:
    """A message sender as the recipient sees it."""

    display_name: str = ""
    address: str = ""  # ``local@domain`` or a platform handle

    @property
    def parts(self) -> tuple[str, str, str]:
        name, local, domain = parse_address(self.address)
        return (self.display_name or name), local, domain


class FeatureExtractor:
    """Extract Layer 2 features against a fixed protected set."""

    def __init__(self, protected: list[str], max_distance: int = 2) -> None:
        self.protected = [p.strip() for p in protected if p.strip()]
        self.max_distance = max_distance
        self.brands = brand_tokens(self.protected)
        self.brand_skeletons = {b: skeleton(b) for b in self.brands}
        self.domains = protected_domains(self.protected)
        self.domain_slds = {sld(d): d for d in self.domains}
        self.sld_skeletons = {s: skeleton(s) for s in self.domain_slds}
        self.name_skeletons = {skeleton(p) for p in self.protected}

    # -- helpers -----------------------------------------------------------------

    def _threshold(self, name: str) -> int:
        if len(name) <= 4:
            return 0
        if len(name) <= 8:
            return min(self.max_distance, 1)
        return self.max_distance

    def _closest_brand(self, token: str) -> tuple[str | None, int]:
        """(brand, skeleton edit distance) for the nearest brand token."""
        sk = skeleton(token)
        best: tuple[str | None, int] = (None, 10**6)
        for brand, bsk in self.brand_skeletons.items():
            d = osa_distance(sk, bsk)
            if d < best[1]:
                best = (brand, d)
        return best

    def _token_is_brand(self, token: str) -> bool:
        return token in self.brands or skeleton(token) in self.brand_skeletons.values()

    def _token_is_lookalike(self, token: str) -> bool:
        if token in self.brands:
            return False
        brand, d = self._closest_brand(token)
        if brand is None:
            return False
        if d == 0:
            return True  # skeleton-equal but not identical: confusable glyphs
        return 0 < d <= self._threshold(brand)

    def _contains_brand(self, text: str) -> bool:
        """Brand token embedded with affixes: ``handshakecareers``, ``my-handshake``."""
        t = skeleton(text)
        return any(bsk in t for bsk in self.brand_skeletons.values() if len(bsk) >= 4)

    # -- domain features -----------------------------------------------------------

    def domain_features(self, domain: str) -> dict[str, float]:
        f = {k: 0.0 for k in FEATURE_NAMES if k.startswith("domain_")}
        if not domain:
            f["domain_missing"] = 1.0
            return f
        raw = domain
        reg = registrable(domain)  # decoded, invisibles stripped
        s = sld(domain)
        f["domain_invisible_chars"] = float(has_invisible(raw))
        f["domain_punycode"] = float("xn--" in raw.casefold())
        f["domain_mixed_script"] = float(is_mixed_script(reg))
        f["domain_free_mail"] = float(reg in FREE_MAIL)
        f["domain_embeds_foreign_domain"] = float(embedded_domain(domain) is not None)
        sld_tokens = [t for t in re.split(r"[^a-z0-9]+", sld(domain)) if t]
        f["domain_lure_words"] = float(
            bool(sld_tokens) and all(t in DOMAIN_LURE_WORDS or t.isdigit() for t in sld_tokens)
            and reg not in FREE_MAIL)
        if reg in self.domains:
            f["domain_is_protected"] = 1.0
            return f
        if not s:
            return f
        ssk = skeleton(s)
        # confusable / typo against protected SLDs and brand tokens
        targets = dict(self.sld_skeletons)
        targets.update(self.brand_skeletons)
        best_name, best_d = None, 10**6
        for name, nsk in targets.items():
            d = osa_distance(ssk, nsk)
            if d < best_d:
                best_name, best_d = name, d
        if best_name is not None:
            if best_d == 0:
                if s in targets:  # same SLD, different TLD
                    f["domain_tld_swap"] = 1.0
                else:
                    f["domain_skeleton_match"] = 1.0
            elif best_d <= self._threshold(best_name):
                f["domain_close_typo"] = 1.0
        if not f["domain_skeleton_match"] and not f["domain_tld_swap"]:
            if self._contains_brand(s):
                f["domain_brand_affix"] = 1.0
            elif skeleton(unleet(s)) in targets.values():
                f["domain_leet_match"] = 1.0
        subs = subdomain_labels(domain)
        if any(self._token_is_brand(lab) or self._contains_brand(lab) for lab in subs):
            f["domain_brand_in_subdomain"] = 1.0
        return f

    # -- sender features -----------------------------------------------------------

    def extract(self, sender: Sender) -> dict[str, float]:
        display, local, domain = sender.parts
        f = {k: 0.0 for k in FEATURE_NAMES}
        f.update(self.domain_features(domain))

        dtoks = tokenize(display)
        f["display_invisible_chars"] = float(has_invisible(display))
        f["display_mixed_script"] = float(is_mixed_script(display))
        f["display_role_word"] = float(any(t in ROLE_WORDS for t in dtoks))
        f["display_brand_token"] = float(
            any(self._token_is_brand(t) for t in dtoks)
            or skeleton(display) in self.name_skeletons
            or any(self._contains_brand(t) for t in dtoks)
        )
        f["display_brand_lookalike"] = float(any(self._token_is_lookalike(t) for t in dtoks))
        claims = f["display_brand_token"] or f["display_brand_lookalike"]
        f["display_claims_brand_off_domain"] = float(bool(claims) and not f["domain_is_protected"])

        ltoks = tokenize(local)
        f["local_role_word"] = float(any(t in ROLE_WORDS for t in ltoks))
        f["local_brand_token"] = float(
            any(self._token_is_brand(t) or self._contains_brand(t) for t in ltoks)
        )
        f["local_brand_lookalike"] = float(any(self._token_is_lookalike(t) for t in ltoks))
        return f
