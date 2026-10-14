"""Lookalike-domain leg: enumerate the registrable lookalike space around protected
domains, find which candidates are live, and score them so a platform can act before
a message is ever sent from one.

Generation is deterministic and offline. Resolution is pluggable: :class:`DnsRdapResolver`
uses the system resolver, ``dig`` for MX when available, and the public RDAP bootstrap
for registration dates; tests inject a fake. Hits can be exported and loaded into
:class:`~impersonation_detector.pipeline.Detector` as a dynamic blocklist.

Scope note: dnstwist pioneered permutation generation. This module reuses the idea but
scores each candidate with the same explainable Layer 2 features the message detector
uses, adds registration recency and mail capability, and closes the loop into the send
pipeline — the parts a platform needs that a standalone CLI does not provide.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from .domains import protected_domains, sld, tld
from .scorer import SenderScorer
from .synth import AFFIXES, HOMOGLYPHS, LEET, PREFIXES, TLDS

# Keyboard neighbours (QWERTY) for fat-finger typos.
_NEIGHBOURS = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "o", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb",
    "j": "hukn", "k": "jilm", "l": "ko", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}
_VOWELS = "aeiou"


@dataclass(frozen=True)
class Candidate:
    domain: str
    technique: str
    source: str  # the protected domain it imitates


@dataclass
class Resolution:
    registered: bool | None = None  # None = unknown
    addresses: tuple[str, ...] = ()
    has_mx: bool | None = None
    created: str | None = None  # ISO date
    registrar: str | None = None
    error: str | None = None

    @property
    def live(self) -> bool:
        return bool(self.addresses) or bool(self.has_mx) or self.registered is True

    @property
    def age_days(self) -> float | None:
        if not self.created:
            return None
        try:
            dt = datetime.fromisoformat(self.created.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


@dataclass
class WatchHit:
    candidate: Candidate
    resolution: Resolution
    score: float
    reasons: list[str]
    risk: float
    action: str

    def to_dict(self) -> dict:
        d = {"domain": self.candidate.domain, "technique": self.candidate.technique,
             "source": self.candidate.source, "score": round(self.score, 4),
             "risk": round(self.risk, 4), "action": self.action, "reasons": self.reasons}
        d.update({f"res_{k}": v for k, v in asdict(self.resolution).items()})
        return d


class LookalikeGenerator:
    """Enumerate lookalike candidates for each protected domain."""

    TECHNIQUES = ("homoglyph", "omission", "transposition", "repetition", "insertion",
                  "replacement", "vowel_swap", "leet", "hyphenation", "tld_swap", "affix",
                  "prefix", "plural")

    def __init__(self, protected: list[str], techniques: tuple[str, ...] | None = None,
                 tlds: tuple[str, ...] = TLDS) -> None:
        self.domains = sorted(protected_domains(protected))
        self.techniques = techniques or self.TECHNIQUES
        self.tlds = tlds

    def _for(self, domain: str) -> list[Candidate]:
        base, suffix = sld(domain), tld(domain)
        out: dict[str, str] = {}

        def add(name: str, technique: str, suf: str = suffix) -> None:
            cand = f"{name}.{suf}".casefold()
            if (name and cand not in self.domains and cand not in out
                    and technique in self.techniques):
                out[cand] = technique

        n = len(base)
        for i, ch in enumerate(base):
            for sub in HOMOGLYPHS.get(ch, ()):
                if len(sub) == 1 and ord(sub) > 127 or sub in ("rn", "vv", "1", "I"):
                    add(base[:i] + sub + base[i + 1:], "homoglyph")
            if n > 3:
                add(base[:i] + base[i + 1:], "omission")
            if i < n - 1 and ch != base[i + 1]:
                add(base[:i] + base[i + 1] + ch + base[i + 2:], "transposition")
            add(base[:i] + ch + base[i:], "repetition")
            for nb in _NEIGHBOURS.get(ch, ""):
                add(base[:i] + nb + base[i + 1:], "replacement")
                add(base[:i] + nb + base[i:], "insertion")
            if ch in _VOWELS:
                for v in _VOWELS:
                    if v != ch:
                        add(base[:i] + v + base[i + 1:], "vowel_swap")
            if ch in LEET:
                add(base[:i] + LEET[ch] + base[i + 1:], "leet")
            if 0 < i < n - 1:
                add(base[:i] + "-" + base[i:], "hyphenation")
        for t in self.tlds:
            if t != suffix:
                add(base, "tld_swap", t)
        for a in AFFIXES:
            add(base + a, "affix")
            for t in ("com", "net", "co", "io", "app"):
                if t != suffix:
                    add(base + a, "affix", t)
        for p in PREFIXES:
            add(p + base, "prefix")
        add(base + "s" if not base.endswith("s") else base[:-1], "plural")
        return [Candidate(d, t, domain) for d, t in out.items()]

    def generate(self, limit: int | None = None) -> list[Candidate]:
        cands: list[Candidate] = []
        seen: set[str] = set()
        for d in self.domains:
            for c in self._for(d):
                if c.domain not in seen:
                    seen.add(c.domain)
                    cands.append(c)
        return cands[:limit] if limit else cands


class Resolver(Protocol):
    def resolve(self, domain: str) -> Resolution: ...


class DnsRdapResolver:
    """System DNS for A/AAAA, ``dig`` for MX when installed, RDAP for registration date."""

    def __init__(self, rdap: bool = True, mx: bool = True, timeout: float = 5.0,
                 pause: float = 0.0) -> None:
        self.rdap = rdap
        self.mx = mx
        self.timeout = timeout
        self.pause = pause

    def _addresses(self, domain: str) -> tuple[str, ...]:
        try:
            infos = socket.getaddrinfo(domain.encode("idna").decode("ascii"), None)
        except (socket.gaierror, UnicodeError, OSError):
            return ()
        return tuple(sorted({i[4][0] for i in infos}))

    def _mx(self, domain: str) -> bool | None:
        try:
            out = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True,
                                 timeout=self.timeout, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        return bool(out.stdout.strip())

    def _rdap(self, domain: str) -> tuple[bool | None, str | None, str | None]:
        url = "https://rdap.org/domain/" + domain.encode("idna").decode("ascii")
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json",
                                                   "User-Agent": "impersonation-detector/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return (False, None, None) if exc.code == 404 else (None, None, None)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return None, None, None
        created = None
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for v in ent.get("vcardArray", [None, []])[1] or []:
                    if v and v[0] == "fn":
                        registrar = v[3]
        return True, created, registrar

    def resolve(self, domain: str) -> Resolution:
        res = Resolution(addresses=self._addresses(domain))
        if self.mx:
            res.has_mx = self._mx(domain)
        if self.rdap:
            res.registered, res.created, res.registrar = self._rdap(domain)
        if res.registered is None and res.addresses:
            res.registered = True
        if self.pause:
            time.sleep(self.pause)
        return res


class StaticResolver:
    """Test double: a mapping of domain -> Resolution; unknown domains are unregistered."""

    def __init__(self, table: dict[str, Resolution] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    def resolve(self, domain: str) -> Resolution:
        self.calls.append(domain)
        return self.table.get(domain, Resolution(registered=False))


@dataclass
class DomainWatch:
    """Generate, resolve, and score lookalike domains for a protected set."""

    protected: list[str]
    resolver: Resolver | None = None
    techniques: tuple[str, ...] | None = None
    new_registration_days: float = 90.0
    _scorer: SenderScorer = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._scorer = SenderScorer(self.protected)
        self.generator = LookalikeGenerator(self.protected, self.techniques)

    def score(self, candidate: Candidate, res: Resolution) -> WatchHit:
        s = self._scorer.score_domain(candidate.domain)
        reasons = [f"L2 {r}" for r in s.reasons[:4]]
        # Cap the lookalike score so live / new / mail-capable evidence can still separate
        # candidates once the name itself is a near-certain lookalike.
        risk = min(s.probability, 0.9)
        if res.live:
            reasons.append("live: " + ", ".join(k for k, v in (("resolves", res.addresses),
                                                              ("mx", res.has_mx),
                                                              ("registered", res.registered)) if v))
            risk = 1 - (1 - risk) * 0.5
        age = res.age_days
        if age is not None and age <= self.new_registration_days:
            reasons.append(f"registered {age:.0f} days ago")
            risk = 1 - (1 - risk) * 0.5
        if res.has_mx:
            reasons.append("can send mail")
            risk = 1 - (1 - risk) * 0.7
        action = "block" if risk >= 0.85 else "watch" if risk >= 0.5 else "note" if res.live else "none"
        return WatchHit(candidate, res, s.probability, reasons, risk, action)

    def scan(self, resolve: bool = True, limit: int | None = None,
             only_live: bool = True) -> list[WatchHit]:
        resolver = self.resolver or DnsRdapResolver()
        hits: list[WatchHit] = []
        for cand in self.generator.generate(limit):
            res = resolver.resolve(cand.domain) if resolve else Resolution()
            if only_live and resolve and not res.live:
                continue
            hits.append(self.score(cand, res))
        hits.sort(key=lambda h: (-h.risk, h.candidate.domain))
        return hits

    @staticmethod
    def blocklist(hits: list[WatchHit], min_action: str = "watch") -> set[str]:
        order = {"none": 0, "note": 1, "watch": 2, "block": 3}
        return {h.candidate.domain for h in hits if order[h.action] >= order[min_action]}
