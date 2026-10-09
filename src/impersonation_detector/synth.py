"""Synthetic sender generator for training and benchmarking Layer 2.

Given a protected set, produce labelled senders covering the impersonation techniques
the scorer must learn, and benign senders that share surface features (role words,
free-mail domains, universities) without impersonating anything. Seeded, so runs are
reproducible.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .domains import brand_tokens, protected_domains, sld, tld
from .features import Sender

# Confusable substitutions actually seen in homograph attacks (Cyrillic/Greek/Latin).
HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("а", "ɑ", "α"), "c": ("с", "ϲ"), "d": ("ԁ",), "e": ("е", "ҽ"), "h": ("һ",),
    "i": ("і", "ı"), "j": ("ј",), "k": ("κ",), "l": ("ӏ", "1", "I"), "m": ("rn",),
    "n": ("ո",), "o": ("о", "0", "ο"), "p": ("р", "ρ"), "s": ("ѕ",), "t": ("т",),
    "u": ("υ", "ս"), "v": ("ν",), "w": ("ԝ", "vv"), "x": ("х",), "y": ("у", "γ"),
}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}
AFFIXES = ("-support", "support", "-help", "-careers", "careers", "-jobs", "jobs", "-team",
           "-verify", "-login", "-secure", "-hr", "-recruiting", "-official", "-alerts")
PREFIXES = ("my", "get", "join", "the", "secure-", "login-", "app-", "team", "hr-", "jobs-")
TLDS = ("com", "net", "org", "co", "io", "app", "support", "careers", "jobs", "info", "xyz",
        "help", "top", "site", "online", "live", "me", "us", "cc", "click")
FREE = ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com", "proton.me",
        "aol.com", "mail.com")
EVIL_DOMAINS = ("verify-login.io", "secure-portal.app", "account-update.net", "hr-portal.co",
                "mail-notice.xyz", "docs-share.site", "talent-connect.online", "auth-check.top")
ROLE_NAMES = ("Support", "Support Team", "Security", "Security Team", "Careers", "Recruiting",
              "Talent Team", "Help Center", "Account Team", "Trust & Safety", "HR", "Admin",
              "Notifications", "Verification Team", "Payroll")
ROLE_LOCALS = ("support", "security", "careers", "recruiting", "talent", "help", "noreply",
               "no-reply", "accounts", "admin", "hr", "verify", "alerts", "team", "payroll")
PERSON_FIRST = ("Jane", "Luis", "Priya", "Aisha", "Tom", "Wei", "Maria", "Sam", "Noah", "Emma",
                "Kofi", "Sofia", "Ethan", "Chloe", "Ravi", "Hannah", "Omar", "Grace", "Leo")
PERSON_LAST = ("Doe", "Garcia", "Patel", "Okafor", "Nguyen", "Chen", "Smith", "Kim", "Rossi",
               "Brown", "Mensah", "Silva", "Johnson", "Lee", "Khan", "Novak", "Diaz", "Wright")
OTHER_COMPANIES = (
    "Acme Robotics", "Northwind Traders", "Lumen Health", "Bluepeak Capital", "Orbital Labs",
    "Granite Analytics", "Cedar Logistics", "Harbor Fintech", "Pioneer Biotech", "Summit Media",
    "Tidewater Energy", "Vertex Consulting", "Maple Software", "Ironclad Systems", "Nimbus Cloud",
    "Redwood Insurance", "Solstice Games", "Crescent Foods", "Atlas Mobility", "Quartz Security",
    "Beacon Education", "Lighthouse Legal", "Juniper Retail", "Falcon Aerospace", "Ember Studio",
)
UNIVERSITIES = ("stanford.edu", "berkeley.edu", "umich.edu", "utexas.edu", "gatech.edu",
                "asu.edu", "osu.edu", "ucla.edu", "nyu.edu", "psu.edu", "wgu.edu", "cuny.edu")
UNI_OFFICES = ("Career Services", "Career Center", "Financial Aid", "Registrar", "IT Help Desk",
               "Student Affairs", "Admissions", "Handshake Admin")  # the last one is benign ON .edu


@dataclass(frozen=True)
class Example:
    sender: Sender
    label: int  # 1 = impersonation
    technique: str


def _company_domain(name: str, rng: random.Random) -> str:
    base = "".join(t for t in name.casefold().split() if t not in {"&"})
    return f"{base}.{rng.choice(('com', 'com', 'com', 'io', 'co', 'net'))}"


class SenderSynth:
    def __init__(self, protected: list[str], seed: int = 7) -> None:
        self.protected = protected
        self.rng = random.Random(seed)
        self.brands = sorted(brand_tokens(protected))
        self.domains = sorted(protected_domains(protected))
        if not self.brands or not self.domains:
            raise ValueError("protected set needs at least one brand token and one domain")
        self.brand_title = {b: b.title() for b in self.brands}

    # -- mutation primitives ---------------------------------------------------------

    def homoglyph(self, word: str, n: int = 1) -> str:
        idx = [i for i, ch in enumerate(word) if ch in HOMOGLYPHS]
        if not idx:
            return word
        out = list(word)
        for i in self.rng.sample(idx, min(n, len(idx))):
            out[i] = self.rng.choice(HOMOGLYPHS[out[i]])
        return "".join(out)

    def typo(self, word: str) -> str:
        if len(word) < 5:
            return word
        kind = self.rng.choice(("swap", "drop", "double", "insert"))
        i = self.rng.randrange(1, len(word) - 1)
        if kind == "swap":
            return word[:i] + word[i + 1] + word[i] + word[i + 2:]
        if kind == "drop":
            return word[:i] + word[i + 1:]
        if kind == "double":
            return word[:i] + word[i] + word[i:]
        return word[:i] + self.rng.choice("abcdefghijklmnopqrstuvwxyz") + word[i:]

    def leet(self, word: str) -> str:
        idx = [i for i, ch in enumerate(word) if ch in LEET]
        if not idx:
            return word
        out = list(word)
        for i in self.rng.sample(idx, min(self.rng.choice((1, 2)), len(idx))):
            out[i] = LEET[out[i]]
        return "".join(out)

    # -- positive (impersonation) senders ----------------------------------------------

    def positive(self) -> Example:
        rng = self.rng
        brand = rng.choice(self.brands)
        dom = rng.choice(self.domains)
        title = self.brand_title[brand]
        role = rng.choice(ROLE_NAMES)
        local = rng.choice(ROLE_LOCALS)
        technique = rng.choice((
            "homoglyph_domain", "homoglyph_domain", "typo_domain", "tld_swap", "affix_domain",
            "prefix_domain", "subdomain_embed", "leet_domain", "freemail_brand_display",
            "brand_display_evil_domain", "punycode_domain", "homoglyph_display", "invisible_chars",
            "brand_local_evil_domain",
        ))
        domain_based = technique in {
            "homoglyph_domain", "typo_domain", "tld_swap", "affix_domain", "prefix_domain",
            "subdomain_embed", "leet_domain", "punycode_domain",
        }
        if domain_based and rng.random() < 0.4:
            # employee impersonation: a person's name on a lookalike domain
            first, last = rng.choice(PERSON_FIRST), rng.choice(PERSON_LAST)
            title, role, local = first, last, f"{first.lower()}.{last.lower()}"
        if technique == "homoglyph_domain":
            d = f"{self.homoglyph(sld(dom), rng.choice((1, 1, 2)))}.{tld(dom)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "typo_domain":
            d = f"{self.typo(sld(dom))}.{tld(dom)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "tld_swap":
            d = f"{sld(dom)}.{rng.choice([t for t in TLDS if t != tld(dom)])}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "affix_domain":
            d = f"{brand}{rng.choice(AFFIXES)}.{rng.choice(TLDS)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "prefix_domain":
            d = f"{rng.choice(PREFIXES)}{brand}.{rng.choice(TLDS)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "subdomain_embed":
            d = f"{dom}.{rng.choice(EVIL_DOMAINS)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "leet_domain":
            d = f"{self.leet(brand)}.{rng.choice(TLDS)}"
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "freemail_brand_display":
            s = Sender(f"{title} {role}", f"{brand}.{local}{rng.randrange(1, 99)}@{rng.choice(FREE)}")
        elif technique == "brand_display_evil_domain":
            s = Sender(f"{title} {role}", f"{local}@{rng.choice(EVIL_DOMAINS)}")
        elif technique == "punycode_domain":
            shown = f"{self.homoglyph(sld(dom))}.{tld(dom)}"
            try:
                d = shown.encode("idna").decode("ascii")
            except UnicodeError:
                d = shown
            s = Sender(f"{title} {role}", f"{local}@{d}")
        elif technique == "homoglyph_display":
            s = Sender(f"{self.homoglyph(title)} {role}", f"{local}@{rng.choice(EVIL_DOMAINS + FREE)}")
        elif technique == "invisible_chars":
            zw = rng.choice((chr(0x200B), chr(0x200C), chr(0x2060)))
            s = Sender(f"{title[:3]}{zw}{title[3:]} {role}", f"{local}@{dom.replace('.', zw + '.')}")
        else:  # brand_local_evil_domain
            s = Sender(f"{rng.choice(PERSON_FIRST)} {rng.choice(PERSON_LAST)}",
                       f"{brand}-{local}@{rng.choice(EVIL_DOMAINS + FREE)}")
        return Example(s, 1, technique)

    # -- benign senders ----------------------------------------------------------------

    def negative(self) -> Example:
        rng = self.rng
        brand = rng.choice(self.brands)
        dom = rng.choice(self.domains)
        title = self.brand_title[brand]
        technique = rng.choice((
            "genuine_brand", "genuine_brand", "other_company", "other_company", "other_company",
            "person_freemail", "person_freemail", "university_office", "university_student",
            "other_company_role", "person_company",
        ))
        if technique == "genuine_brand":
            s = Sender(f"{title} {rng.choice(ROLE_NAMES)}", f"{rng.choice(ROLE_LOCALS)}@{dom}")
        elif technique == "other_company":
            co = rng.choice(OTHER_COMPANIES)
            s = Sender(f"{rng.choice(PERSON_FIRST)} {rng.choice(PERSON_LAST)}",
                       f"{rng.choice(PERSON_FIRST).lower()}@{_company_domain(co, rng)}")
        elif technique == "other_company_role":
            co = rng.choice(OTHER_COMPANIES)
            s = Sender(f"{co} {rng.choice(ROLE_NAMES)}",
                       f"{rng.choice(ROLE_LOCALS)}@{_company_domain(co, rng)}")
        elif technique == "person_freemail":
            first, last = rng.choice(PERSON_FIRST), rng.choice(PERSON_LAST)
            s = Sender(f"{first} {last}", f"{first.lower()}.{last.lower()}{rng.randrange(1, 99)}@{rng.choice(FREE)}")
        elif technique == "university_office":
            s = Sender(rng.choice(UNI_OFFICES), f"{rng.choice(ROLE_LOCALS)}@{rng.choice(UNIVERSITIES)}")
        elif technique == "university_student":
            first, last = rng.choice(PERSON_FIRST), rng.choice(PERSON_LAST)
            s = Sender(f"{first} {last}", f"{first[0].lower()}{last.lower()}@{rng.choice(UNIVERSITIES)}")
        else:  # person_company
            co = rng.choice(OTHER_COMPANIES)
            first, last = rng.choice(PERSON_FIRST), rng.choice(PERSON_LAST)
            s = Sender(f"{first} {last} ({co})", f"{first.lower()}.{last.lower()}@{_company_domain(co, rng)}")
        return Example(s, 0, technique)

    def dataset(self, n_pos: int, n_neg: int) -> list[Example]:
        data = [self.positive() for _ in range(n_pos)] + [self.negative() for _ in range(n_neg)]
        self.rng.shuffle(data)
        return data
