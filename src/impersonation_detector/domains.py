"""Domain, address, and token helpers shared by the sender scorer and the pipeline.

Deliberately dependency-free: a small multi-label public-suffix list covers the
common cases well enough for feature extraction, where the cost of an occasional
mis-split is one noisy feature rather than a wrong decision.
"""

from __future__ import annotations

import re
import unicodedata

FREE_MAIL = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "pm.me", "mail.com", "yandex.com", "gmx.com", "gmx.net", "zoho.com", "tutanota.com",
    "fastmail.com", "hey.com", "mail.ru", "qq.com", "163.com",
})

# Second-level suffixes under which the registrable domain is three labels long.
_MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "co.za", "com.br",
    "com.mx", "com.ar", "com.sg", "com.hk", "com.tw", "co.kr", "com.cn", "com.tr", "com.ng",
    "co.il", "com.my", "com.ph", "com.pk", "com.eg", "com.sa",
})

# Public TLDs common enough that their appearance as an *interior* label of a host
# (``orbitallabs.io.docs-share.site``) signals an embedded-domain deception.
KNOWN_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev", "me", "us",
    "uk", "ca", "de", "fr", "au", "in", "jp", "br", "nl", "se", "no", "es", "it", "ch", "ru", "cn",
    "info", "biz", "xyz", "online", "site", "top", "club", "shop", "store", "tech", "cloud",
    "live", "link", "click", "help", "support", "careers", "jobs", "work", "ly", "gl", "tv",
})

INSTITUTIONAL_TLDS = frozenset({"edu", "gov", "mil", "ac.uk", "edu.au", "ac.jp", "ac.in"})

# Words a sender uses to claim an institutional role. Each one is a feature, not a verdict:
# "careers@berkeley.edu" is benign; "Handshake Careers" <x@gmail.com> is not.
ROLE_WORDS = frozenset({
    "support", "security", "help", "helpdesk", "verify", "verification", "account", "accounts",
    "admin", "administrator", "billing", "careers", "career", "recruit", "recruiter", "recruiting",
    "recruitment", "hr", "talent", "team", "official", "noreply", "no-reply", "donotreply", "alerts",
    "alert", "notifications", "notification", "service", "services", "it", "desk", "payroll",
    "compliance", "trust", "safety", "fraud", "update", "updates", "info", "contact", "onboarding",
    "hiring", "jobs", "employer", "employers",
})

# Generic tokens that never identify a brand on their own.
_GENERIC = ROLE_WORDS | frozenset({
    "com", "net", "org", "edu", "io", "co", "www", "mail", "email", "the", "inc", "llc", "corp",
    "ltd", "group", "global", "online", "app", "my", "get", "join", "use", "go", "login", "secure",
    "portal", "us", "usa",
})

# Zero-width, joiner, bidi-isolate and tag characters, built from code points so the
# source never contains an invisible literal.
_INVISIBLE_CODEPOINTS = (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x034F, 0x061C, 0x180E,
    *range(0x2061, 0x2065), *range(0x206A, 0x2070), *range(0xE0000, 0xE0080),
)
_INVISIBLE = re.compile("[" + "".join(re.escape(chr(c)) for c in _INVISIBLE_CODEPOINTS) + "]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_EMAIL = re.compile(
    r"^\s*(?:\"?([^\"<]*?)\"?\s*<([^\s<>@]+)@([^\s<>@]+)>|([^\s<>@]+)@([^\s<>@]+))\s*$"
)
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                       "@": "a", "$": "s", "|": "l", "!": "i"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                         "@": "a", "$": "s", "|": "i", "!": "i"})


def has_invisible(text: str) -> bool:
    """True when *text* carries zero-width, bidi-control, or C0/C1 control characters."""
    return bool(_INVISIBLE.search(text) or _CONTROL.search(text))


def strip_invisible(text: str) -> str:
    return _CONTROL.sub("", _INVISIBLE.sub("", text))


def decode_idn(host: str) -> str:
    """Decode ``xn--`` labels so a domain is judged by what it displays."""
    if "xn--" not in host.casefold():
        return host
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host


def normalize_host(host: str) -> str:
    """Casefold, strip invisibles, drop any path/port. Punycode is left as-is so
    callers can still see it; :func:`labels` decodes it."""
    host = strip_invisible(host).strip().strip(".").casefold()
    return host.split("/", 1)[0].split(":", 1)[0]


def labels(host: str) -> list[str]:
    return [lab for lab in decode_idn(normalize_host(host)).split(".") if lab]


def registrable(host: str) -> str:
    """The registrable domain (``verify-login.io`` for ``handshake.com.verify-login.io``)."""
    labs = labels(host)
    if len(labs) <= 2:
        return ".".join(labs)
    if ".".join(labs[-2:]) in _MULTI_SUFFIX and len(labs) >= 3:
        return ".".join(labs[-3:])
    return ".".join(labs[-2:])


def sld(host: str) -> str:
    """The second-level label of the registrable domain (``handshake`` for ``handshake.com``)."""
    reg = registrable(host)
    return reg.split(".", 1)[0] if reg else ""


def tld(host: str) -> str:
    reg = registrable(host)
    return reg.split(".", 1)[1] if "." in reg else ""


def subdomain_labels(host: str) -> list[str]:
    labs = labels(host)
    reg_len = len(registrable(host).split(".")) if labs else 0
    return labs[: max(0, len(labs) - reg_len)]


def tokenize(text: str) -> list[str]:
    """Casefolded alphanumeric tokens, NFKC-normalized, invisibles removed."""
    text = unicodedata.normalize("NFKC", strip_invisible(text)).casefold()
    return [t for t in re.split(r"[^\w]+", text) if t]


def unleet(text: str) -> str:
    return text.translate(_LEET)


def unleet_i(text: str) -> str:
    """Alternative reading with ``1`` as ``i`` (``51gn 1n`` → ``sign in``)."""
    return text.translate(_LEET_I)


def unconfuse_ascii(text: str) -> str:
    """ASCII-only confusables UTS #39 folds the *other* way: ``rn`` → ``m``, ``vv`` → ``w``,
    ``cl`` → ``d``. Used as an extra view for cue matching, never as the primary text."""
    return text.replace("rn", "m").replace("RN", "M").replace("vv", "w").replace("VV", "W").replace("cl", "d")


def brand_tokens(protected: list[str]) -> set[str]:
    """Identifying tokens of the protected names: ``{"handshake"}`` from
    ``["handshake.com", "Handshake Support"]``. Generic and role words are dropped."""
    out: set[str] = set()
    for name in protected:
        for tok in tokenize(name):
            if len(tok) >= 4 and tok not in _GENERIC and not tok.isdigit():
                out.add(tok)
    return out


def protected_domains(protected: list[str]) -> set[str]:
    """Registrable domains among the protected names (those containing a dot)."""
    return {registrable(p) for p in protected if "." in p and " " not in p.strip()}


def parse_address(address: str) -> tuple[str, str, str]:
    """Split ``"Name" <local@domain>`` or ``local@domain`` or a bare handle into
    (display_from_address, local, domain). A handle yields ("", handle, "")."""
    m = _EMAIL.match(address or "")
    if not m:
        return "", (address or "").strip().lstrip("@"), ""
    if m.group(2):
        name, local, domain = m.group(1) or "", m.group(2), m.group(3)
    else:
        name, local, domain = "", m.group(4), m.group(5)
    # The domain keeps invisible characters and punycode so features can flag them.
    return name.strip(), local.strip(), domain.strip().strip(".").casefold()


def embedded_domain(host: str) -> str | None:
    """A registrable domain hidden in the subdomain labels of *host*, brand-agnostic.

    ``orbitallabs.io.docs-share.site`` → ``orbitallabs.io``; ``mail.google.com`` → None.
    The rule: an interior label that is a public TLD, preceded by at least one label,
    with the real registrable domain still to its right.
    """
    subs = subdomain_labels(host)
    for i in range(1, len(subs)):
        if subs[i] in KNOWN_TLDS and subs[i - 1] not in KNOWN_TLDS:
            # prefer a two-level suffix (co.uk) when present
            if i + 1 < len(subs) and f"{subs[i]}.{subs[i + 1]}" in _MULTI_SUFFIX:
                return ".".join(subs[i - 1:i + 2])
            return f"{subs[i - 1]}.{subs[i]}"
    return None


def is_institutional(host: str) -> bool:
    """True for university / government registrable domains (``.edu``, ``.gov``, ``ac.uk``)."""
    reg = registrable(host)
    return any(reg == t or reg.endswith("." + t) for t in INSTITUTIONAL_TLDS)
