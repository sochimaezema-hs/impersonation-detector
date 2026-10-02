"""Script detection and mixed-script checks (UTS #39 §5)."""

from __future__ import annotations

from bisect import bisect_right

from ._data import script_ranges

# Scripts that may legitimately appear alongside any other script.
_NEUTRAL = {"Common", "Inherited", "Unknown"}

# UTS #39 "Highly Restrictive" profile: these combinations are allowed.
_ALLOWED_COMBOS = [
    {"Latin", "Han", "Hiragana", "Katakana"},  # Japanese
    {"Latin", "Han", "Bopomofo"},  # Chinese
    {"Latin", "Han", "Hangul"},  # Korean
]


def script_of(ch: str) -> str:
    """Return the Unicode script property of a single character."""
    cp = ord(ch)
    ranges = script_ranges()
    i = bisect_right(ranges, (cp, 0x10FFFF, "￿")) - 1
    if i >= 0:
        lo, hi, script = ranges[i]
        if lo <= cp <= hi:
            return script
    return "Unknown"


def scripts_in(text: str) -> set[str]:
    """Set of non-neutral scripts present in *text*."""
    return {s for s in (script_of(ch) for ch in text) if s not in _NEUTRAL}


def is_mixed_script(text: str) -> bool:
    """True when *text* mixes scripts in a way UTS #39's Highly Restrictive
    profile would reject — e.g. Latin letters with a Cyrillic 'а'."""
    found = scripts_in(text)
    if len(found) <= 1:
        return False
    return not any(found <= combo for combo in _ALLOWED_COMBOS)
