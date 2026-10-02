"""UTS #39 §4 confusable detection: skeleton() and confusable()."""

from __future__ import annotations

import unicodedata

from ._data import confusables


def skeleton(text: str) -> str:
    """Return the UTS #39 skeleton of *text*.

    Algorithm (UTS #39 §4): NFD-normalize, replace each character by its
    confusable prototype, NFD-normalize again. Two strings are confusable
    when their skeletons are equal.
    """
    table = confusables()
    nfd = unicodedata.normalize("NFD", text)
    mapped = "".join(table.get(ch, ch) for ch in nfd)
    return unicodedata.normalize("NFD", mapped)


def confusable(a: str, b: str) -> bool:
    """True when *a* and *b* have identical skeletons (case-sensitive)."""
    return skeleton(a) == skeleton(b)
