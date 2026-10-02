"""Loaders for the Unicode data files shipped with the package.

Both files come from unicode.org and are redistributed under the Unicode License:
- confusables.txt  (UTS #39, https://www.unicode.org/Public/security/latest/)
- Scripts.txt      (UCD,     https://www.unicode.org/Public/UNIDATA/)
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources


def _read(name: str) -> str:
    return resources.files(__package__).joinpath("data", name).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def confusables() -> dict[str, str]:
    """Map each source character to its UTS #39 prototype string."""
    table: dict[str, str] = {}
    for line in _read("confusables.txt").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        src, dst, *_ = (part.strip() for part in line.split(";"))
        source = "".join(chr(int(cp, 16)) for cp in src.split())
        target = "".join(chr(int(cp, 16)) for cp in dst.split())
        table[source] = target
    return table


@lru_cache(maxsize=1)
def script_ranges() -> list[tuple[int, int, str]]:
    """Sorted (lo, hi, script) ranges from Scripts.txt."""
    ranges: list[tuple[int, int, str]] = []
    for line in _read("Scripts.txt").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        cps, script = (part.strip() for part in line.split(";"))
        if ".." in cps:
            lo, hi = (int(x, 16) for x in cps.split(".."))
        else:
            lo = hi = int(cps, 16)
        ranges.append((lo, hi, script))
    ranges.sort()
    return ranges
