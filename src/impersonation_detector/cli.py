"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .lookalike import LookalikeDetector
from .scripts import is_mixed_script, scripts_in
from .skeleton import skeleton


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="impersonation-detector",
        description="Detect lookalike domains, senders, and names (UTS #39 confusables, "
        "mixed scripts, edit distance).",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    chk = sub.add_parser("check", help="check candidates against protected names")
    chk.add_argument("candidates", nargs="+", help="domains, sender names, or strings to test")
    chk.add_argument(
        "-p", "--protected", action="append", required=True,
        help="a protected name (repeatable), e.g. -p handshake.com -p 'Handshake Support'",
    )
    chk.add_argument("-d", "--max-distance", type=int, default=2)
    chk.add_argument("--json", action="store_true", help="machine-readable output")

    sk = sub.add_parser("skeleton", help="print the UTS #39 skeleton and scripts of a string")
    sk.add_argument("text", nargs="+")

    args = parser.parse_args(argv)

    if args.cmd == "skeleton":
        for t in args.text:
            print(f"{t!r}\tskeleton={skeleton(t)!r}\tscripts={sorted(scripts_in(t))}"
                  f"\tmixed={is_mixed_script(t)}")
        return 0

    det = LookalikeDetector(args.protected, max_distance=args.max_distance)
    flagged = 0
    out = []
    for c in args.candidates:
        matches = det.check(c)
        flagged += bool(matches)
        if args.json:
            out.append({"candidate": c, "matches": [
                {"protected": m.protected, "reasons": list(m.reasons), "distance": m.distance}
                for m in matches]})
        elif matches:
            for m in matches:
                print(f"FLAG  {c!r} ~ {m.protected!r}  [{', '.join(m.reasons)}]")
        else:
            print(f"ok    {c!r}")
    if args.json:
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
