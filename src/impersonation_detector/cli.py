"""Command-line entry point.

    impersonation-detector check  "hаndshake.com" -p handshake.com
    impersonation-detector score  "Handshake Support <handshake.support@gmail.com>" -p handshake.com -p Handshake
    impersonation-detector analyze message.json -p handshake.com -p Handshake [--backend ollama --model llama3.1:8b]
    impersonation-detector bench  -p handshake.com -p Handshake [--backend anthropic] [--out benchmarks/]
    impersonation-detector skeleton "pаypal"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .features import Sender
from .intent import LLMIntentClassifier, Message, RuleIntentClassifier, make_backend
from .lookalike import LookalikeDetector
from .pipeline import Detector
from .scorer import SenderScorer
from .scripts import is_mixed_script, scripts_in
from .skeleton import skeleton


def _intent(args) -> RuleIntentClassifier | LLMIntentClassifier:
    if not args.backend or args.backend == "rule":
        return RuleIntentClassifier()
    return LLMIntentClassifier(make_backend(args.backend, args.model))


def _add_protected(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--protected", action="append", required=True,
                   help="a protected name (repeatable), e.g. -p handshake.com -p 'Handshake Support'")


def _add_backend(p: argparse.ArgumentParser) -> None:
    p.add_argument("--backend", default="rule",
                   help="Layer 3 backend: rule (default), ollama[:host], openai[:base_url], anthropic")
    p.add_argument("--model", default=None, help="model name for the chosen backend")


def _read_messages(path: str) -> list[Message]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(rows, dict):
        rows = [rows]
    out = []
    for r in rows:
        out.append(Message(body=r.get("body", ""), sender_name=r.get("sender_name", ""),
                           sender_address=r.get("sender_address", ""), subject=r.get("subject", ""),
                           links=tuple(r.get("links", ())),
                           context=r.get("context", Message.__dataclass_fields__["context"].default)))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="impersonation-detector",
        description="Detect lookalike domains, spoofed senders, and support-team / recruiter "
                    "impersonation in messages.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    chk = sub.add_parser("check", help="Layer 1: check candidates against protected names")
    chk.add_argument("candidates", nargs="+", help="domains, sender names, or strings to test")
    _add_protected(chk)
    chk.add_argument("-d", "--max-distance", type=int, default=2)
    chk.add_argument("--json", action="store_true", help="machine-readable output")

    sc = sub.add_parser("score", help="Layer 2: score senders ('Name <local@domain>' or 'local@domain')")
    sc.add_argument("senders", nargs="+")
    _add_protected(sc)
    sc.add_argument("--json", action="store_true")

    an = sub.add_parser("analyze", help="full pipeline on JSON/JSONL messages (file or '-' for stdin)")
    an.add_argument("path")
    _add_protected(an)
    _add_backend(an)
    an.add_argument("--warn", type=float, default=0.30)
    an.add_argument("--hold", type=float, default=0.60)
    an.add_argument("--block", type=float, default=0.85)

    be = sub.add_parser("bench", help="Layer 4: run the benchmark and write JSON + Markdown reports")
    _add_protected(be)
    _add_backend(be)
    be.add_argument("--out", default="benchmarks", help="output directory")
    be.add_argument("--variants", default=None, help="comma-separated subset of variants")
    be.add_argument("--configs", default=None, help="comma-separated subset of layer configs")
    be.add_argument("--seed", type=int, default=0)
    be.add_argument("--extra", action="append", default=[],
                    help="JSONL of extra messages (e.g. LLM paraphrases) appended to the corpus")

    pa = sub.add_parser("paraphrase", help="generate out-of-sample paraphrases of the seed corpus with an LLM")
    _add_protected(pa)
    _add_backend(pa)
    pa.add_argument("--out", required=True)
    pa.add_argument("-n", type=int, default=1, help="paraphrases per message")

    ex = sub.add_parser("export-seed", help="write the seed corpus for a protected set as JSONL")
    _add_protected(ex)
    ex.add_argument("--out", default="-")

    sk = sub.add_parser("skeleton", help="print the UTS #39 skeleton and scripts of a string")
    sk.add_argument("text", nargs="+")

    args = parser.parse_args(argv)

    if args.cmd == "skeleton":
        for t in args.text:
            print(f"{t!r}\tskeleton={skeleton(t)!r}\tscripts={sorted(scripts_in(t))}"
                  f"\tmixed={is_mixed_script(t)}")
        return 0

    if args.cmd == "check":
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

    if args.cmd == "score":
        scorer = SenderScorer(args.protected)
        out = []
        worst = 0.0
        for s in args.senders:
            res = scorer.score(Sender(address=s))
            worst = max(worst, res.probability)
            if args.json:
                out.append({"sender": s, "probability": round(res.probability, 4), "reasons": res.reasons,
                            "features": {k: v for k, v in res.features.items() if v}})
            else:
                print(f"{res.probability:.3f}  {s!r}  [{', '.join(res.reasons[:4])}]")
        if args.json:
            json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
            print()
        return 1 if worst >= 0.5 else 0

    if args.cmd == "analyze":
        from .pipeline import Thresholds
        det = Detector(args.protected, intent=_intent(args),
                       thresholds=Thresholds(args.warn, args.hold, args.block))
        any_bad = False
        for msg in _read_messages(args.path):
            v = det.analyze(msg)
            any_bad |= not v.allowed
            print(json.dumps(v.to_dict(), ensure_ascii=False))
        return 1 if any_bad else 0

    if args.cmd == "bench":
        from .bench import run_benchmark
        from .bench.run import write_report
        items = None
        if args.extra:
            from .bench import load_seed
            from .bench.paraphrase import read_items
            items = load_seed(args.protected)
            for path in args.extra:
                items += read_items(Path(path))
        rep = run_benchmark(args.protected, intent=_intent(args),
                            variants=args.variants.split(",") if args.variants else None,
                            configs=args.configs.split(",") if args.configs else None,
                            seed=args.seed, items=items)
        j, m = write_report(rep, Path(args.out))
        print(rep.to_markdown())
        print(f"wrote {j}\nwrote {m}", file=sys.stderr)
        return 0

    if args.cmd == "paraphrase":
        from .bench import load_seed
        from .bench.paraphrase import paraphrase_items, write_items
        if args.backend == "rule":
            parser.error("paraphrase needs an LLM backend (--backend ollama|openai|anthropic)")
        items = paraphrase_items(load_seed(args.protected), make_backend(args.backend, args.model), n=args.n)
        write_items(items, Path(args.out))
        print(f"wrote {len(items)} paraphrases to {args.out}", file=sys.stderr)
        return 0

    if args.cmd == "export-seed":
        from .bench import load_seed
        rows = [json.dumps({"id": i.id, "label": i.label, "sender_name": i.sender_name,
                            "sender_address": i.sender_address, "subject": i.subject,
                            "body": i.body, "tags": list(i.tags)}, ensure_ascii=False)
                for i in load_seed(args.protected)]
        text = "\n".join(rows) + "\n"
        if args.out == "-":
            sys.stdout.write(text)
        else:
            Path(args.out).write_text(text, encoding="utf-8")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
