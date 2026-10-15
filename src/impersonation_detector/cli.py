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
    return LLMIntentClassifier(make_backend(args.backend, args.model),
                               cache_path=getattr(args, "cache", None))


def _add_protected(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--protected", action="append", required=True,
                   help="a protected name (repeatable), e.g. -p handshake.com -p 'Handshake Support'")


def _add_backend(p: argparse.ArgumentParser) -> None:
    p.add_argument("--backend", default="rule",
                   help="Layer 3 backend: rule (default), ollama[:host], openai[:base_url], anthropic")
    p.add_argument("--model", default=None, help="model name for the chosen backend")
    p.add_argument("--cache", default=None,
                   help="JSONL file caching LLM responses per message (reruns cost nothing)")


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
    an.add_argument("--blocklist", default=None, help="JSON from `watch --out`, or a newline list of domains")

    be = sub.add_parser("bench", help="Layer 4: run the benchmark and write JSON + Markdown reports")
    _add_protected(be)
    _add_backend(be)
    be.add_argument("--out", default="benchmarks", help="output directory")
    be.add_argument("--variants", default=None, help="comma-separated subset of variants")
    be.add_argument("--configs", default=None, help="comma-separated subset of layer configs")
    be.add_argument("--seed", type=int, default=0)
    be.add_argument("--dump", default=None, help="write one JSONL record per (config, variant, message)")
    be.add_argument("--extra", action="append", default=[],
                    help="JSONL of extra messages (e.g. LLM paraphrases) appended to the corpus")
    be.add_argument("--only-extra", action="store_true",
                    help="benchmark the --extra messages alone (out-of-sample), not seed + extra")

    pa = sub.add_parser("paraphrase", help="generate out-of-sample paraphrases of the seed corpus with an LLM")
    _add_protected(pa)
    _add_backend(pa)
    pa.add_argument("--out", required=True)
    pa.add_argument("-n", type=int, default=1, help="paraphrases per message")
    pa.add_argument("--style", default=None,
                    help="extra instruction appended to the rewrite prompt (e.g. a different register), "
                         "to produce a distinct held-out corpus")
    pa.add_argument("--suffix", default="p", help="id suffix letter (p0, q0, ...)")

    ex = sub.add_parser("export-seed", help="write the seed corpus for a protected set as JSONL")
    _add_protected(ex)
    ex.add_argument("--out", default="-")

    wa = sub.add_parser("watch", help="lookalike-domain leg: enumerate, resolve, and score lookalike domains")
    _add_protected(wa)
    wa.add_argument("--no-resolve", action="store_true", help="generate and score only; no network")
    wa.add_argument("--all", action="store_true", help="include candidates that are not live")
    wa.add_argument("--limit", type=int, default=None)
    wa.add_argument("--no-rdap", action="store_true")
    wa.add_argument("--pause", type=float, default=0.1, help="seconds between lookups")
    wa.add_argument("--out", default=None, help="write hits as JSON (load with analyze --blocklist)")

    ab = sub.add_parser("ato-bench", help="account-takeover leg: synthetic benchmark")
    ab.add_argument("--accounts", type=int, default=200)
    ab.add_argument("--seed", type=int, default=0)
    ab.add_argument("--out", default="benchmarks")

    at = sub.add_parser("ato", help="account-takeover leg: score a JSONL event log (one account or many)")
    at.add_argument("path")
    at.add_argument("--history-days", type=float, default=30.0,
                    help="events older than this many days before the last event form the baseline")

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
        blocklist: set[str] = set()
        if args.blocklist:
            raw = Path(args.blocklist).read_text(encoding="utf-8").strip()
            if raw.startswith("["):
                blocklist = {h["domain"] for h in json.loads(raw) if h.get("action") in ("watch", "block")}
            else:
                blocklist = {line.strip() for line in raw.splitlines() if line.strip()}
        det = Detector(args.protected, intent=_intent(args),
                       thresholds=Thresholds(args.warn, args.hold, args.block), blocklist=blocklist)
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
            items = [] if args.only_extra else load_seed(args.protected)
            for path in args.extra:
                items += read_items(Path(path))
        dump: list[dict] | None = [] if args.dump else None
        rep = run_benchmark(args.protected, intent=_intent(args),
                            variants=args.variants.split(",") if args.variants else None,
                            configs=args.configs.split(",") if args.configs else None,
                            seed=args.seed, items=items, dump=dump)
        j, m = write_report(rep, Path(args.out))
        if dump is not None:
            Path(args.dump).parent.mkdir(parents=True, exist_ok=True)
            Path(args.dump).write_text("".join(json.dumps(d, ensure_ascii=False) + "\n" for d in dump), encoding="utf-8")
            print(f"wrote {args.dump}", file=sys.stderr)
        print(rep.to_markdown())
        print(f"wrote {j}\nwrote {m}", file=sys.stderr)
        return 0

    if args.cmd == "watch":
        from .domainwatch import DnsRdapResolver, DomainWatch
        watch = DomainWatch(args.protected, resolver=DnsRdapResolver(rdap=not args.no_rdap, pause=args.pause))
        hits = watch.scan(resolve=not args.no_resolve, limit=args.limit, only_live=not args.all)
        for h in hits:
            print(f"{h.action:5s} {h.risk:.2f}  {h.candidate.domain:40s} {h.candidate.technique:14s} {'; '.join(h.reasons)}")
        print(f"{len(hits)} candidates" + ("" if args.no_resolve else " live") +
              f" of {len(watch.generator.generate(args.limit))} generated", file=sys.stderr)
        if args.out:
            Path(args.out).write_text(json.dumps([h.to_dict() for h in hits], indent=2, ensure_ascii=False) + "\n")
            print(f"wrote {args.out}", file=sys.stderr)
        return 0

    if args.cmd == "ato-bench":
        from .ato_bench import ato_report_markdown, run_ato_benchmark
        res = run_ato_benchmark(args.accounts, args.seed)
        md = ato_report_markdown(res)
        print(md)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "benchmark_ato.json").write_text(json.dumps(res, indent=2) + "\n")
        (out / "benchmark_ato.md").write_text(md)
        return 0

    if args.cmd == "ato":
        from .ato import AccountTakeoverDetector, CampaignDetector, Event
        rows = [json.loads(line) for line in Path(args.path).read_text(encoding="utf-8").splitlines() if line.strip()]
        events = [Event(r["account_id"], r["kind"], float(r["ts"]), r.get("ip", ""), r.get("device_id", ""),
                        r.get("country", ""), r.get("asn", ""), r.get("lat"), r.get("lon"), r.get("meta", {}))
                  for r in rows]
        campaigns = CampaignDetector().assess(events)
        det = AccountTakeoverDetector(attacker_ips={c["ip"] for c in campaigns})
        by_acct: dict[str, list[Event]] = {}
        for e in events:
            by_acct.setdefault(e.account_id, []).append(e)
        last = max(e.ts for e in events) if events else 0.0
        any_bad = False
        for evs in by_acct.values():
            hist = [e for e in evs if last - e.ts > args.history_days * 86400] or None
            for v in det.assess(evs, history=hist):
                if v.action != "allow":
                    any_bad = True
                    print(json.dumps(v.to_dict()))
        for c in campaigns:
            print(json.dumps({"campaign": c}))
        return 1 if any_bad else 0

    if args.cmd == "paraphrase":
        from .bench import load_seed
        from .bench.paraphrase import paraphrase_items, write_items
        if args.backend == "rule":
            parser.error("paraphrase needs an LLM backend (--backend ollama|openai|anthropic)")
        items = paraphrase_items(load_seed(args.protected), make_backend(args.backend, args.model), n=args.n,
                                 style=args.style, suffix=args.suffix)
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
