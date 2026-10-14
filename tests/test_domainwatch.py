from impersonation_detector.domainwatch import (
    DomainWatch,
    LookalikeGenerator,
    Resolution,
    StaticResolver,
)
from impersonation_detector.intent import Message
from impersonation_detector.pipeline import Detector

PROTECTED = ["handshake.com", "Handshake", "Handshake Support"]


def test_generator_covers_techniques_and_dedups():
    gen = LookalikeGenerator(PROTECTED)
    cands = gen.generate()
    domains = [c.domain for c in cands]
    assert len(domains) == len(set(domains))
    assert "handshake.com" not in domains
    techs = {c.technique for c in cands}
    assert {"homoglyph", "omission", "transposition", "tld_swap", "affix", "prefix",
            "replacement", "insertion", "vowel_swap", "leet", "hyphenation", "repetition"} <= techs
    assert "handshkae.com" in domains and "hand-shake.com" in domains and "handshake.co" in domains
    assert "handshake-support.com" in domains and "myhandshake.com" in domains
    assert any("а" in d for d in domains)  # Cyrillic а homoglyph
    assert 150 < len(domains) < 3000


def test_generator_limit_and_subset():
    gen = LookalikeGenerator(PROTECTED, techniques=("tld_swap",))
    cands = gen.generate(limit=5)
    assert len(cands) == 5 and all(c.technique == "tld_swap" for c in cands)


def test_watch_scores_live_new_mx_domains_highest():
    table = {
        "hаndshake.com": Resolution(registered=True, addresses=("203.0.113.5",), has_mx=True, created="2026-10-01T00:00:00Z"),
        "handshake.co": Resolution(registered=True, addresses=("203.0.113.6",), has_mx=False, created="2015-01-01T00:00:00Z"),
        "handshakes.com": Resolution(registered=True, addresses=(), has_mx=None, created=None),
    }
    res = StaticResolver(table)
    watch = DomainWatch(PROTECTED, resolver=res)
    hits = watch.scan()
    assert [h.candidate.domain for h in hits][:1] == ["hаndshake.com"]
    top = hits[0]
    assert top.action == "block" and "can send mail" in top.reasons and any("days ago" in r for r in top.reasons)
    assert len(hits) == 3 and res.calls  # only live ones kept
    bl = DomainWatch.blocklist(hits, "watch")
    assert "hаndshake.com" in bl


def test_watch_offline_mode_does_not_resolve():
    res = StaticResolver()
    hits = DomainWatch(PROTECTED, resolver=res).scan(resolve=False, limit=20)
    assert len(hits) == 20 and res.calls == []
    assert all(h.resolution.live is False for h in hits)


def test_detector_blocklist_floor():
    det = Detector(PROTECTED, blocklist={"handshake-login.top"})
    v = det.analyze(Message(body="see https://www.handshake-login.top/x", sender_name="Jane",
                            sender_address="jane@acme.io"))
    assert v.action == "block" and any("blocklisted" in r for r in v.reasons)
    v2 = det.analyze(Message(body="hi", sender_name="Jane", sender_address="jane@mail.handshake-login.top"))
    assert v2.action == "block"
