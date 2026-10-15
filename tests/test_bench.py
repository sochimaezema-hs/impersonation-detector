from impersonation_detector.bench import VARIANTS, apply_variant, load_seed, run_benchmark
from impersonation_detector.bench.run import LAYER_CONFIGS, write_report

PROTECTED = ["handshake.com", "Handshake", "Handshake Support"]


def test_seed_loads_and_is_brand_parametric():
    items = load_seed(PROTECTED)
    assert len(items) >= 70
    labels = {i.label for i in items}
    assert labels == {"benign", "support_impersonation", "recruiter_scam", "credential_phish", "payment_redirect"}
    assert any("support@handshake.com" == i.sender_address for i in items)
    other = load_seed(["paypal.com", "PayPal"])
    assert any("support@paypal.com" == i.sender_address for i in other)
    assert len({i.id for i in items}) == len(items)


def test_variants_are_deterministic_and_label_preserving():
    items = load_seed(PROTECTED)
    s01 = next(i for i in items if i.id == "s01")
    for name in VARIANTS:
        a = apply_variant(name, s01, "handshake", seed=1)
        b = apply_variant(name, s01, "handshake", seed=1)
        assert a == b and a.label == s01.label
    assert chr(0x200B) in apply_variant("zero_width", s01, "handshake").body
    assert "ignore all previous instructions" in apply_variant("injection", s01, "handshake").body.lower() \
        or "disregard prior instructions" in apply_variant("injection", s01, "handshake").body.lower() \
        or "developer mode" in apply_variant("injection", s01, "handshake").body.lower()
    s04 = next(i for i in items if i.id == "s04")
    assert "handshake.com.mail-notice.xyz" in apply_variant("link_subdomain", s04, "handshake").body


def test_benchmark_runs_with_rule_backend(tmp_path):
    rep = run_benchmark(PROTECTED, variants=["clean", "injection", "sender_homoglyph"],
                        configs=["L1", "L1+L2", "L3", "L1+L2+L3"])
    assert set(rep.results) == {"L1", "L1+L2", "L3", "L1+L2+L3"}
    full_clean = rep.results["L1+L2+L3"]["clean"]
    assert full_clean["recall"] >= 0.8, full_clean
    assert full_clean["fpr"] <= 0.15, full_clean
    # UTS #39 has no confusable for Cyrillic т or Greek κ, so L1 alone misses a few;
    # L2's mixed-script feature closes the gap.
    assert rep.results["L1"]["sender_homoglyph"]["recall"] >= 0.8
    assert rep.results["L1+L2"]["sender_homoglyph"]["recall"] >= 0.95
    # the rule classifier cannot be hijacked: it never obeys instructions
    assert rep.results["L3"]["injection"]["hijacked"] == 0
    j, m = write_report(rep, tmp_path)
    assert j.exists() and m.exists() and "| L1+L2+L3 |" in m.read_text()
    assert set(LAYER_CONFIGS) >= set(rep.results)


def test_paraphrase_roundtrip_and_extra_items(tmp_path):
    from impersonation_detector.bench.paraphrase import paraphrase_items, read_items, write_items
    from impersonation_detector.intent import StaticBackend

    items = load_seed(PROTECTED)[:3]
    be = StaticBackend("Rewritten text number one, long enough.", "Rewritten text number two, long enough.",
                       "Rewritten text number three, long enough.")
    para = paraphrase_items(items, be)
    assert [p.body for p in para] == ["Rewritten text number one, long enough.", "Rewritten text number two, long enough.",
                                      "Rewritten text number three, long enough."]
    assert para[0].label == items[0].label and "paraphrase" in para[0].tags
    path = tmp_path / "p.jsonl"
    write_items(para, path)
    assert read_items(path) == para
    rep = run_benchmark(PROTECTED, variants=["clean"], configs=["L3"], items=items + para)
    assert rep.n_seed == 6


def test_cli_smoke(tmp_path, capsys):
    from impersonation_detector.cli import main
    assert main(["check", "hаndshake.com", "-p", "handshake.com"]) == 1
    assert main(["score", "Handshake Support <handshake.support@gmail.com>", "-p", "handshake.com", "-p", "Handshake"]) == 1
    msg = tmp_path / "m.json"
    msg.write_text('{"body": "hi there", "sender_name": "Jane", "sender_address": "jane@acme.io"}')
    assert main(["analyze", str(msg), "-p", "handshake.com"]) == 0
    out = capsys.readouterr().out
    assert '"action": "allow"' in out
    assert main(["bench", "-p", "handshake.com", "-p", "Handshake", "--variants", "clean",
                 "--configs", "L3", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "benchmark_rule.md").exists()
    assert main(["export-seed", "-p", "handshake.com", "-p", "Handshake", "--out", str(tmp_path / "s.jsonl")]) == 0
    assert len((tmp_path / "s.jsonl").read_text().splitlines()) == 76


def test_benchmark_dump_records():
    dump: list[dict] = []
    run_benchmark(PROTECTED, variants=["clean"], configs=["L3"], dump=dump)
    assert len(dump) == 76 and {"id", "label", "flagged", "intent", "confidence", "action"} <= set(dump[0])
