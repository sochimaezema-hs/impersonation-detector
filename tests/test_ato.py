from impersonation_detector.ato import (
    AccountTakeoverDetector,
    Baseline,
    CampaignDetector,
    Event,
    haversine_km,
)
from impersonation_detector.ato_bench import AtoSynth, run_ato_benchmark

T0 = 1_780_000_000.0
SF = ("US", 37.77, -122.42)
LAG = ("NG", 6.52, 3.38)


def login(acct, ts, where=SF, ip="10.0.0.1", dev="dev1", asn="AS1", kind="login"):
    return Event(acct, kind, ts, ip, dev, where[0], asn, where[1], where[2])


def normal_history(acct="a1", days=20):
    ev = []
    for d in range(days):
        t = T0 + d * 86400 + 9 * 3600
        ev.append(login(acct, t))
        ev.append(Event(acct, "message_sent", t + 100))
    return ev


def test_baseline_learns_devices_countries_and_rate():
    b = Baseline.from_history(normal_history())
    assert b.established and b.devices == {"dev1"} and b.countries == {"US"}
    assert 0 < b.messages_per_hour < 1


def test_haversine_sf_to_lagos():
    assert 12_000 < haversine_km(*SF[1:], *LAG[1:]) < 13_500


def test_normal_day_is_allowed():
    hist = normal_history()
    t = T0 + 21 * 86400 + 9 * 3600
    day = [login("a1", t), Event("a1", "message_sent", t + 50), Event("a1", "profile_change", t + 100)]
    det = AccountTakeoverDetector()
    vs = det.assess(hist + day, history=hist)
    assert vs and all(v.action == "allow" for v in vs)


def test_legit_email_change_from_known_device_only_warns_at_most():
    hist = normal_history()
    t = T0 + 21 * 86400 + 9 * 3600
    day = [login("a1", t), Event("a1", "email_change", t + 100, "10.0.0.1", "dev1")]
    w = AccountTakeoverDetector().worst(hist + day, history=hist)
    assert w.action in ("allow", "warn")


def test_classic_takeover_chain_blocks_with_reasons():
    hist = normal_history()
    t = T0 + 21 * 86400 + 3 * 3600
    atk = [login("a1", t - 400 + k * 40, LAG, "203.0.113.9", "devX", "AS9", kind="login_failed") for k in range(6)]
    atk += [login("a1", t, LAG, "203.0.113.9", "devX", "AS9"),
            Event("a1", "password_reset", t + 60, "203.0.113.9", "devX"),
            Event("a1", "email_change", t + 120, "203.0.113.9", "devX")]
    atk += [Event("a1", "message_sent", t + 200 + m * 10) for m in range(25)]
    det = AccountTakeoverDetector()
    w = det.worst(hist + atk, history=hist)
    assert w.action == "block", w.to_dict()
    f = w.features
    assert f["new_device"] and f["new_country"] and f["sensitive_chain"]
    joined = " ".join(w.reasons)
    assert "unseen device" in joined and "unseen country" in joined
    vs = det.assess(hist + atk, history=hist)
    assert any(v.features["failed_burst_then_success"] for v in vs)
    assert any(v.features["mass_messaging"] for v in vs)


def test_impossible_travel_then_reset():
    hist = normal_history()
    t = T0 + 21 * 86400 + 9 * 3600
    ev = [login("a1", t), login("a1", t + 1800, LAG, "203.0.113.9", "devX", "AS9"),
          Event("a1", "password_reset", t + 1900, "203.0.113.9", "devX")]
    w = AccountTakeoverDetector().worst(hist + ev, history=hist)
    assert w.action in ("hold", "block") and w.features["impossible_travel"]


def test_campaign_detector_finds_shared_ip_and_feeds_attacker_ips():
    ev = []
    for k in range(8):
        acct = f"u{k}"
        ev.append(Event(acct, "login_failed", T0 + k * 10, "198.51.100.4"))
        ev.append(Event(acct, "login_failed", T0 + k * 10 + 5, "198.51.100.4"))
    ev.append(Event("u3", "login", T0 + 100, "198.51.100.4"))
    alerts = CampaignDetector().assess(ev)
    assert alerts and alerts[0]["ip"] == "198.51.100.4" and alerts[0]["accounts"] == 8
    assert alerts[0]["compromised"] == ["u3"]
    hist = normal_history("u3")
    t = T0 + 21 * 86400
    day = [login("u3", t, ip="198.51.100.4"), Event("u3", "email_change", t + 50, "198.51.100.4", "dev1")]
    plain = AccountTakeoverDetector().worst(hist + day, history=hist)
    informed = AccountTakeoverDetector(attacker_ips={"198.51.100.4"}).worst(hist + day, history=hist)
    assert informed.risk > plain.risk and informed.features["shared_attacker_ip"]


def test_synthetic_benchmark_is_deterministic_and_separates():
    a = run_ato_benchmark(60, seed=1)
    b = run_ato_benchmark(60, seed=1)
    assert a == b
    r = a["per_account+campaign_ip"]
    assert r["recall"] >= 0.9, a
    assert r["fpr"] <= 0.1, a
    assert a["per_account+campaign_ip"]["recall"] >= a["per_account"]["recall"]
    s = AtoSynth(3)
    acc = s.account(1)
    assert len(s.history(acc)) > 10
