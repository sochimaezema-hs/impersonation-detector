from impersonation_detector.bench import apply_variant, load_seed
from impersonation_detector.domains import embedded_domain, is_institutional
from impersonation_detector.intent import (
    LLMIntentClassifier,
    Message,
    RuleIntentClassifier,
    StaticBackend,
)
from impersonation_detector.pipeline import Detector, sender_facts

PROTECTED = ["handshake.com", "Handshake", "Handshake Support"]
det = Detector(PROTECTED)


def test_embedded_domain_is_brand_agnostic():
    assert embedded_domain("orbitallabs.io.docs-share.site") == "orbitallabs.io"
    assert embedded_domain("handshake.com.verify-login.io") == "handshake.com"
    assert embedded_domain("www.example.co.uk.evil.top") == "example.co.uk"
    for ok in ("mail.google.com", "careers.acmerobotics.com", "a.b.c.stanford.edu", "mail.hr.acme.com"):
        assert embedded_domain(ok) is None, ok
    assert is_institutional("careers.berkeley.edu") and not is_institutional("acme.com")


def test_sender_facts_shapes():
    f, emb = sender_facts({"handshake.com"}, "handshake.com", True, ["handshake.com"], set(), False, False)
    assert f == ("sender:platform-domain", "display:claims-platform-brand", "links:platform-only")
    f, emb = sender_facts({"handshake.com"}, "gmail.com", True, ["handshake-verify.app"], {"handshake-verify.app"}, False, True)
    assert "sender:free-webmail" in f and "links:off-platform" in f and "links:lookalike" in f
    f, emb = sender_facts({"handshake.com"}, "orbitallabs.io", False, ["orbitallabs.io.docs-share.site"], set(), False, False)
    assert "links:embedded-domain" in f and emb == ("orbitallabs.io inside docs-share.site",)
    f, _ = sender_facts({"handshake.com"}, "acme.io", False, ["acme.io"], set(), False, False)
    assert "links:same-as-sender" in f
    f, _ = sender_facts({"handshake.com"}, "berkeley.edu", False, [], set(), False, False)
    assert f == ("sender:institutional-domain", "links:none")


def test_c07_third_party_embedded_link_is_blocked_by_every_config():
    m = Message(body="Here is your interview link: https://orbitallabs.io.docs-share.site/meet. "
                     "Sign in with your Handshake account to join.",
                sender_name="Ethan Wright", sender_address="ethan.wright@orbitallabs.io")
    v = det.analyze(m)
    assert v.action == "block" and any("embeds the sender's own domain" in r for r in v.reasons), v.to_dict()
    # an LLM that answers benign is still overridden by the floor
    d2 = Detector(PROTECTED, intent=LLMIntentClassifier(StaticBackend('{"label":"benign","confidence":0.95,"signals":[]}')))
    assert d2.analyze(m).action == "block"


def test_fusion_discounts_llm_false_positive_on_genuine_platform_notice():
    be = StaticBackend('{"label":"support_impersonation","confidence":0.9,"signals":["authority_claim","urgency"]}')
    d = Detector(PROTECTED, intent=LLMIntentClassifier(be))
    m = Message(body="Your Handshake password was changed just now. If this was you, no action is needed. "
                     "If not, reset your password from the sign-in page and contact support.",
                sender_name="Handshake", sender_address="no-reply@handshake.com")
    v = d.analyze(m)
    assert v.action == "allow" and any(r.startswith("fusion:") for r in v.reasons), v.to_dict()
    # facts reached the model
    assert "sender:platform-domain" in be.calls[0][1] and "links:none" in be.calls[0][1]


def test_fusion_does_not_discount_spoofed_from_with_sensitive_ask_or_offplatform_link():
    be = StaticBackend('{"label":"credential_phish","confidence":0.9,"signals":["credential_request"]}')
    d = Detector(PROTECTED, intent=LLMIntentClassifier(be))
    otp = Message(body="To finish verifying your account, reply with the 6-digit verification code we just sent.",
                  sender_name="Handshake Support", sender_address="support@handshake.com")
    assert d.analyze(otp).action in ("hold", "block")
    be2 = StaticBackend('{"label":"support_impersonation","confidence":0.9,"signals":["urgency","authority_claim"]}')
    d2 = Detector(PROTECTED, intent=LLMIntentClassifier(be2))
    spoof = Message(body="Official notification from Handshake. Your account is at risk. Verify now at "
                         "http://account-update.net/handshake or lose access within 24 hours.",
                    sender_name="Handshake Support", sender_address="support@handshake.com")
    assert d2.analyze(spoof).action in ("hold", "block")


def test_rule_classifier_uses_facts():
    r = RuleIntentClassifier()
    notice = Message(body="We removed a fraudulent posting. If you shared personal information, see "
                          "https://handshake.com/safety.", sender_name="Handshake Trust & Safety",
                     sender_address="trust@handshake.com",
                     sender_facts=("sender:platform-domain", "display:claims-platform-brand", "links:platform-only"))
    assert r.classify(notice).label == "benign"
    fake = Message(body="Your account is limited. Update your details here today.",
                   sender_name="Handshake Support", sender_address="hs.support@gmail.com",
                   sender_facts=("sender:free-webmail", "display:claims-platform-brand", "links:none"))
    assert r.classify(fake).label != "benign"


def test_body_variants_leave_urls_untouched():
    items = load_seed(PROTECTED)
    b16 = next(i for i in items if i.id == "b16")
    for name in ("homoglyph", "zero_width", "leet", "spaced", "synonym"):
        out = apply_variant(name, b16, "handshake")
        assert "https://handshake.com/safety" in out.body, name
