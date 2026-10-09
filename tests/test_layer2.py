from impersonation_detector.domains import (
    brand_tokens,
    parse_address,
    registrable,
    sld,
    subdomain_labels,
    tokenize,
)
from impersonation_detector.features import FEATURE_NAMES, FeatureExtractor, Sender
from impersonation_detector.scorer import SenderScorer

PROTECTED = ["handshake.com", "joinhandshake.com", "Handshake", "Handshake Support"]


def test_registrable_and_sld():
    assert registrable("handshake.com.verify-login.io") == "verify-login.io"
    assert registrable("mail.handshake.com") == "handshake.com"
    assert registrable("careers.ox.ac.uk") == "ox.ac.uk"
    puny = "hаndshake.com".encode("idna").decode("ascii")  # Cyrillic а
    assert sld(puny) == "hаndshake"  # judged by what it displays
    assert subdomain_labels("handshake.com.verify-login.io") == ["handshake", "com"]


def test_parse_address_forms():
    assert parse_address("support@handshake.com") == ("", "support", "handshake.com")
    assert parse_address('"Handshake Support" <support@evil.io>') == (
        "Handshake Support", "support", "evil.io")
    assert parse_address("Jane Doe <jane.doe@acme.io>") == ("Jane Doe", "jane.doe", "acme.io")
    assert parse_address("@handshake_support") == ("", "handshake_support", "")


def test_brand_tokens_drop_generic_words():
    assert brand_tokens(PROTECTED) == {"handshake", "joinhandshake"}
    assert tokenize("Hand\u200bshake Support") == ["handshake", "support"]


def _feat(sender: Sender) -> dict[str, float]:
    return FeatureExtractor(PROTECTED).extract(sender)


def test_features_genuine_sender_is_protected_only():
    f = _feat(Sender("Handshake Support", "support@handshake.com"))
    assert f["domain_is_protected"] == 1.0
    assert f["display_claims_brand_off_domain"] == 0.0
    assert f["domain_skeleton_match"] == 0.0


def test_features_homograph_domain():
    f = _feat(Sender("Jane Doe", "jane.doe@hаndshake.com"))  # Cyrillic а
    assert f["domain_skeleton_match"] == 1.0
    assert f["domain_mixed_script"] == 1.0
    assert f["domain_is_protected"] == 0.0


def test_features_punycode_and_invisible():
    puny = "hаndshake.com".encode("idna").decode("ascii")
    f = _feat(Sender("", f"support@{puny}"))
    assert f["domain_punycode"] == 1.0 and f["domain_skeleton_match"] == 1.0
    f = _feat(Sender("Hand\u200bshake Support", "support@hand\u200bshake.com"))
    assert f["display_invisible_chars"] == 1.0 and f["domain_invisible_chars"] == 1.0


def test_features_brand_in_subdomain_and_affix_and_tld_swap():
    assert _feat(Sender("", "x@handshake.com.verify-login.io"))["domain_brand_in_subdomain"] == 1.0
    assert _feat(Sender("", "x@handshake-support.net"))["domain_brand_affix"] == 1.0
    assert _feat(Sender("", "x@handshake.co"))["domain_tld_swap"] == 1.0
    assert _feat(Sender("", "x@h4ndshake.com"))["domain_leet_match"] == 1.0


def test_features_display_claims_brand_off_domain():
    f = _feat(Sender("Handshake Support", "handshake.support22@gmail.com"))
    assert f["display_claims_brand_off_domain"] == 1.0
    assert f["domain_free_mail"] == 1.0
    assert f["local_brand_token"] == 1.0
    assert f["display_role_word"] == 1.0


def test_features_university_office_is_not_impersonation():
    f = _feat(Sender("Career Services", "careers@berkeley.edu"))
    assert f["display_role_word"] == 1.0
    assert f["display_claims_brand_off_domain"] == 0.0
    assert sum(f[k] for k in FEATURE_NAMES if k.startswith("domain_")) == 0.0


def test_scorer_orders_cases_sensibly():
    sc = SenderScorer(PROTECTED)
    genuine = sc.score(Sender("Handshake Support", "support@handshake.com")).probability
    uni = sc.score(Sender("Career Services", "careers@berkeley.edu")).probability
    person = sc.score(Sender("Jane Doe", "jane.doe92@gmail.com")).probability
    other = sc.score(Sender("Acme Recruiting", "talent@acmerobotics.com")).probability
    homograph = sc.score(Sender("Jane Doe", "jane.doe@hаndshake.com")).probability
    freemail = sc.score(Sender("Handshake Support", "handshake.support@gmail.com")).probability
    subdomain = sc.score(Sender("Handshake", "no-reply@handshake.com.secure-portal.app")).probability
    affix = sc.score(Sender("Luis Garcia", "luis@handshake-careers.io")).probability
    for benign in (genuine, uni, person, other):
        assert benign < 0.3, benign
    for bad in (homograph, freemail, subdomain, affix):
        assert bad > 0.7, bad


def test_scorer_reasons_and_domain_only():
    sc = SenderScorer(PROTECTED)
    s = sc.score(Sender("Handshake Support", "handshake.support@gmail.com"))
    assert "display_claims_brand_off_domain" in s.reasons[:3]
    link = sc.score_domain("handshake.com.verify-login.io")
    assert link.probability > 0.7 and "domain_brand_in_subdomain" in link.reasons
    assert sc.score_domain("handshake.com").probability < 0.2
