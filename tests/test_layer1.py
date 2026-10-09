from impersonation_detector import (
    LookalikeDetector,
    confusable,
    is_mixed_script,
    scripts_in,
    skeleton,
)
from impersonation_detector.distance import osa_distance


def test_skeleton_maps_cyrillic_a_to_latin():
    assert skeleton("hаndshake") == skeleton("handshake")  # Cyrillic а
    assert confusable("pаypal", "paypal")


def test_skeleton_folds_ascii_confusables_too():
    # UTS #39 maps 'm' -> 'rn' and 'l'/'1'/'I' together, so skeletons are
    # not identity even for ASCII; that is what catches "rnicrosoft.com".
    assert skeleton("rn") == skeleton("m")
    assert confusable("rnicrosoft.com", "microsoft.com")
    assert skeleton("handshake.com") == skeleton("handshake.com")


def test_scripts_and_mixed_script():
    assert scripts_in("handshake") == {"Latin"}
    assert scripts_in("hаndshake") == {"Latin", "Cyrillic"}
    assert is_mixed_script("hаndshake")
    assert not is_mixed_script("handshake")
    assert not is_mixed_script("東京 tokyo")  # Han + Latin allowed


def test_fold_skeleton_handles_uppercase_prototypes():
    from impersonation_detector import fold_skeleton
    assert fold_skeleton("h0me") == fold_skeleton("home")  # '0' maps to 'O' in UTS #39
    det = LookalikeDetector(["dropbox.com"])
    assert det.check("dr0pbox.com") and det.check("DROPBOX.C0M")


def test_osa_distance():
    assert osa_distance("handshake", "handshake") == 0
    assert osa_distance("handshake", "handshkae") == 1  # transposition
    assert osa_distance("handshake", "handshak") == 1
    assert osa_distance("handshake", "hanshake") == 1


def test_detector_flags_homograph_and_typo_but_not_genuine():
    det = LookalikeDetector(["handshake.com", "Handshake Support"])
    assert det.check("handshake.com") == []
    assert det.check("HANDSHAKE.COM") == []
    m = det.check("hаndshake.com")
    assert m and m[0].protected == "handshake.com"
    assert "confusable-skeleton" in m[0].reasons
    assert any(r.startswith("mixed-script") for r in m[0].reasons)
    m = det.check("handshkae.com")
    assert m and "edit-distance<=2" in m[0].reasons
    m = det.check("Handshake Suppport")
    assert m and m[0].protected == "Handshake Support"


def test_detector_decodes_punycode():
    det = LookalikeDetector(["handshake.com"])
    puny = "hаndshake.com".encode("idna").decode("ascii")
    assert puny.startswith("xn--")
    m = det.check(puny)
    assert m and "punycode" in m[0].reasons


def test_short_names_are_not_over_flagged():
    det = LookalikeDetector(["a.co"])
    assert det.check("b.co") == []
