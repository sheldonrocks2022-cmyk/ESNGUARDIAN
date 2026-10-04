from esn_guardian.cogs.security_max import (
    join_risk_score,
    normalize_name,
    scam_score,
    username_similarity,
)


def test_normalize_name_removes_decorations():
    assert normalize_name("R@id-er_001!") == "raider001"


def test_username_similarity_catches_coordinated_names():
    assert username_similarity("raider_001", "raider_002") >= 0.70
    assert username_similarity("raider_001", "completelyDifferent") < 0.70


def test_scam_score_prioritizes_composite_phishing():
    safe = scam_score("Here is the project page: https://github.com/example/repo")
    risky = scam_score(
        "FREE NITRO - verify your account and scan this QR https://bit.ly/example",
        ("verify-qr.png",),
    )
    executable = scam_score("Open this update", ("security-update.exe",))
    assert safe < 55
    assert risky >= 55
    assert executable >= 40


def test_join_risk_is_adaptive():
    established = join_risk_score(
        account_age_days=800,
        default_avatar=False,
        name_cluster=1,
        similar_names=0,
    )
    coordinated_new = join_risk_score(
        account_age_days=0,
        default_avatar=True,
        name_cluster=4,
        similar_names=3,
    )
    assert established == 0
    assert coordinated_new >= 70
