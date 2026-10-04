from esn_guardian.cogs.security_v6 import (
    adaptive_risk_score,
    attack_chain_score,
    raid_fingerprint_score,
    scam_text_score,
)


def test_adaptive_risk_prioritizes_new_high_signal_accounts():
    low = adaptive_risk_score(account_age_days=400)
    high = adaptive_risk_score(
        account_age_days=0,
        weighted_cases=18,
        dangerous_roles=1,
        failed_verifications=2,
        external_app_events=1,
        raid_cluster_score=10,
    )
    assert low < high
    assert 0 <= high <= 100
    assert high >= 75


def test_attack_chain_combinations_escalate_more_than_single_events():
    single = attack_chain_score(["channel_delete"])
    chained = attack_chain_score(
        ["webhook_change", "permission_escalation", "channel_delete"]
    )
    assert chained > single
    assert chained >= 28


def test_raid_fingerprinting_detects_coordinated_young_cluster():
    benign = raid_fingerprint_score([200, 500], ["alice", "bob"])
    attack = raid_fingerprint_score(
        [0, 0, 1, 1, 2, 2],
        ["raider", "raider", "raider", "raider", "raider", "raider"],
    )
    assert attack > benign
    assert attack >= 18


def test_scam_composite_scores_multiple_indicators():
    ordinary = scam_text_score("hello everyone")
    suspicious = scam_text_score(
        "Free Nitro! Verify your account and scan this QR: https://bit.ly/example",
        ("verify-qr.png",),
    )
    assert suspicious > ordinary
    assert suspicious >= 7
