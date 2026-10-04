from esn_guardian.cogs.security_v7 import (
    anomaly_score,
    evidence_hash,
    state_from_score,
    trust_score,
)


def test_v7_state_machine_tightens_by_profile():
    assert state_from_score(0, "maximum") == "NORMAL"
    assert state_from_score(12, "maximum") == "ELEVATED"
    assert state_from_score(25, "maximum") == "HIGH"
    assert state_from_score(40, "maximum") == "CRITICAL"
    assert state_from_score(60, "maximum") == "PANIC"
    assert state_from_score(25, "community") == "ELEVATED"


def test_v7_evidence_hash_is_chained_and_stable():
    first = evidence_hash("GENESIS", '{"event":"one"}')
    second = evidence_hash(first, '{"event":"two"}')
    assert first == evidence_hash("GENESIS", '{"event":"one"}')
    assert second != first
    assert second != evidence_hash("GENESIS", '{"event":"two"}')


def test_v7_behavior_anomaly_needs_history_and_combined_signals():
    assert anomaly_score(5, 0.0, 0.0, 10, 1) == 0
    score = anomaly_score(30, 0.01, 0.02, 9, 2)
    assert score >= 70


def test_v7_trust_score_rewards_age_and_recovery_but_penalizes_incidents():
    trusted = trust_score(800, 0, 1, True)
    risky = trust_score(1, 45, 0, False)
    assert trusted > risky
    assert 0 <= risky <= 100
    assert 0 <= trusted <= 100
