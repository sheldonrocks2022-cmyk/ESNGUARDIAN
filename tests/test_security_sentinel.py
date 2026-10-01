from esn_guardian.cogs.security_sentinel import (
    anomaly_score,
    chain_summary,
    classify_action,
    severity_from_score,
)


def test_classify_action_categories():
    assert classify_action("ANTINUKE_BAN") == "destructive"
    assert classify_action("GUARDIAN_TAMPER_REVERTED") == "tamper"
    assert classify_action("UNAUTHORIZED_WEBHOOK") == "automation"
    assert classify_action("ROLE_PERMISSION_ESCALATION") == "privilege"
    assert classify_action("GUARDIAN_PANIC") == "recovery"


def test_anomaly_score_increases_with_correlation():
    quiet = anomaly_score(
        base_weight=1,
        burst_count=1,
        category_count=1,
        target_count=1,
        subject_case_count=1,
        rare_action=False,
    )
    correlated = anomaly_score(
        base_weight=8,
        burst_count=8,
        category_count=4,
        target_count=6,
        subject_case_count=12,
        rare_action=True,
    )
    assert quiet < correlated
    assert correlated <= 100


def test_severity_boundaries():
    assert severity_from_score(0) == "NORMAL"
    assert severity_from_score(15) == "WATCH"
    assert severity_from_score(35) == "ELEVATED"
    assert severity_from_score(60) == "HIGH"
    assert severity_from_score(80) == "CRITICAL"


def test_chain_summary_is_deterministic():
    assert chain_summary({"destructive", "privilege", "automation"}) == (
        "privilege -> automation -> destructive"
    )
