from esn_guardian.cogs.security_resilience import readiness_grade, readiness_score


def test_readiness_grade_boundaries():
    assert readiness_grade(100) == "READY"
    assert readiness_grade(90) == "READY"
    assert readiness_grade(89) == "STRONG"
    assert readiness_grade(75) == "STRONG"
    assert readiness_grade(74) == "DEGRADED"
    assert readiness_grade(55) == "DEGRADED"
    assert readiness_grade(54) == "WEAK"
    assert readiness_grade(30) == "WEAK"
    assert readiness_grade(29) == "CRITICAL"


def test_readiness_score_perfect():
    assert readiness_score(
        missing_cogs=0,
        missing_permissions=0,
        disabled_layers=0,
        has_backup=True,
        has_snapshot=True,
        integrity_ok=True,
    ) == 100


def test_readiness_score_penalizes_failures():
    degraded = readiness_score(
        missing_cogs=1,
        missing_permissions=2,
        disabled_layers=2,
        has_backup=False,
        has_snapshot=False,
        integrity_ok=False,
    )
    assert degraded < 55
    assert degraded >= 0
