from esn_guardian.cogs.security_intelligence import case_weight, correlation_should_contain, risk_level


def test_case_weight_prioritizes_serious_security_events():
    assert case_weight("ANTINUKE_BAN") >= 8
    assert case_weight("EXTERNAL_APP_BAN") >= 8
    assert case_weight("AUTOMOD_WARN") < case_weight("GUARDIAN_TAMPER_ALERT")


def test_correlation_requires_multiple_serious_families():
    assert not correlation_should_contain(["ANTINUKE_BAN"] * 5)
    assert not correlation_should_contain(["AUTOMOD_WARN"] * 20)
    assert correlation_should_contain(
        ["ANTINUKE_BAN", "ANTINUKE_ROLE_REVERT", "EXTERNAL_APP_BAN", "UNAPPROVED_BOT_BANNED"]
    )


def test_risk_level_boundaries():
    assert risk_level(0) == "LOW"
    assert risk_level(6) == "GUARDED"
    assert risk_level(18) == "ELEVATED"
    assert risk_level(40) == "HIGH"
    assert risk_level(70) == "CRITICAL"
