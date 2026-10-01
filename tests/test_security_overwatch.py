from esn_guardian.cogs.security_overwatch import case_digest, diff_payloads, posture_score, trend_label


def test_case_digest_is_stable_and_chained():
    case = {
        "case_id": 1,
        "guild_id": 2,
        "target_id": 3,
        "moderator_id": 4,
        "action": "ANTINUKE_BAN",
        "reason": "test",
        "channel_id": 5,
        "details": "{}",
        "created_at": "2026-10-01 00:00:00",
    }
    first = case_digest(case)
    assert first == case_digest(case)
    assert first != case_digest(case, "different")


def test_policy_diff_reports_nested_changes():
    changes = diff_payloads(
        {"security": {"automod_enabled": 1}, "permissions": {"ban": True}},
        {"security": {"automod_enabled": 0}, "permissions": {"ban": True}},
    )
    assert len(changes) == 1
    assert "automod_enabled" in changes[0]


def test_trend_labels():
    assert trend_label(30, 20) == "RISING FAST"
    assert trend_label(8, 20) == "RISING"
    assert trend_label(1, 30) == "FALLING"
    assert trend_label(2, 5) == "STABLE"


def test_posture_score_deductions():
    assert posture_score(missing_permissions=0, disabled_layers=0, ledger_ok=True, active_incident=False) == 100
    assert posture_score(missing_permissions=1, disabled_layers=1, ledger_ok=True, active_incident=False) == 85
    assert posture_score(missing_permissions=0, disabled_layers=0, ledger_ok=False, active_incident=True) == 65
