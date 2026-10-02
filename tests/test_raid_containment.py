from datetime import UTC, datetime, timedelta

from esn_guardian.cogs.security import (
    fast_burst_limit,
    raid_mode_active,
    raid_trigger_reason,
    should_activate_raid,
)


def test_raid_mode_active_only_before_expiry():
    now = datetime.now(UTC)
    assert raid_mode_active(now + timedelta(minutes=1), now) is True
    assert raid_mode_active(now - timedelta(seconds=1), now) is False
    assert raid_mode_active(None, now) is False


def test_raid_activates_at_threshold():
    assert should_activate_raid(9, 10, False) is False
    assert should_activate_raid(10, 10, False) is True
    assert should_activate_raid(15, 10, False) is True


def test_active_raid_does_not_retrigger_full_lockdown():
    assert should_activate_raid(10, 10, True) is False
    assert should_activate_raid(50, 10, True) is False


def test_fast_burst_threshold_scales_with_configured_limit():
    assert fast_burst_limit(3) == 3
    assert fast_burst_limit(8) == 4
    assert fast_burst_limit(25) == 13
    assert fast_burst_limit(100) == 50


def test_fast_burst_can_trigger_before_full_window_limit():
    reason = raid_trigger_reason(
        join_count=4,
        fast_count=4,
        young_count=0,
        join_limit=8,
        min_account_age_days=3,
        already_active=False,
    )
    assert reason is not None
    assert "Fast join burst" in reason


def test_young_account_burst_triggers_when_age_checks_enabled():
    reason = raid_trigger_reason(
        join_count=3,
        fast_count=2,
        young_count=3,
        join_limit=8,
        min_account_age_days=3,
        already_active=False,
    )
    assert reason is not None
    assert "Young-account burst" in reason


def test_young_account_burst_disabled_when_minimum_age_is_zero():
    reason = raid_trigger_reason(
        join_count=2,
        fast_count=2,
        young_count=3,
        join_limit=8,
        min_account_age_days=0,
        already_active=False,
    )
    assert reason is None


def test_active_raid_never_retriggers_detection():
    reason = raid_trigger_reason(
        join_count=100,
        fast_count=100,
        young_count=100,
        join_limit=8,
        min_account_age_days=3,
        already_active=True,
    )
    assert reason is None
