from datetime import UTC, datetime, timedelta

from esn_guardian.cogs.security import raid_mode_active, should_activate_raid


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
