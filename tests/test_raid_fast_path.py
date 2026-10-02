from datetime import UTC, datetime, timedelta

from esn_guardian.cogs.security import (
    MESSAGE_POLICY_CACHE_SECONDS,
    RAID_CONFIG_CACHE_SECONDS,
    RAID_CONTAINMENT_MINUTES,
    RAID_KICK_CONCURRENCY,
    raid_mode_active,
    should_activate_raid,
)


def test_raid_fast_path_constants_are_bounded():
    assert MESSAGE_POLICY_CACHE_SECONDS >= 30
    assert RAID_CONFIG_CACHE_SECONDS >= 30
    assert RAID_CONTAINMENT_MINUTES >= 5
    assert 2 <= RAID_KICK_CONCURRENCY <= 8


def test_active_containment_extends_without_retriggering_lockdown():
    now = datetime.now(UTC)
    assert raid_mode_active(now + timedelta(minutes=RAID_CONTAINMENT_MINUTES), now)
    assert not should_activate_raid(100, 10, True)


def test_threshold_activation_is_immediate():
    assert not should_activate_raid(9, 10, False)
    assert should_activate_raid(10, 10, False)
