"""Regression tests for bounded raid containment under join storms."""

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest

from esn_guardian.cogs.security import SecurityCog
from esn_guardian.cogs.security_max import SecurityMaxCog


def test_queue_saturation_does_not_launch_unbounded_tasks():
    cog = SecurityCog(NS())
    cog._raid_kick_queue = asyncio.Queue(maxsize=1)
    cog._raid_kick_queue.put_nowait((object(), "already queued"))
    cog._note_raid_failure = MagicMock()
    guild = NS(id=44, owner_id=1)
    member = NS(id=234, bot=False, guild=guild)

    assert cog._enqueue_raid_kick(member, "storm") is False
    assert cog._raid_kick_queue.qsize() == 1
    assert (44, 234) not in cog._raid_queued
    cog._note_raid_failure.assert_called_once_with(
        member, "raid removal queue at capacity"
    )


@pytest.mark.asyncio
async def test_kick_worker_survives_unexpected_exception():
    cog = SecurityCog(NS())
    guild = NS(id=44, owner_id=1)
    member_a = NS(id=234, bot=False, guild=guild)
    member_b = NS(id=235, bot=False, guild=guild)
    cog._note_raid_failure = MagicMock()
    cog._kick_for_raid = AsyncMock(side_effect=[RuntimeError("unexpected"), True])
    worker = asyncio.create_task(cog._raid_kick_worker())

    try:
        cog._raid_queued.update({(44, 234), (44, 235)})
        cog._raid_kick_queue.put_nowait((member_a, "storm"))
        cog._raid_kick_queue.put_nowait((member_b, "storm"))
        await asyncio.wait_for(cog._raid_kick_queue.join(), timeout=2)
        assert cog._kick_for_raid.await_count == 2
        cog._note_raid_failure.assert_called_once_with(
            member_a, "unexpected removal error"
        )
        assert not cog._raid_queued
    finally:
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker


@pytest.mark.asyncio
async def test_max_cluster_raid_only_activates_once_and_targets_matching_names():
    now = datetime.now(UTC)
    guild = NS(id=44)
    security = NS(
        raid_locks=defaultdict(asyncio.Lock),
        raid_mode_until={},
        _raid_trigger_count=defaultdict(int),
        _schedule_raid_persist=MagicMock(),
        _queue_recent_raid_joiners=MagicMock(return_value=2),
        _lockdown=AsyncMock(),
    )
    security.is_raid_mode_active = lambda guild_id: (
        security.raid_mode_until.get(guild_id, now) > now
        if guild_id in security.raid_mode_until
        else False
    )
    bot = NS(get_cog=lambda name: security if name == "SecurityCog" else None)
    max_cog = SecurityMaxCog(bot)
    max_cog._case = AsyncMock()
    max_cog.recent_joins[44].extend([
        (now, 1001, "raider_001", 0, True),
        (now, 1002, "raider_002", 0, True),
        (now, 1003, "unrelated", 365, False),
    ])

    await max_cog._activate_raid_v4(guild, "similar accounts", suspect_name="raider_003")
    await max_cog._activate_raid_v4(guild, "similar accounts", suspect_name="raider_003")
    await asyncio.sleep(0)

    assert security._raid_trigger_count[44] == 1
    security._schedule_raid_persist.assert_called_once()
    security._queue_recent_raid_joiners.assert_called_once_with(
        guild, [1001, 1002], "similar accounts"
    )
    security._lockdown.assert_awaited_once()
    max_cog._case.assert_awaited_once()
