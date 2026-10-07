"""Regression tests for Guardian v8 ULTRA multi-canary hardening."""

import json
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from esn_guardian.cogs.security_ultra import SecurityUltraCog, DECOY_MESH


def bot_mock():
    database = NS(
        fetchone=AsyncMock(return_value=None),
        fetchall=AsyncMock(return_value=[]),
        execute=AsyncMock(),
        create_case=AsyncMock(return_value=99),
        setting=AsyncMock(return_value={"security_log_channel_id": None}),
    )
    return NS(user=NS(id=900), database=database, get_cog=lambda name: None)


@pytest.mark.asyncio
async def test_canary_attribution_requires_owner_safe_known_actor():
    bot = bot_mock()
    cog = SecurityUltraCog(bot)
    cog._honeypots[10] = (20, 30, True)
    cog._tripwire = AsyncMock(return_value=True)
    guild = NS(id=10, owner_id=1)

    assert not await cog._canary_signal(guild, None, "channel", 20, "Deleted")
    assert not await cog._canary_signal(guild, NS(id=1), "channel", 20, "Deleted")
    assert not await cog._canary_signal(guild, NS(id=900), "channel", 20, "Deleted")
    assert await cog._canary_signal(guild, NS(id=88), "channel", 20, "Deleted")
    cog._tripwire.assert_awaited_once_with(
        guild, 88, "CANARY_CHANNEL_DELETE", 95, target_id=20,
    )


@pytest.mark.asyncio
async def test_unregistered_decoy_is_not_attributed():
    bot = bot_mock()
    cog = SecurityUltraCog(bot)
    cog._honeypots[10] = (20, 30, True)
    guild = NS(id=10, owner_id=1)
    assert not await cog._canary_signal(guild, NS(id=88), "role", 999, "Changed")
    bot.database.fetchone.assert_awaited_once()
    assert bot.database.create_case.await_count == 0


@pytest.mark.asyncio
async def test_two_assets_do_not_quarantine_without_owner_opt_in():
    bot = bot_mock()
    cog = SecurityUltraCog(bot)
    guild = NS(id=10, owner_id=1)
    # No opt-in row -> the expensive risk checks must never run.
    assert not await cog._maybe_contain_correlated_canary(guild, 88)
    bot.database.fetchone.assert_awaited_once()


@pytest.mark.asyncio
async def test_one_mutation_is_insufficient_even_with_opt_in():
    bot = bot_mock()
    bot.database.fetchone.side_effect = [{"auto_contain": 1}, {"targets": 1}]
    cog = SecurityUltraCog(bot)
    guild = NS(id=10, owner_id=1)
    assert not await cog._maybe_contain_correlated_canary(guild, 88)
    assert bot.database.fetchone.await_count == 2


@pytest.mark.asyncio
async def test_correlated_mutations_never_contain_recovery_staff():
    bot = bot_mock()
    bot.database.fetchone.side_effect = [{"auto_contain": 1}, {"targets": 2}]
    recovery = NS(_is_recovery=AsyncMock(return_value=True))
    bot.get_cog = lambda name: recovery if name == "SecurityV7Cog" else None
    cog = SecurityUltraCog(bot)
    top = MagicMock()
    member = NS(id=88, bot=False, roles=[])
    guild = NS(
        id=10, owner_id=1,
        me=NS(top_role=top), get_member=lambda user_id: member,
    )
    assert not await cog._maybe_contain_correlated_canary(guild, 88)
    recovery._is_recovery.assert_awaited_once_with(guild, member)


@pytest.mark.asyncio
async def test_correlated_mutations_quarantine_once_with_two_targets():
    bot = bot_mock()
    bot.database.fetchone.side_effect = [
        {"auto_contain": 1}, {"targets": 2}, None,
        {"auto_contain": 1},
    ]
    max_cog = NS(quarantine_member=AsyncMock(return_value=True))
    bot.get_cog = lambda name: max_cog if name == "SecurityMaxCog" else None
    member = NS(id=88, bot=False, roles=[])
    guild = NS(id=10, owner_id=1, me=NS(top_role=MagicMock()),
               get_member=lambda user_id: member)
    cog = SecurityUltraCog(bot)
    assert await cog._maybe_contain_correlated_canary(guild, 88)
    assert not await cog._maybe_contain_correlated_canary(guild, 88)
    max_cog.quarantine_member.assert_awaited_once()
    bot.database.create_case.assert_awaited_once()


@pytest.mark.asyncio
async def test_mesh_reuses_existing_assets_without_creating_duplicates():
    bot = bot_mock()
    bot.database.fetchall.return_value = [
        {"slot": slot, "asset_type": kind, "asset_id": i + 500}
        for i, (slot, kind, _name) in enumerate(DECOY_MESH)
    ]
    cog = SecurityUltraCog(bot)
    guild = MagicMock()
    guild.id = 20
    guild.owner_id = 11
    guild.me.guild_permissions = discord.Permissions(
        manage_roles=True, manage_channels=True
    )
    existing = [MagicMock(id=i + 500) for i in range(len(DECOY_MESH))]
    guild.get_channel.side_effect = lambda identifier: next(
        (asset for asset in existing if asset.id == identifier), None
    )
    guild.get_role.side_effect = guild.get_channel.side_effect
    vault = MagicMock(id=200, mention="#vault", name="vault")
    role = MagicMock(id=201, name="decoy")
    msg = await cog._install_decoy_mesh(
        guild, 11, vault, role, already_exists=True
    )
    assert "New/repaired satellites: 0" in msg
    guild.create_text_channel.assert_not_called()
    guild.create_role.assert_not_called()


@pytest.mark.asyncio
async def test_staff_restore_assigns_each_saved_role_exactly_once():
    bot = bot_mock()
    orig_permissions = discord.Permissions(manage_roles=True).value
    bot.database.fetchone.return_value = {
        "role_ids": json.dumps([{"id": 45, "permissions": orig_permissions}])
    }
    cog = SecurityUltraCog(bot)
    role = MagicMock()
    role.id = 45
    role.managed = False
    role.is_default.return_value = False
    role.permissions.value = orig_permissions
    role.__ge__.return_value = False
    guild = NS(id=12, owner_id=1, me=NS(top_role=MagicMock()),
               get_role=lambda id_: role if id_ == 45 else None)
    member = NS(id=78, add_roles=AsyncMock())
    result = await cog._restore_staff(guild, member)
    assert "1 role(s)" in result
    member.add_roles.assert_awaited_once_with(
        role, reason="Guardian ULTRA owner-approved role recovery"
    )
