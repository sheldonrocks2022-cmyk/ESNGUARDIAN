from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock, patch

import discord
import pytest

from esn_guardian.cogs.security_ultra import (
    SecurityUltraCog, dangerous_role, permission_risks, raid_preview,
    reversible_roles,
)
from esn_guardian.main import EXTENSIONS


class Role:
    def __init__(self, name, id_, rank, *, admin=False, managed=False, default=False):
        self.name = name
        self.id = id_
        self.rank = rank
        self.managed = managed
        self.default = default
        self.permissions = discord.Permissions(administrator=admin)

    def is_default(self):
        return self.default

    def __lt__(self, other):
        return self.rank < other.rank

    def __ge__(self, other):
        return self.rank >= other.rank


def make_bot():
    db = NS(
        fetchone=AsyncMock(return_value=None),
        execute=AsyncMock(),
        create_case=AsyncMock(return_value=11),
        setting=AsyncMock(return_value={"security_log_channel_id": None}),
    )
    return NS(database=db, user=NS(id=99), get_cog=lambda name: None)


def test_ultra_cog_is_registered():
    assert "esn_guardian.cogs.security_ultra" in EXTENSIONS


def test_raid_preview_is_only_a_decision_helper():
    assert "Fast join burst" in raid_preview(4, 4, 0, 8, 3)
    assert "Young-account burst" in raid_preview(3, 2, 3, 8, 3)
    assert "No existing" in raid_preview(0, 0, 0, 8, 3)


def test_privilege_scan_catches_unguardable_roles_and_everyone():
    everyone = Role("@everyone", 1, 0, admin=True, default=True)
    guardian = Role("Guardian", 99, 5)
    elevated = Role("Danger", 2, 6, admin=True)
    guild = NS(
        default_role=everyone,
        me=NS(top_role=guardian, guild_permissions=discord.Permissions.none()),
        roles=[everyone, guardian, elevated],
    )
    problems = permission_risks(guild)
    assert any("@everyone" in issue for issue in problems)
    assert any("cannot contain" in issue for issue in problems)


def test_owner_and_bot_are_never_staff_locked():
    everyone = Role("@everyone", 1, 0, default=True)
    admin = Role("admin", 2, 2, admin=True)
    me = NS(top_role=Role("Guardian", 99, 10))
    guild = NS(owner_id=42)
    assert dangerous_role(admin)
    assert not reversible_roles(NS(id=42, guild=guild, bot=False, roles=[admin]), me)
    assert not reversible_roles(NS(id=7, guild=guild, bot=True, roles=[admin]), me)
    assert reversible_roles(
        NS(id=7, guild=guild, bot=False, roles=[everyone, admin]), me
    ) == [admin]


@pytest.mark.asyncio
async def test_tripwire_records_once_and_exempts_owner_and_bot():
    bot = make_bot()
    cog = SecurityUltraCog(bot)
    guild = NS(id=12, owner_id=42)
    assert await cog._tripwire(guild, 42, "BUTTON", 40) is False
    assert await cog._tripwire(guild, 99, "BUTTON", 40) is False
    assert await cog._tripwire(guild, 500, "BUTTON", 40) is True
    assert await cog._tripwire(guild, 500, "BUTTON", 40) is False
    assert bot.database.execute.await_count == 1
    assert bot.database.create_case.await_count == 1


@pytest.mark.asyncio
async def test_staff_lock_creates_permission_snapshot_before_removal():
    bot = make_bot()
    cog = SecurityUltraCog(bot)
    admin = Role("Mod", 22, 4, admin=True)
    me = NS(top_role=Role("Guardian", 99, 10))
    guild = NS(id=18, owner_id=1, me=me)
    member = NS(
        id=6, guild=guild, bot=False, roles=[admin],
        remove_roles=AsyncMock(),
    )
    result = await cog._staff_lock(member, "Suspected compromise")
    assert "locked" in result
    sql, values = bot.database.execute.await_args.args
    assert "INSERT INTO ultra_staff_locks" in sql
    assert json.loads(values[2]) == [
        {"id": admin.id, "permissions": admin.permissions.value}
    ]
    member.remove_roles.assert_awaited_once()


@pytest.mark.asyncio
async def test_staff_unlock_rejects_role_permission_escalation():
    bot = make_bot()
    cog = SecurityUltraCog(bot)
    role = Role("Mod", 22, 4, admin=True)
    role_snapshot = {"id": role.id, "permissions": discord.Permissions.none().value}
    bot.database.fetchone.return_value = {
        "role_ids": json.dumps([role_snapshot])
    }
    guild = NS(
        id=18, owner_id=1, me=NS(top_role=Role("Guardian", 99, 10)),
        get_role=lambda id_: role if id_ == 22 else None,
    )
    member = NS(id=6, add_roles=AsyncMock())
    result = await cog._restore_staff(guild, member)
    assert "Manual review required" in result
    member.add_roles.assert_not_awaited()
    bot.database.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_regular_member_update_does_not_read_lock_database():
    bot = make_bot()
    cog = SecurityUltraCog(bot)
    # The hot path receives many nickname/avatar updates.
    cog._honeypots[18] = (None, None, False)
    admin = Role("Admin", 22, 4, admin=True)
    guild = NS(id=18, owner_id=1)
    before = NS(id=6, guild=guild, bot=False, roles=[admin])
    after = NS(id=6, guild=guild, bot=False, roles=[admin])
    await cog.on_member_update(before, after)
    bot.database.fetchone.assert_not_awaited()
