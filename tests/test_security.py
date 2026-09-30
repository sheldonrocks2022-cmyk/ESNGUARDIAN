from datetime import UTC, datetime
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from esn_guardian.cogs.common import can_target, safe_public_role, require_role
from esn_guardian.cogs.moderation import ModerationCog
from esn_guardian.cogs.security import SecurityCog
from esn_guardian.cogs.verification import VerificationView
from esn_guardian.config import Settings
from esn_guardian.database import Database
from esn_guardian.main import GuardianBot, EXTENSIONS


class Role:
    def __init__(self, guild, rank, **permissions):
        self.guild = guild
        self.rank = rank
        self.managed = False
        self.permissions = discord.Permissions(**permissions)
    def is_default(self):
        return self.rank == 0
    def __lt__(self, other):
        return self.rank < other.rank
    def __ge__(self, other):
        return self.rank >= other.rank


def members():
    guild = NS(id=1, owner_id=1)
    guild.me = NS(id=99, top_role=Role(guild, 10))
    actor = NS(id=2, guild=guild, top_role=Role(guild, 5))
    target = NS(id=3, guild=guild, top_role=Role(guild, 2))
    return guild, actor, target


@pytest.mark.parametrize('target_id,rank,expected', [(3,2,True),(3,5,False),(3,6,False),(1,2,False),(2,2,False),(99,2,False),(3,10,False)])
def test_target_hierarchy(target_id, rank, expected):
    guild, actor, target = members()
    target.id = target_id
    target.top_role = Role(guild, rank)
    assert can_target(guild, actor, target) is expected


@pytest.mark.parametrize('permission', ['administrator','manage_roles','manage_webhooks','ban_members','manage_guild'])
def test_public_roles_reject_privileges(permission):
    guild, _, _ = members()
    assert not safe_public_role(Role(guild, 2, **{permission: True}), guild)


def test_public_role_validation():
    guild, _, _ = members()
    assert safe_public_role(Role(guild, 2), guild)
    assert not safe_public_role(Role(guild, 0), guild)
    assert not safe_public_role(Role(guild, 10), guild)
    role = Role(guild, 2); role.managed = True
    assert not safe_public_role(role, guild)
    assert not safe_public_role(Role(NS(id=9), 2), guild)


async def test_role_grant_cannot_escalate():
    guild, actor, _ = members()
    interaction = NS(guild=guild, user=actor, response=NS(is_done=lambda:False, send_message=AsyncMock()))
    assert not await require_role(interaction, Role(guild, 2, administrator=True))
    assert not await require_role(interaction, Role(guild, 5))
    assert await require_role(interaction, Role(guild, 2))


async def test_unknown_audit_actor_does_not_crash_or_ban():
    db = NS(fetchone=AsyncMock(return_value={'enabled':1, 'window_seconds':15,'action_limit':3}))
    cog = SecurityCog(NS(database=db, user=NS(id=99)))
    cog._audit_executor = AsyncMock(return_value=None)
    guild = NS(id=1, owner_id=1, ban=AsyncMock())
    await cog._check_nuke_action(guild, discord.AuditLogAction.kick, 3, 'kick')
    guild.ban.assert_not_awaited()
    assert not cog.audit_events


async def test_audit_lookup_runs_without_name_error():
    cog = SecurityCog(NS())
    guild = NS(audit_logs=MagicMock())
    async def entries():
        yield NS(target=NS(id=3), user=NS(id=4))
    guild.audit_logs.return_value = entries()
    assert (await cog._audit_executor(guild, discord.AuditLogAction.ban, 3)).id == 4


async def test_first_violation_deletes_message():
    member = MagicMock(spec=discord.Member)
    member.id = 3
    message = NS(guild=NS(id=1), author=member, delete=AsyncMock(), channel=NS(id=4))
    cog = SecurityCog(NS(database=NS(fetchone=AsyncMock(return_value={'count':0}))))
    cog._security_case = AsyncMock()
    await cog._enforce_message_violation(message, 'phishing')
    message.delete.assert_awaited_once()
    assert cog._security_case.call_args.args[2] == 'AUTOMOD_WARN'


async def test_verification_button_respects_maintenance():
    member = MagicMock(spec=discord.Member)
    db = NS(is_guild_blacklisted=AsyncMock(return_value=False), state_enabled=AsyncMock(return_value=True), fetchone=AsyncMock())
    interaction = NS(guild=NS(id=1), user=member, response=NS(is_done=lambda:False, send_message=AsyncMock()))
    view = VerificationView(NS(database=db))
    await view.children[0].callback(interaction)
    db.fetchone.assert_not_awaited()
    member.add_roles.assert_not_called()


async def test_lockdown_preserves_and_restores_permissions_after_restart(tmp_path):
    db = Database(tmp_path/'test.db'); await db.connect(); await db.ensure_guild(1)
    try:
        overwrite = discord.PermissionOverwrite(send_messages=True, view_channel=False, attach_files=False)
        channel = NS(id=2, overwrites_for=lambda _:overwrite, set_permissions=AsyncMock())
        guild = NS(id=1, default_role=NS(id=1), text_channels=[channel])
        cog = SecurityCog(NS(database=db)); cog._security_case = AsyncMock()
        await cog._lockdown(guild, 'test')
        assert overwrite.send_messages is False and overwrite.view_channel is False
        cog = SecurityCog(NS(database=db)); cog._security_case = AsyncMock()
        assert await cog._unlockdown(guild, 'restore') == 1
        assert overwrite.send_messages is True and overwrite.view_channel is False and overwrite.attach_files is False
        assert not (await db.setting(1))['lockdown_active']
    finally:
        await db.close()


async def test_permission_checks_reject_manage_guild_without_ban():
    interaction = NS(permissions=discord.Permissions(manage_guild=True))
    with pytest.raises(discord.app_commands.MissingPermissions):
        await ModerationCog.ban.checks[0](interaction)


async def test_antinuke_disable_requires_server_owner():
    guild, actor, _ = members()
    assert not await SecurityCog.antinuke_disable.checks[0](NS(guild=guild, user=actor))
    actor.id = guild.owner_id
    assert await SecurityCog.antinuke_disable.checks[0](NS(guild=guild, user=actor))


async def test_all_extensions_load_offline(tmp_path):
    bot = GuardianBot(Settings('unused', 1, tmp_path/'smoke.db', 'INFO'))
    try:
        await bot._async_setup_hook()
        await bot.setup_hook()
        assert set(bot.extensions) == set(EXTENSIONS)
        assert bot.allowed_mentions.everyone is False
        assert bot.tree.get_command('security') is not None
    finally:
        await bot.close()


async def test_external_user_app_triggers_immediate_ban():
    member = NS(id=3)
    guild = NS(
        id=1,
        owner_id=1,
        get_member=lambda user_id: member if user_id == 3 else None,
        fetch_member=AsyncMock(),
        ban=AsyncMock(),
    )
    metadata = NS(user=NS(id=3), is_user_integration=lambda: True)
    message = NS(
        guild=guild,
        interaction_metadata=metadata,
        application_id=123456789,
        channel=NS(id=4),
        delete=AsyncMock(),
    )
    cog = SecurityCog(NS(user=NS(id=99)))
    cog._security_case = AsyncMock()

    assert await cog._enforce_external_app_zero_tolerance(message) is True
    message.delete.assert_awaited_once()
    guild.ban.assert_awaited_once()
    assert guild.ban.call_args.args[0] is member
    assert cog._security_case.call_args.args[2] == "EXTERNAL_APP_BAN"


async def test_server_installed_app_does_not_trigger_external_app_ban():
    guild = NS(id=1, owner_id=1, ban=AsyncMock())
    metadata = NS(user=NS(id=3), is_user_integration=lambda: False)
    message = NS(
        guild=guild,
        interaction_metadata=metadata,
        application_id=123456789,
        channel=NS(id=4),
        delete=AsyncMock(),
    )
    cog = SecurityCog(NS(user=NS(id=99)))
    cog._security_case = AsyncMock()

    assert await cog._enforce_external_app_zero_tolerance(message) is False
    message.delete.assert_not_awaited()
    guild.ban.assert_not_awaited()
    cog._security_case.assert_not_awaited()
