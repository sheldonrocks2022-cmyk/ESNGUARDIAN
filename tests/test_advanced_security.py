from types import SimpleNamespace as NS

import discord

from esn_guardian.cogs.advanced_security import AdvancedSecurityCog, USE_EXTERNAL_APPS_BIT


def test_credential_detector_targets_high_confidence_secrets():
    assert AdvancedSecurityCog._contains_credential("github_pat_" + "A" * 24)
    assert AdvancedSecurityCog._contains_credential("AKIA" + "A" * 16)
    assert AdvancedSecurityCog._contains_credential("-----BEGIN PRIVATE KEY-----")
    assert not AdvancedSecurityCog._contains_credential("hello this is a normal Discord message")


def test_external_app_permission_bit_matches_discord_py():
    permissions = discord.Permissions.none()
    permissions.use_external_apps = True
    assert permissions.value & USE_EXTERNAL_APPS_BIT


def test_guardian_group_only_exposes_recovery_controls():
    names = {command.name for command in AdvancedSecurityCog.guardian.commands}
    assert names == {"snapshot", "approve-bot", "unapprove-bot", "panic", "audit", "status"}


async def test_destructive_threshold_contains_non_owner():
    cog = AdvancedSecurityCog(NS(user=NS(id=99)))
    cog._contain_actor = __import__("unittest.mock").mock.AsyncMock()
    guild = NS(id=1, owner_id=1)
    actor = NS(id=5)
    await cog._record_destructive(guild, actor, "one")
    await cog._record_destructive(guild, actor, "two")
    cog._contain_actor.assert_not_awaited()
    await cog._record_destructive(guild, actor, "three")
    cog._contain_actor.assert_awaited_once()
