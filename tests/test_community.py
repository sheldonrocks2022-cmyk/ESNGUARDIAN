import asyncio
import time
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from esn_guardian.cogs.community import CommunityCog
from esn_guardian.cogs.tickets import TicketsCog
from esn_guardian.database import Database
from esn_guardian.config import Settings
from esn_guardian.main import GuardianBot


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path/'community.db')
    await database.connect()
    await database.ensure_guild(1)
    yield database
    await database.close()


def context(database):
    support = MagicMock(spec=discord.Role)
    support.id = 8; support.managed = False; support.is_default.return_value = False
    member = MagicMock(spec=discord.Member)
    member.id = 2; member.roles = []; member.guild_permissions = discord.Permissions.none()
    everyone = MagicMock(spec=discord.Role); everyone.id = 1
    bot_member = MagicMock(spec=discord.Member); bot_member.id = 99
    channel = NS(id=4, mention='<#4>', send=AsyncMock(), edit=AsyncMock(), overwrites={member:discord.PermissionOverwrite(view_channel=True,send_messages=True)})
    guild = NS(id=1, owner_id=10, default_role=everyone, me=bot_member, get_role=lambda _:support, fetch_channel=AsyncMock(return_value=channel), create_text_channel=AsyncMock(return_value=channel))
    channel.guild = guild
    channel.permissions_for = lambda _: discord.Permissions(send_messages=True)
    interaction = NS(guild=guild,guild_id=1,user=member,channel=channel,channel_id=4,response=NS(defer=AsyncMock(),is_done=lambda:True),followup=NS(send=AsyncMock()))
    return NS(database=database), interaction


async def test_ticket_requires_support_configuration(db):
    bot, interaction = context(db)
    await TicketsCog.ticket.callback(TicketsCog(bot), interaction, 'help')
    interaction.guild.create_text_channel.assert_not_awaited()


async def test_concurrent_requests_create_one_ticket_and_grant_support(db):
    await db.execute('UPDATE ticket_config SET support_role_id=8 WHERE guild_id=1')
    bot, interaction = context(db); cog=TicketsCog(bot)
    await asyncio.gather(*(TicketsCog.ticket.callback(cog,interaction,'help') for _ in range(2)))
    interaction.guild.create_text_channel.assert_awaited_once()
    permissions=interaction.guild.create_text_channel.call_args.kwargs['overwrites']
    assert permissions[interaction.guild.get_role(8)].view_channel is True
    assert permissions[interaction.guild.default_role].view_channel is False


async def test_close_rejects_other_member_and_preserves_active_record(db):
    await db.execute('INSERT INTO tickets VALUES (1,3,4,?)',(time.time(),))
    bot, interaction=context(db)
    await TicketsCog.close_ticket.callback(TicketsCog(bot),interaction)
    interaction.channel.edit.assert_not_awaited()
    assert (await db.fetchone('SELECT channel_id FROM tickets'))['channel_id']==4


async def test_owner_can_close_and_cooldown_survives_cog_restart(db):
    await db.execute('UPDATE ticket_config SET support_role_id=8 WHERE guild_id=1')
    await db.execute('INSERT INTO tickets VALUES (1,2,4,?)',(time.time(),))
    bot, interaction=context(db)
    await TicketsCog.close_ticket.callback(TicketsCog(bot),interaction)
    assert interaction.channel.edit.call_args.kwargs['overwrites'][interaction.user].send_messages is False
    assert (await db.fetchone('SELECT channel_id FROM tickets'))['channel_id'] is None
    await TicketsCog.ticket.callback(TicketsCog(bot),interaction,'again')
    interaction.guild.create_text_channel.assert_not_awaited()


async def test_failed_close_keeps_record(db):
    await db.execute('INSERT INTO tickets VALUES (1,2,4,?)',(time.time(),))
    bot, interaction=context(db)
    interaction.channel.edit.side_effect=discord.Forbidden(NS(status=403,reason='Forbidden'),'no permission')
    await TicketsCog.close_ticket.callback(TicketsCog(bot),interaction)
    assert (await db.fetchone('SELECT channel_id FROM tickets'))['channel_id']==4


async def test_announcement_concurrency_and_restart_cooldown(db):
    bot, interaction=context(db); cog=CommunityCog(bot)
    await asyncio.gather(*(CommunityCog.smpannounce.callback(cog,interaction,interaction.channel,'news') for _ in range(2)))
    interaction.channel.send.assert_awaited_once()
    await CommunityCog.smpannounce.callback(CommunityCog(bot),interaction,interaction.channel,'news')
    interaction.channel.send.assert_awaited_once()
    assert interaction.channel.send.call_args.kwargs['allowed_mentions'].everyone is False


async def test_failed_announcement_does_not_consume_cooldown(db):
    bot, interaction=context(db)
    interaction.channel.send.side_effect=discord.Forbidden(NS(status=403,reason='Forbidden'),'no permission')
    await CommunityCog.smpannounce.callback(CommunityCog(bot),interaction,interaction.channel,'news')
    assert (await db.setting(1))['ad_last_sent_at'] is None


async def test_config_includes_security_verification_and_ticket_settings(db):
    bot, interaction=context(db)
    await CommunityCog.config.callback(CommunityCog(bot),interaction)
    output='\n'.join(c.kwargs['embed'].description for c in interaction.followup.send.call_args_list)
    for label in ['AutoMod','Anti-nuke','Raid','Verification','Tickets','Support Role Id','Flood Limit']:
        assert label in output


async def test_command_cleanup_and_ticket_registration(tmp_path):
    bot=GuardianBot(Settings('unused',1,tmp_path/'registration.db','INFO'))
    try:
        await bot._async_setup_hook(); await bot.setup_hook()
        names={command.name for command in bot.tree.get_commands()}
        assert {'ticket','ticket-close','ticket-config','smp','smpannounce','config'} <= names
        assert not ({'players','ip','port','joinhelp','setup','poll','setup_ad','ad_on','ad_off','ad_status','report_ad'} & names)
    finally:
        await bot.close()


async def test_deleted_ticket_releases_active_slot(db):
    await db.execute('INSERT INTO tickets VALUES (1,2,4,?)',(time.time(),))
    bot, interaction=context(db)
    await TicketsCog(bot).on_guild_channel_delete(interaction.channel)
    assert (await db.fetchone('SELECT channel_id FROM tickets'))['channel_id'] is None
