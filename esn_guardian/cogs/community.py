from __future__ import annotations

import asyncio
import logging
import random
from collections import defaultdict
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import (
    audit_log_actor,
    format_member_details,
    guild_owner_only,
    guild_only,
    log_event,
    notify_user,
    respond,
    set_protected_footer,
    staff_only,
    safe_public_role,
    require_role,
)

SMP_INFO = "**Minecraft Bedrock**\nServer: **ESN SMP**\nIP: `esnsmp.ggwp.cc`\nPort: `17058`\nDiscord: https://discord.gg/huFsDxkZ2g"
LOG_FIELDS = {
    "moderation": "moderation_log_channel_id",
    "security": "security_log_channel_id",
    "member": "member_log_channel_id",
    "message": "message_log_channel_id",
    "verification": "verification_log_channel_id",
    "system": "system_log_channel_id",
    "guild": "guild_log_channel_id",
    "voice": "voice_log_channel_id",
    "invite": "invite_log_channel_id",
    "role": "role_log_channel_id",
    "command": "command_log_channel_id",
}
BEDROCK_RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
LOG = logging.getLogger("esn_guardian.cogs.community")
HELP_GUIDES = {
    "setup": "**ESN Guardian Setup**\n1. Give Guardian View Channels, Send Messages, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, Manage Webhooks, Read Message History, and View Audit Log.\n2. Put Guardian above every role it must protect.\n3. Run `/security harden` to enable the secure baseline, external-app lock, recovery snapshot, bot approval, webhook/integration guards, credential protection, and rollback.\n4. Set log routes with `/logs`.\n5. Configure verification and tickets if your server uses them.\n6. Run `/guardian audit` and keep the security score clean.\n\nUse `/help section:<category>` for the command catalogue.",
    "moderation": "**Moderation Commands**\n`/warn`, `/warnings`, `/timeout`, `/untimeout`, `/kick`, `/ban`, `/unban`\n`/clear`, `/slowmode`, `/nickname`, `/role`, `/massrole`\n`/case`, `/history`,  `/lockdown`, `/unlockdown`\n\nStaff permission is required. Every moderation action creates a case ID and can be sent to the moderation log channel.",
    "security": "**Security Commands**\nCore: `/security harden`, `/security status`, `/security scan`, `/security cases`\nAutoMod: `/security automod`, `/security thresholds`, `/security links`, `/security allow-domain`, `/security remove-domain`, `/security add-word`, `/security remove-word`, `/security words`, `/security domains`, `/security check-link`, `/security reset-automod`\nRaid: `/security raid`, `/security raid-status`, `/security quarantine`, `/security release`, `/security member`\nAnti-nuke: `/antinuke setup`, `/antinuke enable`, `/antinuke disable`, `/antinuke status`, `/antinuke trust`, `/antinuke untrust`\nAdvanced: `/guardian audit`, `/guardian status`, `/guardian snapshot`, `/guardian approve-bot`, `/guardian unapprove-bot`, `/guardian panic`\n\nUse `/security harden` first, then `/guardian audit`.",
    "verification": "**Verification Commands**\n`/verification setup` posts the persistent VERIFY button and stores its message.\n`/verification enable` and `/verification disable` control access.\n`/verification status` shows roles and account-age settings.\n`/verification reset` clears verification records for one member or the whole server.\n`/verify` lets a member run the same checks without using the button.\n\nPut the verified role below the bot's highest role; configure the unverified role with restricted channel permissions.",
    "community": "**Community Commands**\nConfiguration: `/config`, `/welcome`, `/goodbye`, `/autorole`, `/logs`, `/panel`\nCommunity: `/ticket`, `/ticket-close`, `/ticket-config`, `/suggest`\nStaff utility: `/smpannounce`\n\nWebsite information, live ESN status, SMP connection details, store information, and general ESN links now stay on the ESN website instead of duplicating them inside Guardian.",
    "owner": "**Owner Commands**\n`/botstats`, `/backupdb`, `/backupstatus`, `/servers`, `/synccommands`, `/broadcast`, `/maintenance`, `/blacklist`, `/unblacklist`\n\nOnly the configured bot owner can use these operational commands.",
}


class BedrockStatusProtocol(asyncio.DatagramProtocol):
    def __init__(self, response: asyncio.Future[bytes], payload: bytes) -> None:
        self.response = response
        self.payload = payload
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.transport.sendto(self.payload)

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if data[:1] == b"\x1c" and not self.response.done():
            self.response.set_result(data)

    def error_received(self, exception: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exception)


class ControlPanel(discord.ui.View):
    def __init__(self, bot: commands.Bot, *, esn: bool = False) -> None:
        super().__init__(timeout=None)
        self.bot = bot
        self.esn = esn
        labels = (("SMP", "smp"), ("Status", "status"), ("Security", "security"), ("Rules", "rules"), ("Discord", "discord"), ("Support", "support")) if esn else (("Security", "security"), ("AutoMod", "automod"), ("Verification", "verification"), ("Logs", "logs"), ("Settings", "settings"), ("Lockdown", "lockdown"), ("Statistics", "statistics"), ("Help", "help"))
        for label, action in labels:
            button = discord.ui.Button(label=label, custom_id=f"esn_guardian:{'esn' if esn else 'control'}:{action}", style=discord.ButtonStyle.danger if action == "lockdown" else discord.ButtonStyle.secondary)
            button.callback = self._callback(action)
            self.add_item(button)

    def _callback(self, action: str):
        async def callback(interaction: discord.Interaction) -> None:
            if action == "smp":
                await respond(interaction, SMP_INFO)
            elif action in {"status", "players"}:
                community = self.bot.get_cog("CommunityCog")
                if isinstance(community, CommunityCog):
                    await respond(interaction, await community._bedrock_status())
                else:
                    await respond(interaction, "SMP status is temporarily unavailable.")
            elif action == "discord":
                await respond(interaction, "https://discord.gg/huFsDxkZ2g")
            elif action == "lockdown":
                if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
                    await respond(interaction, "Staff permission is required.")
                    return
                await respond(interaction, "Use `/lockdown` to confirm the incident reason and lock channels.")
            elif action in {"security", "automod", "verification", "logs", "settings", "ads", "statistics", "rules", "support", "help"}:
                text = {"security": "Security controls:  `/lockdown`, `/unlockdown`.", "automod": "AutoMod is actively monitoring flood, mention, duplicate, caps, links, and configured blocked words.", "verification": "Configure with `/verification setup`, then `/verification enable`.", "logs": "Set each route with `/logs category:<name> channel:<channel>`.", "settings": "Use `/config` to inspect current server settings.", "ads": "Advertising controls have been retired. Staff can use `/smpannounce`.", "statistics": f"Serving {len(self.bot.guilds)} servers.", "rules": "Ask your server staff for the current rules.", "support": "Support: https://discord.gg/huFsDxkZ2g", "help": "Use `/help` for setup instructions and the full command guide."}[action]
                await respond(interaction, text)
        return callback


class CommunityCog(commands.Cog):

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._smp_online: bool | None = None
        self.announcement_locks = defaultdict(asyncio.Lock)

    async def cog_load(self) -> None:
        self.bot.add_view(ControlPanel(self.bot))

    def cog_unload(self) -> None:

    async def _send_member_notice(self, channel: discord.TextChannel, member: discord.Member, title: str, color: discord.Color) -> None:
        details = format_member_details(member)[:4096]
        embed = set_protected_footer(discord.Embed(title=title, description=details, color=color, timestamp=datetime.now(UTC)))
        embed.set_thumbnail(url=member.display_avatar.url)
        try:
            await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            try:
                await channel.send(f"**{title}**\n{details}"[:2000], allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:
                LOG.exception("Could not send %s notice for %s (%s) in %s (%s)", title, member, member.id, member.guild.name, member.guild.id)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        settings = await self.bot.database.setting(member.guild.id)
        autorole = member.guild.get_role(settings["autorole_id"]) if settings["autorole_id"] else None
        if autorole and safe_public_role(autorole, member.guild):
            try:
                await member.add_roles(autorole, reason="ESN Guardian autorole")
            except discord.HTTPException:
                await log_event(self.bot, member.guild, "system_log_channel_id", "Autorole failure", description=f"Could not assign {autorole.mention} to {member.mention}.", color=discord.Color.red())
        channel = member.guild.get_channel(settings["welcome_channel_id"]) if settings["welcome_channel_id"] else None
        if isinstance(channel, discord.TextChannel):
            await self._send_member_notice(channel, member, "Member joined", discord.Color.green())
        await log_event(self.bot, member.guild, "member_log_channel_id", "Member joined", description=format_member_details(member), color=discord.Color.green())

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        settings = await self.bot.database.setting(member.guild.id)
        channel = member.guild.get_channel(settings["goodbye_channel_id"]) if settings["goodbye_channel_id"] else None
        if isinstance(channel, discord.TextChannel):
            await self._send_member_notice(channel, member, "Member left", discord.Color.orange())
        await log_event(self.bot, member.guild, "member_log_channel_id", "Member left", description=format_member_details(member), color=discord.Color.orange())

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        if before.nick != after.nick:
            await log_event(self.bot, after.guild, "member_log_channel_id", "Member nickname changed", description=f"User: {after.mention} ({after.id})\nBefore: {before.nick or 'None'}\nAfter: {after.nick or 'None'}\nTimezone: Unknown (Discord does not expose a user timezone via the API)", color=discord.Color.blurple())
        if before.roles != after.roles:
            added = [role for role in after.roles if role not in before.roles]
            removed = [role for role in before.roles if role not in after.roles]
            if added or removed:
                actor = await audit_log_actor(after.guild, discord.AuditLogAction.member_role_update, after.id)
                await log_event(self.bot, after.guild, "member_log_channel_id", "Member roles updated", description=f"User: {after.mention} ({after.id})\nAdded: {', '.join(role.mention for role in added) if added else 'None'}\nRemoved: {', '.join(role.mention for role in removed) if removed else 'None'}\nUpdated by: {actor}", color=discord.Color.blurple())
        if before.timed_out_until != after.timed_out_until:
            await log_event(self.bot, after.guild, "member_log_channel_id", "Member timeout updated", description=f"User: {after.mention} ({after.id})\nBefore: {before.timed_out_until or 'None'}\nAfter: {after.timed_out_until or 'None'}", color=discord.Color.orange())

    @commands.Cog.listener()
    async def on_user_update(self, before: discord.User, after: discord.User) -> None:
        if before.name == after.name and before.global_name == after.global_name:
            return
        for guild in self.bot.guilds:
            member = guild.get_member(after.id)
            if member is None:
                continue
            await log_event(self.bot, guild, "member_log_channel_id", "User profile updated", description=f"User: {member.mention} ({member.id})\nUsername: {before.name} -> {after.name}\nGlobal name: {before.global_name or 'None'} -> {after.global_name or 'None'}\nTimezone: Unknown (Discord does not expose a user timezone via the API)", color=discord.Color.blurple())

    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState) -> None:
        if before.channel == after.channel and before.mute == after.mute and before.deaf == after.deaf and before.self_mute == after.self_mute and before.self_deaf == after.self_deaf:
            return
        description = (
            f"User: {member.mention} ({member.id})\n"
            f"Before: {before.channel.mention if before.channel else 'No voice channel'}\n"
            f"After: {after.channel.mention if after.channel else 'No voice channel'}\n"
            f"Mute: {before.mute} -> {after.mute}\n"
            f"Deaf: {before.deaf} -> {after.deaf}\n"
            f"Self mute: {before.self_mute} -> {after.self_mute}\n"
            f"Self deaf: {before.self_deaf} -> {after.self_deaf}\n"
            f"Timezone: Unknown (Discord does not expose a user timezone via the API)"
        )
        await log_event(self.bot, member.guild, "voice_log_channel_id", "Voice state updated", description=description, color=discord.Color.blue())

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        actor = await audit_log_actor(channel.guild, discord.AuditLogAction.channel_create, channel.id)
        await log_event(self.bot, channel.guild, "guild_log_channel_id", "Channel created", description=f"Channel: {channel.mention if isinstance(channel, discord.abc.GuildChannel) else channel.name}\nType: {channel.type}\nCreated by: {actor}", color=discord.Color.green())

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        actor = await audit_log_actor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
        await log_event(self.bot, channel.guild, "guild_log_channel_id", "Channel deleted", description=f"Channel: #{channel.name}\nType: {channel.type}\nDeleted by: {actor}", color=discord.Color.orange())

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        if before.name == after.name and before.position == after.position:
            return
        actor = await audit_log_actor(after.guild, discord.AuditLogAction.channel_update, after.id)
        await log_event(self.bot, after.guild, "guild_log_channel_id", "Channel updated", description=f"Channel: #{before.name} -> #{after.name}\nType: {after.type}\nPosition: {before.position} -> {after.position}\nUpdated by: {actor}", color=discord.Color.blurple())

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role) -> None:
        actor = await audit_log_actor(role.guild, discord.AuditLogAction.role_create, role.id)
        await log_event(self.bot, role.guild, "role_log_channel_id", "Role created", description=f"Role: {role.mention}\nName: {role.name}\nColor: {role.color}\nPermissions: {role.permissions.value}\nCreated by: {actor}", color=discord.Color.green())

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        actor = await audit_log_actor(role.guild, discord.AuditLogAction.role_delete, role.id)
        await log_event(self.bot, role.guild, "role_log_channel_id", "Role deleted", description=f"Role: {role.name}\nColor: {role.color}\nPermissions: {role.permissions.value}\nDeleted by: {actor}", color=discord.Color.orange())

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.name == after.name and before.color == after.color and before.permissions == after.permissions:
            return
        actor = await audit_log_actor(after.guild, discord.AuditLogAction.role_update, after.id)
        await log_event(self.bot, after.guild, "role_log_channel_id", "Role updated", description=f"Role: {after.mention}\nBefore: {before.name} | {before.color} | {before.permissions.value}\nAfter: {after.name} | {after.color} | {after.permissions.value}\nUpdated by: {actor}", color=discord.Color.blurple())

    @commands.Cog.listener()
    async def on_invite_create(self, invite: discord.Invite) -> None:
        creator = invite.inviter or invite.guild.owner if invite.guild else None
        await log_event(self.bot, invite.guild, "invite_log_channel_id", "Invite created", description=f"Code: {invite.code}\nChannel: {invite.channel.mention if invite.channel else 'Unknown'}\nCreated by: {creator.mention if creator else 'Unknown'}\nCreator ID: {creator.id if creator else 'Unknown'}\nMax age: {invite.max_age}s\nMax uses: {invite.max_uses}\nTemporary: {invite.temporary}", color=discord.Color.green())

    @commands.Cog.listener()
    async def on_invite_delete(self, invite: discord.Invite) -> None:
        await log_event(self.bot, invite.guild, "invite_log_channel_id", "Invite deleted", description=f"Code: {invite.code}\nChannel: {invite.channel.mention if invite.channel else 'Unknown'}\nTemporary: {invite.temporary}\nUses: {invite.uses}", color=discord.Color.orange())

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message) -> None:
        if message.guild and not message.author.bot:
            attachments = ", ".join(item.url for item in message.attachments) if message.attachments else "None"
            await log_event(self.bot, message.guild, "message_log_channel_id", "Message deleted", description=f"User: {message.author.mention} ({message.author.id})\nChannel: {message.channel.mention}\nMessage ID: {message.id}\nContent: {message.content or '[no text]'}\nAttachments: {attachments}\nJump URL: {message.jump_url if hasattr(message, 'jump_url') else 'Unavailable'}")

    @commands.Cog.listener()
    async def on_bulk_message_delete(self, messages: list[discord.Message]) -> None:
        if not messages or messages[0].guild is None:
            return
        guild = messages[0].guild
        channel = messages[0].channel
        authors = sorted({message.author.id for message in messages if not message.author.bot})
        await log_event(self.bot, guild, "message_log_channel_id", "Bulk messages deleted", description=f"Count: {len(messages)}\nChannel: {channel.mention}\nAuthor IDs: {', '.join(str(author_id) for author_id in authors) if authors else 'No non-bot authors'}")

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if before.guild and not before.author.bot and before.content != after.content:
            await log_event(self.bot, before.guild, "message_log_channel_id", "Message edited", description=f"User: {before.author.mention} ({before.author.id})\nChannel: {before.channel.mention}\nMessage ID: {before.id}\nBefore: {before.content or '[no text]'}\nAfter: {after.content or '[no text]'}\nJump URL: {after.jump_url if hasattr(after, 'jump_url') else 'Unavailable'}")

    async def _panel(self, interaction: discord.Interaction, esn: bool) -> None:
        assert interaction.guild is not None and isinstance(interaction.channel, discord.TextChannel)
        title = "ESN PANEL" if esn else "ESN GUARDIAN CONTROL PANEL"
        embed = set_protected_footer(discord.Embed(title=title, color=discord.Color.blurple()))
        message = await interaction.channel.send(embed=embed, view=ControlPanel(self.bot, esn=esn))
        await self.bot.database.execute("INSERT OR REPLACE INTO panel_messages (guild_id, panel_type, channel_id, message_id) VALUES (?, ?, ?, ?)", (interaction.guild.id, "esnpanel" if esn else "panel", message.channel.id, message.id))
        await respond(interaction, "Panel posted.")

    async def _bedrock_status(self) -> str:
        try:
            fields = await self._bedrock_status_fields()
            return f"Online: yes\nPlayers: {fields[4]}/{fields[5]}\nMOTD: {fields[1]}\n{SMP_INFO}"
        except (asyncio.TimeoutError, OSError, ValueError):
            return f"Online: unavailable\nThe Bedrock server did not respond to a status query.\n{SMP_INFO}"

    async def _bedrock_status_fields(self) -> list[str]:
        response = await self._bedrock_ping("esnsmp.ggwp.cc", 17058)
        return self._parse_bedrock_pong(response)

    @tasks.loop(minutes=3)
    async def smp_status_monitor(self) -> None:
        try:
            fields = await self._bedrock_status_fields()
            is_online = True
        except (asyncio.TimeoutError, OSError, ValueError):
            fields = None
            is_online = False

        if self._smp_online is None:
            self._smp_online = is_online
            LOG.info("Initial ESN SMP status: %s", "online" if is_online else "unavailable")
            return
        if self._smp_online == is_online:
            return

        self._smp_online = is_online
        message = (
            f"ESN SMP is online. Players: {fields[4]}/{fields[5]}\nMOTD: {fields[1]}\n{SMP_INFO}"
            if is_online and fields is not None
            else f"ESN SMP is currently unavailable. The server did not respond to a status query.\n{SMP_INFO}"
        )
        delivered = 0
        for user_id in await self.bot.database.status_subscriber_ids("smp"):
            user = self.bot.get_user(user_id)
            if user is None:
                try:
                    user = await self.bot.fetch_user(user_id)
                except discord.HTTPException:
                    continue
            if await notify_user(user, message):
                delivered += 1
        LOG.info("ESN SMP status changed to %s; notified %s subscriber(s)", "online" if is_online else "unavailable", delivered)

    @smp_status_monitor.before_loop
    async def before_smp_status_monitor(self) -> None:
        await self.bot.wait_until_ready()

    @app_commands.command(description="Show the ESN Guardian setup and command guide.")
    @app_commands.choices(section=[app_commands.Choice(name=name.title(), value=name) for name in HELP_GUIDES])
    async def help(self, interaction: discord.Interaction, section: app_commands.Choice[str] | None = None) -> None:
        await respond(interaction, HELP_GUIDES[section.value if section else "setup"])

    async def _bedrock_ping(self, host: str, port: int) -> bytes:
        loop = asyncio.get_running_loop()
        response: asyncio.Future[bytes] = loop.create_future()
        timestamp = int(loop.time() * 1000).to_bytes(8, "big")
        client_guid = random.getrandbits(64).to_bytes(8, "big")
        payload = b"\x01" + timestamp + BEDROCK_RAKNET_MAGIC + client_guid
        transport, _ = await loop.create_datagram_endpoint(
            lambda: BedrockStatusProtocol(response, payload),
            remote_addr=(host, port),
        )
        try:
            return await asyncio.wait_for(response, timeout=5)
        finally:
            transport.close()

    @staticmethod
    def _parse_bedrock_pong(response: bytes) -> list[str]:
        if len(response) < 35 or response[17:33] != BEDROCK_RAKNET_MAGIC:
            raise ValueError("Invalid Bedrock status response")
        description_length = int.from_bytes(response[33:35], "big")
        description = response[35:35 + description_length].decode("utf-8")
        fields = description.split(";")
        if len(fields) < 6 or fields[0] != "MCPE":
            raise ValueError("Invalid Bedrock status description")
        return fields

    @app_commands.command(description="Post the persistent ESN Guardian staff control panel.")
    @guild_only()
    @staff_only()
    async def panel(self, interaction: discord.Interaction) -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        await self._panel(interaction, False)


    @app_commands.command(description="Show the configured server settings.")
    @guild_only()
    @staff_only()
    async def config(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        settings = await self.bot.database.setting(interaction.guild_id)
        sections = ["Server settings"]
        sections.extend(f"{key.replace('_', ' ').title()}: {value if value is not None else 'Not set'}"
                        for key, value in dict(settings).items()
                        if key not in {"guild_id", "ad_enabled", "ad_channel_id", "created_at", "updated_at"})
        for table, label in (("security_config", "AutoMod"), ("anti_nuke_config", "Anti-nuke"),
                             ("raid_config", "Raid"), ("verification_config", "Verification"),
                             ("ticket_config", "Tickets")):
            row = await self.bot.database.fetchone(f"SELECT * FROM {table} WHERE guild_id = ?", (interaction.guild_id,))
            sections.append(f"\n{label}")
            sections.extend(f"{key.replace('_', ' ').title()}: {value if value is not None else 'Not set'}"
                            for key, value in dict(row or {}).items() if key != "guild_id")
        text = "\n".join(sections)
        # Split on lines so every setting remains visible, even with long templates.
        while text:
            split = text.rfind("\n", 0, 3900) if len(text) > 3900 else len(text)
            if split <= 0:
                split = 3900
            await respond(interaction, text[:split])
            text = text[split:].lstrip("\n")

    @app_commands.command(description="Set the channel for automatic detailed join notices.")
    @guild_only()
    @guild_owner_only()
    async def welcome(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "welcome_channel_id", channel.id)
        try:
            await channel.send(
                embed=set_protected_footer(discord.Embed(title="Join notices configured", description="Future joins will include the member's user ID, account and server timestamps, names, roles, status, and available membership flags.", color=discord.Color.green(), timestamp=datetime.now(UTC))),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await respond(interaction, "Join notice channel was saved, but I could not post a test entry. Check my View Channel and Send Messages permissions.")
            return
        await respond(interaction, f"Detailed join notices will go to {channel.mention}.")

    @app_commands.command(description="Set the channel for automatic detailed leave notices.")
    @guild_only()
    @guild_owner_only()
    async def goodbye(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "goodbye_channel_id", channel.id)
        try:
            await channel.send(
                embed=set_protected_footer(discord.Embed(title="Leave notices configured", description="Future leaves will include the member's user ID, account and server timestamps, names, roles, status, and available membership flags.", color=discord.Color.orange(), timestamp=datetime.now(UTC))),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await respond(interaction, "Leave notice channel was saved, but I could not post a test entry. Check my View Channel and Send Messages permissions.")
            return
        await respond(interaction, f"Detailed leave notices will go to {channel.mention}.")

    @app_commands.command(description="Configure the automatic member role.")
    @guild_only()
    @staff_only()
    async def autorole(self, interaction: discord.Interaction, role: discord.Role | None = None) -> None:
        if role is not None:
            if not safe_public_role(role, interaction.guild):
                await respond(interaction, "Autoroles must be non-privileged roles below the allowed hierarchy.")
                return
            if not await require_role(interaction, role):
                return
        await self.bot.database.update_setting(interaction.guild_id, "autorole_id", role.id if role else None)
        await respond(interaction, "Autorole updated." if role else "Autorole disabled.")



    @app_commands.command(description="Set a detailed event log channel.")
    @guild_only()
    @staff_only()
    @app_commands.choices(category=[app_commands.Choice(name=name.title(), value=name) for name in LOG_FIELDS])
    async def logs(self, interaction: discord.Interaction, category: app_commands.Choice[str], channel: discord.TextChannel) -> None:
        await self.bot.database.update_setting(interaction.guild_id, LOG_FIELDS[category.value], channel.id)
        try:
            await channel.send(
                embed=set_protected_footer(discord.Embed(title=f"{category.name} logging configured", description="ESN Guardian can write to this log channel.", color=discord.Color.green())),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await respond(interaction, f"{category.name} logs were saved, but I could not post a test entry. Check my View Channel and Send Messages permissions.")
            return
        await respond(interaction, f"{category.name} logs will go to {channel.mention}. Test entry posted.")





async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(CommunityCog(bot))