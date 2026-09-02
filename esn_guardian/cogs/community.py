from __future__ import annotations

import asyncio
import random
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, log_event, respond, set_protected_footer, staff_only

SMP_INFO = "**Minecraft Bedrock**\nServer: **ESN SMP**\nIP: `esnsmp.ggwp.cc`\nPort: `17058`\nDiscord: https://discord.gg/huFsDxkZ2g"
LOG_FIELDS = {"moderation": "moderation_log_channel_id", "security": "security_log_channel_id", "member": "member_log_channel_id", "message": "message_log_channel_id", "verification": "verification_log_channel_id", "system": "system_log_channel_id"}
BEDROCK_RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
HELP_GUIDES = {
    "setup": "**ESN Guardian Setup**\n1. Give the bot View Channels, Send Messages, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, Read Message History, and View Audit Log.\n2. Ensure the bot role is above every role it must manage.\n3. Run `/setup`.\n4. Set log routes with `/logs` for moderation, security, member, message, verification, and system events.\n5. Run `/security scan`, configure `/security raid`, then enable `/antinuke setup`.\n6. Configure `/verification setup`, then `/verification enable` if members must verify.\n7. Post staff controls with `/panel` and the community panel with `/esnpanel`.\n\nUse `/help section:<category>` for the full command catalogue.",
    "moderation": "**Moderation Commands**\n`/warn`, `/warnings`, `/timeout`, `/untimeout`, `/kick`, `/ban`, `/unban`\n`/clear`, `/purge`, `/slowmode`, `/nickname`, `/role`, `/massrole`\n`/case`, `/history`, `/lock`, `/unlock`, `/lockdown`, `/unlockdown`\n\nStaff permission is required. Every moderation action creates a case ID and can be sent to the moderation log channel.",
    "security": "**Security Commands**\nAutoMod: `/security automod`, `/security thresholds`, `/security links`, `/security allow-domain`, `/security remove-domain`, `/security add-word`, `/security remove-word`, `/security words`, `/security domains`, `/security check-link`, `/security reset-automod`\nRaid and review: `/security raid`, `/security raid-status`, `/security quarantine`, `/security release`, `/security member`, `/security cases`, `/security scan`, `/security status`, `/security trusted`\nAnti-nuke: `/antinuke setup`, `/antinuke enable`, `/antinuke disable`, `/antinuke status`, `/antinuke trust`, `/antinuke untrust`\n\nUse `/security scan` before enabling anti-nuke. It needs View Audit Log, Ban Members, Manage Channels, and Manage Roles.",
    "verification": "**Verification Commands**\n`/verification setup` posts the persistent VERIFY button and stores its message.\n`/verification enable` and `/verification disable` control access.\n`/verification status` shows roles and account-age settings.\n`/verification reset` clears verification records for one member or the whole server.\n`/verify` lets a member run the same checks without using the button.\n\nPut the verified role below the bot's highest role; configure the unverified role with restricted channel permissions.",
    "community": "**Community And SMP Commands**\nConfiguration: `/config`, `/welcome`, `/goodbye`, `/autorole`, `/logs`, `/panel`, `/esnpanel`, `/health`\nCommunity: `/ticket`, `/suggest`, `/poll`\nESN SMP: `/smp`, `/ip`, `/port`, `/status`, `/players`, `/discord`, `/smpannounce`, `/smpfaq`, `/joinhelp`\n\nSMP host: `esnsmp.ggwp.cc:17058`. `/status` and `/players` perform a live Bedrock UDP query.",
    "ads": "**Opt-In Advertising Commands**\n`/setup-ad` chooses this server's ad channel and cooldown.\n`/ad-on` explicitly opts the server in; `/ad-off` opts it out.\n`/ad-now` and `/smpannounce` send an approved message only to this server's configured opt-in channel.\n`/ad-status`, `/ad-cooldown`, `/ad-network`, `/advertisers`, and `/adstats` show local opt-in settings.\n`/report-ad` logs an advertising concern to staff.\n\nGuardian never sends advertisements to a server that has not opted in.",
    "owner": "**Owner Commands**\n`/botstats`, `/servers`, `/broadcast`, `/maintenance`, `/blacklist`, `/unblacklist`\n\nOnly the Discord user ID configured as `BOT_OWNER_ID` can use these commands. `/maintenance` prevents normal guild commands until disabled. `/blacklist` removes Guardian from the specified guild and blocks future use.",
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
        labels = (("SMP", "smp"), ("Status", "status"), ("Players", "players"), ("Ads", "ads"), ("Security", "security"), ("Rules", "rules"), ("Discord", "discord"), ("Support", "support")) if esn else (("Security", "security"), ("AutoMod", "automod"), ("Verification", "verification"), ("Logs", "logs"), ("Settings", "settings"), ("Lockdown", "lockdown"), ("Statistics", "statistics"), ("Help", "help"))
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
                text = {"security": "Security controls: `/lock`, `/unlock`, `/lockdown`, `/unlockdown`.", "automod": "AutoMod is actively monitoring flood, mention, duplicate, caps, links, and configured blocked words.", "verification": "Configure with `/verification setup`, then `/verification enable`.", "logs": "Set each route with `/logs category:<name> channel:<channel>`.", "settings": "Use `/config` to inspect current server settings.", "ads": "Manage opt-in advertising with `/setup-ad`, `/ad-on`, `/ad-off`, and `/ad-status`.", "statistics": f"Serving {len(self.bot.guilds)} servers.", "rules": "Ask your server staff for the current rules.", "support": "Support: https://discord.gg/huFsDxkZ2g", "help": "Use `/help` for setup instructions and the full command guide."}[action]
                await respond(interaction, text)
        return callback


class CommunityCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        self.bot.add_view(ControlPanel(self.bot))
        self.bot.add_view(ControlPanel(self.bot, esn=True))

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        settings = await self.bot.database.setting(member.guild.id)
        autorole = member.guild.get_role(settings["autorole_id"]) if settings["autorole_id"] else None
        if autorole:
            try:
                await member.add_roles(autorole, reason="ESN Guardian autorole")
            except discord.HTTPException:
                await log_event(self.bot, member.guild, "system_log_channel_id", "Autorole failure", description=f"Could not assign {autorole.mention} to {member.mention}.", color=discord.Color.red())
        channel = member.guild.get_channel(settings["welcome_channel_id"]) if settings["welcome_channel_id"] else None
        if isinstance(channel, discord.TextChannel) and settings["welcome_message"]:
            try:
                await channel.send(settings["welcome_message"].replace("{user}", member.mention).replace("{server}", member.guild.name), allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False))
            except discord.HTTPException:
                pass
        await log_event(self.bot, member.guild, "member_log_channel_id", "Member joined", description=f"User: {member.mention} ({member.id})")

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        settings = await self.bot.database.setting(member.guild.id)
        channel = member.guild.get_channel(settings["goodbye_channel_id"]) if settings["goodbye_channel_id"] else None
        if isinstance(channel, discord.TextChannel) and settings["goodbye_message"]:
            try:
                await channel.send(settings["goodbye_message"].replace("{user}", member.name).replace("{server}", member.guild.name), allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:
                pass

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message) -> None:
        if message.guild and not message.author.bot:
            await log_event(self.bot, message.guild, "message_log_channel_id", "Message deleted", description=f"User: {message.author.mention} ({message.author.id})\nChannel: {message.channel.mention}\nContent: {message.content or '[no text]'}")

    @commands.Cog.listener()
    async def on_bulk_message_delete(self, messages: list[discord.Message]) -> None:
        if not messages or messages[0].guild is None:
            return
        guild = messages[0].guild
        channel = messages[0].channel
        await log_event(self.bot, guild, "message_log_channel_id", "Bulk messages deleted", description=f"Count: {len(messages)}\nChannel: {channel.mention}")

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if before.guild and not before.author.bot and before.content != after.content:
            await log_event(self.bot, before.guild, "message_log_channel_id", "Message edited", description=f"User: {before.author.mention} ({before.author.id})\nChannel: {before.channel.mention}\nBefore: {before.content}\nAfter: {after.content}")

    async def _panel(self, interaction: discord.Interaction, esn: bool) -> None:
        assert interaction.guild is not None and isinstance(interaction.channel, discord.TextChannel)
        title = "ESN PANEL" if esn else "ESN GUARDIAN CONTROL PANEL"
        embed = set_protected_footer(discord.Embed(title=title, color=discord.Color.blurple()))
        message = await interaction.channel.send(embed=embed, view=ControlPanel(self.bot, esn=esn))
        await self.bot.database.execute("INSERT OR REPLACE INTO panel_messages (guild_id, panel_type, channel_id, message_id) VALUES (?, ?, ?, ?)", (interaction.guild.id, "esnpanel" if esn else "panel", message.channel.id, message.id))
        await respond(interaction, "Panel posted.")

    async def _bedrock_status(self) -> str:
        try:
            response = await self._bedrock_ping("esnsmp.ggwp.cc", 17058)
            fields = self._parse_bedrock_pong(response)
            return f"Online: yes\nPlayers: {fields[4]}/{fields[5]}\nMOTD: {fields[1]}\n{SMP_INFO}"
        except (asyncio.TimeoutError, OSError, ValueError):
            return f"Online: unavailable\nThe Bedrock server did not respond to a status query.\n{SMP_INFO}"

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

    @app_commands.command(description="Post the persistent ESN community panel.")
    @guild_only()
    async def esnpanel(self, interaction: discord.Interaction) -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        await self._panel(interaction, True)

    @app_commands.command(description="Initialize ESN Guardian settings for this server.")
    @guild_only()
    @staff_only()
    async def setup(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await respond(interaction, "Server settings initialized. Configure logs, verification, welcome, and roles with their slash commands.")

    @app_commands.command(description="Show the configured server settings.")
    @guild_only()
    @staff_only()
    async def config(self, interaction: discord.Interaction) -> None:
        settings = await self.bot.database.setting(interaction.guild_id)
        await respond(interaction, f"Lockdown: {'active' if settings['lockdown_active'] else 'inactive'}\nWelcome: <#{settings['welcome_channel_id']}>\nAutorole: <@&{settings['autorole_id']}>\nAds: {'enabled' if settings['ad_enabled'] else 'disabled'}")

    @app_commands.command(description="Configure welcome messages.")
    @guild_only()
    @staff_only()
    async def welcome(self, interaction: discord.Interaction, channel: discord.TextChannel, message: str) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "welcome_channel_id", channel.id)
        await self.bot.database.update_setting(interaction.guild_id, "welcome_message", message)
        try:
            await channel.send(
                message.replace("{user}", "a new member").replace("{server}", interaction.guild.name),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await respond(interaction, "Welcome message was saved, but I could not post its preview. Check my View Channel and Send Messages permissions.")
            return
        await respond(interaction, "Welcome message configured and preview posted.")

    @app_commands.command(description="Configure goodbye messages.")
    @guild_only()
    @staff_only()
    async def goodbye(self, interaction: discord.Interaction, channel: discord.TextChannel, message: str) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "goodbye_channel_id", channel.id)
        await self.bot.database.update_setting(interaction.guild_id, "goodbye_message", message)
        try:
            await channel.send(
                message.replace("{user}", "a departing member").replace("{server}", interaction.guild.name),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await respond(interaction, "Goodbye message was saved, but I could not post its preview. Check my View Channel and Send Messages permissions.")
            return
        await respond(interaction, "Goodbye message configured and preview posted.")

    @app_commands.command(description="Configure the automatic member role.")
    @guild_only()
    @staff_only()
    async def autorole(self, interaction: discord.Interaction, role: discord.Role | None = None) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "autorole_id", role.id if role else None)
        await respond(interaction, "Autorole updated." if role else "Autorole disabled.")

    @app_commands.command(description="Create a private support ticket channel.")
    @guild_only()
    async def ticket(self, interaction: discord.Interaction, subject: str) -> None:
        assert interaction.guild is not None and isinstance(interaction.user, discord.Member)
        overwrites = {interaction.guild.default_role: discord.PermissionOverwrite(view_channel=False), interaction.user: discord.PermissionOverwrite(view_channel=True, send_messages=True), interaction.guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True)}
        try:
            channel = await interaction.guild.create_text_channel(f"ticket-{interaction.user.id}", topic=f"Ticket: {subject}", overwrites=overwrites, reason="ESN Guardian support ticket")
        except discord.HTTPException:
            await respond(interaction, "I could not create a ticket channel. Check my Manage Channels permission.")
            return
        await channel.send(f"{interaction.user.mention}\nSubject: {subject}", allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False))
        await respond(interaction, f"Ticket created: {channel.mention}")

    @app_commands.command(description="Submit a suggestion for staff and the community.")
    @guild_only()
    async def suggest(self, interaction: discord.Interaction, suggestion: str) -> None:
        assert isinstance(interaction.channel, discord.TextChannel)
        embed = discord.Embed(title="Suggestion", description=suggestion, color=discord.Color.gold())
        embed.set_author(name=str(interaction.user), icon_url=interaction.user.display_avatar.url)
        set_protected_footer(embed)
        message = await interaction.channel.send(embed=embed)
        await message.add_reaction("👍")
        await message.add_reaction("👎")
        await respond(interaction, "Suggestion posted.")

    @app_commands.command(description="Create a vote with approve and reject reactions.")
    @guild_only()
    @staff_only()
    async def poll(self, interaction: discord.Interaction, question: str) -> None:
        assert isinstance(interaction.channel, discord.TextChannel)
        embed = set_protected_footer(discord.Embed(title="Poll", description=question, color=discord.Color.teal()))
        message = await interaction.channel.send(embed=embed)
        await message.add_reaction("✅")
        await message.add_reaction("❌")
        await respond(interaction, "Poll posted.")

    @app_commands.command(description="Set one of the six log channels.")
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

    @app_commands.command(description="Show ESN SMP connection information.")
    async def smp(self, interaction: discord.Interaction) -> None: await respond(interaction, SMP_INFO)
    @app_commands.command(description="Show the ESN SMP IP.")
    async def ip(self, interaction: discord.Interaction) -> None: await respond(interaction, "`esnsmp.ggwp.cc`")
    @app_commands.command(description="Show the ESN SMP port.")
    async def port(self, interaction: discord.Interaction) -> None: await respond(interaction, "`17058`")
    @app_commands.command(description="Query the live ESN SMP Bedrock status.")
    async def status(self, interaction: discord.Interaction) -> None: await respond(interaction, await self._bedrock_status())
    @app_commands.command(description="Query the live ESN SMP Bedrock player count.")
    async def players(self, interaction: discord.Interaction) -> None: await respond(interaction, await self._bedrock_status())
    @app_commands.command(description="Show the ESN SMP Discord.")
    async def discord(self, interaction: discord.Interaction) -> None: await respond(interaction, "https://discord.gg/huFsDxkZ2g")
    @app_commands.command(description="Show ESN SMP joining help.")
    async def joinhelp(self, interaction: discord.Interaction) -> None: await respond(interaction, "In Minecraft Bedrock, add `esnsmp.ggwp.cc` on port `17058`.")
    @app_commands.command(description="Show ESN SMP frequently asked questions.")
    async def smpfaq(self, interaction: discord.Interaction) -> None:
        await self.joinhelp.callback(self, interaction)

    @app_commands.command(description="Configure this server's opt-in ad channel and cooldown.")
    @guild_only()
    @staff_only()
    async def setup_ad(self, interaction: discord.Interaction, channel: discord.TextChannel, cooldown_minutes: app_commands.Range[int, 5, 10080] = 60) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "ad_channel_id", channel.id)
        await self.bot.database.update_setting(interaction.guild_id, "ad_cooldown_seconds", cooldown_minutes * 60)
        await respond(interaction, "Ad channel and cooldown configured. Use `/ad-on` to opt in.")

    @app_commands.command(description="Opt this server into the ESN ad network.")
    @guild_only()
    @staff_only()
    async def ad_on(self, interaction: discord.Interaction) -> None:
        settings = await self.bot.database.setting(interaction.guild_id)
        if not settings["ad_channel_id"]:
            await respond(interaction, "Configure an ad channel first with `/setup-ad`.")
            return
        await self.bot.database.update_setting(interaction.guild_id, "ad_enabled", 1)
        await respond(interaction, "This server has opted in to the ad network.")

    @app_commands.command(description="Opt this server out of the ESN ad network.")
    @guild_only()
    @staff_only()
    async def ad_off(self, interaction: discord.Interaction) -> None:
        await self.bot.database.update_setting(interaction.guild_id, "ad_enabled", 0)
        await respond(interaction, "This server has opted out of the ad network.")

    @app_commands.command(description="Show this server's ad network configuration.")
    @guild_only()
    @staff_only()
    async def ad_status(self, interaction: discord.Interaction) -> None:
        settings = await self.bot.database.setting(interaction.guild_id)
        await respond(interaction, f"Opt-in: {'yes' if settings['ad_enabled'] else 'no'}\nChannel: <#{settings['ad_channel_id']}>\nCooldown: {settings['ad_cooldown_seconds'] // 60} minutes")
    @app_commands.command(description="Show the configured ad cooldown.")
    @guild_only()
    @staff_only()
    async def ad_cooldown(self, interaction: discord.Interaction) -> None:
        await self.ad_status.callback(self, interaction)

    @app_commands.command(description="Show this server's ad-network status.")
    @guild_only()
    @staff_only()
    async def ad_network(self, interaction: discord.Interaction) -> None:
        await self.ad_status.callback(self, interaction)

    @app_commands.command(description="Show ad-network advertiser information.")
    @guild_only()
    @staff_only()
    async def advertisers(self, interaction: discord.Interaction) -> None:
        await self.ad_status.callback(self, interaction)

    @app_commands.command(description="Show local ad network statistics.")
    @guild_only()
    @staff_only()
    async def adstats(self, interaction: discord.Interaction) -> None:
        await self.ad_status.callback(self, interaction)

    @app_commands.command(description="Send a server-approved ESN SMP announcement to its configured ad channel.")
    @guild_only()
    @staff_only()
    async def smpannounce(self, interaction: discord.Interaction, message: str) -> None:
        settings = await self.bot.database.setting(interaction.guild_id)
        channel = interaction.guild.get_channel(settings["ad_channel_id"]) if settings["ad_channel_id"] else None
        if not settings["ad_enabled"] or not isinstance(channel, discord.TextChannel):
            await respond(interaction, "Ads are not enabled and configured for this server.")
            return
        await channel.send(message, allowed_mentions=discord.AllowedMentions.none())
        await respond(interaction, "Announcement sent.")

    @app_commands.command(description="Send a server-approved ESN SMP announcement now.")
    @guild_only()
    @staff_only()
    async def ad_now(self, interaction: discord.Interaction, message: str) -> None:
        await self.smpannounce.callback(self, interaction, message)

    @app_commands.command(description="Report an ad-network issue to server staff.")
    @guild_only()
    async def report_ad(self, interaction: discord.Interaction, details: str) -> None:
        await log_event(self.bot, interaction.guild, "security_log_channel_id", "Ad report", description=f"Reporter: {interaction.user.mention}\nDetails: {details}")
        await respond(interaction, "Your report was logged for staff.")

    @app_commands.command(description="Show Guardian health and connection status.")
    async def health(self, interaction: discord.Interaction) -> None:
        database_ok = self.bot.database.connection is not None
        uptime = datetime.now(UTC) - self.bot.started_at
        await respond(interaction, f"Bot: online\nDatabase: {'online' if database_ok else 'offline'}\nDiscord latency: {round(self.bot.latency * 1000)}ms\nUptime: {str(uptime).split('.')[0]}\nServers: {len(self.bot.guilds)}\nSecurity, automation, and verification: loaded")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(CommunityCog(bot))