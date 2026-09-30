from __future__ import annotations

import io

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import command_embed, notify_user, respond


OWNER_IDS = {
    1515077206886453469,
    1392224478175690752,
    1434663490160955407,
}


def owner_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        configured_owner = getattr(getattr(interaction.client, "settings", None), "owner_id", None)
        allowed = set(OWNER_IDS)
        if configured_owner is not None:
            allowed.add(int(configured_owner))
        return interaction.user.id in allowed
    return app_commands.check(predicate)


class OwnerCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _notify_user_by_id(self, user_id: int, message: str) -> bool:
        user = self.bot.get_user(user_id)
        if user is None:
            try:
                user = await self.bot.fetch_user(user_id)
            except discord.HTTPException:
                return False
        return await notify_user(user, message)

    @app_commands.command(description="Show bot-wide operational statistics.")
    @owner_only()
    async def botstats(self, interaction: discord.Interaction) -> None:
        await respond(interaction, f"Servers: {len(self.bot.guilds)}\nUsers cached: {len(self.bot.users)}\nLatency: {round(self.bot.latency * 1000)}ms\nDatabase: {'online' if self.bot.database.connection else 'offline'}")

    @app_commands.command(description="List servers currently served by the bot.")
    @owner_only()
    async def servers(self, interaction: discord.Interaction) -> None:
        total_members = sum(guild.member_count or 0 for guild in self.bot.guilds)
        server_list = "\n".join(
            f"{guild.name} ({guild.id}) - {guild.member_count or 0:,} members"
            for guild in sorted(self.bot.guilds, key=lambda guild: guild.name.casefold())
        ) or "No servers."
        attachment = discord.File(io.BytesIO(server_list.encode("utf-8")), filename="servers.txt")
        await interaction.response.send_message(
            embed=command_embed(f"Servers: {len(self.bot.guilds):,}\nCombined members: {total_members:,}", title="Connected servers"),
            file=attachment,
            ephemeral=True,
        )

    @app_commands.command(description="Refresh slash commands in one server or every connected server.")
    @owner_only()
    async def synccommands(self, interaction: discord.Interaction, guild_id: str | None = None) -> None:
        if guild_id is None:
            guilds = list(self.bot.guilds)
        else:
            try:
                target_id = int(guild_id)
            except ValueError:
                await respond(interaction, "Provide a numeric server ID, or leave it empty to sync every connected server.")
                return
            guild = self.bot.get_guild(target_id)
            if guild is None:
                await respond(interaction, "I am not connected to that server.")
                return
            guilds = [guild]

        await interaction.response.defer(ephemeral=True)
        synced = 0
        failed = 0
        command_count = 0
        for guild in guilds:
            try:
                commands_synced = await self.bot.sync_guild_commands(guild)
            except discord.HTTPException:
                failed += 1
            else:
                synced += 1
                command_count += len(commands_synced)
        scope = f"server `{guild_id}`" if guild_id is not None else "all connected servers"
        await respond(interaction, f"Synced {command_count} command(s) across {synced} {scope}; failed: {failed}.")

    @app_commands.command(description="Ban a user from every server served by the bot.")
    @owner_only()
    async def globalban(self, interaction: discord.Interaction, user_id: str, reason: str) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        if target_id in OWNER_IDS:
            await respond(interaction, "A configured bot owner cannot be globally banned.")
            return

        await interaction.response.defer(ephemeral=True)
        await self.bot.database.execute(
            "INSERT INTO global_bans (user_id, reason, banned_by_id) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET reason = excluded.reason, banned_by_id = excluded.banned_by_id",
            (target_id, reason, interaction.user.id),
        )
        banned = 0
        failed = 0
        target = discord.Object(id=target_id)
        for guild in self.bot.guilds:
            try:
                await guild.ban(target, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
                banned += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
        await self._notify_user_by_id(
            target_id,
            f"You have been globally banned by ESN Guardian.\nReason: {reason}",
        )
        await respond(interaction, f"Global ban saved for `{target_id}`. Banned in {banned} server(s); failed in {failed}.")

    @app_commands.command(description="Remove a user from the global-ban list.")
    @owner_only()
    async def globalunban(self, interaction: discord.Interaction, user_id: str) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        await interaction.response.defer(ephemeral=True)
        await self.bot.database.execute("DELETE FROM global_bans WHERE user_id = ?", (target_id,))
        unbanned = 0
        failed = 0
        target = discord.Object(id=target_id)
        for guild in self.bot.guilds:
            try:
                await guild.unban(target, reason="ESN Guardian global ban removed")
                unbanned += 1
            except discord.NotFound:
                continue
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
        await self._notify_user_by_id(target_id, "Your ESN Guardian global ban has been removed.")
        await respond(interaction, f"Removed `{target_id}` from the global-ban list. Unbanned in {unbanned} server(s); failed in {failed}.")

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        reason = await self.bot.database.global_ban_reason(member.id)
        if reason is None:
            return
        try:
            await member.guild.ban(member, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
        except (discord.Forbidden, discord.HTTPException):
            return

    @app_commands.command(description="Send an announcement to configured system log channels.")
    @owner_only()
    async def broadcast(self, interaction: discord.Interaction, message: str) -> None:
        await interaction.response.defer(ephemeral=True)
        delivered = 0
        for guild in self.bot.guilds:
            settings = await self.bot.database.setting(guild.id)
            channel = guild.get_channel(settings["system_log_channel_id"]) if settings["system_log_channel_id"] else None
            if isinstance(channel, discord.TextChannel):
                try:
                    await channel.send(message, allowed_mentions=discord.AllowedMentions.none())
                    delivered += 1
                except discord.HTTPException:
                    continue
        await respond(interaction, f"Broadcast delivered to {delivered} configured system channels.")

    @app_commands.command(description="Enable or disable maintenance mode notice.")
    @owner_only()
    async def maintenance(self, interaction: discord.Interaction, enabled: bool) -> None:
        await self.bot.database.set_state_enabled("maintenance", enabled)
        notification = (
            "ESN Guardian maintenance has started. Normal server commands are temporarily unavailable."
            if enabled
            else "ESN Guardian maintenance has ended. Normal server commands are available again."
        )
        delivered = 0
        for user_id in await self.bot.database.status_subscriber_ids("bot"):
            if user_id == interaction.user.id:
                continue
            if await self._notify_user_by_id(user_id, notification):
                delivered += 1
        await respond(interaction, f"Maintenance mode {'enabled' if enabled else 'disabled'}. Notified {delivered} bot-status subscriber(s). Use `/broadcast` to communicate the change in servers.")

    @app_commands.command(description="Send a direct status update to subscribers.")
    @owner_only()
    @app_commands.choices(topic=[
        app_commands.Choice(name="ESN SMP", value="smp"),
        app_commands.Choice(name="ESN Guardian", value="bot"),
    ])
    async def statusupdate(self, interaction: discord.Interaction, topic: app_commands.Choice[str], message: str) -> None:
        await interaction.response.defer(ephemeral=True)
        delivered = 0
        for user_id in await self.bot.database.status_subscriber_ids(topic.value):
            if await self._notify_user_by_id(user_id, f"{topic.name} status update:\n{message}"):
                delivered += 1
        await respond(interaction, f"Delivered the {topic.name} update to {delivered} subscriber(s).")

    @app_commands.command(description="Block a server from using the bot.")
    @owner_only()
    async def blacklist(self, interaction: discord.Interaction, guild_id: str, reason: str) -> None:
        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(interaction, "Provide a numeric server ID.")
            return
        await self.bot.database.execute("INSERT OR REPLACE INTO guild_blacklist (guild_id, reason) VALUES (?, ?)", (target_id, reason))
        guild = self.bot.get_guild(target_id)
        if guild is not None:
            if guild.owner is not None:
                await notify_user(
                    guild.owner,
                    f"ESN Guardian has blacklisted **{guild.name}** (`{guild.id}`) and will now leave the server.\nReason: {reason}",
                )
            await guild.leave()
        await respond(interaction, f"Blacklisted server `{target_id}`.")

    @app_commands.command(description="Remove a server from the bot blacklist.")
    @owner_only()
    async def unblacklist(self, interaction: discord.Interaction, guild_id: str) -> None:
        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(interaction, "Provide a numeric server ID.")
            return
        await self.bot.database.execute("DELETE FROM guild_blacklist WHERE guild_id = ?", (target_id,))
        await respond(interaction, f"Removed server `{target_id}` from the blacklist.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OwnerCog(bot))
