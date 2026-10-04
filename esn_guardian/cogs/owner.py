from __future__ import annotations

import io

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import command_embed, notify_user, respond, defer_response


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
        self._global_bans: dict[int, str] = {}

    async def cog_load(self) -> None:
        rows = await self.bot.database.fetchall(
            "SELECT user_id, reason FROM global_bans"
        )
        self._global_bans = {
            int(row["user_id"]): str(row["reason"])
            for row in rows
        }

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

    @app_commands.command(description="Create a verified backup of Guardian's SQLite database.")
    @owner_only()
    async def backupdb(self, interaction: discord.Interaction) -> None:
        await defer_response(interaction)
        try:
            path = await self.bot.database.backup("manual")
        except Exception:
            await respond(interaction, "Database backup failed. Check the Raven console for the logged error.")
            return
        await respond(interaction, f"Database backup created: `{path.name if path else 'unavailable'}`.")

    @app_commands.command(description="Show Guardian database backup status.")
    @owner_only()
    async def backupstatus(self, interaction: discord.Interaction) -> None:
        info = self.bot.database.backup_info()
        latest = info["latest"] or "none yet"
        await respond(
            interaction,
            f"Database: `{info['database']}`\nBackups kept: {info['count']}\nLatest backup: `{latest}`",
        )

    @app_commands.command(description="List servers currently served by the bot.")
    @owner_only()
    async def servers(self, interaction: discord.Interaction) -> None:
        total_members = sum(guild.member_count or 0 for guild in self.bot.guilds)
        server_list = "\n".join(
            f"{guild.name} ({guild.id}) - {guild.member_count or 0:,} members"
            for guild in sorted(self.bot.guilds, key=lambda guild: guild.name.casefold())
        ) or "No servers."
        attachment = discord.File(io.BytesIO(server_list.encode("utf-8")), filename="servers.txt")
        if interaction.response.is_done():
            await interaction.followup.send(
                embed=command_embed(f"Servers: {len(self.bot.guilds):,}\nCombined members: {total_members:,}", title="Connected servers"),
                file=attachment,
                ephemeral=True,
            )
        else:
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

        await defer_response(interaction)
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
    async def globalban(
        self,
        interaction: discord.Interaction,
        user_id: str,
        reason: str,
        confidence: app_commands.Range[int, 1, 100] = 100,
        evidence_case_id: int | None = None,
    ) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        if target_id in OWNER_IDS:
            await respond(interaction, "A configured bot owner cannot be globally banned.")
            return

        await defer_response(interaction)
        await self.bot.database.execute(
            "INSERT INTO global_bans (user_id, reason, banned_by_id) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET reason = excluded.reason, banned_by_id = excluded.banned_by_id",
            (target_id, reason, interaction.user.id),
        )
        self._global_bans[target_id] = reason
        banned = 0
        failed = 0
        target = discord.Object(id=target_id)
        for guild in self.bot.guilds:
            outcome = "failed"
            try:
                await guild.ban(target, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
                banned += 1
                outcome = "banned"
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
            v7 = self.bot.get_cog("SecurityV7Cog")
            if v7 is not None and hasattr(v7, "_evidence"):
                try:
                    await v7._evidence(
                        guild.id,
                        interaction.user.id,
                        "GLOBAL_BAN_ENFORCEMENT",
                        target_id,
                        {
                            "reason": reason[:500],
                            "outcome": outcome,
                            "confidence": int(confidence),
                            "evidence_case_id": evidence_case_id,
                            "source_server_id": interaction.guild_id,
                            "source": "bot_owner_globalban",
                        },
                    )
                except Exception:
                    pass
        await self._notify_user_by_id(
            target_id,
            f"You have been globally banned by ESN Guardian.\nReason: {reason}",
        )
        evidence_text = f" • evidence case #{evidence_case_id}" if evidence_case_id is not None else ""
        await respond(
            interaction,
            f"Global ban saved for `{target_id}`. Confidence: {int(confidence)}%{evidence_text}. "
            f"Banned in {banned} server(s); failed in {failed}.",
        )

    @app_commands.command(description="Remove a user from the global-ban list.")
    @owner_only()
    async def globalunban(self, interaction: discord.Interaction, user_id: str) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        await defer_response(interaction)
        await self.bot.database.execute("DELETE FROM global_bans WHERE user_id = ?", (target_id,))
        self._global_bans.pop(target_id, None)
        unbanned = 0
        failed = 0
        target = discord.Object(id=target_id)
        for guild in self.bot.guilds:
            outcome = "not_banned"
            try:
                await guild.unban(target, reason="ESN Guardian global ban removed")
                unbanned += 1
                outcome = "unbanned"
            except discord.NotFound:
                outcome = "not_banned"
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
                outcome = "failed"
            v7 = self.bot.get_cog("SecurityV7Cog")
            if v7 is not None and hasattr(v7, "_evidence"):
                try:
                    await v7._evidence(
                        guild.id,
                        interaction.user.id,
                        "GLOBAL_BAN_REMOVAL",
                        target_id,
                        {"outcome": outcome, "source": "bot_owner_globalunban"},
                    )
                except Exception:
                    pass
        await self._notify_user_by_id(target_id, "Your ESN Guardian global ban has been removed.")
        await respond(interaction, f"Removed `{target_id}` from the global-ban list. Unbanned in {unbanned} server(s); failed in {failed}.")

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        reason = self._global_bans.get(member.id)
        if reason is None:
            return
        try:
            await member.guild.ban(member, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
        except (discord.Forbidden, discord.HTTPException):
            return

    @app_commands.command(description="Send an announcement to configured system log channels.")
    @owner_only()
    async def broadcast(self, interaction: discord.Interaction, message: str) -> None:
        await defer_response(interaction)
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


    @app_commands.command(description="Block a server from using the bot.")
    @owner_only()
    async def blacklist(self, interaction: discord.Interaction, guild_id: str, reason: str) -> None:
        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(interaction, "Provide a numeric server ID.")
            return
        await self.bot.database.blacklist_guild(target_id, reason)
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
        await self.bot.database.unblacklist_guild(target_id)
        await respond(interaction, f"Removed server `{target_id}` from the blacklist.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OwnerCog(bot))
