from __future__ import annotations

import io

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import notify_user, respond


def owner_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        return (
            interaction.client.settings.owner_id is not None
            and interaction.user.id == interaction.client.settings.owner_id
        )

    return app_commands.check(predicate)


class OwnerCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _notify_user_by_id(self, user_id: int, message: str) -> None:
        user = self.bot.get_user(user_id)

        if user is None:
            try:
                user = await self.bot.fetch_user(user_id)
            except discord.HTTPException:
                return

        await notify_user(user, message)

    # =========================================================
    # BOT STATS
    # =========================================================

    @app_commands.command(
        name="botstats",
        description="Show bot-wide operational statistics."
    )
    async def botstats(self, interaction: discord.Interaction) -> None:
        database_status = (
            "online"
            if self.bot.database.connection
            else "offline"
        )

        await respond(
            interaction,
            f"Servers: {len(self.bot.guilds)}\n"
            f"Users cached: {len(self.bot.users)}\n"
            f"Latency: {round(self.bot.latency * 1000)}ms\n"
            f"Database: {database_status}"
        )

    # =========================================================
    # SERVERS
    # =========================================================

    @app_commands.command(
        description="List servers currently served by the bot."
    )
    @owner_only()
    async def servers(
        self,
        interaction: discord.Interaction
    ) -> None:

        total_members = sum(
            guild.member_count or 0
            for guild in self.bot.guilds
        )

        server_list = "\n".join(
            f"{guild.name} ({guild.id}) - "
            f"{guild.member_count or 0:,} members"
            for guild in sorted(
                self.bot.guilds,
                key=lambda guild: guild.name.casefold()
            )
        ) or "No servers."

        attachment = discord.File(
            io.BytesIO(server_list.encode("utf-8")),
            filename="servers.txt"
        )

        await interaction.response.send_message(
            f"Servers: {len(self.bot.guilds):,}\n"
            f"Combined members: {total_members:,}",
            file=attachment,
            ephemeral=True,
        )

    # =========================================================
    # GLOBAL BAN
    # =========================================================

    @app_commands.command(
        description="Ban a user from every server served by the bot."
    )
    @owner_only()
    async def globalban(
        self,
        interaction: discord.Interaction,
        user_id: str,
        reason: str
    ) -> None:

        try:
            target_id = int(user_id)
        except ValueError:
            await respond(
                interaction,
                "Provide a numeric user ID."
            )
            return

        if target_id == self.bot.settings.owner_id:
            await respond(
                interaction,
                "The configured bot owner cannot be globally banned."
            )
            return

        await interaction.response.defer(ephemeral=True)

        await self.bot.database.execute(
            "INSERT INTO global_bans "
            "(user_id, reason, banned_by_id) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "reason = excluded.reason, "
            "banned_by_id = excluded.banned_by_id",
            (
                target_id,
                reason,
                interaction.user.id
            ),
        )

        banned = 0
        failed = 0
        target = discord.Object(id=target_id)

        for guild in self.bot.guilds:
            try:
                await guild.ban(
                    target,
                    reason=f"ESN Guardian global ban: {reason}",
                    delete_message_seconds=0
                )
                banned += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1

        await self._notify_user_by_id(
            target_id,
            "You have been globally banned by ESN Guardian.\n"
            f"Reason: {reason}",
        )

        await interaction.followup.send(
            f"Global ban saved for `{target_id}`. "
            f"Banned in {banned} server(s); "
            f"failed in {failed}.",
            ephemeral=True,
        )

    # =========================================================
    # GLOBAL UNBAN
    # =========================================================

    @app_commands.command(
        description="Remove a user from the global-ban list."
    )
    @owner_only()
    async def globalunban(
        self,
        interaction: discord.Interaction,
        user_id: str
    ) -> None:

        try:
            target_id = int(user_id)
        except ValueError:
            await respond(
                interaction,
                "Provide a numeric user ID."
            )
            return

        await interaction.response.defer(ephemeral=True)

        await self.bot.database.execute(
            "DELETE FROM global_bans WHERE user_id = ?",
            (target_id,)
        )

        unbanned = 0
        failed = 0
        target = discord.Object(id=target_id)

        for guild in self.bot.guilds:
            try:
                await guild.unban(
                    target,
                    reason="ESN Guardian global ban removed"
                )
                unbanned += 1
            except discord.NotFound:
                continue
            except (discord.Forbidden, discord.HTTPException):
                failed += 1

        await self._notify_user_by_id(
            target_id,
            "Your ESN Guardian global ban has been removed."
        )

        await interaction.followup.send(
            f"Removed `{target_id}` from the global-ban list. "
            f"Unbanned in {unbanned} server(s); "
            f"failed in {failed}.",
            ephemeral=True,
        )

    # =========================================================
    # GLOBAL BAN JOIN CHECK
    # =========================================================

    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member
    ) -> None:

        reason = await self.bot.database.global_ban_reason(
            member.id
        )

        if reason is None:
            return

        try:
            await member.guild.ban(
                member,
                reason=f"ESN Guardian global ban: {reason}",
                delete_message_seconds=0
            )
        except (discord.Forbidden, discord.HTTPException):
            return

    # =========================================================
    # BROADCAST
    # =========================================================

    @app_commands.command(
        description="Send an announcement to configured system log channels."
    )
    @owner_only()
    async def broadcast(
        self,
        interaction: discord.Interaction,
        message: str
    ) -> None:

        await interaction.response.defer(ephemeral=True)

        delivered = 0

        for guild in self.bot.guilds:
            settings = await self.bot.database.setting(
                guild.id
            )

            channel = (
                guild.get_channel(
                    settings["system_log_channel_id"]
                )
                if settings["system_log_channel_id"]
                else None
            )

            if isinstance(channel, discord.TextChannel):
                try:
                    await channel.send(
                        message,
                        allowed_mentions=discord.AllowedMentions.none()
                    )
                    delivered += 1
                except discord.HTTPException:
                    continue

        await interaction.followup.send(
            f"Broadcast delivered to {delivered} "
            f"configured system channels.",
            ephemeral=True,
        )

    # =========================================================
    # MAINTENANCE
    # =========================================================

    @app_commands.command(
        description="Enable or disable maintenance mode notice."
    )
    @owner_only()
    async def maintenance(
        self,
        interaction: discord.Interaction,
        enabled: bool
    ) -> None:

        await self.bot.database.set_state_enabled(
            "maintenance",
            enabled
        )

        await respond(
            interaction,
            f"Maintenance mode "
            f"{'enabled' if enabled else 'disabled'}. "
            "Use `/broadcast` to communicate the change."
        )

    # =========================================================
    # SERVER BLACKLIST
    # =========================================================

    @app_commands.command(
        description="Block a server from using the bot."
    )
    @owner_only()
    async def blacklist(
        self,
        interaction: discord.Interaction,
        guild_id: str,
        reason: str
    ) -> None:

        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(
                interaction,
                "Provide a numeric server ID."
            )
            return

        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guild_blacklist "
            "(guild_id, reason) VALUES (?, ?)",
            (target_id, reason)
        )

        guild = self.bot.get_guild(target_id)

        if guild is not None:
            if guild.owner is not None:
                await notify_user(
                    guild.owner,
                    f"ESN Guardian has blacklisted "
                    f"**{guild.name}** (`{guild.id}`) "
                    "and will now leave the server.\n"
                    f"Reason: {reason}",
                )

            await guild.leave()

        await respond(
            interaction,
            f"Blacklisted server `{target_id}`."
        )

    # =========================================================
    # SERVER UNBLACKLIST
    # =========================================================

    @app_commands.command(
        description="Remove a server from the bot blacklist."
    )
    @owner_only()
    async def unblacklist(
        self,
        interaction: discord.Interaction,
        guild_id: str
    ) -> None:

        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(
                interaction,
                "Provide a numeric server ID."
            )
            return

        await self.bot.database.execute(
            "DELETE FROM guild_blacklist WHERE guild_id = ?",
            (target_id,)
        )

        await respond(
            interaction,
            f"Removed server `{target_id}` from the blacklist."
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OwnerCog(bot))
