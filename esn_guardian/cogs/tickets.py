from __future__ import annotations

import asyncio
import time
from collections import defaultdict

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, respond, staff_only


class TicketsCog(commands.Cog):
    """One open ticket per member, with persistent records and private archives."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.locks = defaultdict(asyncio.Lock)

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        await self.bot.database.execute(
            "UPDATE tickets SET channel_id = NULL WHERE guild_id = ? AND channel_id = ?",
            (channel.guild.id, channel.id),
        )

    @app_commands.command(name="ticket-config", description="Choose the role that can access new support tickets.")
    @guild_only()
    @staff_only()
    @app_commands.checks.has_permissions(manage_roles=True)
    async def configure(self, interaction: discord.Interaction, support_role: discord.Role) -> None:
        if (support_role.guild.id != interaction.guild_id or support_role.is_default()
            or support_role.managed or (interaction.user.id != interaction.guild.owner_id
                                       and support_role >= interaction.user.top_role)):
            await respond(interaction, "Choose an unmanaged support role below your role, other than @everyone.")
            return
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE ticket_config SET support_role_id = ? WHERE guild_id = ?", (support_role.id, interaction.guild_id))
        await respond(interaction, "Support role saved. This applies to new tickets; existing ticket access is unchanged.")

    @app_commands.command(description="Open a private support ticket. One active ticket per member.")
    @guild_only()
    async def ticket(self, interaction: discord.Interaction, subject: app_commands.Range[str, 1, 200]) -> None:
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        async with self.locks[guild.id]:
            await self.bot.database.ensure_guild(guild.id)
            config = await self.bot.database.fetchone("SELECT support_role_id FROM ticket_config WHERE guild_id = ?", (guild.id,))
            support = guild.get_role(config["support_role_id"]) if config["support_role_id"] else None
            if support is None or support.is_default() or support.managed:
                await respond(interaction, "Staff must configure a support role with `/ticket-config` first.")
                return
            previous = await self.bot.database.fetchone("SELECT * FROM tickets WHERE guild_id = ? AND user_id = ?", (guild.id, interaction.user.id))
            if previous and previous["channel_id"]:
                try:
                    await guild.fetch_channel(previous["channel_id"])
                except discord.NotFound:
                    pass
                except discord.HTTPException:
                    await respond(interaction, "I cannot check your existing ticket right now. Try again shortly.")
                    return
                else:
                    await respond(interaction, f"You already have a ticket: <#{previous['channel_id']}>.")
                    return
            if previous and time.time() - previous["opened_at"] < 60:
                await respond(interaction, "Wait one minute between opening tickets.")
                return
            count = await self.bot.database.fetchone("SELECT COUNT(*) AS count FROM tickets WHERE guild_id = ? AND channel_id IS NOT NULL", (guild.id,))
            if count["count"] >= 25:
                await respond(interaction, "The server has 25 open tickets. Staff need to close one first.")
                return
            overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=False),
                interaction.user: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
                support: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
                guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True, read_message_history=True),
            }
            try:
                channel = await guild.create_text_channel(f"ticket-{interaction.user.id}", topic=f"Ticket: {subject}", overwrites=overwrites, reason="Guardian support ticket")
            except discord.HTTPException:
                await respond(interaction, "I could not create the ticket. Check my Manage Channels permission.")
                return
            await self.bot.database.execute("INSERT OR REPLACE INTO tickets (guild_id, user_id, channel_id, opened_at) VALUES (?, ?, ?, ?)", (guild.id, interaction.user.id, channel.id, time.time()))
            await respond(interaction, f"Ticket created: {channel.mention}. Use `/ticket-close` inside it when finished.")

    @app_commands.command(name="ticket-close", description="Close this ticket and retain its private message history.")
    @guild_only()
    async def close_ticket(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        async with self.locks[guild.id]:
            row = await self.bot.database.fetchone("SELECT * FROM tickets WHERE guild_id = ? AND channel_id = ?", (guild.id, interaction.channel_id))
            if row is None:
                await respond(interaction, "Run this inside an active Guardian ticket.")
                return
            config = await self.bot.database.fetchone("SELECT support_role_id FROM ticket_config WHERE guild_id = ?", (guild.id,))
            support_ids = {role.id for role in interaction.user.roles}
            authorized = (interaction.user.id == row["user_id"] or interaction.user.guild_permissions.manage_guild
                          or (config and config["support_role_id"] in support_ids))
            if not authorized:
                await respond(interaction, "Only the ticket opener or support staff can close this ticket.")
                return
            channel = interaction.channel
            # Preserve every existing overwrite and remove the opener's send access.
            overwrites = dict(channel.overwrites)
            opener = next((target for target in overwrites if target.id == row["user_id"] and not isinstance(target, discord.Role)), None)
            if opener is not None:
                overwrite = overwrites[opener]
                overwrite.send_messages = False
                overwrite.send_messages_in_threads = False
                overwrite.create_public_threads = False
                overwrite.create_private_threads = False
                overwrites[opener] = overwrite
            try:
                await channel.edit(name=f"closed-{row['user_id']}", overwrites=overwrites, reason=f"Ticket closed by {interaction.user.id}")
            except discord.HTTPException:
                await respond(interaction, "I could not close this ticket. Its active record has been kept so you can retry.")
                return
            await self.bot.database.execute("UPDATE tickets SET channel_id = NULL WHERE guild_id = ? AND user_id = ?", (guild.id, row["user_id"]))
            await respond(interaction, "Ticket closed. The channel remains private and its message history is preserved.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(TicketsCog(bot))
