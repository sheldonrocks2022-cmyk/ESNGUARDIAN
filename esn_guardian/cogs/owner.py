from __future__ import annotations

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import respond


def owner_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        return interaction.client.settings.owner_id is not None and interaction.user.id == interaction.client.settings.owner_id
    return app_commands.check(predicate)


class OwnerCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(description="Show bot-wide operational statistics.")
    @owner_only()
    async def botstats(self, interaction: discord.Interaction) -> None:
        await respond(interaction, f"Servers: {len(self.bot.guilds)}\nUsers cached: {len(self.bot.users)}\nLatency: {round(self.bot.latency * 1000)}ms\nDatabase: {'online' if self.bot.database.connection else 'offline'}")

    @app_commands.command(description="List servers currently served by the bot.")
    @owner_only()
    async def servers(self, interaction: discord.Interaction) -> None:
        names = "\n".join(f"{guild.name} ({guild.id})" for guild in self.bot.guilds[:50]) or "No servers."
        await respond(interaction, names)

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
        await interaction.followup.send(f"Broadcast delivered to {delivered} configured system channels.", ephemeral=True)

    @app_commands.command(description="Enable or disable maintenance mode notice.")
    @owner_only()
    async def maintenance(self, interaction: discord.Interaction, enabled: bool) -> None:
        await self.bot.database.set_state_enabled("maintenance", enabled)
        await respond(interaction, f"Maintenance mode {'enabled' if enabled else 'disabled'}. Use `/broadcast` to communicate the change.")

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