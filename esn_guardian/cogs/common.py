from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import discord
from discord import app_commands

if TYPE_CHECKING:
    from esn_guardian.main import GuardianBot

LOG = logging.getLogger("esn_guardian.cogs")
OBSIDIAN_BLUE = discord.Color(0x0B3D91)
PROTECTED_FOOTER = "Protected by ESN Guardian"


def set_protected_footer(embed: discord.Embed) -> discord.Embed:
    embed.set_footer(text=PROTECTED_FOOTER)
    return embed


def command_embed(content: str, *, title: str = "ESN Guardian") -> discord.Embed:
    embed = discord.Embed(title=title, description=content[:4096], color=OBSIDIAN_BLUE, timestamp=datetime.now(UTC))
    return set_protected_footer(embed)


def guild_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.guild is None:
            return False
        bot = interaction.client
        if await bot.database.is_guild_blacklisted(interaction.guild.id):
            return interaction.user.id == bot.settings.owner_id
        if await bot.database.state_enabled("maintenance"):
            return interaction.user.id == bot.settings.owner_id
        return True
    return app_commands.check(predicate)


def staff_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        return isinstance(interaction.user, discord.Member) and interaction.user.guild_permissions.manage_guild
    return app_commands.check(predicate)


async def respond(interaction: discord.Interaction, content: str, *, ephemeral: bool = True) -> None:
    embed = command_embed(content)
    if interaction.response.is_done():
        await interaction.followup.send(embed=embed, ephemeral=ephemeral)
    else:
        await interaction.response.send_message(embed=embed, ephemeral=ephemeral)


async def notify_user(user: discord.abc.User, content: str) -> bool:
    try:
        await user.send(content, allowed_mentions=discord.AllowedMentions.none())
    except (discord.Forbidden, discord.HTTPException):
        return False
    return True


async def log_event(bot: "GuardianBot", guild: discord.Guild, setting_field: str, title: str, *, description: str, color: discord.Color = discord.Color.blurple()) -> None:
    settings = await bot.database.setting(guild.id)
    channel_id = settings[setting_field]
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if not isinstance(channel, discord.TextChannel):
        return
    embed = discord.Embed(title=title, description=description[:4096], color=color, timestamp=datetime.now(UTC))
    set_protected_footer(embed)
    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except (discord.Forbidden, discord.HTTPException):
        LOG.exception("Could not write %s log for guild %s", setting_field, guild.id)


async def discord_action(interaction: discord.Interaction, operation: object, success: str) -> bool:
    try:
        await operation  # type: ignore[misc]
    except discord.Forbidden:
        await respond(interaction, "I lack permission to perform that action.")
    except discord.HTTPException as error:
        LOG.warning("Discord API action failed: %s", error)
        await respond(interaction, "Discord rejected the action. Please retry shortly.")
    else:
        await respond(interaction, success)
        return True
    return False
