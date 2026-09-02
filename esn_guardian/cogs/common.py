from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
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


def guild_owner_only() -> app_commands.check:
    async def predicate(interaction: discord.Interaction) -> bool:
        return interaction.guild is not None and interaction.user.id == interaction.guild.owner_id
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


def format_discord_timestamp(value: datetime | None) -> str:
    return discord.utils.format_dt(value, style="F") if value else "Unknown"


def format_member_details(member: discord.abc.User | discord.Member) -> str:
    if not isinstance(member, discord.Member):
        return (
            f"User: {member.mention if hasattr(member, 'mention') else member.name} ({member.id})\n"
            f"Username: {getattr(member, 'name', 'Unknown')}\n"
            f"Global name: {getattr(member, 'global_name', 'None') or 'None'}\n"
            f"Timezone: Unknown (Discord does not expose a user timezone via the API)\n"
            f"Account created: {format_discord_timestamp(getattr(member, 'created_at', None))}"
        )

    status = str(member.status).title() if member.status is not None else "Unknown"
    flags = []
    if member.bot:
        flags.append("Bot")
    if member.premium_since is not None:
        flags.append("Server booster")
    if member.timed_out_until is not None:
        flags.append(f"Timed out until {format_discord_timestamp(member.timed_out_until)}")
    if member.pending:
        flags.append("Pending member")
    roles = ", ".join(role.mention for role in reversed(member.roles) if role.name != "@everyone") or "No roles"
    return (
        f"User: {member.mention} ({member.id})\n"
        f"Username: {member.name}\n"
        f"Global name: {member.global_name or 'None'}\n"
        f"Display name: {member.display_name}\n"
        f"Nickname: {member.nick or 'None'}\n"
        f"Bot account: {'Yes' if member.bot else 'No'}\n"
        f"Status: {status}\n"
        f"Timezone: Unknown (Discord does not expose a user timezone via the API)\n"
        f"Account created: {format_discord_timestamp(member.created_at)}\n"
        f"Joined server: {format_discord_timestamp(member.joined_at)}\n"
        f"Top role: {member.top_role.mention if member.top_role else 'None'}\n"
        f"Roles: {roles}\n"
        f"Flags: {' | '.join(flags) if flags else 'None'}"
    )


def render_member_template(template: str, member: discord.Member, *, guild: discord.Guild | None = None, event: str = "event") -> str:
    guild = guild or member.guild
    role_count = str(max(len(member.roles) - 1, 0))
    values = {
        "{user}": member.mention,
        "{member}": member.mention,
        "{user_id}": str(member.id),
        "{username}": member.name,
        "{global_name}": member.global_name or member.name,
        "{display_name}": member.display_name,
        "{nickname}": member.nick or "None",
        "{guild}": guild.name,
        "{server}": guild.name,
        "{guild_id}": str(guild.id),
        "{member_count}": str(guild.member_count),
        "{account_created}": format_discord_timestamp(member.created_at),
        "{joined_server}": format_discord_timestamp(member.joined_at),
        "{timezone}": "Unknown (Discord does not expose a user timezone via the API)",
        "{status}": str(member.status).title() if member.status is not None else "Unknown",
        "{role_count}": role_count,
        "{top_role}": member.top_role.mention if member.top_role else "None",
        "{event}": event,
    }
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(key, str(value))
    return rendered


async def audit_log_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> str:
    await asyncio.sleep(1)
    try:
        async for entry in guild.audit_logs(action=action, limit=5, after=datetime.now(UTC) - timedelta(minutes=1)):
            if getattr(entry.target, "id", None) == target_id:
                return f"{entry.user.mention} ({entry.user.id})" if entry.user else "Unknown"
    except (discord.Forbidden, discord.HTTPException):
        return "Unknown (missing View Audit Log permission)"
    return "Unknown"


async def log_event(bot: "GuardianBot", guild: discord.Guild, setting_field: str, title: str, *, description: str, color: discord.Color = discord.Color.blurple()) -> None:
    settings = await bot.database.setting(guild.id)
    channel_id = settings[setting_field]
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if not isinstance(channel, discord.TextChannel):
        return
    embed = discord.Embed(title=title, description=description[:4096], color=OBSIDIAN_BLUE, timestamp=datetime.now(UTC))
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
