from __future__ import annotations

from datetime import timedelta

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import discord_action, guild_only, log_event, notify_user, respond, staff_only


class ModerationCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def _case(self, interaction: discord.Interaction, target: discord.abc.User | None, action: str, reason: str) -> int:
        assert interaction.guild is not None
        return await self.bot.database.create_case(interaction.guild.id, target.id if target else None, interaction.user.id, action, reason, interaction.channel_id)

    async def _log_case(self, interaction: discord.Interaction, case_id: int, target: discord.abc.User | None, action: str, reason: str) -> None:
        assert interaction.guild is not None
        await log_event(self.bot, interaction.guild, "moderation_log_channel_id", f"{action} | Case #{case_id}", description=f"Target: {target.mention if target else 'N/A'}\nModerator: {interaction.user.mention}\nReason: {reason}")
        if target is not None:
            await notify_user(
                target,
                f"Moderation notice from **{interaction.guild.name}** (`{interaction.guild.id}`)\n"
                f"Action: {action}\nCase #{case_id}\nReason: {reason}",
            )

    @app_commands.command(description="Issue a formal warning.")
    @guild_only()
    @staff_only()
    async def warn(self, interaction: discord.Interaction, member: discord.Member, reason: str) -> None:
        case_id = await self._case(interaction, member, "WARN", reason)
        await self.bot.database.execute("INSERT INTO warnings (case_id, guild_id, user_id) VALUES (?, ?, ?)", (case_id, interaction.guild_id, member.id))
        await self._log_case(interaction, case_id, member, "WARN", reason)
        await respond(interaction, f"Warned {member.mention}. Case #{case_id}.")

    @app_commands.command(description="List active warnings for a member.")
    @guild_only()
    @staff_only()
    async def warnings(self, interaction: discord.Interaction, member: discord.Member) -> None:
        rows = await self.bot.database.fetchall("SELECT c.case_id, c.reason, c.created_at FROM warnings w JOIN cases c ON c.case_id = w.case_id WHERE w.guild_id = ? AND w.user_id = ? AND w.active = 1 ORDER BY c.case_id DESC", (interaction.guild_id, member.id))
        text = "\n".join(f"#{row['case_id']} - {row['reason']} ({row['created_at']})" for row in rows) or "No active warnings."
        await respond(interaction, text)

    @app_commands.command(description="Timeout a member.")
    @guild_only()
    @staff_only()
    async def timeout(self, interaction: discord.Interaction, member: discord.Member, minutes: app_commands.Range[int, 1, 40320], reason: str) -> None:
        case_id = await self._case(interaction, member, "TIMEOUT", reason)
        if await discord_action(interaction, member.timeout(timedelta(minutes=minutes), reason=f"Case #{case_id}: {reason}"), f"Timed out {member.mention}. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "TIMEOUT", reason)

    @app_commands.command(description="Remove a member timeout.")
    @guild_only()
    @staff_only()
    async def untimeout(self, interaction: discord.Interaction, member: discord.Member, reason: str = "Timeout removed") -> None:
        case_id = await self._case(interaction, member, "UNTIMEOUT", reason)
        if await discord_action(interaction, member.timeout(None, reason=f"Case #{case_id}: {reason}"), f"Removed timeout for {member.mention}. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "UNTIMEOUT", reason)

    @app_commands.command(description="Kick a member.")
    @guild_only()
    @staff_only()
    async def kick(self, interaction: discord.Interaction, member: discord.Member, reason: str) -> None:
        case_id = await self._case(interaction, member, "KICK", reason)
        if await discord_action(interaction, member.kick(reason=f"Case #{case_id}: {reason}"), f"Kicked {member}. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "KICK", reason)

    @app_commands.command(description="Ban a member.")
    @guild_only()
    @staff_only()
    async def ban(self, interaction: discord.Interaction, member: discord.Member, reason: str, delete_message_days: app_commands.Range[int, 0, 7] = 0) -> None:
        case_id = await self._case(interaction, member, "BAN", reason)
        if await discord_action(interaction, interaction.guild.ban(member, reason=f"Case #{case_id}: {reason}", delete_message_seconds=delete_message_days * 86400), f"Banned {member}. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "BAN", reason)

    @app_commands.command(description="Unban a user by ID.")
    @guild_only()
    @staff_only()
    async def unban(self, interaction: discord.Interaction, user_id: str, reason: str = "Unbanned") -> None:
        try:
            user = await self.bot.fetch_user(int(user_id))
        except (ValueError, discord.HTTPException):
            await respond(interaction, "Provide a valid Discord user ID.")
            return
        case_id = await self._case(interaction, user, "UNBAN", reason)
        if await discord_action(interaction, interaction.guild.unban(user, reason=f"Case #{case_id}: {reason}"), f"Unbanned {user}. Case #{case_id}."):
            await self._log_case(interaction, case_id, user, "UNBAN", reason)

    @app_commands.command(description="Delete recent messages.")
    @guild_only()
    @staff_only()
    async def clear(self, interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]) -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        await interaction.response.defer(ephemeral=True)
        deleted = await interaction.channel.purge(limit=amount)
        case_id = await self._case(interaction, None, "CLEAR", f"Deleted {len(deleted)} messages")
        await self._log_case(interaction, case_id, None, "CLEAR", f"Deleted {len(deleted)} messages in {interaction.channel.mention}")
        await respond(interaction, f"Deleted {len(deleted)} messages. Case #{case_id}.")

    @app_commands.command(description="Set channel slowmode in seconds.")
    @guild_only()
    @staff_only()
    async def slowmode(self, interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 21600]) -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        case_id = await self._case(interaction, None, "SLOWMODE", f"Set to {seconds} seconds")
        if await discord_action(interaction, interaction.channel.edit(slowmode_delay=seconds, reason=f"Case #{case_id}"), f"Slowmode set to {seconds}s. Case #{case_id}."):
            await self._log_case(interaction, case_id, None, "SLOWMODE", f"Set to {seconds} seconds")

    @app_commands.command(description="Show a moderation case.")
    @guild_only()
    @staff_only()
    async def case(self, interaction: discord.Interaction, case_id: int) -> None:
        row = await self.bot.database.fetchone("SELECT * FROM cases WHERE case_id = ? AND guild_id = ?", (case_id, interaction.guild_id))
        if row is None:
            await respond(interaction, "Case not found.")
            return
        await respond(interaction, f"Case #{row['case_id']} | {row['action']}\nTarget: <@{row['target_id']}>\nModerator: <@{row['moderator_id']}>\nReason: {row['reason']}\nAt: {row['created_at']}")

    @app_commands.command(description="Show moderation history for a member.")
    @guild_only()
    @staff_only()
    async def history(self, interaction: discord.Interaction, member: discord.Member) -> None:
        rows = await self.bot.database.fetchall("SELECT case_id, action, reason, created_at FROM cases WHERE guild_id = ? AND target_id = ? ORDER BY case_id DESC LIMIT 20", (interaction.guild_id, member.id))
        text = "\n".join(f"#{row['case_id']} {row['action']}: {row['reason']}" for row in rows) or "No cases found."
        await respond(interaction, text)

    @app_commands.command(description="Change a member nickname.")
    @guild_only()
    @staff_only()
    async def nickname(self, interaction: discord.Interaction, member: discord.Member, nickname: str | None, reason: str = "Nickname changed") -> None:
        case_id = await self._case(interaction, member, "NICKNAME", reason)
        if await discord_action(interaction, member.edit(nick=nickname, reason=f"Case #{case_id}: {reason}"), f"Updated nickname. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "NICKNAME", reason)

    @app_commands.command(description="Add or remove a role from a member.")
    @guild_only()
    @staff_only()
    async def role(self, interaction: discord.Interaction, member: discord.Member, role: discord.Role, remove: bool = False, reason: str = "Role updated") -> None:
        case_id = await self._case(interaction, member, "ROLE_REMOVE" if remove else "ROLE_ADD", reason)
        action = member.remove_roles(role, reason=f"Case #{case_id}: {reason}") if remove else member.add_roles(role, reason=f"Case #{case_id}: {reason}")
        if await discord_action(interaction, action, f"Role updated for {member.mention}. Case #{case_id}."):
            await self._log_case(interaction, case_id, member, "ROLE", reason)

    @app_commands.command(description="Add or remove a role for all eligible members.")
    @guild_only()
    @staff_only()
    async def massrole(self, interaction: discord.Interaction, role: discord.Role, remove: bool = False, include_bots: bool = False) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        changed = 0
        for member in interaction.guild.members:
            if (member.bot and not include_bots) or role >= interaction.guild.me.top_role:
                continue
            try:
                await (member.remove_roles(role, reason=f"Mass role by {interaction.user}") if remove else member.add_roles(role, reason=f"Mass role by {interaction.user}"))
                changed += 1
            except discord.HTTPException:
                continue
        case_id = await self._case(interaction, None, "MASSROLE", f"{'Removed' if remove else 'Added'} {role.name} for {changed} members")
        await self._log_case(interaction, case_id, None, "MASSROLE", f"{'Removed' if remove else 'Added'} {role.mention} for {changed} members")
        await respond(interaction, f"Updated {changed} members. Case #{case_id}.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ModerationCog(bot))