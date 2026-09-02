from __future__ import annotations

from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, log_event, respond, set_protected_footer, staff_only


class VerificationView(discord.ui.View):
    def __init__(self, bot: commands.Bot) -> None:
        super().__init__(timeout=None)
        self.bot = bot

    @discord.ui.button(label="VERIFY", style=discord.ButtonStyle.success, emoji="✅", custom_id="esn_guardian:verify")
    async def verify(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await respond(interaction, "Verification is available only in a server.")
            return
        config = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id = ?", (interaction.guild.id,))
        if config is None or not config["enabled"]:
            await respond(interaction, "Verification is not enabled here.")
            return
        existing = await self.bot.database.fetchone("SELECT 1 FROM verified_members WHERE guild_id = ? AND user_id = ?", (interaction.guild.id, interaction.user.id))
        if existing:
            await respond(interaction, "You are already verified.")
            return
        age = datetime.now(UTC) - interaction.user.created_at
        if age < timedelta(days=config["min_account_age_days"]):
            await respond(interaction, f"Your account must be at least {config['min_account_age_days']} days old.")
            return
        verified_role = interaction.guild.get_role(config["verified_role_id"]) if config["verified_role_id"] else None
        unverified_role = interaction.guild.get_role(config["unverified_role_id"]) if config["unverified_role_id"] else None
        if verified_role is None:
            await respond(interaction, "Verification is incomplete: ask staff to configure the verified role.")
            return
        try:
            await interaction.user.add_roles(verified_role, reason="ESN Guardian verification")
            if unverified_role and unverified_role in interaction.user.roles:
                await interaction.user.remove_roles(unverified_role, reason="ESN Guardian verification")
        except (discord.Forbidden, discord.HTTPException):
            await respond(interaction, "I could not update your verification roles. Staff need to check my role permissions.")
            return
        await self.bot.database.execute("INSERT OR IGNORE INTO verified_members (guild_id, user_id) VALUES (?, ?)", (interaction.guild.id, interaction.user.id))
        case_id = await self.bot.database.create_case(interaction.guild.id, interaction.user.id, self.bot.user.id if self.bot.user else None, "VERIFY", "Member verified", interaction.channel_id)
        await log_event(self.bot, interaction.guild, "verification_log_channel_id", f"Verified | Case #{case_id}", description=f"Member: {interaction.user.mention} ({interaction.user.id})")
        await respond(interaction, "You are verified. Access has been updated.")


class VerificationCog(commands.Cog):
    verification = app_commands.Group(name="verification", description="Configure member verification.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        self.bot.add_view(VerificationView(self.bot))

    @verification.command(name="setup", description="Post or replace the verification message.")
    @guild_only()
    @staff_only()
    async def setup(self, interaction: discord.Interaction, channel: discord.TextChannel, verified_role: discord.Role, unverified_role: discord.Role | None = None, minimum_account_age_days: app_commands.Range[int, 0, 365] = 0) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        embed = set_protected_footer(discord.Embed(title="ESN Guardian Verification", description="Press VERIFY to complete verification.", color=discord.Color.green()))
        try:
            message = await channel.send(embed=embed, view=VerificationView(self.bot), allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            await respond(interaction, "I could not post in that channel.")
            return
        await self.bot.database.ensure_guild(interaction.guild.id)
        await self.bot.database.execute("UPDATE verification_config SET channel_id=?, message_id=?, verified_role_id=?, unverified_role_id=?, min_account_age_days=? WHERE guild_id=?", (channel.id, message.id, verified_role.id, unverified_role.id if unverified_role else None, minimum_account_age_days, interaction.guild.id))
        await self.bot.database.execute("INSERT OR REPLACE INTO panel_messages (guild_id, panel_type, channel_id, message_id) VALUES (?, 'verification', ?, ?)", (interaction.guild.id, channel.id, message.id))
        await respond(interaction, f"Verification panel posted in {channel.mention}.")

    @verification.command(name="enable", description="Enable verification.")
    @guild_only()
    @staff_only()
    async def enable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.execute("UPDATE verification_config SET enabled=1 WHERE guild_id=?", (interaction.guild_id,))
        await respond(interaction, "Verification enabled.")

    @verification.command(name="disable", description="Disable verification.")
    @guild_only()
    @staff_only()
    async def disable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.execute("UPDATE verification_config SET enabled=0 WHERE guild_id=?", (interaction.guild_id,))
        await respond(interaction, "Verification disabled.")

    @verification.command(name="reset", description="Clear verification records so members can verify again.")
    @guild_only()
    @staff_only()
    async def reset(self, interaction: discord.Interaction, member: discord.Member | None = None) -> None:
        if member:
            await self.bot.database.execute("DELETE FROM verified_members WHERE guild_id=? AND user_id=?", (interaction.guild_id, member.id))
            await respond(interaction, f"Reset verification for {member.mention}.")
        else:
            await self.bot.database.execute("DELETE FROM verified_members WHERE guild_id=?", (interaction.guild_id,))
            await respond(interaction, "Reset verification records for this server.")

    @verification.command(name="status", description="Show verification configuration.")
    @guild_only()
    @staff_only()
    async def status(self, interaction: discord.Interaction) -> None:
        config = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id=?", (interaction.guild_id,))
        assert config is not None
        await respond(interaction, f"Enabled: {'yes' if config['enabled'] else 'no'}\nChannel: <#{config['channel_id']}>\nVerified role: <@&{config['verified_role_id']}>\nMinimum account age: {config['min_account_age_days']} days")

    @app_commands.command(description="Verify yourself using the server verification rules.")
    @guild_only()
    async def verify(self, interaction: discord.Interaction) -> None:
        view = VerificationView(self.bot)
        button = next(child for child in view.children if isinstance(child, discord.ui.Button))
        await button.callback(interaction)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VerificationCog(bot))