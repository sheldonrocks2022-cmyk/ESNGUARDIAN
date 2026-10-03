from __future__ import annotations

import random
import time
from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import (
    guild_only,
    log_event,
    respond,
    safe_public_role,
    set_protected_footer,
    staff_only,
)


def _attempt_store(bot: commands.Bot) -> dict[tuple[int, int], float]:
    store = getattr(bot, "_verification_attempts", None)
    if store is None:
        store = {}
        setattr(bot, "_verification_attempts", store)
    return store


async def _verification_config(bot: commands.Bot, guild_id: int):
    return await bot.database.fetchone(
        "SELECT * FROM verification_config WHERE guild_id = ?",
        (guild_id,),
    )


async def _complete_verification(
    bot: commands.Bot,
    interaction: discord.Interaction,
    config,
) -> None:
    if interaction.guild is None or not isinstance(interaction.user, discord.Member):
        await respond(interaction, "Verification is available only in a server.")
        return

    existing = await bot.database.fetchone(
        "SELECT 1 FROM verified_members WHERE guild_id = ? AND user_id = ?",
        (interaction.guild.id, interaction.user.id),
    )
    if existing:
        await respond(interaction, "You are already verified.")
        return

    age = datetime.now(UTC) - interaction.user.created_at
    minimum_age = int(config["min_account_age_days"] or 0)
    if age < timedelta(days=minimum_age):
        await respond(interaction, f"Your account must be at least {minimum_age} days old.")
        return

    verified_role = (
        interaction.guild.get_role(config["verified_role_id"])
        if config["verified_role_id"]
        else None
    )
    unverified_role = (
        interaction.guild.get_role(config["unverified_role_id"])
        if config["unverified_role_id"]
        else None
    )
    if (
        verified_role is None
        or not safe_public_role(verified_role, interaction.guild)
        or (unverified_role is not None and not safe_public_role(unverified_role, interaction.guild))
        or verified_role == unverified_role
    ):
        await respond(
            interaction,
            "Verification is incomplete: ask staff to configure the verified role.",
        )
        return

    try:
        await interaction.user.add_roles(
            verified_role,
            reason="ESN Guardian verification",
        )
        if unverified_role and unverified_role in interaction.user.roles:
            await interaction.user.remove_roles(
                unverified_role,
                reason="ESN Guardian verification",
            )
    except (discord.Forbidden, discord.HTTPException):
        await respond(
            interaction,
            "I could not update your verification roles. Staff need to check my role permissions.",
        )
        return

    await bot.database.execute(
        "INSERT OR IGNORE INTO verified_members (guild_id, user_id) VALUES (?, ?)",
        (interaction.guild.id, interaction.user.id),
    )
    case_id = await bot.database.create_case(
        interaction.guild.id,
        interaction.user.id,
        bot.user.id if bot.user else None,
        "VERIFY",
        "Member verified",
        interaction.channel_id,
        details={
            "account_age_days": age.days,
            "captcha_enabled": bool(config["captcha_enabled"]),
        },
    )
    await log_event(
        bot,
        interaction.guild,
        "verification_log_channel_id",
        f"Verified | Case #{case_id}",
        description=(
            f"Member: {interaction.user.mention} ({interaction.user.id})\n"
            f"Account age: {age.days} days\n"
            f"Challenge: {'enabled' if config['captcha_enabled'] else 'disabled'}"
        ),
        color=discord.Color.green(),
    )
    await respond(interaction, "You are verified. Access has been updated.")


class VerificationChallengeModal(discord.ui.Modal):
    def __init__(self, bot: commands.Bot, config, code: str) -> None:
        super().__init__(title="ESN Guardian Human Check", timeout=120)
        self.bot = bot
        self.config = config
        self.code = code
        self.answer = discord.ui.TextInput(
            label=f"Type this code: {code}",
            placeholder=code,
            required=True,
            min_length=len(code),
            max_length=len(code),
        )
        self.add_item(self.answer)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await respond(interaction, "Verification is available only in a server.")
            return

        if self.answer.value.strip().upper() != self.code:
            await self.bot.database.create_case(
                interaction.guild.id,
                interaction.user.id,
                self.bot.user.id if self.bot.user else None,
                "VERIFY_CHALLENGE_FAILED",
                "Verification human-check failed",
                interaction.channel_id,
            )
            await respond(interaction, "That verification code was incorrect. Try again.")
            return

        await _complete_verification(self.bot, interaction, self.config)


class VerificationView(discord.ui.View):
    def __init__(self, bot: commands.Bot) -> None:
        super().__init__(timeout=None)
        self.bot = bot

    @discord.ui.button(
        label="VERIFY",
        style=discord.ButtonStyle.success,
        emoji="✅",
        custom_id="esn_guardian:verify",
    )
    async def verify(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await respond(interaction, "Verification is available only in a server.")
            return
        if (
            await self.bot.database.is_guild_blacklisted(interaction.guild.id)
            or await self.bot.database.state_enabled("maintenance")
        ):
            await respond(interaction, "Verification is currently unavailable.")
            return

        config = await _verification_config(self.bot, interaction.guild.id)
        if config is None or not config["enabled"]:
            await respond(interaction, "Verification is not enabled here.")
            return

        existing = await self.bot.database.fetchone(
            "SELECT 1 FROM verified_members WHERE guild_id = ? AND user_id = ?",
            (interaction.guild.id, interaction.user.id),
        )
        if existing:
            await respond(interaction, "You are already verified.")
            return

        cooldown = max(5, int(config["cooldown_seconds"] or 30))
        store = _attempt_store(self.bot)
        key = (interaction.guild.id, interaction.user.id)
        now = time.monotonic()
        previous = store.get(key)
        if previous is not None and now - previous < cooldown:
            remaining = max(1, int(cooldown - (now - previous)))
            await respond(
                interaction,
                f"Please wait {remaining} seconds before trying verification again.",
            )
            return
        store[key] = now

        if len(store) > 10000:
            cutoff = now - 600
            for stale_key, seen_at in list(store.items()):
                if seen_at < cutoff:
                    store.pop(stale_key, None)

        age = datetime.now(UTC) - interaction.user.created_at
        minimum_age = int(config["min_account_age_days"] or 0)
        if age < timedelta(days=minimum_age):
            await respond(
                interaction,
                f"Your account must be at least {minimum_age} days old.",
            )
            return

        if config["captcha_enabled"]:
            code = f"{random.SystemRandom().randrange(10000, 100000)}"
            await interaction.response.send_modal(
                VerificationChallengeModal(self.bot, config, code)
            )
            return

        await _complete_verification(self.bot, interaction, config)


class VerificationCog(commands.Cog):
    verification = app_commands.Group(
        name="verification",
        description="Configure member verification.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        self.bot.add_view(VerificationView(self.bot))

    @verification.command(
        name="setup",
        description="Post or replace the verification message.",
    )
    @guild_only()
    @staff_only()
    async def setup(
        self,
        interaction: discord.Interaction,
        channel: discord.TextChannel,
        verified_role: discord.Role,
        unverified_role: discord.Role | None = None,
        minimum_account_age_days: app_commands.Range[int, 0, 365] = 0,
        captcha_enabled: bool = True,
        cooldown_seconds: app_commands.Range[int, 5, 300] = 30,
    ) -> None:
        assert interaction.guild is not None
        if (
            not safe_public_role(verified_role, interaction.guild)
            or (
                unverified_role is not None
                and not safe_public_role(unverified_role, interaction.guild)
            )
            or verified_role == unverified_role
            or (
                interaction.user.id != interaction.guild.owner_id
                and any(
                    role >= interaction.user.top_role
                    for role in (verified_role, unverified_role)
                    if role is not None
                )
            )
        ):
            await respond(
                interaction,
                "Choose distinct, non-privileged, unmanaged roles below your role and my role.",
            )
            return

        await interaction.response.defer(ephemeral=True)
        embed = set_protected_footer(
            discord.Embed(
                title="ESN Guardian Verification",
                description=(
                    "Press VERIFY to complete verification.\n"
                    + (
                        "A short human-check code is required."
                        if captcha_enabled
                        else "Human-check challenge is disabled for this server."
                    )
                ),
                color=discord.Color.green(),
            )
        )
        try:
            message = await channel.send(
                embed=embed,
                view=VerificationView(self.bot),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except (discord.Forbidden, discord.HTTPException):
            await respond(interaction, "I could not post in that channel.")
            return

        await self.bot.database.ensure_guild(interaction.guild.id)
        await self.bot.database.execute(
            "UPDATE verification_config "
            "SET channel_id=?, message_id=?, verified_role_id=?, unverified_role_id=?, "
            "min_account_age_days=?, captcha_enabled=?, cooldown_seconds=? "
            "WHERE guild_id=?",
            (
                channel.id,
                message.id,
                verified_role.id,
                unverified_role.id if unverified_role else None,
                minimum_account_age_days,
                1 if captcha_enabled else 0,
                cooldown_seconds,
                interaction.guild.id,
            ),
        )
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO panel_messages "
            "(guild_id, panel_type, channel_id, message_id) "
            "VALUES (?, 'verification', ?, ?)",
            (interaction.guild.id, channel.id, message.id),
        )
        await respond(interaction, f"Verification panel posted in {channel.mention}.")

    @verification.command(name="enable", description="Enable verification.")
    @guild_only()
    @staff_only()
    async def enable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.execute(
            "UPDATE verification_config SET enabled=1 WHERE guild_id=?",
            (interaction.guild_id,),
        )
        await respond(interaction, "Verification enabled.")

    @verification.command(name="disable", description="Disable verification.")
    @guild_only()
    @staff_only()
    async def disable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.execute(
            "UPDATE verification_config SET enabled=0 WHERE guild_id=?",
            (interaction.guild_id,),
        )
        await respond(interaction, "Verification disabled.")

    @verification.command(
        name="reset",
        description="Clear verification records so members can verify again.",
    )
    @guild_only()
    @staff_only()
    async def reset(
        self,
        interaction: discord.Interaction,
        member: discord.Member | None = None,
    ) -> None:
        if member:
            await self.bot.database.execute(
                "DELETE FROM verified_members WHERE guild_id=? AND user_id=?",
                (interaction.guild_id, member.id),
            )
            await respond(interaction, f"Reset verification for {member.mention}.")
        else:
            await self.bot.database.execute(
                "DELETE FROM verified_members WHERE guild_id=?",
                (interaction.guild_id,),
            )
            await respond(interaction, "Reset verification records for this server.")

    @verification.command(
        name="status",
        description="Show verification configuration.",
    )
    @guild_only()
    @staff_only()
    async def status(self, interaction: discord.Interaction) -> None:
        config = await self.bot.database.fetchone(
            "SELECT * FROM verification_config WHERE guild_id=?",
            (interaction.guild_id,),
        )
        assert config is not None
        await respond(
            interaction,
            (
                f"Enabled: {'yes' if config['enabled'] else 'no'}\n"
                f"Channel: <#{config['channel_id']}>\n"
                f"Verified role: <@&{config['verified_role_id']}>\n"
                f"Minimum account age: {config['min_account_age_days']} days\n"
                f"Human check: {'enabled' if config['captcha_enabled'] else 'disabled'}\n"
                f"Retry cooldown: {config['cooldown_seconds']} seconds"
            ),
        )

    @app_commands.command(
        description="Verify yourself using the server verification rules."
    )
    @guild_only()
    async def verify(self, interaction: discord.Interaction) -> None:
        view = VerificationView(self.bot)
        button = next(
            child for child in view.children if isinstance(child, discord.ui.Button)
        )
        await button.callback(interaction)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VerificationCog(bot))
