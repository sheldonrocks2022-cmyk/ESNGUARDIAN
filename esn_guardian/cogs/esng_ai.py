from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import discord
from discord.ext import commands

TRIGGER_RE = re.compile(r"^ESNG(?:\s*[:,-]\s*|\s+|$)", re.IGNORECASE)
STORE_AI_URL = "https://esnoffical.com/store-ai"


def extract_esng_prompt(content: str) -> str | None:
    match = TRIGGER_RE.match(content.strip())
    if match is None:
        return None
    return content.strip()[match.end():].strip()


def _contains(prompt: str, *terms: str) -> bool:
    normalized = prompt.casefold()
    return any(term in normalized for term in terms)


class ESNGuardianAICog(commands.Cog):
    """Local Guardian-aware assistant. It only responds to messages beginning with ESNG."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.cooldowns: dict[tuple[int, int], datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=UTC))

    async def _security_status(self, guild: discord.Guild) -> str:
        await self.bot.database.ensure_guild(guild.id)
        security = await self.bot.database.fetchone("SELECT * FROM security_config WHERE guild_id = ?", (guild.id,))
        antinuke = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (guild.id,))
        raid = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (guild.id,))
        verification = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id = ?", (guild.id,))
        settings = await self.bot.database.setting(guild.id)
        return (
            "**Guardian security status**\n"
            f"AutoMod: {'ON' if security and security['automod_enabled'] else 'OFF'}\n"
            f"Anti-nuke: {'ON' if antinuke and antinuke['enabled'] else 'OFF'}\n"
            f"Raid protection: {'ON' if raid and raid['enabled'] else 'OFF'}\n"
            f"Verification: {'ON' if verification and verification['enabled'] else 'OFF'}\n"
            f"Lockdown: {'ACTIVE' if settings['lockdown_active'] else 'inactive'}"
        )

    async def _answer(self, guild: discord.Guild, prompt: str) -> str:
        p = prompt.casefold().strip()

        if not p or _contains(p, "help", "what can you do", "commands"):
            return (
                "**ESNG AI** is Guardian's built-in assistant.\n"
                "Try: ESNG security status, ESNG anti-nuke, ESNG raid protection, "
                "ESNG verification, ESNG tickets, ESNG moderation, ESNG bot status, "
                "or ESNG store."
            )

        if _contains(p, "security status", "guardian status", "protection status"):
            return await self._security_status(guild)

        if _contains(p, "bot status", "online", "uptime", "latency"):
            uptime = datetime.now(UTC) - self.bot.started_at
            total_seconds = max(int(uptime.total_seconds()), 0)
            days, remainder = divmod(total_seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes, _ = divmod(remainder, 60)
            return (
                "**Guardian bot status**\n"
                f"Online: yes\nLatency: {round(self.bot.latency * 1000)} ms\n"
                f"Uptime: {days}d {hours}h {minutes}m\nServers: {len(self.bot.guilds)}"
            )

        if _contains(p, "anti-nuke", "antinuke", "nuke"):
            return (
                "**Anti-nuke** watches destructive Discord audit-log actions such as channel/role destruction, "
                "dangerous permission escalation, mass moderation activity, webhook abuse, and untrusted bot additions. "
                "Trusted users and the server owner are exempt. The server owner controls it with /antinuke commands."
            )

        if _contains(p, "raid", "join flood", "mass join"):
            return (
                "**Raid protection** watches rapid joins and suspiciously new accounts. "
                "It can quarantine suspicious members and trigger an emergency lockdown when the configured join threshold is exceeded. "
                "Staff configure it with /security raid."
            )

        if _contains(p, "automod", "spam", "phishing", "links", "invite"):
            return (
                "**AutoMod** checks flood spam, repeated messages, mass mentions, caps, blocked words, Discord invites, "
                "strict-link allowlists, and phishing-style links. Dangerous-link checks also apply to staff messages."
            )

        if _contains(p, "verification", "verify"):
            return (
                "**Verification** gives approved members the configured verified role after server checks. "
                "It can enforce minimum account age and safely rejects privileged or unmanageable role configurations."
            )

        if _contains(p, "ticket", "support"):
            return (
                "**Tickets** create private support channels for the member, configured support role, and Guardian. "
                "Use /ticket to open one and /ticket-close inside the ticket when the issue is resolved."
            )

        if _contains(p, "moderation", "mod commands", "ban", "kick", "timeout", "warn"):
            return (
                "**Moderation** includes warnings, timeouts, kicks, bans, unbans, role changes, nickname changes, slowmode, "
                "message clearing, cases, and member history. Guardian checks the caller's Discord permission and role hierarchy before acting."
            )

        if _contains(p, "lockdown", "lock down"):
            return (
                "**Lockdown** blocks @everyone from sending messages across text channels during an incident. "
                "Guardian stores the previous channel send permissions in SQLite and restores them when lockdown is released."
            )

        if _contains(p, "store", "buy", "product", "bundle", "price"):
            return (
                f"For ESN products, bundles, prices, delivery, and verified checkout information, use **ESN Store AI**: {STORE_AI_URL}"
            )

        if _contains(p, "privacy", "data", "database"):
            return (
                "Guardian stores server-scoped settings, moderation/security cases, ticket state, and verification state in SQLite. "
                "Bot tokens belong in environment variables and should never be posted in Discord or committed to GitHub."
            )

        return (
            "I don't have a verified Guardian answer for that yet. "
            "Try ESNG help to see what I currently know. I won't invent security settings or commands."
        )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return

        prompt = extract_esng_prompt(message.content)
        if prompt is None:
            return

        key = (message.guild.id, message.author.id)
        now = datetime.now(UTC)
        if now - self.cooldowns[key] < timedelta(seconds=3):
            return
        self.cooldowns[key] = now

        answer = await self._answer(message.guild, prompt[:1000])
        embed = discord.Embed(
            title="ESNG AI",
            description=answer[:4096],
            color=discord.Color(0x0B3D91),
            timestamp=now,
        )
        embed.set_footer(text="Protected by ESN Guardian • Trigger: ESNG")
        try:
            await message.reply(embed=embed, mention_author=False, allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            return


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ESNGuardianAICog(bot))
