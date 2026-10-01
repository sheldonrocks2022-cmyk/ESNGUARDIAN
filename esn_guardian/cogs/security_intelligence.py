from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import discord
from discord.ext import commands, tasks

from esn_guardian.cogs.common import log_event

LOG = logging.getLogger("esn_guardian.intelligence")

CRITICAL_PERMISSION_NAMES = (
    "view_audit_log",
    "manage_messages",
    "moderate_members",
    "kick_members",
    "ban_members",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
)

CASE_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("GUARDIAN_TAMPER", 10),
    ("ANTINUKE_", 9),
    ("EXTERNAL_APP_", 9),
    ("UNAPPROVED_BOT_", 9),
    ("AUTO_ROLLBACK_FAILED", 9),
    ("CREDENTIAL_LEAK", 8),
    ("WEBHOOK", 8),
    ("INTEGRATION", 8),
    ("ROLE_DELETE", 8),
    ("CHANNEL_DELETE", 8),
    ("ROLE_PERMISSION", 8),
    ("LOCKDOWN", 7),
    ("SUSPICIOUS_JOIN", 5),
    ("QUARANTINE", 5),
    ("AUTOMOD_", 3),
)

CONTAINMENT_PREFIXES = (
    "ANTINUKE_",
    "EXTERNAL_APP_",
    "UNAPPROVED_BOT_",
    "GUARDIAN_TAMPER",
    "AUTO_ROLLBACK_FAILED",
    "CREDENTIAL_LEAK",
    "WEBHOOK",
    "INTEGRATION",
    "ROLE_DELETE",
    "CHANNEL_DELETE",
    "ROLE_PERMISSION",
)


def case_weight(action: str) -> int:
    normalized = action.upper()
    for marker, weight in CASE_WEIGHTS:
        if normalized.startswith(marker) or marker in normalized:
            return weight
    return 1


def _case_family(action: str) -> str:
    normalized = action.upper()
    for marker in CONTAINMENT_PREFIXES:
        if normalized.startswith(marker) or marker in normalized:
            return marker
    return normalized.split("_", 1)[0]


def correlation_should_contain(actions: list[str]) -> bool:
    """Require a real multi-signal spike before automatic lockdown."""
    serious = [action for action in actions if case_weight(action) >= 8]
    if len(serious) < 4:
        return False
    families = {_case_family(action) for action in serious}
    return len(families) >= 2 and sum(case_weight(action) for action in serious) >= 32


def risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 18:
        return "ELEVATED"
    if score >= 6:
        return "GUARDED"
    return "LOW"


class SecurityIntelligenceCog(commands.Cog):
    """Correlates Guardian telemetry without replacing the existing protection cogs."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._containment_cooldown: dict[int, datetime] = {}
        self._permission_warning_cooldown: dict[int, datetime] = {}

    async def cog_load(self) -> None:
        self.incident_correlation_loop.start()
        self.security_heartbeat_loop.start()

    async def cog_unload(self) -> None:
        self.incident_correlation_loop.cancel()
        self.security_heartbeat_loop.cancel()

    async def recent_cases(self, guild_id: int, *, minutes: int = 60, limit: int = 25) -> list[Any]:
        minutes = max(1, min(minutes, 10080))
        limit = max(1, min(limit, 100))
        return await self.bot.database.fetchall(
            "SELECT case_id, target_id, moderator_id, action, reason, channel_id, details, created_at "
            "FROM cases WHERE guild_id = ? AND created_at >= datetime('now', ?) "
            "ORDER BY case_id DESC LIMIT ?",
            (guild_id, f"-{minutes} minutes", limit),
        )

    async def explain_case(self, guild_id: int, case_id: int) -> str | None:
        row = await self.bot.database.fetchone(
            "SELECT case_id, target_id, moderator_id, action, reason, channel_id, details, created_at "
            "FROM cases WHERE guild_id = ? AND case_id = ?",
            (guild_id, case_id),
        )
        if row is None:
            return None
        details = ""
        try:
            parsed = json.loads(row["details"] or "{}")
            if isinstance(parsed, dict) and parsed:
                safe_pairs = [f"{key}={value}" for key, value in list(parsed.items())[:6]]
                details = "\nDetails: " + ", ".join(safe_pairs)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        return (
            f"Case #{row['case_id']} — {row['action']}\n"
            f"Time: {row['created_at']} UTC\n"
            f"Target ID: {row['target_id'] or 'N/A'}\n"
            f"Reason: {row['reason']}"
            f"{details}"
        )

    async def snapshot(self, guild: discord.Guild) -> dict[str, Any]:
        await self.bot.database.ensure_guild(guild.id)
        rows_10m = await self.recent_cases(guild.id, minutes=10, limit=100)
        rows_1h = await self.recent_cases(guild.id, minutes=60, limit=100)
        rows_24h = await self.recent_cases(guild.id, minutes=1440, limit=100)

        security = await self.bot.database.fetchone("SELECT * FROM security_config WHERE guild_id = ?", (guild.id,))
        antinuke = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (guild.id,))
        raid = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (guild.id,))
        guardian = await self.bot.database.fetchone("SELECT * FROM guardian_config WHERE guild_id = ?", (guild.id,))
        verification = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id = ?", (guild.id,))
        settings = await self.bot.database.setting(guild.id)
        blocked_apps = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM blocked_external_apps WHERE guild_id = ?",
            (guild.id,),
        )

        bot_member = guild.me
        missing_permissions = [
            permission
            for permission in CRITICAL_PERMISSION_NAMES
            if bot_member is None or not getattr(bot_member.guild_permissions, permission, False)
        ]

        score = sum(case_weight(str(row["action"])) for row in rows_10m)
        score += len(missing_permissions) * 8
        if antinuke is None or not antinuke["enabled"]:
            score += 10
        if guardian is None or not guardian["rollback_enabled"]:
            score += 8
        if guardian is None or not guardian["webhook_guard"]:
            score += 6
        if settings["lockdown_active"]:
            score += 20

        recent_actions = Counter(str(row["action"]) for row in rows_1h)
        return {
            "risk_score": score,
            "risk_level": risk_level(score),
            "cases_10m": len(rows_10m),
            "cases_1h": len(rows_1h),
            "cases_24h": len(rows_24h),
            "top_actions": recent_actions.most_common(5),
            "missing_permissions": missing_permissions,
            "automod": bool(security and security["automod_enabled"]),
            "antinuke": bool(antinuke and antinuke["enabled"]),
            "raid": bool(raid and raid["enabled"]),
            "verification": bool(verification and verification["enabled"]),
            "lockdown": bool(settings["lockdown_active"]),
            "rollback": bool(guardian and guardian["rollback_enabled"]),
            "webhook_guard": bool(guardian and guardian["webhook_guard"]),
            "integration_guard": bool(guardian and guardian["integration_guard"]),
            "credential_guard": bool(guardian and guardian["credential_guard"]),
            "external_app_lock": bool(guardian and guardian["external_app_lock"]),
            "bot_approval": bool(guardian and guardian["bot_approval"]),
            "panic": bool(guardian and guardian["panic_mode"]),
            "blocked_apps": int(blocked_apps["count"]) if blocked_apps else 0,
            "backup": self.bot.database.backup_info(),
        }

    async def recommendations(self, guild: discord.Guild) -> list[str]:
        data = await self.snapshot(guild)
        items: list[str] = []
        if data["missing_permissions"]:
            pretty = ", ".join(name.replace("_", " ") for name in data["missing_permissions"])
            items.append(f"Restore Guardian permissions: {pretty}.")
        if not data["antinuke"]:
            items.append("Enable anti-nuke protection.")
        if not data["rollback"]:
            items.append("Enable automatic rollback.")
        if not data["webhook_guard"]:
            items.append("Enable webhook guard.")
        if not data["integration_guard"]:
            items.append("Enable integration guard.")
        if not data["credential_guard"]:
            items.append("Enable credential-leak guard.")
        if not data["bot_approval"]:
            items.append("Enable bot approval so unknown bots cannot remain in the server.")
        if not data["external_app_lock"]:
            items.append("Enable the external-app lock.")
        if data["cases_10m"] >= 3:
            items.append("Review the newest security cases; activity is elevated right now.")
        if not items:
            items.append("Core Guardian protections are enabled and no immediate configuration gap was detected.")
        return items[:8]

    async def threat_report(self, guild: discord.Guild) -> str:
        data = await self.snapshot(guild)
        top = ", ".join(f"{name} ×{count}" for name, count in data["top_actions"]) or "none"
        missing = ", ".join(name.replace("_", " ") for name in data["missing_permissions"]) or "none"
        return (
            "**Live Guardian threat report**\n"
            f"Risk: {data['risk_level']} ({data['risk_score']} signals)\n"
            f"Security cases: {data['cases_10m']} / 10m • {data['cases_1h']} / 1h • {data['cases_24h']} / 24h\n"
            f"Top recent actions: {top}\n"
            f"Lockdown: {'ACTIVE' if data['lockdown'] else 'inactive'} • PANIC: {'ACTIVE' if data['panic'] else 'inactive'}\n"
            f"Blocked external apps: {data['blocked_apps']}\n"
            f"Missing Guardian permissions: {missing}"
        )

    async def health_report(self, guild: discord.Guild) -> str:
        data = await self.snapshot(guild)
        backup = data["backup"]
        return (
            "**Guardian security health**\n"
            f"AutoMod: {'ON' if data['automod'] else 'OFF'} • Anti-nuke: {'ON' if data['antinuke'] else 'OFF'} • Raid: {'ON' if data['raid'] else 'OFF'}\n"
            f"Rollback: {'ON' if data['rollback'] else 'OFF'} • Webhooks: {'ON' if data['webhook_guard'] else 'OFF'} • Integrations: {'ON' if data['integration_guard'] else 'OFF'}\n"
            f"Credential guard: {'ON' if data['credential_guard'] else 'OFF'} • Bot approval: {'ON' if data['bot_approval'] else 'OFF'} • External apps: {'LOCKED' if data['external_app_lock'] else 'open'}\n"
            f"Backups: {backup.get('count', 0)} • Latest: {backup.get('latest') or 'none'}"
        )

    async def timeline(self, guild_id: int, *, limit: int = 8) -> str:
        rows = await self.recent_cases(guild_id, minutes=1440, limit=limit)
        if not rows:
            return "No Guardian security cases were recorded in the last 24 hours."
        lines = [
            f"#{row['case_id']} • {row['action']} • {row['created_at']} UTC • {str(row['reason'])[:160]}"
            for row in rows
        ]
        return "**Recent Guardian incidents**\n" + "\n".join(lines)

    @tasks.loop(seconds=30)
    async def incident_correlation_loop(self) -> None:
        now = datetime.now(UTC)
        for guild in list(self.bot.guilds):
            try:
                rows = await self.recent_cases(guild.id, minutes=2, limit=50)
                actions = [str(row["action"]) for row in rows]
                if not correlation_should_contain(actions):
                    continue

                last = self._containment_cooldown.get(guild.id)
                if last is not None and now - last < timedelta(minutes=10):
                    continue

                settings = await self.bot.database.setting(guild.id)
                if settings["lockdown_active"]:
                    continue

                security = self.bot.get_cog("SecurityCog")
                if security is None or not hasattr(security, "_lockdown"):
                    continue

                changed = await security._lockdown(
                    guild,
                    "ESN Guardian adaptive containment: correlated high-severity security events",
                )
                if not changed:
                    continue

                self._containment_cooldown[guild.id] = now
                await self.bot.database.create_case(
                    guild.id,
                    None,
                    self.bot.user.id if self.bot.user else None,
                    "ADAPTIVE_CONTAINMENT",
                    "Guardian correlated at least four serious events from multiple security families within two minutes.",
                )
                try:
                    await self.bot.database.backup("adaptive-containment")
                except Exception:
                    LOG.exception("Incident backup failed for guild %s", guild.id)
            except Exception:
                LOG.exception("Guardian incident correlation failed for guild %s", guild.id)

    @incident_correlation_loop.before_loop
    async def before_incident_correlation_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=5)
    async def security_heartbeat_loop(self) -> None:
        now = datetime.now(UTC)
        for guild in list(self.bot.guilds):
            try:
                await self.bot.database.ensure_guild(guild.id)
                bot_member = guild.me
                missing = [
                    permission
                    for permission in CRITICAL_PERMISSION_NAMES
                    if bot_member is None or not getattr(bot_member.guild_permissions, permission, False)
                ]
                if not missing:
                    continue
                last = self._permission_warning_cooldown.get(guild.id)
                if last is not None and now - last < timedelta(hours=1):
                    continue
                self._permission_warning_cooldown[guild.id] = now
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    "Guardian protection degraded",
                    description="Missing permissions: " + ", ".join(name.replace("_", " ") for name in missing),
                    color=discord.Color.orange(),
                )
            except Exception:
                LOG.exception("Guardian security heartbeat failed for guild %s", guild.id)

    @security_heartbeat_loop.before_loop
    async def before_security_heartbeat_loop(self) -> None:
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityIntelligenceCog(bot))
