from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, log_event, respond, staff_only

LOG = logging.getLogger("esn_guardian.resilience")

REQUIRED_COGS = (
    "SecurityCog",
    "AdvancedSecurityCog",
    "SecurityIntelligenceCog",
    "SecurityOverwatchCog",
    "SecuritySentinelCog",
)
REQUIRED_PERMISSIONS = (
    "view_audit_log",
    "manage_messages",
    "moderate_members",
    "kick_members",
    "ban_members",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
)


def readiness_score(
    *,
    missing_cogs: int,
    missing_permissions: int,
    disabled_layers: int,
    has_backup: bool,
    has_snapshot: bool,
    integrity_ok: bool,
) -> int:
    score = 100
    score -= min(35, max(0, missing_cogs) * 10)
    score -= min(32, max(0, missing_permissions) * 4)
    score -= min(28, max(0, disabled_layers) * 4)
    if not has_backup:
        score -= 10
    if not has_snapshot:
        score -= 10
    if not integrity_ok:
        score -= 20
    return max(0, min(100, score))


def readiness_grade(score: int) -> str:
    if score >= 90:
        return "READY"
    if score >= 75:
        return "STRONG"
    if score >= 55:
        return "DEGRADED"
    if score >= 30:
        return "WEAK"
    return "CRITICAL"


class SecurityResilienceCog(commands.Cog):
    """Guardian self-health, recovery readiness, and non-destructive security drills."""

    resilience = app_commands.Group(
        name="resilience",
        description="Guardian recovery readiness and self-health checks.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._last_alert: dict[int, datetime] = {}

    async def cog_load(self) -> None:
        await self.bot.database.execute(
            """CREATE TABLE IF NOT EXISTS guardian_resilience_history (
                check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                missing_cogs INTEGER NOT NULL,
                missing_permissions INTEGER NOT NULL,
                disabled_layers INTEGER NOT NULL,
                integrity_ok INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        await self.bot.database.execute(
            """CREATE INDEX IF NOT EXISTS idx_guardian_resilience_history_guild
               ON guardian_resilience_history(guild_id, check_id DESC)"""
        )
        self.resilience_loop.start()

    def cog_unload(self) -> None:
        self.resilience_loop.cancel()

    async def snapshot(self, guild: discord.Guild) -> dict[str, Any]:
        missing_cogs = [name for name in REQUIRED_COGS if self.bot.get_cog(name) is None]

        bot_member = guild.me
        missing_permissions = [
            name
            for name in REQUIRED_PERMISSIONS
            if bot_member is None or not getattr(bot_member.guild_permissions, name, False)
        ]

        await self.bot.database.ensure_guild(guild.id)
        await self.bot.database.execute(
            "INSERT OR IGNORE INTO guardian_config (guild_id) VALUES (?)",
            (guild.id,),
        )

        security = await self.bot.database.fetchone(
            "SELECT automod_enabled FROM security_config WHERE guild_id = ?",
            (guild.id,),
        )
        antinuke = await self.bot.database.fetchone(
            "SELECT enabled FROM anti_nuke_config WHERE guild_id = ?",
            (guild.id,),
        )
        raid = await self.bot.database.fetchone(
            "SELECT enabled FROM raid_config WHERE guild_id = ?",
            (guild.id,),
        )
        guardian = await self.bot.database.fetchone(
            "SELECT external_app_lock, bot_approval, webhook_guard, integration_guard, "
            "credential_guard, rollback_enabled FROM guardian_config WHERE guild_id = ?",
            (guild.id,),
        )

        layers = {
            "automod": bool(security and security["automod_enabled"]),
            "antinuke": bool(antinuke and antinuke["enabled"]),
            "raid": bool(raid and raid["enabled"]),
            "external_app_lock": bool(guardian and guardian["external_app_lock"]),
            "bot_approval": bool(guardian and guardian["bot_approval"]),
            "webhook_guard": bool(guardian and guardian["webhook_guard"]),
            "integration_guard": bool(guardian and guardian["integration_guard"]),
            "credential_guard": bool(guardian and guardian["credential_guard"]),
            "rollback": bool(guardian and guardian["rollback_enabled"]),
        }
        disabled_layers = [name for name, enabled in layers.items() if not enabled]

        backup_info = self.bot.database.backup_info()
        has_backup = int(backup_info.get("count", 0) or 0) > 0
        snapshot_row = await self.bot.database.fetchone(
            "SELECT created_at FROM guardian_snapshots WHERE guild_id = ?",
            (guild.id,),
        )
        has_snapshot = snapshot_row is not None

        integrity_ok = True
        overwatch = self.bot.get_cog("SecurityOverwatchCog")
        if overwatch is not None and hasattr(overwatch, "verify_ledger"):
            try:
                result = await overwatch.verify_ledger(guild.id)
                integrity_ok = bool(result.get("ok"))
            except Exception:
                LOG.exception("Resilience could not verify ledger for guild %s", guild.id)
                integrity_ok = False

        score = readiness_score(
            missing_cogs=len(missing_cogs),
            missing_permissions=len(missing_permissions),
            disabled_layers=len(disabled_layers),
            has_backup=has_backup,
            has_snapshot=has_snapshot,
            integrity_ok=integrity_ok,
        )

        return {
            "score": score,
            "grade": readiness_grade(score),
            "missing_cogs": missing_cogs,
            "missing_permissions": missing_permissions,
            "disabled_layers": disabled_layers,
            "has_backup": has_backup,
            "backup_count": int(backup_info.get("count", 0) or 0),
            "latest_backup": backup_info.get("latest"),
            "has_snapshot": has_snapshot,
            "snapshot_at": snapshot_row["created_at"] if snapshot_row else None,
            "integrity_ok": integrity_ok,
            "layers": layers,
        }

    async def record_snapshot(self, guild: discord.Guild) -> dict[str, Any]:
        data = await self.snapshot(guild)
        await self.bot.database.execute(
            "INSERT INTO guardian_resilience_history "
            "(guild_id, score, grade, missing_cogs, missing_permissions, disabled_layers, integrity_ok) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                guild.id,
                data["score"],
                data["grade"],
                len(data["missing_cogs"]),
                len(data["missing_permissions"]),
                len(data["disabled_layers"]),
                1 if data["integrity_ok"] else 0,
            ),
        )
        return data

    async def status_report(self, guild: discord.Guild) -> str:
        data = await self.snapshot(guild)
        return (
            "**Guardian Resilience**\n"
            f"Readiness: {data['score']}/100 ({data['grade']})\n"
            f"Missing security modules: {', '.join(data['missing_cogs']) if data['missing_cogs'] else 'none'}\n"
            f"Missing permissions: {', '.join(name.replace('_', ' ') for name in data['missing_permissions']) if data['missing_permissions'] else 'none'}\n"
            f"Disabled protection layers: {', '.join(data['disabled_layers']) if data['disabled_layers'] else 'none'}\n"
            f"Tamper-evident ledger: {'OK' if data['integrity_ok'] else 'FAILED'}\n"
            f"Recovery snapshot: {data['snapshot_at'] or 'none'}\n"
            f"Backups: {data['backup_count']} • Latest: {data['latest_backup'] or 'none'}"
        )

    async def drill_report(self, guild: discord.Guild) -> str:
        data = await self.snapshot(guild)
        checks = [
            ("Core security modules loaded", not data["missing_cogs"]),
            ("Critical Discord permissions available", not data["missing_permissions"]),
            ("Protection layers enabled", not data["disabled_layers"]),
            ("Case ledger verifies", data["integrity_ok"]),
            ("Recovery snapshot exists", data["has_snapshot"]),
            ("At least one database backup exists", data["has_backup"]),
        ]
        lines = ["**Guardian non-destructive security drill**"]
        for name, passed in checks:
            lines.append(f"{'PASS' if passed else 'FAIL'} — {name}")
        lines.append(
            "This drill changes nothing in the server. It verifies whether Guardian is prepared to respond and recover."
        )
        return "\n".join(lines)

    async def recovery_plan(self, guild: discord.Guild) -> str:
        data = await self.snapshot(guild)
        steps: list[str] = []

        if data["missing_permissions"]:
            steps.append(
                "Restore Guardian's missing Discord permissions: "
                + ", ".join(name.replace("_", " ") for name in data["missing_permissions"])
                + "."
            )
        if data["missing_cogs"]:
            steps.append(
                "Restart or repair Guardian so these modules load: "
                + ", ".join(data["missing_cogs"])
                + "."
            )
        if data["disabled_layers"]:
            steps.append(
                "Review and re-enable protection layers that should be active: "
                + ", ".join(data["disabled_layers"])
                + "."
            )
        if not data["integrity_ok"]:
            steps.append(
                "Treat the case ledger integrity failure as high priority; preserve current backups and investigate before approving a new baseline."
            )
        if not data["has_snapshot"]:
            steps.append(
                "Create a trusted Guardian recovery snapshot after confirming the current server state is clean."
            )
        if not data["has_backup"]:
            steps.append("Create an immediate Guardian database backup.")
        if not steps:
            steps.append(
                "No readiness gaps are currently detected. Continue monitoring Sentinel, Overwatch, and scheduled backups."
            )

        return "**Guardian recovery readiness plan**\n" + "\n".join(
            f"{index}. {step}" for index, step in enumerate(steps, start=1)
        )

    @tasks.loop(minutes=5)
    async def resilience_loop(self) -> None:
        for guild in list(self.bot.guilds):
            security = self.bot.get_cog("SecurityCog")
            if (
                security is not None
                and hasattr(security, "is_raid_mode_active")
                and security.is_raid_mode_active(guild.id)
            ):
                continue
            try:
                data = await self.record_snapshot(guild)
                if data["score"] >= 55:
                    continue
                now = datetime.now(UTC)
                last = self._last_alert.get(guild.id)
                if last is not None and now - last < timedelta(hours=1):
                    continue
                self._last_alert[guild.id] = now
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    f"Guardian resilience degraded — {data['grade']}",
                    description=(
                        f"Readiness score: {data['score']}/100\n"
                        f"Missing modules: {len(data['missing_cogs'])}\n"
                        f"Missing permissions: {len(data['missing_permissions'])}\n"
                        f"Disabled layers: {len(data['disabled_layers'])}\n"
                        f"Ledger integrity: {'OK' if data['integrity_ok'] else 'FAILED'}"
                    ),
                    color=discord.Color.red() if data["score"] < 30 else discord.Color.orange(),
                )
            except Exception:
                LOG.exception("Guardian resilience check failed for guild %s", guild.id)

    @resilience_loop.before_loop
    async def before_resilience_loop(self) -> None:
        await self.bot.wait_until_ready()

    @resilience.command(name="status", description="Show Guardian recovery readiness and self-health.")
    @guild_only()
    @staff_only()
    async def resilience_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.status_report(interaction.guild))

    @resilience.command(name="drill", description="Run a non-destructive Guardian security readiness drill.")
    @guild_only()
    @staff_only()
    async def resilience_drill(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.drill_report(interaction.guild))

    @resilience.command(name="recovery-plan", description="Generate a recovery readiness plan from live Guardian state.")
    @guild_only()
    @staff_only()
    async def resilience_recovery_plan(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.recovery_plan(interaction.guild))


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityResilienceCog(bot))
