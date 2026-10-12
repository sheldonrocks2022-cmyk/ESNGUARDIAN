from __future__ import annotations

import logging
import os
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import defer_response, guild_only, guild_owner_only, respond, staff_only

LOG = logging.getLogger("esn_guardian.coordinator")

REQUIRED_PERMISSIONS = (
    "view_audit_log", "manage_messages", "moderate_members", "kick_members",
    "ban_members", "manage_roles", "manage_channels", "manage_webhooks",
)
SEVERITY = {"NORMAL": 0, "WATCH": 1, "CONTAINMENT": 2, "LOCKDOWN": 3, "RECOVERY": 4}


class ProtectionCoordinatorCog(commands.Cog):
    """Central coordination, durable recovery journal, config validation and safe drills."""

    guardian = app_commands.Group(name="guardian-core", description="Guardian central protection coordinator.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._claims: dict[tuple[int, str], tuple[datetime, str, str]] = {}
        self._signals: dict[int, deque[tuple[datetime, int, str]]] = defaultdict(lambda: deque(maxlen=200))

    async def cog_load(self) -> None:
        for sql in (
            """CREATE TABLE IF NOT EXISTS guardian_incident_state (
                guild_id INTEGER PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'NORMAL',
                reason TEXT NOT NULL DEFAULT 'No active incident',
                incident_id TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_recovery_journal (
                operation_id TEXT PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                engine TEXT NOT NULL,
                event_key TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_recovery_guild
               ON guardian_recovery_journal(guild_id, status, expires_at)""",
        ):
            await self.bot.database.execute(sql)
        self.cleanup_loop.start()

    def cog_unload(self) -> None:
        self.cleanup_loop.cancel()

    async def claim(self, guild_id: int, event_key: str, engine: str, *, seconds: int = 30) -> tuple[bool, str]:
        """Let exactly one protection engine own a response to the same event."""
        now = datetime.now(UTC)
        key = (guild_id, event_key)
        existing = self._claims.get(key)
        if existing and existing[0] > now:
            return False, existing[1]
        op_id = uuid.uuid4().hex
        self._claims[key] = (now + timedelta(seconds=max(5, seconds)), engine, op_id)
        return True, op_id

    async def begin_recovery(self, guild_id: int, engine: str, event_key: str, reason: str, *, seconds: int = 120) -> str:
        operation_id = uuid.uuid4().hex
        expires = datetime.now(UTC) + timedelta(seconds=max(10, seconds))
        await self.bot.database.execute(
            "INSERT INTO guardian_recovery_journal "
            "(operation_id,guild_id,engine,event_key,reason,status,expires_at) VALUES (?,?,?,?,?,'active',?)",
            (operation_id, guild_id, engine, event_key[:250], reason[:1000], expires.strftime("%Y-%m-%d %H:%M:%S")),
        )
        if hasattr(self.bot, "suppress_security_events"):
            self.bot.suppress_security_events(guild_id, seconds=seconds, reason=f"{engine}:{operation_id} {reason}")
        return operation_id

    async def owns_recovery(self, guild_id: int, *, event_key: str | None = None) -> bool:
        if event_key:
            row = await self.bot.database.fetchone(
                "SELECT 1 FROM guardian_recovery_journal WHERE guild_id=? AND event_key=? AND status='active' "
                "AND expires_at > CURRENT_TIMESTAMP LIMIT 1", (guild_id, event_key[:250]),
            )
        else:
            row = await self.bot.database.fetchone(
                "SELECT 1 FROM guardian_recovery_journal WHERE guild_id=? AND status='active' "
                "AND expires_at > CURRENT_TIMESTAMP LIMIT 1", (guild_id,),
            )
        return row is not None

    async def finish_recovery(self, operation_id: str, status: str = "complete") -> None:
        await self.bot.database.execute(
            "UPDATE guardian_recovery_journal SET status=? WHERE operation_id=?",
            (status[:32], operation_id),
        )

    async def signal(self, guild_id: int, score: int, reason: str) -> str:
        now = datetime.now(UTC)
        signals = self._signals[guild_id]
        signals.append((now, max(0, min(100, score)), reason[:300]))
        while signals and now - signals[0][0] > timedelta(minutes=5):
            signals.popleft()
        peak = max((item[1] for item in signals), default=0)
        count = len(signals)
        desired = "NORMAL"
        if peak >= 90 or (peak >= 70 and count >= 4):
            desired = "LOCKDOWN"
        elif peak >= 70 or count >= 5:
            desired = "CONTAINMENT"
        elif peak >= 35 or count >= 2:
            desired = "WATCH"
        await self.set_state(guild_id, desired, reason)
        return desired

    async def set_state(self, guild_id: int, state: str, reason: str) -> None:
        state = state if state in SEVERITY else "WATCH"
        current = await self.bot.database.fetchone(
            "SELECT state FROM guardian_incident_state WHERE guild_id=?", (guild_id,),
        )
        old = str(current["state"]) if current else "NORMAL"
        incident_id = uuid.uuid4().hex[:12] if state != "NORMAL" and old == "NORMAL" else None
        await self.bot.database.execute(
            "INSERT INTO guardian_incident_state(guild_id,state,reason,incident_id) VALUES (?,?,?,?) "
            "ON CONFLICT(guild_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,"
            "incident_id=COALESCE(guardian_incident_state.incident_id,excluded.incident_id),updated_at=CURRENT_TIMESTAMP",
            (guild_id, state, reason[:1000], incident_id),
        )

    async def state(self, guild_id: int) -> tuple[str, str]:
        row = await self.bot.database.fetchone(
            "SELECT state,reason FROM guardian_incident_state WHERE guild_id=?", (guild_id,),
        )
        return (str(row["state"]), str(row["reason"])) if row else ("NORMAL", "No active incident")

    async def validate(self, guild: discord.Guild) -> list[str]:
        gaps: list[str] = []
        me = guild.me
        missing = [p for p in REQUIRED_PERMISSIONS if me is None or not getattr(me.guild_permissions, p, False)]
        if missing:
            gaps.append("Missing permissions: " + ", ".join(missing))

        raid = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id=?", (guild.id,))
        if raid and raid["enabled"]:
            role_id = int(raid["quarantine_role_id"] or 0)
            role = guild.get_role(role_id) if role_id else None
            if role is None:
                gaps.append("Raid protection is enabled but quarantine role is missing.")
            elif me is None or role >= me.top_role:
                gaps.append("Quarantine role is above Guardian and cannot be managed.")

        verification = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id=?", (guild.id,))
        if verification and verification["enabled"]:
            verified = guild.get_role(int(verification["verified_role_id"] or 0))
            channel = guild.get_channel(int(verification["channel_id"] or 0))
            if verified is None:
                gaps.append("Verification is enabled but Verified role is missing.")
            if channel is None:
                gaps.append("Verification is enabled but verification channel is missing.")

        settings = await self.bot.database.setting(guild.id)
        if not settings["security_log_channel_id"]:
            gaps.append("Security log channel is not configured.")

        if not self.bot.database.backup_info().get("count"):
            gaps.append("No local database backup exists.")
        if not os.getenv("GUARDIAN_BACKUP_ENDPOINT", "").strip():
            gaps.append("Off-host backup endpoint is not configured.")
        return gaps

    async def selftest(self, guild: discord.Guild) -> tuple[int, list[str]]:
        gaps = await self.validate(guild)
        checks = 10
        failed = min(checks, len(gaps))
        db_ok = await self.bot.database.quick_check()
        if not db_ok:
            gaps.append("SQLite quick_check failed.")
            failed = min(checks, failed + 1)
        for cog in ("SecurityCog", "ProtectionV6Cog", "SecurityV7Cog", "SecurityMaxCog", "SecuritySentinelCog"):
            if self.bot.get_cog(cog) is None:
                gaps.append(f"{cog} is not loaded.")
                failed = min(checks, failed + 1)
        score = max(0, round(100 * (checks - failed) / checks))
        return score, gaps

    async def safe_drill(self, guild: discord.Guild) -> dict[str, bool]:
        """Pure/non-destructive regression drill. Never mutates Discord resources."""
        first, token = await self.claim(guild.id, "drill:duplicate", "drill-a", seconds=5)
        second, owner = await self.claim(guild.id, "drill:duplicate", "drill-b", seconds=5)
        op = await self.begin_recovery(guild.id, "drill", "drill:recovery", "non-destructive coordinator drill", seconds=15)
        journal = await self.owns_recovery(guild.id, event_key="drill:recovery")
        await self.finish_recovery(op)
        after = await self.owns_recovery(guild.id, event_key="drill:recovery")
        return {
            "duplicate_claim": bool(first and not second and owner == "drill-a"),
            "recovery_journal": bool(journal and not after),
            "database": bool(await self.bot.database.quick_check()),
            "token_created": bool(token),
        }

    @tasks.loop(minutes=5)
    async def cleanup_loop(self) -> None:
        now = datetime.now(UTC)
        for key, value in list(self._claims.items()):
            if value[0] <= now:
                self._claims.pop(key, None)
        await self.bot.database.execute(
            "UPDATE guardian_recovery_journal SET status='expired' "
            "WHERE status='active' AND expires_at <= CURRENT_TIMESTAMP"
        )

    @cleanup_loop.before_loop
    async def before_cleanup(self) -> None:
        await self.bot.wait_until_ready()

    @guardian.command(name="status", description="Show the unified Guardian protection state.")
    @guild_only()
    @staff_only()
    async def status_command(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        state, reason = await self.state(interaction.guild.id)
        gaps = await self.validate(interaction.guild)
        active = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM guardian_recovery_journal WHERE guild_id=? AND status='active' "
            "AND expires_at > CURRENT_TIMESTAMP", (interaction.guild.id,),
        )
        await respond(
            interaction,
            "**Guardian Central Control**\n"
            f"Incident state: {state}\nReason: {reason}\n"
            f"Active recovery operations: {int(active['count']) if active else 0}\n"
            f"Configuration gaps: {len(gaps)}\n"
            + ("\n".join(f"• {gap}" for gap in gaps[:8]) if gaps else "All central checks healthy."),
        )

    @guardian.command(name="selftest", description="Run Guardian's unified non-destructive readiness test.")
    @guild_only()
    @staff_only()
    async def selftest_command(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await defer_response(interaction)
        score, gaps = await self.selftest(interaction.guild)
        await respond(
            interaction,
            f"**Guardian Unified Self-Test**\nReadiness: {score}/100\n"
            f"Failed/gaps: {len(gaps)}\n"
            + ("\n".join(f"• {gap}" for gap in gaps[:12]) if gaps else "No readiness gaps detected."),
        )

    @guardian.command(name="drill", description="Run safe duplicate-response and recovery-journal regression drills.")
    @guild_only()
    @guild_owner_only()
    async def drill_command(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await defer_response(interaction)
        result = await self.safe_drill(interaction.guild)
        await respond(
            interaction,
            "**Guardian Safe Drill**\n"
            + "\n".join(f"{name}: {'PASS' if ok else 'FAIL'}" for name, ok in result.items()),
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ProtectionCoordinatorCog(bot))
