from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, guild_owner_only, log_event, respond, staff_only
from esn_guardian.cogs.security_intelligence import case_weight, risk_level

LOG = logging.getLogger("esn_guardian.overwatch")
GENESIS_HASH = "GENESIS"

CRITICAL_GUARDIAN_PERMISSIONS = (
    "view_audit_log",
    "manage_messages",
    "moderate_members",
    "kick_members",
    "ban_members",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
)


def _row_value(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return None


def case_digest(case: dict[str, Any], previous_hash: str = GENESIS_HASH) -> str:
    payload = {
        "case_id": case.get("case_id"),
        "guild_id": case.get("guild_id"),
        "target_id": case.get("target_id"),
        "moderator_id": case.get("moderator_id"),
        "action": case.get("action"),
        "reason": case.get("reason"),
        "channel_id": case.get("channel_id"),
        "details": case.get("details") or "{}",
        "created_at": case.get("created_at"),
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def trend_label(recent_score: int, previous_score: int) -> str:
    expected_recent = previous_score / 5
    if recent_score >= max(12, expected_recent * 2.25):
        return "RISING FAST"
    if recent_score >= max(6, expected_recent * 1.35):
        return "RISING"
    if previous_score >= 10 and recent_score <= expected_recent * 0.45:
        return "FALLING"
    return "STABLE"


def posture_score(*, missing_permissions: int, disabled_layers: int, ledger_ok: bool, active_incident: bool) -> int:
    deduction = missing_permissions * 7 + disabled_layers * 8
    if not ledger_ok:
        deduction += 20
    if active_incident:
        deduction += 15
    return max(0, 100 - min(100, deduction))


def _flatten(prefix: str, value: Any, output: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            _flatten(child, value[key], output)
        return
    output[prefix] = value


def diff_payloads(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    left: dict[str, Any] = {}
    right: dict[str, Any] = {}
    _flatten("", before, left)
    _flatten("", after, right)
    changes = []
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            changes.append(f"{key}: {left.get(key)!r} -> {right.get(key)!r}")
    return changes


class SecurityOverwatchCog(commands.Cog):
    """Tamper-evident Guardian telemetry, drift detection, and incident tracking."""

    overwatch = app_commands.Group(
        name="overwatch",
        description="Guardian security intelligence, integrity, and incident controls.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._integrity_alert_cooldown: dict[int, datetime] = {}

    async def cog_load(self) -> None:
        for statement in (
            """CREATE TABLE IF NOT EXISTS guardian_security_ledger (
                guild_id INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                case_id INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                case_hash TEXT NOT NULL,
                sealed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (guild_id, sequence),
                UNIQUE (guild_id, case_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_policy_baseline (
                guild_id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                closed_at TEXT
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_incidents_open
               ON guardian_incidents(guild_id, closed_at, incident_id DESC)""",
        ):
            await self.bot.database.execute(statement)

        self.ledger_loop.start()
        self.policy_drift_loop.start()
        self.incident_loop.start()

    def cog_unload(self) -> None:
        self.ledger_loop.cancel()
        self.policy_drift_loop.cancel()
        self.incident_loop.cancel()

    @staticmethod
    def _case_dict(row: Any) -> dict[str, Any]:
        return {
            "case_id": _row_value(row, "case_id"),
            "guild_id": _row_value(row, "guild_id"),
            "target_id": _row_value(row, "target_id"),
            "moderator_id": _row_value(row, "moderator_id"),
            "action": _row_value(row, "action"),
            "reason": _row_value(row, "reason"),
            "channel_id": _row_value(row, "channel_id"),
            "details": _row_value(row, "details"),
            "created_at": _row_value(row, "created_at"),
        }

    async def sync_ledger(self, guild_id: int, *, batch_size: int = 500) -> int:
        last = await self.bot.database.fetchone(
            "SELECT sequence, case_id, case_hash FROM guardian_security_ledger "
            "WHERE guild_id = ? ORDER BY sequence DESC LIMIT 1",
            (guild_id,),
        )
        sequence = int(last["sequence"]) if last is not None else 0
        last_case_id = int(last["case_id"]) if last is not None else 0
        previous_hash = str(last["case_hash"]) if last is not None else GENESIS_HASH

        rows = await self.bot.database.fetchall(
            "SELECT case_id, guild_id, target_id, moderator_id, action, reason, channel_id, details, created_at "
            "FROM cases WHERE guild_id = ? AND case_id > ? ORDER BY case_id ASC LIMIT ?",
            (guild_id, last_case_id, max(1, min(batch_size, 2000))),
        )
        count = 0
        for row in rows:
            sequence += 1
            case = self._case_dict(row)
            digest = case_digest(case, previous_hash)
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO guardian_security_ledger "
                "(guild_id, sequence, case_id, previous_hash, case_hash) VALUES (?, ?, ?, ?, ?)",
                (guild_id, sequence, int(row["case_id"]), previous_hash, digest),
            )
            previous_hash = digest
            count += 1
        return count

    async def verify_ledger(self, guild_id: int) -> dict[str, Any]:
        rows = await self.bot.database.fetchall(
            "SELECT l.sequence, l.case_id, l.previous_hash, l.case_hash, "
            "c.guild_id AS c_guild_id, c.target_id, c.moderator_id, c.action, c.reason, "
            "c.channel_id, c.details, c.created_at "
            "FROM guardian_security_ledger l "
            "LEFT JOIN cases c ON c.guild_id = l.guild_id AND c.case_id = l.case_id "
            "WHERE l.guild_id = ? ORDER BY l.sequence ASC",
            (guild_id,),
        )
        previous_hash = GENESIS_HASH
        checked = 0
        for row in rows:
            checked += 1
            if row["c_guild_id"] is None:
                return {"ok": False, "checked": checked, "reason": f"Case #{row['case_id']} is missing from the database."}
            if str(row["previous_hash"]) != previous_hash:
                return {"ok": False, "checked": checked, "reason": f"Ledger chain break at sequence {row['sequence']}."}
            case = {
                "case_id": int(row["case_id"]),
                "guild_id": int(row["c_guild_id"]),
                "target_id": row["target_id"],
                "moderator_id": row["moderator_id"],
                "action": row["action"],
                "reason": row["reason"],
                "channel_id": row["channel_id"],
                "details": row["details"],
                "created_at": row["created_at"],
            }
            expected = case_digest(case, previous_hash)
            if expected != str(row["case_hash"]):
                return {"ok": False, "checked": checked, "reason": f"Case #{row['case_id']} no longer matches its sealed hash."}
            previous_hash = expected
        return {"ok": True, "checked": checked, "reason": "Ledger chain verified."}

    async def _policy_payload(self, guild: discord.Guild) -> dict[str, Any]:
        await self.bot.database.ensure_guild(guild.id)
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_config (guild_id) VALUES (?)", (guild.id,))
        security = await self.bot.database.fetchone("SELECT * FROM security_config WHERE guild_id = ?", (guild.id,))
        antinuke = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (guild.id,))
        raid = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (guild.id,))
        guardian = await self.bot.database.fetchone("SELECT * FROM guardian_config WHERE guild_id = ?", (guild.id,))
        bot_member = guild.me
        permissions = {
            name: bool(bot_member and getattr(bot_member.guild_permissions, name, False))
            for name in CRITICAL_GUARDIAN_PERMISSIONS
        }
        return {
            "security": dict(security) if security is not None else {},
            "antinuke": dict(antinuke) if antinuke is not None else {},
            "raid": dict(raid) if raid is not None else {},
            "guardian": dict(guardian) if guardian is not None else {},
            "guardian_permissions": permissions,
        }

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def seal_policy(self, guild: discord.Guild) -> str:
        payload = await self._policy_payload(guild)
        fingerprint = self._fingerprint(payload)
        await self.bot.database.execute(
            "INSERT INTO guardian_policy_baseline (guild_id, fingerprint, payload_json) VALUES (?, ?, ?) "
            "ON CONFLICT(guild_id) DO UPDATE SET fingerprint=excluded.fingerprint, "
            "payload_json=excluded.payload_json, updated_at=CURRENT_TIMESTAMP",
            (guild.id, fingerprint, json.dumps(payload, ensure_ascii=True, sort_keys=True)),
        )
        return fingerprint

    async def policy_drift(self, guild: discord.Guild) -> dict[str, Any]:
        current = await self._policy_payload(guild)
        current_fp = self._fingerprint(current)
        row = await self.bot.database.fetchone(
            "SELECT fingerprint, payload_json, updated_at FROM guardian_policy_baseline WHERE guild_id = ?",
            (guild.id,),
        )
        if row is None:
            await self.seal_policy(guild)
            return {"changed": False, "changes": [], "fingerprint": current_fp, "initialized": True}
        try:
            previous = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            previous = {}
        changes = diff_payloads(previous, current) if str(row["fingerprint"]) != current_fp else []
        return {
            "changed": bool(changes),
            "changes": changes,
            "fingerprint": current_fp,
            "updated_at": row["updated_at"],
            "initialized": False,
        }

    async def _weighted_window(self, guild_id: int, start_modifier: str, end_modifier: str | None = None) -> tuple[int, list[Any]]:
        if end_modifier is None:
            rows = await self.bot.database.fetchall(
                "SELECT action, reason, created_at FROM cases "
                "WHERE guild_id = ? AND created_at >= datetime('now', ?) ORDER BY case_id DESC LIMIT 250",
                (guild_id, start_modifier),
            )
        else:
            rows = await self.bot.database.fetchall(
                "SELECT action, reason, created_at FROM cases "
                "WHERE guild_id = ? AND created_at >= datetime('now', ?) AND created_at < datetime('now', ?) "
                "ORDER BY case_id DESC LIMIT 250",
                (guild_id, start_modifier, end_modifier),
            )
        score = sum(case_weight(str(row["action"])) for row in rows)
        return score, rows

    async def trend_report(self, guild: discord.Guild) -> dict[str, Any]:
        recent_score, recent_rows = await self._weighted_window(guild.id, "-10 minutes")
        previous_score, previous_rows = await self._weighted_window(guild.id, "-60 minutes", "-10 minutes")
        return {
            "label": trend_label(recent_score, previous_score),
            "recent_score": recent_score,
            "previous_score": previous_score,
            "recent_cases": len(recent_rows),
            "previous_cases": len(previous_rows),
        }

    async def active_incident(self, guild_id: int) -> Any | None:
        return await self.bot.database.fetchone(
            "SELECT * FROM guardian_incidents WHERE guild_id = ? AND closed_at IS NULL "
            "ORDER BY incident_id DESC LIMIT 1",
            (guild_id,),
        )

    async def posture(self, guild: discord.Guild) -> dict[str, Any]:
        intelligence = self.bot.get_cog("SecurityIntelligenceCog")
        snapshot = await intelligence.snapshot(guild) if intelligence is not None and hasattr(intelligence, "snapshot") else {}
        ledger = await self.verify_ledger(guild.id)
        incident = await self.active_incident(guild.id)
        disabled = sum(
            1 for key in ("automod", "antinuke", "raid", "rollback", "webhook_guard", "integration_guard", "credential_guard", "external_app_lock", "bot_approval")
            if snapshot and not snapshot.get(key)
        )
        missing = len(snapshot.get("missing_permissions", [])) if snapshot else 0
        score = posture_score(
            missing_permissions=missing,
            disabled_layers=disabled,
            ledger_ok=bool(ledger["ok"]),
            active_incident=incident is not None,
        )
        trend = await self.trend_report(guild)
        return {
            "score": score,
            "level": risk_level(max(0, 100 - score)),
            "ledger": ledger,
            "trend": trend,
            "disabled_layers": disabled,
            "missing_permissions": snapshot.get("missing_permissions", []) if snapshot else [],
            "active_incident": dict(incident) if incident is not None else None,
            "snapshot": snapshot,
        }

    async def member_risk_report(self, guild: discord.Guild, member_id: int) -> str:
        member = guild.get_member(member_id)
        rows = await self.bot.database.fetchall(
            "SELECT case_id, action, reason, created_at FROM cases "
            "WHERE guild_id = ? AND target_id = ? ORDER BY case_id DESC LIMIT 20",
            (guild.id, member_id),
        )
        recent_score = sum(case_weight(str(row["action"])) for row in rows[:10])
        high_risk_roles = []
        account_age = "unknown"
        if member is not None:
            account_age = f"{(datetime.now(UTC) - member.created_at).days} days"
            for role in member.roles:
                if any(
                    getattr(role.permissions, name, False)
                    for name in ("administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks", "ban_members")
                ):
                    high_risk_roles.append(role.name)
        last = rows[0] if rows else None
        return (
            f"**Member security profile — {member_id}**\n"
            f"Account age: {account_age}\n"
            f"Recorded cases: {len(rows)}\n"
            f"Weighted recent risk signals: {recent_score}\n"
            f"High-risk roles: {', '.join(high_risk_roles[:8]) if high_risk_roles else 'none detected'}\n"
            f"Latest case: #{last['case_id']} {last['action']} — {last['reason']}" if last else
            f"**Member security profile — {member_id}**\nAccount age: {account_age}\nRecorded cases: 0\nHigh-risk roles: {', '.join(high_risk_roles[:8]) if high_risk_roles else 'none detected'}"
        )

    async def integrity_report(self, guild: discord.Guild) -> str:
        await self.sync_ledger(guild.id)
        ledger = await self.verify_ledger(guild.id)
        drift = await self.policy_drift(guild)
        backup = self.bot.database.backup_info()
        return (
            "**Guardian integrity report**\n"
            f"Case ledger: {'VERIFIED' if ledger['ok'] else 'FAILED'} ({ledger['checked']} sealed cases checked)\n"
            f"Ledger detail: {ledger['reason']}\n"
            f"Policy baseline: {'CHANGED' if drift['changed'] else 'matches current state'}\n"
            f"Detected policy differences: {len(drift['changes'])}\n"
            f"Database backups: {backup.get('count', 0)} • Latest: {backup.get('latest') or 'none'}"
        )

    async def posture_report(self, guild: discord.Guild) -> str:
        data = await self.posture(guild)
        missing = ", ".join(str(x).replace("_", " ") for x in data["missing_permissions"]) or "none"
        incident = data["active_incident"]
        return (
            "**Guardian defense posture**\n"
            f"Posture score: {data['score']}/100\n"
            f"Threat trend: {data['trend']['label']}\n"
            f"Recent weighted activity: {data['trend']['recent_score']} / previous 50m: {data['trend']['previous_score']}\n"
            f"Disabled protection layers: {data['disabled_layers']}\n"
            f"Missing Guardian permissions: {missing}\n"
            f"Tamper-evident ledger: {'OK' if data['ledger']['ok'] else 'FAILED'}\n"
            f"Active incident: {'#' + str(incident['incident_id']) + ' ' + incident['severity'] if incident else 'none'}"
        )

    async def incident_report(self, guild_id: int) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT incident_id, severity, reason, opened_at, closed_at FROM guardian_incidents "
            "WHERE guild_id = ? ORDER BY incident_id DESC LIMIT 8",
            (guild_id,),
        )
        if not rows:
            return "No persistent Guardian incident sessions have been recorded."
        return "**Guardian incident sessions**\n" + "\n".join(
            f"#{row['incident_id']} • {row['severity']} • opened {row['opened_at']} UTC • "
            f"{'ACTIVE' if row['closed_at'] is None else 'closed ' + str(row['closed_at']) + ' UTC'} • {str(row['reason'])[:120]}"
            for row in rows
        )

    async def drift_report(self, guild: discord.Guild) -> str:
        drift = await self.policy_drift(guild)
        if not drift["changed"]:
            return "**Security policy drift**\nNo unsealed configuration differences are currently detected."
        return (
            "**Security policy drift detected**\n"
            + "\n".join(f"• {item}" for item in drift["changes"][:12])
            + ("\n• Additional changes omitted." if len(drift["changes"]) > 12 else "")
        )

    @tasks.loop(seconds=60)
    async def ledger_loop(self) -> None:
        for guild in list(self.bot.guilds):
            security = self.bot.get_cog("SecurityCog")
            if (
                security is not None
                and hasattr(security, "is_raid_mode_active")
                and security.is_raid_mode_active(guild.id)
            ):
                continue
            try:
                await self.sync_ledger(guild.id)
                result = await self.verify_ledger(guild.id)
                if result["ok"]:
                    continue
                now = datetime.now(UTC)
                previous = self._integrity_alert_cooldown.get(guild.id)
                if previous is not None and now - previous < timedelta(hours=1):
                    continue
                self._integrity_alert_cooldown[guild.id] = now
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    "Guardian integrity failure",
                    description=result["reason"],
                    color=discord.Color.red(),
                )
                try:
                    await self.bot.database.backup("integrity-alert")
                except Exception:
                    LOG.exception("Could not create integrity-alert backup for guild %s", guild.id)
            except Exception:
                LOG.exception("Guardian ledger loop failed for guild %s", guild.id)

    @ledger_loop.before_loop
    async def before_ledger_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=3)
    async def policy_drift_loop(self) -> None:
        for guild in list(self.bot.guilds):
            security = self.bot.get_cog("SecurityCog")
            if (
                security is not None
                and hasattr(security, "is_raid_mode_active")
                and security.is_raid_mode_active(guild.id)
            ):
                continue
            try:
                drift = await self.policy_drift(guild)
                if not drift["changed"]:
                    continue
                changes = drift["changes"]
                await self.bot.database.create_case(
                    guild.id,
                    None,
                    self.bot.user.id if self.bot.user else None,
                    "SECURITY_POLICY_DRIFT",
                    f"Guardian security configuration changed in {len(changes)} tracked fields.",
                    details={"changes": changes[:25]},
                )
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    "Guardian security policy changed",
                    description="\n".join(changes[:12]),
                    color=discord.Color.orange(),
                )
                await self.seal_policy(guild)
            except Exception:
                LOG.exception("Guardian policy drift loop failed for guild %s", guild.id)

    @policy_drift_loop.before_loop
    async def before_policy_drift_loop(self) -> None:
        await self.bot.wait_until_ready()
        for guild in list(self.bot.guilds):
            try:
                row = await self.bot.database.fetchone(
                    "SELECT 1 FROM guardian_policy_baseline WHERE guild_id = ?",
                    (guild.id,),
                )
                if row is None:
                    await self.seal_policy(guild)
            except Exception:
                LOG.exception("Could not initialize Guardian policy baseline for guild %s", guild.id)

    @tasks.loop(seconds=60)
    async def incident_loop(self) -> None:
        for guild in list(self.bot.guilds):
            security = self.bot.get_cog("SecurityCog")
            if (
                security is not None
                and hasattr(security, "is_raid_mode_active")
                and security.is_raid_mode_active(guild.id)
            ):
                continue
            try:
                score, rows = await self._weighted_window(guild.id, "-5 minutes")
                active = await self.active_incident(guild.id)
                serious = [row for row in rows if case_weight(str(row["action"])) >= 8]
                if active is None and (score >= 30 or len(serious) >= 3):
                    severity = "CRITICAL" if score >= 55 or len(serious) >= 5 else "HIGH"
                    evidence = [
                        {"action": str(row["action"]), "reason": str(row["reason"])[:200], "created_at": str(row["created_at"])}
                        for row in rows[:12]
                    ]
                    await self.bot.database.execute(
                        "INSERT INTO guardian_incidents (guild_id, severity, reason, evidence_json) VALUES (?, ?, ?, ?)",
                        (
                            guild.id,
                            severity,
                            f"Guardian observed {len(rows)} security cases with weighted score {score} inside five minutes.",
                            json.dumps(evidence, ensure_ascii=True),
                        ),
                    )
                    await self.bot.database.backup("incident-open")
                    await log_event(
                        self.bot,
                        guild,
                        "security_log_channel_id",
                        f"Guardian incident opened — {severity}",
                        description=f"Weighted 5-minute score: {score}. Serious signals: {len(serious)}.",
                        color=discord.Color.red(),
                    )
                elif active is not None and score < 6:
                    opened = datetime.fromisoformat(str(active["opened_at"]).replace("Z", "+00:00"))
                    if opened.tzinfo is None:
                        opened = opened.replace(tzinfo=UTC)
                    if datetime.now(UTC) - opened >= timedelta(minutes=10):
                        await self.bot.database.execute(
                            "UPDATE guardian_incidents SET closed_at = CURRENT_TIMESTAMP WHERE incident_id = ?",
                            (active["incident_id"],),
                        )
            except Exception:
                LOG.exception("Guardian incident loop failed for guild %s", guild.id)

    @incident_loop.before_loop
    async def before_incident_loop(self) -> None:
        await self.bot.wait_until_ready()

    @overwatch.command(name="status", description="Show Guardian's full live defense posture.")
    @guild_only()
    @staff_only()
    async def overwatch_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.posture_report(interaction.guild))

    @overwatch.command(name="integrity", description="Verify the tamper-evident case ledger and policy baseline.")
    @guild_only()
    @staff_only()
    async def overwatch_integrity(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.integrity_report(interaction.guild))

    @overwatch.command(name="incidents", description="Show recent persistent Guardian incident sessions.")
    @guild_only()
    @staff_only()
    async def overwatch_incidents(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self.incident_report(interaction.guild_id))

    @overwatch.command(name="seal", description="Seal the current security configuration as the approved policy baseline.")
    @guild_only()
    @guild_owner_only()
    async def overwatch_seal(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        fingerprint = await self.seal_policy(interaction.guild)
        await respond(interaction, f"Guardian policy baseline sealed. Fingerprint: `{fingerprint[:16]}…`")

    @overwatch.command(name="backup", description="Create an immediate verified Guardian incident backup.")
    @guild_only()
    @guild_owner_only()
    async def overwatch_backup(self, interaction: discord.Interaction) -> None:
        path = await self.bot.database.backup("manual-overwatch")
        await respond(interaction, f"Verified Guardian backup created: `{path.name if path else 'unavailable'}`")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityOverwatchCog(bot))
