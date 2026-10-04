from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import statistics
import time
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiohttp
from cryptography.fernet import Fernet
import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, guild_owner_only, log_event, respond, staff_only

LOG = logging.getLogger("esn_guardian.security_v7")

POLICIES = {
    "community": {"elevated": 18, "high": 32, "critical": 48, "panic": 68, "two_person": 0},
    "high": {"elevated": 14, "high": 25, "critical": 40, "panic": 58, "two_person": 1},
    "maximum": {"elevated": 10, "high": 20, "critical": 32, "panic": 48, "two_person": 1},
}
STATE_ORDER = ("NORMAL", "ELEVATED", "HIGH", "CRITICAL", "PANIC")
CATASTROPHIC = {
    "massrole", "globalban", "globalunban", "protection release", "shield restore",
    "shield temp-role", "antinuke disable", "verification disable",
}
DANGEROUS = ("administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks", "ban_members", "kick_members", "moderate_members")
LOG_FIELDS = (
    "moderation_log_channel_id", "security_log_channel_id", "member_log_channel_id",
    "message_log_channel_id", "verification_log_channel_id", "system_log_channel_id",
    "guild_log_channel_id", "voice_log_channel_id", "invite_log_channel_id",
    "role_log_channel_id", "command_log_channel_id",
)


def state_from_score(score: int, profile: str = "maximum") -> str:
    policy = POLICIES.get(profile, POLICIES["maximum"])
    if score >= policy["panic"]:
        return "PANIC"
    if score >= policy["critical"]:
        return "CRITICAL"
    if score >= policy["high"]:
        return "HIGH"
    if score >= policy["elevated"]:
        return "ELEVATED"
    return "NORMAL"


def evidence_hash(previous_hash: str, payload: str) -> str:
    return hashlib.sha256((previous_hash + "|" + payload).encode("utf-8")).hexdigest()


def anomaly_score(samples: int, action_frequency: float, hour_frequency: float, recent_count: int, typical_count: float) -> int:
    if samples < 10:
        return 0
    score = 0
    if action_frequency <= 0.02:
        score += 30
    elif action_frequency <= 0.08:
        score += 18
    if hour_frequency <= 0.03:
        score += 18
    elif hour_frequency <= 0.10:
        score += 8
    if typical_count > 0 and recent_count >= max(5, typical_count * 3):
        score += 28
    return min(100, score)


def trust_score(account_age_days: int, incident_weight: int, protected_roles: int, recovery: bool) -> int:
    score = 55
    score += 18 if account_age_days >= 365 else 10 if account_age_days >= 90 else -18 if account_age_days < 7 else 0
    score += 15 if recovery else 0
    score += min(12, protected_roles * 4)
    score -= min(60, max(0, incident_weight))
    return max(0, min(100, score))


class SecurityV7Cog(commands.Cog):
    shield = app_commands.Group(name="shield", description="Guardian v7 predictive defense and recovery.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.last_event: dict[int, int] = defaultdict(int)
        self.recent: dict[int, deque[dict[str, Any]]] = defaultdict(deque)
        self.actor_recent: dict[tuple[int, int], deque[datetime]] = defaultdict(deque)
        self.state: dict[int, str] = defaultdict(lambda: "NORMAL")
        self.evidence_dedupe: dict[tuple[int, str], float] = {}
        self.previous_check = None
        self.session: aiohttp.ClientSession | None = None
        self.dashboard_runner: Any | None = None
        self.behavior_alerts: dict[tuple[int, int], datetime] = {}

    async def cog_load(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS guardian_v7_config (
                guild_id INTEGER PRIMARY KEY, profile TEXT NOT NULL DEFAULT 'maximum',
                state TEXT NOT NULL DEFAULT 'NORMAL', two_person INTEGER NOT NULL DEFAULT 1,
                protected_assets INTEGER NOT NULL DEFAULT 1, behavior_baselines INTEGER NOT NULL DEFAULT 1,
                privilege_paths INTEGER NOT NULL DEFAULT 1, evidence_chain INTEGER NOT NULL DEFAULT 1,
                offhost_replication INTEGER NOT NULL DEFAULT 1, predictive_alerts INTEGER NOT NULL DEFAULT 1,
                emergency_minimal INTEGER NOT NULL DEFAULT 1,
                custom_elevated INTEGER, custom_high INTEGER, custom_critical INTEGER, custom_panic INTEGER,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_assets (
                guild_id INTEGER NOT NULL, asset_type TEXT NOT NULL, asset_id INTEGER NOT NULL,
                label TEXT, canary INTEGER NOT NULL DEFAULT 0, created_by_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, asset_type, asset_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_behavior (
                guild_id INTEGER NOT NULL, actor_id INTEGER NOT NULL, samples INTEGER NOT NULL DEFAULT 0,
                actions_json TEXT NOT NULL DEFAULT '{}', hours_json TEXT NOT NULL DEFAULT '{}',
                buckets_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, actor_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_evidence (
                evidence_id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
                source_event_id INTEGER, actor_id INTEGER, event_kind TEXT NOT NULL, target_id INTEGER,
                payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_approvals (
                approval_code TEXT PRIMARY KEY, guild_id INTEGER NOT NULL, command_name TEXT NOT NULL,
                requester_id INTEGER NOT NULL, approver_id INTEGER, expires_at TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_recovery_team (
                guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, added_by_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(guild_id, user_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_reputation (
                subject_type TEXT NOT NULL, subject_key TEXT NOT NULL, reputation INTEGER NOT NULL DEFAULT 0,
                evidence_count INTEGER NOT NULL DEFAULT 0, last_reason TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(subject_type, subject_key)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_false_positives (
                guild_id INTEGER NOT NULL, source_type TEXT NOT NULL, source_id INTEGER NOT NULL,
                reviewed_by_id INTEGER NOT NULL, reason TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, source_type, source_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_temp_roles (
                guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role_id INTEGER NOT NULL,
                granted_by_id INTEGER NOT NULL, expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, user_id, role_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v7_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
                metric_name TEXT NOT NULL, value REAL NOT NULL, detail TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
        )
        for statement in statements:
            await self.bot.database.execute(statement)
        self.previous_check = self.bot.tree.interaction_check
        self.bot.tree.interaction_check = self._interaction_check
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        self.ingest_loop.start()
        self.state_loop.start()
        self.watch_loop.start()
        self.temp_role_loop.start()
        self.dashboard_loop.start()
        self.remote_sync_loop.start()
        await self._start_dashboard_server()

    def cog_unload(self) -> None:
        for loop in (self.ingest_loop, self.state_loop, self.watch_loop, self.temp_role_loop, self.dashboard_loop, self.remote_sync_loop):
            loop.cancel()
        if self.previous_check is not None:
            self.bot.tree.interaction_check = self.previous_check
        if self.session is not None:
            asyncio.create_task(self.session.close())
        if self.dashboard_runner is not None:
            asyncio.create_task(self.dashboard_runner.cleanup())

    async def _config(self, guild_id: int):
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_v7_config (guild_id) VALUES (?)", (guild_id,))
        return await self.bot.database.fetchone("SELECT * FROM guardian_v7_config WHERE guild_id=?", (guild_id,))

    def thresholds(self, guild_id: int) -> tuple[int, int]:
        current = self.state[guild_id]
        if current == "PANIC":
            return 8, 14
        if current == "CRITICAL":
            return 10, 18
        if current == "HIGH":
            return 12, 22
        if current == "ELEVATED":
            return 15, 25
        return 18, 28

    async def _is_recovery(self, guild: discord.Guild, user: discord.abc.User) -> bool:
        if user.id == guild.owner_id:
            return True
        row = await self.bot.database.fetchone(
            "SELECT 1 FROM guardian_v7_recovery_team WHERE guild_id=? AND user_id=?",
            (guild.id, user.id),
        )
        return row is not None

    async def _interaction_check(self, interaction: discord.Interaction) -> bool:
        if self.previous_check is not None:
            if not await self.previous_check(interaction):
                return False
        if interaction.guild is None or interaction.command is None:
            return True
        config = await self._config(interaction.guild.id)
        command_name = interaction.command.qualified_name.casefold()
        dynamic_catastrophic = command_name in CATASTROPHIC
        if command_name == "guardian panic" and getattr(interaction.namespace, "enabled", True) is False:
            dynamic_catastrophic = True
        if command_name == "security automod" and getattr(interaction.namespace, "enabled", True) is False:
            dynamic_catastrophic = True
        if not config["two_person"] or not dynamic_catastrophic:
            return True
        now = datetime.now(UTC)
        rows = await self.bot.database.fetchall(
            "SELECT * FROM guardian_v7_approvals WHERE guild_id=? AND command_name=? AND requester_id=? "
            "ORDER BY created_at DESC LIMIT 5",
            (interaction.guild.id, command_name, interaction.user.id),
        )
        for row in rows:
            try:
                expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
            except ValueError:
                continue
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if not row["consumed"] and row["approver_id"] is not None and expires > now:
                await self.bot.database.execute(
                    "UPDATE guardian_v7_approvals SET consumed=1 WHERE approval_code=?",
                    (row["approval_code"],),
                )
                return True
        code = secrets.token_hex(3).upper()
        expires = now + timedelta(minutes=3)
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_approvals "
            "(approval_code,guild_id,command_name,requester_id,expires_at) VALUES (?,?,?,?,?)",
            (code, interaction.guild.id, command_name, interaction.user.id, expires.isoformat()),
        )
        if not interaction.response.is_done():
            await interaction.response.send_message(
                f"Guardian v7 requires a second trusted person to approve /{command_name}. "
                f"Approval code: {code}. A different recovery-team member or the server owner must run "
                f"/shield approve code:{code} within 3 minutes, then you can rerun the command.",
                ephemeral=True,
            )
        await self._evidence(interaction.guild.id, interaction.user.id, "TWO_PERSON_APPROVAL", None, {"command": command_name, "code": code})
        return False

    async def _evidence(
        self,
        guild_id: int,
        actor_id: int | None,
        kind: str,
        target_id: int | None,
        payload: dict[str, Any],
        source_event_id: int | None = None,
    ) -> int | None:
        canonical = json.dumps(
            {"kind": kind, "actor_id": actor_id, "target_id": target_id, **payload},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        previous = await self.bot.database.fetchone(
            "SELECT evidence_hash FROM guardian_v7_evidence WHERE guild_id=? ORDER BY evidence_id DESC LIMIT 1",
            (guild_id,),
        )
        previous_hash = str(previous["evidence_hash"]) if previous else "GENESIS"
        digest = evidence_hash(previous_hash, canonical)
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_evidence "
            "(guild_id,source_event_id,actor_id,event_kind,target_id,payload_json,previous_hash,evidence_hash) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (guild_id, source_event_id, actor_id, kind, target_id, canonical, previous_hash, digest),
        )
        row = await self.bot.database.fetchone(
            "SELECT evidence_id FROM guardian_v7_evidence WHERE guild_id=? ORDER BY evidence_id DESC LIMIT 1",
            (guild_id,),
        )
        return int(row["evidence_id"]) if row else None

    async def verify_chain(self, guild_id: int) -> dict[str, Any]:
        rows = await self.bot.database.fetchall(
            "SELECT evidence_id,payload_json,previous_hash,evidence_hash FROM guardian_v7_evidence "
            "WHERE guild_id=? ORDER BY evidence_id ASC",
            (guild_id,),
        )
        previous = "GENESIS"
        checked = 0
        for row in rows:
            if str(row["previous_hash"]) != previous:
                return {"ok": False, "checked": checked, "reason": f"Previous-hash mismatch at evidence {row['evidence_id']}."}
            expected = evidence_hash(previous, str(row["payload_json"]))
            if not hmac.compare_digest(expected, str(row["evidence_hash"])):
                return {"ok": False, "checked": checked, "reason": f"Hash mismatch at evidence {row['evidence_id']}."}
            previous = expected
            checked += 1
        return {"ok": True, "checked": checked, "reason": "Evidence chain verified."}

    async def _learn_behavior(self, guild: discord.Guild, event: dict[str, Any]) -> None:
        actor_id = event["actor_id"]
        if actor_id is None or guild.get_member(actor_id) is None:
            return
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_v7_behavior WHERE guild_id=? AND actor_id=?",
            (guild.id, actor_id),
        )
        samples = int(row["samples"]) if row else 0
        try:
            actions = json.loads(str(row["actions_json"])) if row else {}
            hours = json.loads(str(row["hours_json"])) if row else {}
            buckets = json.loads(str(row["buckets_json"])) if row else []
        except (TypeError, json.JSONDecodeError):
            actions, hours, buckets = {}, {}, []
        kind = event["kind"]
        hour = str(event["created_at"].hour)
        actions[kind] = int(actions.get(kind, 0)) + 1
        hours[hour] = int(hours.get(hour, 0)) + 1
        samples += 1
        window = self.actor_recent[(guild.id, actor_id)]
        window.append(event["created_at"])
        while window and datetime.now(UTC) - window[0] > timedelta(minutes=5):
            window.popleft()
        buckets.append(len(window))
        buckets = buckets[-40:]
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_behavior "
            "(guild_id,actor_id,samples,actions_json,hours_json,buckets_json) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(guild_id,actor_id) DO UPDATE SET samples=excluded.samples,actions_json=excluded.actions_json,"
            "hours_json=excluded.hours_json,buckets_json=excluded.buckets_json,updated_at=CURRENT_TIMESTAMP",
            (guild.id, actor_id, samples, json.dumps(actions), json.dumps(hours), json.dumps(buckets)),
        )
        if samples < 10:
            return
        action_frequency = actions[kind] / samples
        hour_frequency = hours[hour] / samples
        typical = statistics.median(buckets[:-1]) if len(buckets) > 2 else max(1, len(window))
        score = anomaly_score(samples, action_frequency, hour_frequency, len(window), float(typical))
        if score < 55:
            return
        key = (guild.id, actor_id)
        previous = self.behavior_alerts.get(key)
        now = datetime.now(UTC)
        if previous and now - previous < timedelta(minutes=5):
            return
        self.behavior_alerts[key] = now
        await self._evidence(
            guild.id, actor_id, "BEHAVIOR_ANOMALY", event["target_id"],
            {"score": score, "event_kind": kind, "action_frequency": action_frequency, "hour_frequency": hour_frequency},
        )
        if score >= 70:
            v6 = self.bot.get_cog("ProtectionV6Cog")
            member = guild.get_member(actor_id)
            if v6 is not None and member is not None:
                await v6._signal(
                    guild, member, "command_abuse",
                    f"Guardian v7 compromised-staff behavior anomaly score={score}; event={kind}",
                    target_id=event["target_id"], score=min(14, score // 7),
                )

    async def _reputation(self, event: dict[str, Any]) -> None:
        kind, target_id = event["kind"], event["target_id"]
        subject_type = "application" if kind == "external_app" else "bot" if kind == "unapproved_bot" else "webhook" if kind == "webhook_change" else None
        if subject_type is None or target_id is None:
            return
        row = await self.bot.database.fetchone(
            "SELECT reputation,evidence_count FROM guardian_v7_reputation WHERE subject_type=? AND subject_key=?",
            (subject_type, str(target_id)),
        )
        reputation = int(row["reputation"]) if row else 0
        count = int(row["evidence_count"]) if row else 0
        reputation = max(-100, reputation - min(30, max(5, int(event["score"]) * 2)))
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_reputation "
            "(subject_type,subject_key,reputation,evidence_count,last_reason) VALUES (?,?,?,?,?) "
            "ON CONFLICT(subject_type,subject_key) DO UPDATE SET reputation=excluded.reputation,"
            "evidence_count=excluded.evidence_count,last_reason=excluded.last_reason,updated_at=CURRENT_TIMESTAMP",
            (subject_type, str(target_id), reputation, count + 1, event["detail"][:500]),
        )

    async def _ingest(self, guild: discord.Guild, row: Any) -> None:
        actor_id = int(row["actor_id"]) if row["actor_id"] is not None else None
        target_id = int(row["target_id"]) if row["target_id"] is not None else None
        key = f"{actor_id}:{row['kind']}:{target_id}:{str(row['detail'])[:80]}"
        dedupe = (guild.id, key)
        now_mono = time.monotonic()
        if now_mono - self.evidence_dedupe.get(dedupe, -1000) < 4:
            return
        self.evidence_dedupe[dedupe] = now_mono
        try:
            created = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
        except ValueError:
            created = datetime.now(UTC)
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        event = {
            "event_id": int(row["event_id"]), "actor_id": actor_id, "kind": str(row["kind"]),
            "score": int(row["score"]), "detail": str(row["detail"]), "target_id": target_id,
            "created_at": created,
        }
        self.recent[guild.id].append(event)
        cutoff = datetime.now(UTC) - timedelta(minutes=5)
        while self.recent[guild.id] and self.recent[guild.id][0]["created_at"] < cutoff:
            self.recent[guild.id].popleft()
        await self._evidence(
            guild.id, actor_id, event["kind"], target_id,
            {"score": event["score"], "detail": event["detail"][:1000], "created_at": created.isoformat()},
            source_event_id=event["event_id"],
        )
        latency = max(0.0, (datetime.now(UTC) - created).total_seconds() * 1000)
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_metrics (guild_id,metric_name,value,detail) VALUES (?,'response_latency_ms',?,?)",
            (guild.id, latency, event["kind"][:80]),
        )
        await self._learn_behavior(guild, event)
        await self._reputation(event)

    def score(self, guild_id: int) -> int:
        now = datetime.now(UTC)
        total = 0.0
        kinds, actors = set(), set()
        for event in self.recent[guild_id]:
            age = (now - event["created_at"]).total_seconds()
            if age > 300:
                continue
            total += event["score"] * max(0.25, 1 - age / 300)
            kinds.add(event["kind"])
            if event["actor_id"] is not None:
                actors.add(event["actor_id"])
        if len(kinds) >= 4:
            total += 10
        if len(actors) >= 3:
            total += 7
        return min(100, round(total))

    async def _set_state(self, guild: discord.Guild, new_state: str, score: int) -> None:
        old = self.state[guild.id]
        if old == new_state:
            return
        self.state[guild.id] = new_state
        await self.bot.database.execute(
            "UPDATE guardian_v7_config SET state=?,updated_at=CURRENT_TIMESTAMP WHERE guild_id=?",
            (new_state, guild.id),
        )
        await self._evidence(guild.id, None, "STATE_CHANGE", None, {"from": old, "to": new_state, "score": score})
        await log_event(
            self.bot, guild, "security_log_channel_id",
            f"Guardian v7 state: {old} -> {new_state}",
            description=f"Predictive five-minute risk score: {score}/100.",
            color=discord.Color.red() if new_state in {"CRITICAL", "PANIC"} else discord.Color.orange() if new_state != "NORMAL" else discord.Color.green(),
        )
        if new_state == "PANIC":
            v6 = self.bot.get_cog("ProtectionV6Cog")
            if v6 is not None:
                await v6._activate_panic(guild, None, f"Guardian v7 predictive state reached PANIC at score {score}/100")

    async def privilege_paths(self, guild: discord.Guild) -> list[dict[str, Any]]:
        result = []
        bot_member = guild.me
        for member in guild.members:
            if member.bot or not (member.guild_permissions.manage_roles or member.guild_permissions.administrator):
                continue
            for role in guild.roles:
                if role.is_default() or role.managed or role >= member.top_role:
                    continue
                if not any(getattr(role.permissions, name, False) for name in DANGEROUS):
                    continue
                result.append({
                    "member_id": member.id, "member": str(member), "target_role": role.name,
                    "target_role_id": role.id, "guardian_can_revoke": bool(bot_member and role < bot_member.top_role),
                })
                if len(result) >= 100:
                    return result
        return result

    async def trust_graph(self, guild: discord.Guild) -> str:
        recovery_rows = await self.bot.database.fetchall(
            "SELECT user_id FROM guardian_v7_recovery_team WHERE guild_id=?", (guild.id,)
        )
        recovery = {int(row["user_id"]) for row in recovery_rows}
        incidents = await self.bot.database.fetchall(
            "SELECT actor_id,SUM(score) AS score FROM guardian_v6_events WHERE guild_id=? "
            "AND actor_id IS NOT NULL AND created_at>=datetime('now','-1 day') GROUP BY actor_id",
            (guild.id,),
        )
        weights = {int(row["actor_id"]): int(row["score"] or 0) for row in incidents}
        protected = await self.bot.database.fetchall(
            "SELECT asset_id FROM guardian_v7_assets WHERE guild_id=? AND asset_type='role'", (guild.id,)
        )
        protected_ids = {int(row["asset_id"]) for row in protected}
        scored = []
        for member in guild.members:
            if member.bot:
                continue
            age = max(0, (datetime.now(UTC) - member.created_at).days)
            pr = sum(role.id in protected_ids for role in member.roles)
            scored.append((trust_score(age, weights.get(member.id, 0), pr, member.id in recovery or member.id == guild.owner_id), member))
        scored.sort(key=lambda item: item[0])
        paths = await self.privilege_paths(guild)
        lines = ["**Guardian v7 trust graph**", f"Privilege-escalation paths: {len(paths)}", "Lowest trust scores:"]
        lines += [f"• {member} ({member.id}) — trust {score}/100" for score, member in scored[:8]]
        return "\n".join(lines)[:4000]

    async def _asset(self, guild_id: int, kind: str, asset_id: int):
        return await self.bot.database.fetchone(
            "SELECT * FROM guardian_v7_assets WHERE guild_id=? AND asset_type=? AND asset_id=?",
            (guild_id, kind, asset_id),
        )

    async def _asset_violation(self, guild: discord.Guild, actor: discord.User | discord.Member | None, kind: str, asset_id: int, detail: str, canary: bool) -> None:
        await self._evidence(
            guild.id, actor.id if actor else None, "CANARY_TRIGGERED" if canary else "PROTECTED_ASSET_TAMPER",
            asset_id, {"asset_type": kind, "detail": detail},
        )
        v6 = self.bot.get_cog("ProtectionV6Cog")
        if v6 is not None:
            await v6._signal(
                guild, actor, "guardian_tamper",
                f"Guardian v7 {'canary' if canary else 'protected asset'} triggered: {kind} {asset_id}; {detail}",
                target_id=asset_id, score=14 if canary else 10,
            )

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        row = await self._asset(after.guild.id, "channel", after.id)
        if row is None:
            return
        v6 = self.bot.get_cog("ProtectionV6Cog")
        actor = await v6._audit_executor(after.guild, discord.AuditLogAction.channel_update, after.id) if v6 else None
        if actor is not None and await self._is_recovery(after.guild, actor) and not row["canary"]:
            return
        await self._asset_violation(after.guild, actor, "channel", after.id, f"Protected channel changed: {after.name}", bool(row["canary"]))
        if v6:
            await v6._heal_channel(after)

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        row = await self._asset(channel.guild.id, "channel", channel.id)
        if row is None:
            return
        v6 = self.bot.get_cog("ProtectionV6Cog")
        actor = await v6._audit_executor(channel.guild, discord.AuditLogAction.channel_delete, channel.id) if v6 else None
        await self._asset_violation(channel.guild, actor, "channel", channel.id, f"Protected channel deleted: {channel.name}", bool(row["canary"]))

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        row = await self._asset(after.guild.id, "role", after.id)
        if row is None:
            return
        v6 = self.bot.get_cog("ProtectionV6Cog")
        actor = await v6._audit_executor(after.guild, discord.AuditLogAction.role_update, after.id) if v6 else None
        if actor is not None and await self._is_recovery(after.guild, actor) and not row["canary"]:
            return
        await self._asset_violation(after.guild, actor, "role", after.id, f"Protected role changed: {after.name}", bool(row["canary"]))
        if v6:
            await v6._heal_role(after)

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        row = await self._asset(role.guild.id, "role", role.id)
        if row is None:
            return
        v6 = self.bot.get_cog("ProtectionV6Cog")
        actor = await v6._audit_executor(role.guild, discord.AuditLogAction.role_delete, role.id) if v6 else None
        await self._asset_violation(role.guild, actor, "role", role.id, f"Protected role deleted: {role.name}", bool(row["canary"]))

    @tasks.loop(seconds=10)
    async def ingest_loop(self) -> None:
        for guild in list(self.bot.guilds):
            rows = await self.bot.database.fetchall(
                "SELECT event_id,actor_id,kind,score,detail,target_id,created_at FROM guardian_v6_events "
                "WHERE guild_id=? AND event_id>? ORDER BY event_id ASC LIMIT 500",
                (guild.id, self.last_event[guild.id]),
            )
            for row in rows:
                await self._ingest(guild, row)
                self.last_event[guild.id] = max(self.last_event[guild.id], int(row["event_id"]))

    @ingest_loop.before_loop
    async def before_ingest_loop(self) -> None:
        await self.bot.wait_until_ready()
        for guild in list(self.bot.guilds):
            row = await self.bot.database.fetchone(
                "SELECT MAX(event_id) AS max_id FROM guardian_v6_events WHERE guild_id=?", (guild.id,)
            )
            self.last_event[guild.id] = int(row["max_id"] or 0) if row else 0

    @tasks.loop(seconds=20)
    async def state_loop(self) -> None:
        health = getattr(self.bot, "runtime_health", {})
        minimal = not bool(health.get("database_ok", True)) or float(health.get("event_loop_lag_ms", 0) or 0) >= 1500
        setattr(self.bot, "guardian_minimal_mode", minimal)
        for guild in list(self.bot.guilds):
            config = await self._config(guild.id)
            profile = str(config["profile"])
            score = self.score(guild.id)
            if profile == "custom" and all(config[name] is not None for name in ("custom_elevated", "custom_high", "custom_critical", "custom_panic")):
                thresholds = {
                    "elevated": int(config["custom_elevated"]),
                    "high": int(config["custom_high"]),
                    "critical": int(config["custom_critical"]),
                    "panic": int(config["custom_panic"]),
                }
                if score >= thresholds["panic"]:
                    new_state = "PANIC"
                elif score >= thresholds["critical"]:
                    new_state = "CRITICAL"
                elif score >= thresholds["high"]:
                    new_state = "HIGH"
                elif score >= thresholds["elevated"]:
                    new_state = "ELEVATED"
                else:
                    new_state = "NORMAL"
            else:
                new_state = state_from_score(score, profile)
            if minimal and STATE_ORDER.index(new_state) < STATE_ORDER.index("HIGH"):
                new_state = "HIGH"
            await self._set_state(guild, new_state, score)

    @state_loop.before_loop
    async def before_state_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=1)
    async def watch_loop(self) -> None:
        for guild in list(self.bot.guilds):
            rows = await self.bot.database.fetchall(
                "SELECT asset_type,asset_id,label,canary FROM guardian_v7_assets WHERE guild_id=?", (guild.id,)
            )
            for row in rows:
                kind, asset_id = str(row["asset_type"]), int(row["asset_id"])
                exists = guild.get_channel(asset_id) is not None if kind == "channel" else guild.get_role(asset_id) is not None if kind == "role" else guild.get_member(asset_id) is not None
                if not exists:
                    await self._asset_violation(guild, None, kind, asset_id, f"Protected asset missing: {row['label'] or asset_id}", bool(row["canary"]))

    @watch_loop.before_loop
    async def before_watch_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(seconds=30)
    async def temp_role_loop(self) -> None:
        now = datetime.now(UTC)
        rows = await self.bot.database.fetchall("SELECT * FROM guardian_v7_temp_roles")
        for row in rows:
            try:
                expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
            except ValueError:
                expires = now
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires > now:
                continue
            guild = self.bot.get_guild(int(row["guild_id"]))
            if guild:
                member, role = guild.get_member(int(row["user_id"])), guild.get_role(int(row["role_id"]))
                if member and role and role in member.roles:
                    try:
                        await member.remove_roles(role, reason="Guardian v7 temporary/JIT staff access expired")
                    except (discord.Forbidden, discord.HTTPException):
                        pass
            await self.bot.database.execute(
                "DELETE FROM guardian_v7_temp_roles WHERE guild_id=? AND user_id=? AND role_id=?",
                (row["guild_id"], row["user_id"], row["role_id"]),
            )

    @temp_role_loop.before_loop
    async def before_temp_role_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def dashboard_payload(self) -> dict[str, Any]:
        guilds = []
        for guild in list(self.bot.guilds):
            chain = await self.verify_chain(guild.id)
            backup = self.bot.database.backup_info()
            guilds.append({
                "guild_id": guild.id, "name": guild.name, "state": self.state[guild.id],
                "risk_score": self.score(guild.id), "evidence_chain_ok": chain["ok"],
                "backup_count": int(backup.get("count", 0) or 0), "backup_latest_at": backup.get("latest_at"),
            })
        health = dict(getattr(self.bot, "runtime_health", {}))
        if isinstance(health.get("last_check"), datetime):
            health["last_check"] = health["last_check"].isoformat()
        return {
            "guardian": "ESN Guardian", "version": "v7 MAX", "online": not self.bot.is_closed(),
            "minimal_mode": bool(getattr(self.bot, "guardian_minimal_mode", False)),
            "runtime": health, "guilds": guilds, "generated_at": datetime.now(UTC).isoformat(),
        }

    @tasks.loop(seconds=30)
    async def dashboard_loop(self) -> None:
        payload = await self.dashboard_payload()
        path = Path("data") / "guardian_status.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        temp.replace(path)

    @dashboard_loop.before_loop
    async def before_dashboard_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def _start_dashboard_server(self) -> None:
        raw = os.getenv("GUARDIAN_DASHBOARD_PORT", "").strip()
        if not raw:
            return
        try:
            port = int(raw)
        except ValueError:
            return
        from aiohttp import web
        async def health(request: web.Request) -> web.Response:
            token = os.getenv("GUARDIAN_DASHBOARD_TOKEN", "")
            if token and not hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + token):
                raise web.HTTPUnauthorized()
            return web.json_response(await self.dashboard_payload())
        app = web.Application()
        app.router.add_get("/health", health)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self.dashboard_runner = runner

    def _subject_hash(self, value: str) -> str:
        salt = os.getenv("GUARDIAN_INTEL_SALT", "guardian-local").encode()
        return hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()

    @tasks.loop(minutes=10)
    async def remote_sync_loop(self) -> None:
        endpoint = os.getenv("GUARDIAN_THREAT_INTEL_ENDPOINT", "").strip()
        if not endpoint or self.session is None:
            return
        rows = await self.bot.database.fetchall(
            "SELECT subject_type,subject_key,reputation,evidence_count FROM guardian_v7_reputation "
            "WHERE reputation<0 ORDER BY updated_at DESC LIMIT 100"
        )
        payload = {
            "source": "ESN Guardian v7",
            "subjects": [
                {"type": row["subject_type"], "hash": self._subject_hash(str(row["subject_key"])),
                 "reputation": int(row["reputation"]), "evidence_count": int(row["evidence_count"])}
                for row in rows
            ],
        }
        headers = {}
        token = os.getenv("GUARDIAN_THREAT_INTEL_TOKEN", "")
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            async with self.session.post(endpoint, json=payload, headers=headers) as response:
                if response.status >= 400:
                    LOG.warning("Guardian threat-intel endpoint returned %s", response.status)
        except Exception:
            LOG.warning("Guardian threat-intel sync failed", exc_info=True)

    @remote_sync_loop.before_loop
    async def before_remote_sync_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def offhost_backup(self) -> str:
        endpoint = os.getenv("GUARDIAN_BACKUP_ENDPOINT", "").strip()
        if not endpoint or self.session is None:
            return "not configured"
        encryption_key = os.getenv("GUARDIAN_BACKUP_ENCRYPTION_KEY", "").strip()
        if not encryption_key:
            return "encryption key not configured"
        try:
            cipher = Fernet(encryption_key.encode("utf-8"))
        except Exception:
            return "invalid encryption key"
        backup = await self.bot.database.backup("v7-offhost")
        if backup is None:
            return "backup unavailable"
        encrypted = cipher.encrypt(backup.read_bytes())
        data = aiohttp.FormData()
        data.add_field(
            "backup",
            encrypted,
            filename=backup.name + ".fernet",
            content_type="application/octet-stream",
        )
        headers = {}
        token = os.getenv("GUARDIAN_BACKUP_TOKEN", "")
        if token:
            headers["Authorization"] = "Bearer " + token
        async with self.session.post(endpoint, data=data, headers=headers) as response:
            return "encrypted upload complete" if response.status < 400 else f"HTTP {response.status}"

    async def simulate_role_permission(self, guild: discord.Guild, role: discord.Role, permission_name: str) -> dict[str, Any]:
        if permission_name not in DANGEROUS:
            raise ValueError("Unsupported permission")
        holders = [member for member in role.members if not member.bot]
        reachable_roles = []
        if permission_name in {"administrator", "manage_roles"}:
            for target in guild.roles:
                if target.is_default() or target.managed or target >= role:
                    continue
                if any(getattr(target.permissions, name, False) for name in DANGEROUS):
                    reachable_roles.append(target)
        bot_member = guild.me
        guardian_can_revoke = bool(bot_member and role < bot_member.top_role)
        return {
            "permission": permission_name,
            "holders": len(holders),
            "holder_ids": [member.id for member in holders[:25]],
            "reachable_dangerous_roles": len(reachable_roles),
            "reachable_names": [target.name for target in reachable_roles[:20]],
            "guardian_can_revoke": guardian_can_revoke,
            "risk": (
                "CRITICAL"
                if permission_name == "administrator"
                else "HIGH"
                if permission_name in {"manage_roles", "manage_guild", "manage_webhooks"}
                else "ELEVATED"
            ),
        }

    async def chaos_report(self, guild: discord.Guild) -> str:
        from esn_guardian.cogs.security_v6 import (
            adaptive_risk_score,
            attack_chain_score,
            raid_fingerprint_score,
            scam_text_score,
        )
        chain = attack_chain_score(["webhook_change", "permission_escalation", "channel_delete"])
        raid = raid_fingerprint_score([0, 0, 1, 1, 2, 2], ["raider"] * 6)
        risk = adaptive_risk_score(
            account_age_days=0,
            weighted_cases=18,
            dangerous_roles=1,
            failed_verifications=2,
            external_app_events=1,
            raid_cluster_score=10,
        )
        scam = scam_text_score(
            "Free Nitro! Verify your account and scan this QR: https://bit.ly/example",
            ("verify-qr.png",),
        )
        modules = all(
            self.bot.get_cog(name) is not None
            for name in ("SecurityCog", "AdvancedSecurityCog", "ProtectionV6Cog", "SecurityV7Cog")
        )
        checks = {
            "compromised staff attack chain": chain >= 28,
            "coordinated young-account raid": raid >= 18,
            "adaptive high-risk account": risk >= 75,
            "QR/link scam composite": scam >= 7,
            "critical protection modules loaded": modules,
        }
        return (
            "**Guardian v7 non-destructive chaos test**\n"
            + "\n".join(f"• {'PASS' if ok else 'FAIL'} — {name}" for name, ok in checks.items())
            + f"\nAttack-chain score: {chain} • Raid score: {raid} • Account risk: {risk} • Scam score: {scam}"
        )

    async def benchmark(self, guild: discord.Guild) -> dict[str, Any]:
        checks = []
        bot_member = guild.me
        for permission in ("view_audit_log", "manage_messages", "moderate_members", "kick_members", "ban_members", "manage_roles", "manage_channels", "manage_webhooks"):
            checks.append((permission, bool(bot_member and getattr(bot_member.guild_permissions, permission, False))))
        for cog_name in ("SecurityCog", "AdvancedSecurityCog", "SecuritySentinelCog", "SecurityOverwatchCog", "SecurityResilienceCog", "ProtectionV6Cog", "SecurityV7Cog"):
            checks.append((cog_name, self.bot.get_cog(cog_name) is not None))
        try:
            checks.append(("database_integrity", await self.bot.database.quick_check()))
        except Exception:
            checks.append(("database_integrity", False))
        chain = await self.verify_chain(guild.id)
        checks.append(("evidence_chain", bool(chain["ok"])))
        backup = self.bot.database.backup_info()
        checks.append(("backup_exists", int(backup.get("count", 0) or 0) > 0))
        paths = await self.privilege_paths(guild)
        checks.append(("no_uncontainable_privilege_paths", not any(not path["guardian_can_revoke"] for path in paths)))
        passed = sum(ok for _, ok in checks)
        score = round(100 * passed / max(1, len(checks)))
        return {"score": score, "grade": "S" if score >= 95 else "A" if score >= 88 else "B" if score >= 75 else "C" if score >= 60 else "F", "checks": checks, "paths": paths}

    async def replay(self, guild_id: int) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT evidence_id,actor_id,event_kind,target_id,created_at FROM guardian_v7_evidence "
            "WHERE guild_id=? ORDER BY evidence_id DESC LIMIT 30",
            (guild_id,),
        )
        if not rows:
            return "**Guardian v7 incident replay**\nNo evidence events recorded yet."
        lines = ["**Guardian v7 incident replay**"]
        for row in reversed(rows):
            lines.append(
                f"• {row['created_at']} UTC — {row['event_kind']} actor={row['actor_id'] or 'unknown'} target={row['target_id'] or 'none'}"
            )
        return "\n".join(lines)[:4000]

    @shield.command(name="status", description="Show Guardian v7 predictive protection status.")
    @guild_only()
    @staff_only()
    async def shield_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        chain = await self.verify_chain(interaction.guild.id)
        config = await self._config(interaction.guild.id)
        paths = await self.privilege_paths(interaction.guild)
        await respond(interaction, (
            "**Guardian Protection v7 MAX**\n"
            f"State: {self.state[interaction.guild.id]}\n"
            f"Predictive risk: {self.score(interaction.guild.id)}/100\n"
            f"Policy: {config['profile']}\n"
            f"Emergency minimal mode: {'ACTIVE' if getattr(self.bot, 'guardian_minimal_mode', False) else 'standby'}\n"
            f"Evidence chain: {'VERIFIED' if chain['ok'] else 'FAILED'} ({chain['checked']} records)\n"
            f"Privilege paths: {len(paths)}\n"
            f"Two-person catastrophic approval: {'ON' if config['two_person'] else 'OFF'}\n"
            f"Off-host backup: {'configured' if os.getenv('GUARDIAN_BACKUP_ENDPOINT') else 'not configured'}\n"
            f"External watchdog API: {'enabled' if os.getenv('GUARDIAN_DASHBOARD_PORT') else 'status-file only'}"
        ))

    @shield.command(name="profile", description="Set Guardian v7 policy profile.")
    @app_commands.choices(profile=[
        app_commands.Choice(name="Community", value="community"),
        app_commands.Choice(name="High Security", value="high"),
        app_commands.Choice(name="Maximum Lockdown", value="maximum"),
    ])
    @guild_only()
    @guild_owner_only()
    async def shield_profile(self, interaction: discord.Interaction, profile: app_commands.Choice[str]) -> None:
        policy = POLICIES[profile.value]
        await self.bot.database.execute(
            "INSERT INTO guardian_v7_config (guild_id,profile,two_person) VALUES (?,?,?) "
            "ON CONFLICT(guild_id) DO UPDATE SET profile=excluded.profile,two_person=excluded.two_person,updated_at=CURRENT_TIMESTAMP",
            (interaction.guild_id, profile.value, int(policy["two_person"])),
        )
        await respond(interaction, f"Guardian v7 profile set to {profile.name}.")

    @shield.command(name="custom-policy", description="Set custom Guardian v7 predictive state thresholds.")
    @guild_only()
    @guild_owner_only()
    async def custom_policy(
        self,
        interaction: discord.Interaction,
        elevated: app_commands.Range[int, 5, 70],
        high: app_commands.Range[int, 10, 80],
        critical: app_commands.Range[int, 15, 90],
        panic: app_commands.Range[int, 20, 100],
        two_person: bool = True,
    ) -> None:
        if not (elevated < high < critical < panic):
            await respond(interaction, "Thresholds must increase in order: elevated < high < critical < panic.")
            return
        await self.bot.database.execute(
            "UPDATE guardian_v7_config SET profile='custom',two_person=?,custom_elevated=?,custom_high=?,"
            "custom_critical=?,custom_panic=?,updated_at=CURRENT_TIMESTAMP WHERE guild_id=?",
            (1 if two_person else 0, elevated, high, critical, panic, interaction.guild_id),
        )
        await respond(
            interaction,
            f"Custom Guardian v7 policy saved: ELEVATED {elevated}, HIGH {high}, CRITICAL {critical}, PANIC {panic}.",
        )

    @shield.command(name="approve", description="Approve another staff member's protected catastrophic action.")
    @guild_only()
    async def shield_approve(self, interaction: discord.Interaction, code: str) -> None:
        assert interaction.guild is not None
        if not await self._is_recovery(interaction.guild, interaction.user):
            await respond(interaction, "Only the server owner or Guardian recovery team can approve protected actions.")
            return
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_v7_approvals WHERE approval_code=? AND guild_id=?",
            (code.upper(), interaction.guild.id),
        )
        if row is None:
            await respond(interaction, "That approval code does not exist.")
            return
        if int(row["requester_id"]) == interaction.user.id:
            await respond(interaction, "You cannot approve your own protected action.")
            return
        expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= datetime.now(UTC) or row["consumed"]:
            await respond(interaction, "That approval expired or was already consumed.")
            return
        await self.bot.database.execute(
            "UPDATE guardian_v7_approvals SET approver_id=? WHERE approval_code=?",
            (interaction.user.id, code.upper()),
        )
        await respond(interaction, f"Approved /{row['command_name']} for <@{row['requester_id']}>. They can rerun it now.")

    @shield.command(name="protect-channel", description="Protect a critical channel/category.")
    @guild_only()
    @guild_owner_only()
    async def protect_channel(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_v7_assets (guild_id,asset_type,asset_id,label,canary,created_by_id) VALUES (?,'channel',?,?,0,?)",
            (interaction.guild_id, channel.id, channel.name, interaction.user.id),
        )
        await respond(interaction, f"{channel.mention} is now protected by Guardian v7.")

    @shield.command(name="protect-role", description="Protect a critical role.")
    @guild_only()
    @guild_owner_only()
    async def protect_role(self, interaction: discord.Interaction, role: discord.Role) -> None:
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_v7_assets (guild_id,asset_type,asset_id,label,canary,created_by_id) VALUES (?,'role',?,?,0,?)",
            (interaction.guild_id, role.id, role.name, interaction.user.id),
        )
        await respond(interaction, f"{role.mention} is now protected by Guardian v7.")

    @shield.command(name="canary", description="Create Guardian honeypot canary assets.")
    @guild_only()
    @guild_owner_only()
    async def canary(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        role = await guild.create_role(name="Guardian Canary • DO NOT TOUCH", permissions=discord.Permissions.none(), mentionable=False, reason="Guardian v7 canary")
        overwrites = {guild.default_role: discord.PermissionOverwrite(view_channel=False)}
        if guild.me:
            overwrites[guild.me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)
        channel = await guild.create_text_channel("guardian-canary", overwrites=overwrites, reason="Guardian v7 canary")
        for kind, asset_id, label in (("role", role.id, role.name), ("channel", channel.id, channel.name)):
            await self.bot.database.execute(
                "INSERT OR REPLACE INTO guardian_v7_assets (guild_id,asset_type,asset_id,label,canary,created_by_id) VALUES (?,?,?,?,1,?)",
                (guild.id, kind, asset_id, label, interaction.user.id),
            )
        await respond(interaction, f"Guardian v7 canaries created: {role.name} and {channel.mention}. Legitimate staff should never modify them.")

    @shield.command(name="simulate-role", description="Simulate the risk of granting a dangerous permission to a role.")
    @app_commands.choices(permission=[
        app_commands.Choice(name="Administrator", value="administrator"),
        app_commands.Choice(name="Manage Server", value="manage_guild"),
        app_commands.Choice(name="Manage Roles", value="manage_roles"),
        app_commands.Choice(name="Manage Channels", value="manage_channels"),
        app_commands.Choice(name="Manage Webhooks", value="manage_webhooks"),
        app_commands.Choice(name="Ban Members", value="ban_members"),
        app_commands.Choice(name="Kick Members", value="kick_members"),
        app_commands.Choice(name="Moderate Members", value="moderate_members"),
    ])
    @guild_only()
    @staff_only()
    async def simulate_role(
        self,
        interaction: discord.Interaction,
        role: discord.Role,
        permission: app_commands.Choice[str],
    ) -> None:
        assert interaction.guild is not None
        data = await self.simulate_role_permission(interaction.guild, role, permission.value)
        await respond(
            interaction,
            (
                f"**Guardian permission simulation — {role.name}**\n"
                f"Proposed permission: {permission.name}\n"
                f"Risk: {data['risk']}\n"
                f"Members inheriting it: {data['holders']}\n"
                f"Dangerous roles reachable: {data['reachable_dangerous_roles']}\n"
                f"Guardian can revoke this role: {'yes' if data['guardian_can_revoke'] else 'NO'}\n"
                f"Reachable roles: {', '.join(data['reachable_names']) if data['reachable_names'] else 'none'}"
            ),
        )

    @shield.command(name="chaos-test", description="Safely simulate attack scenarios without changing the server.")
    @guild_only()
    @staff_only()
    async def chaos_test(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await respond(interaction, await self.chaos_report(interaction.guild))

    @shield.command(name="reputation", description="Show Guardian's cross-server application, bot, or webhook reputation.")
    @app_commands.choices(subject_type=[
        app_commands.Choice(name="Application", value="application"),
        app_commands.Choice(name="Bot", value="bot"),
        app_commands.Choice(name="Webhook", value="webhook"),
    ])
    @guild_only()
    @staff_only()
    async def reputation(
        self,
        interaction: discord.Interaction,
        subject_type: app_commands.Choice[str],
        subject_id: str,
    ) -> None:
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_v7_reputation WHERE subject_type=? AND subject_key=?",
            (subject_type.value, subject_id),
        )
        if row is None:
            await respond(interaction, "Guardian has no negative reputation evidence for that subject.")
            return
        await respond(
            interaction,
            (
                f"**Guardian reputation — {subject_type.name} {subject_id}**\n"
                f"Score: {row['reputation']} (0 is neutral; more negative is worse)\n"
                f"Evidence count: {row['evidence_count']}\n"
                f"Latest reason: {row['last_reason']}"
            ),
        )

    @shield.command(name="benchmark", description="Run a safe non-destructive Guardian protection benchmark.")
    @guild_only()
    @staff_only()
    async def benchmark_cmd(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        result = await self.benchmark(interaction.guild)
        failed = [name for name, ok in result["checks"] if not ok]
        await respond(interaction, (
            f"**Guardian v7 benchmark**\nScore: {result['score']}/100 • Grade {result['grade']}\n"
            f"Privilege paths: {len(result['paths'])}\nFailed checks: {', '.join(failed) if failed else 'none'}"
        ))

    @shield.command(name="replay", description="Replay the latest Guardian evidence timeline.")
    @guild_only()
    @staff_only()
    async def replay_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self.replay(interaction.guild_id))

    @shield.command(name="trust-graph", description="Show Guardian's trust graph.")
    @guild_only()
    @staff_only()
    async def trust_graph_cmd(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await respond(interaction, await self.trust_graph(interaction.guild))

    @shield.command(name="privilege-paths", description="Show dangerous role-escalation paths.")
    @guild_only()
    @staff_only()
    async def privilege_paths_cmd(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        paths = await self.privilege_paths(interaction.guild)
        if not paths:
            await respond(interaction, "No direct Manage Roles to dangerous-role escalation paths detected.")
            return
        lines = ["**Guardian v7 privilege paths**"]
        for path in paths[:20]:
            lines.append(
                f"• {path['member']} ({path['member_id']}) -> {path['target_role']} • Guardian revoke: {'yes' if path['guardian_can_revoke'] else 'NO'}"
            )
        await respond(interaction, "\n".join(lines)[:4000])

    @shield.command(name="recovery-add", description="Add a trusted Guardian recovery-team member.")
    @guild_only()
    @guild_owner_only()
    async def recovery_add(self, interaction: discord.Interaction, member: discord.Member) -> None:
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_v7_recovery_team (guild_id,user_id,added_by_id) VALUES (?,?,?)",
            (interaction.guild_id, member.id, interaction.user.id),
        )
        await respond(interaction, f"{member.mention} is now a Guardian recovery-team member. They still cannot disable Guardian.")

    @shield.command(name="recovery-remove", description="Remove a Guardian recovery-team member.")
    @guild_only()
    @guild_owner_only()
    async def recovery_remove(self, interaction: discord.Interaction, member: discord.Member) -> None:
        await self.bot.database.execute(
            "DELETE FROM guardian_v7_recovery_team WHERE guild_id=? AND user_id=?",
            (interaction.guild_id, member.id),
        )
        await respond(interaction, f"{member.mention} was removed from the Guardian recovery team.")

    @shield.command(name="temp-role", description="Grant an existing staff role temporarily.")
    @guild_only()
    @guild_owner_only()
    async def temp_role(self, interaction: discord.Interaction, member: discord.Member, role: discord.Role, minutes: app_commands.Range[int, 1, 1440]) -> None:
        assert interaction.guild is not None
        bot_member = interaction.guild.me
        if role.is_default() or role.managed or bot_member is None or role >= bot_member.top_role:
            await respond(interaction, "Guardian cannot safely manage that role.")
            return
        expires = datetime.now(UTC) + timedelta(minutes=int(minutes))
        await member.add_roles(role, reason=f"Guardian v7 JIT staff access for {minutes} minutes")
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_v7_temp_roles (guild_id,user_id,role_id,granted_by_id,expires_at) VALUES (?,?,?,?,?)",
            (interaction.guild.id, member.id, role.id, interaction.user.id, expires.isoformat()),
        )
        await respond(interaction, f"Granted {role.mention} to {member.mention} until {discord.utils.format_dt(expires, style='R')}.")

    @shield.command(name="review", description="Mark a Guardian case or v7 event as a false positive.")
    @app_commands.choices(source_type=[
        app_commands.Choice(name="Case", value="case"),
        app_commands.Choice(name="V7 event", value="event"),
    ])
    @guild_only()
    @guild_owner_only()
    async def review(self, interaction: discord.Interaction, source_type: app_commands.Choice[str], source_id: int, reason: str = "Approved legitimate activity") -> None:
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_v7_false_positives "
            "(guild_id,source_type,source_id,reviewed_by_id,reason) VALUES (?,?,?,?,?)",
            (interaction.guild_id, source_type.value, source_id, interaction.user.id, reason[:500]),
        )
        await self._evidence(interaction.guild_id, interaction.user.id, "FALSE_POSITIVE_REVIEW", source_id, {"source_type": source_type.value, "reason": reason[:500]})
        if source_type.value == "event":
            event_row = await self.bot.database.fetchone(
                "SELECT event_id,kind,target_id FROM guardian_v6_events WHERE guild_id=? AND event_id=?",
                (interaction.guild_id, source_id),
            )
            if event_row is not None:
                self.recent[interaction.guild_id] = deque(
                    event for event in self.recent[interaction.guild_id]
                    if int(event["event_id"]) != source_id
                )
                kind = str(event_row["kind"])
                target_id = event_row["target_id"]
                subject_type = (
                    "application" if kind == "external_app"
                    else "bot" if kind == "unapproved_bot"
                    else "webhook" if kind == "webhook_change"
                    else None
                )
                if subject_type is not None and target_id is not None:
                    reputation_row = await self.bot.database.fetchone(
                        "SELECT reputation FROM guardian_v7_reputation WHERE subject_type=? AND subject_key=?",
                        (subject_type, str(target_id)),
                    )
                    if reputation_row is not None:
                        adjusted = min(0, int(reputation_row["reputation"]) + 20)
                        await self.bot.database.execute(
                            "UPDATE guardian_v7_reputation SET reputation=?,last_reason=? WHERE subject_type=? AND subject_key=?",
                            (adjusted, "False-positive review: " + reason[:300], subject_type, str(target_id)),
                        )
        await respond(interaction, f"Marked {source_type.name} #{source_id} as reviewed/legitimate and recalibrated current v7 risk where applicable.")

    @shield.command(name="integrity", description="Verify Guardian's cryptographic incident evidence chain.")
    @guild_only()
    @staff_only()
    async def integrity(self, interaction: discord.Interaction) -> None:
        result = await self.verify_chain(interaction.guild_id)
        await respond(interaction, f"Evidence chain: {'VERIFIED' if result['ok'] else 'FAILED'}\nChecked: {result['checked']}\n{result['reason']}")

    @shield.command(name="backup-offhost", description="Replicate a verified database backup to the configured external endpoint.")
    @guild_only()
    @guild_owner_only()
    async def backup_offhost(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, "Off-host backup result: " + await self.offhost_backup())


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityV7Cog(bot))
