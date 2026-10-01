from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, log_event, respond, staff_only
from esn_guardian.cogs.security_intelligence import case_weight

LOG = logging.getLogger("esn_guardian.sentinel")

IGNORED_ACTION_PREFIXES = ("SENTINEL_",)


def classify_action(action: str) -> str:
    a = action.upper()
    if any(token in a for token in ("DELETE", "BAN", "KICK", "NUKE", "LOCKDOWN", "MASS_", "DESTROY")):
        return "destructive"
    if any(token in a for token in ("ROLE", "PERMISSION", "ADMIN", "PRIVILEGE", "OWNER")):
        return "privilege"
    if any(token in a for token in ("WEBHOOK", "INTEGRATION", "BOT_", "EXTERNAL_APP", "AUTOMATION")):
        return "automation"
    if any(token in a for token in ("TAMPER", "INTEGRITY", "POLICY_DRIFT", "LEDGER")):
        return "tamper"
    if any(token in a for token in ("PANIC", "ROLLBACK", "RESTORE", "RECOVERY", "BACKUP")):
        return "recovery"
    if any(token in a for token in ("RAID", "FLOOD", "SPAM", "MENTION", "INVITE", "LINK")):
        return "abuse"
    if any(token in a for token in ("CREDENTIAL", "TOKEN", "SECRET")):
        return "credential"
    return "other"


def anomaly_score(
    *,
    base_weight: int,
    burst_count: int,
    category_count: int,
    target_count: int,
    subject_case_count: int,
    rare_action: bool,
) -> int:
    score = max(0, int(base_weight)) * 5
    score += max(0, burst_count - 2) * 4
    score += max(0, category_count - 1) * 9
    score += max(0, target_count - 2) * 3
    score += min(15, max(0, subject_case_count - 3) * 2)
    if rare_action:
        score += 8
    return max(0, min(100, score))


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "ELEVATED"
    if score >= 15:
        return "WATCH"
    return "NORMAL"


def chain_summary(categories: set[str]) -> str:
    ordered = [
        name
        for name in (
            "privilege",
            "automation",
            "tamper",
            "destructive",
            "recovery",
            "credential",
            "abuse",
            "other",
        )
        if name in categories
    ]
    return " -> ".join(ordered) if ordered else "none"


class SecuritySentinelCog(commands.Cog):
    """Behavior correlation and explainable anomaly intelligence for Guardian."""

    sentinel = app_commands.Group(
        name="sentinel",
        description="Guardian Sentinel behavioral threat intelligence.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        for statement in (
            """CREATE TABLE IF NOT EXISTS guardian_sentinel_state (
                guild_id INTEGER PRIMARY KEY,
                last_case_id INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_sentinel_signals (
                signal_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                case_id INTEGER NOT NULL,
                subject_id INTEGER,
                target_id INTEGER,
                action TEXT NOT NULL,
                category TEXT NOT NULL,
                score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                explanation_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, case_id)
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_sentinel_signals_guild
               ON guardian_sentinel_signals(guild_id, signal_id DESC)""",
            """CREATE TABLE IF NOT EXISTS guardian_sentinel_subject_profile (
                guild_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL,
                total_cases INTEGER NOT NULL DEFAULT 0,
                weighted_score INTEGER NOT NULL DEFAULT 0,
                last_action TEXT,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, subject_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_sentinel_action_baseline (
                guild_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, action)
            )""",
        ):
            await self.bot.database.execute(statement)
        await self._initialize_state()
        self.sentinel_loop.start()

    def cog_unload(self) -> None:
        self.sentinel_loop.cancel()

    async def _initialize_state(self) -> None:
        for guild in list(self.bot.guilds):
            row = await self.bot.database.fetchone(
                "SELECT 1 FROM guardian_sentinel_state WHERE guild_id = ?",
                (guild.id,),
            )
            if row is not None:
                continue
            latest = await self.bot.database.fetchone(
                "SELECT COALESCE(MAX(case_id), 0) AS max_case_id FROM cases WHERE guild_id = ?",
                (guild.id,),
            )
            last_case_id = int(latest["max_case_id"]) if latest is not None else 0
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO guardian_sentinel_state (guild_id, last_case_id) VALUES (?, ?)",
                (guild.id, last_case_id),
            )

    async def _recent_context(
        self,
        guild_id: int,
        subject_id: int | None,
        case_id: int,
    ) -> dict[str, Any]:
        if subject_id is None:
            return {
                "burst_count": 1,
                "category_count": 1,
                "target_count": 0,
                "subject_case_count": 0,
                "categories": set(),
            }

        rows = await self.bot.database.fetchall(
            "SELECT action, target_id FROM cases "
            "WHERE guild_id = ? AND moderator_id = ? AND case_id <= ? "
            "AND created_at >= datetime('now', '-5 minutes') "
            "ORDER BY case_id DESC LIMIT 50",
            (guild_id, subject_id, case_id),
        )
        categories = {classify_action(str(row["action"])) for row in rows}
        targets = {int(row["target_id"]) for row in rows if row["target_id"] is not None}
        profile = await self.bot.database.fetchone(
            "SELECT total_cases FROM guardian_sentinel_subject_profile WHERE guild_id = ? AND subject_id = ?",
            (guild_id, subject_id),
        )
        return {
            "burst_count": max(1, len(rows)),
            "category_count": max(1, len(categories)),
            "target_count": len(targets),
            "subject_case_count": int(profile["total_cases"]) if profile is not None else 0,
            "categories": categories,
        }

    async def _analyze_case(self, guild: discord.Guild, row: Any) -> dict[str, Any] | None:
        action = str(row["action"])
        if action.startswith(IGNORED_ACTION_PREFIXES):
            return None

        case_id = int(row["case_id"])
        target_id = int(row["target_id"]) if row["target_id"] is not None else None
        moderator_id = int(row["moderator_id"]) if row["moderator_id"] is not None else None
        bot_id = self.bot.user.id if self.bot.user else None
        subject_id = target_id if target_id is not None else (moderator_id if moderator_id != bot_id else None)
        category = classify_action(action)
        context = await self._recent_context(guild.id, subject_id, case_id)

        baseline = await self.bot.database.fetchone(
            "SELECT seen_count FROM guardian_sentinel_action_baseline WHERE guild_id = ? AND action = ?",
            (guild.id, action),
        )
        seen_count = int(baseline["seen_count"]) if baseline is not None else 0
        rare_action = seen_count < 2

        score = anomaly_score(
            base_weight=case_weight(action),
            burst_count=int(context["burst_count"]),
            category_count=int(context["category_count"]),
            target_count=int(context["target_count"]),
            subject_case_count=int(context["subject_case_count"]),
            rare_action=rare_action,
        )
        severity = severity_from_score(score)
        categories = set(context["categories"])
        categories.add(category)

        explanation = {
            "base_weight": case_weight(action),
            "burst_count": context["burst_count"],
            "category_count": context["category_count"],
            "target_count": context["target_count"],
            "subject_case_count": context["subject_case_count"],
            "rare_action": rare_action,
            "chain": chain_summary(categories),
        }

        await self.bot.database.execute(
            "INSERT INTO guardian_sentinel_signals "
            "(guild_id, case_id, subject_id, target_id, action, category, score, severity, explanation_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(guild_id, case_id) DO NOTHING",
            (
                guild.id,
                case_id,
                subject_id,
                target_id,
                action,
                category,
                score,
                severity,
                json.dumps(explanation, ensure_ascii=True, sort_keys=True),
            ),
        )
        await self.bot.database.execute(
            "INSERT INTO guardian_sentinel_action_baseline (guild_id, action, seen_count) VALUES (?, ?, 1) "
            "ON CONFLICT(guild_id, action) DO UPDATE SET "
            "seen_count=seen_count+1, last_seen_at=CURRENT_TIMESTAMP",
            (guild.id, action),
        )

        if subject_id is not None:
            await self.bot.database.execute(
                "INSERT INTO guardian_sentinel_subject_profile "
                "(guild_id, subject_id, total_cases, weighted_score, last_action) VALUES (?, ?, 1, ?, ?) "
                "ON CONFLICT(guild_id, subject_id) DO UPDATE SET "
                "total_cases=total_cases+1, weighted_score=weighted_score+excluded.weighted_score, "
                "last_action=excluded.last_action, last_seen_at=CURRENT_TIMESTAMP",
                (guild.id, subject_id, score, action),
            )

        if score >= 60:
            await log_event(
                self.bot,
                guild,
                "security_log_channel_id",
                f"Guardian Sentinel — {severity}",
                description=(
                    f"Case #{case_id}: {action}\n"
                    f"Actor: {subject_id or 'unknown'} • Target: {target_id or 'none'}\n"
                    f"Sentinel score: {score}/100\n"
                    f"Correlation chain: {explanation['chain']}\n"
                    "Sentinel is advisory; deterministic Guardian protections remain responsible for enforcement."
                ),
                color=discord.Color.red() if score >= 80 else discord.Color.orange(),
            )

        return {
            "case_id": case_id,
            "subject_id": subject_id,
            "target_id": target_id,
            "action": action,
            "category": category,
            "score": score,
            "severity": severity,
            "explanation": explanation,
        }

    async def _scan_guild(self, guild: discord.Guild) -> int:
        state = await self.bot.database.fetchone(
            "SELECT last_case_id FROM guardian_sentinel_state WHERE guild_id = ?",
            (guild.id,),
        )
        if state is None:
            await self._initialize_state()
            return 0

        last_case_id = int(state["last_case_id"])
        rows = await self.bot.database.fetchall(
            "SELECT case_id, target_id, moderator_id, action, reason, created_at "
            "FROM cases WHERE guild_id = ? AND case_id > ? ORDER BY case_id ASC LIMIT 250",
            (guild.id, last_case_id),
        )

        processed = 0
        newest = last_case_id
        for row in rows:
            newest = max(newest, int(row["case_id"]))
            try:
                await self._analyze_case(guild, row)
                processed += 1
            except Exception:
                LOG.exception("Sentinel failed to analyze case %s in guild %s", row["case_id"], guild.id)

        if newest != last_case_id:
            await self.bot.database.execute(
                "INSERT INTO guardian_sentinel_state (guild_id, last_case_id) VALUES (?, ?) "
                "ON CONFLICT(guild_id) DO UPDATE SET "
                "last_case_id=excluded.last_case_id, updated_at=CURRENT_TIMESTAMP",
                (guild.id, newest),
            )
        return processed

    async def live_report(self, guild: discord.Guild) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT signal_id, case_id, subject_id, target_id, action, category, score, severity, created_at "
            "FROM guardian_sentinel_signals WHERE guild_id = ? "
            "AND created_at >= datetime('now', '-30 minutes') "
            "ORDER BY signal_id DESC LIMIT 100",
            (guild.id,),
        )

        if not rows:
            return (
                "**Guardian Sentinel**\n"
                "No Sentinel signals were recorded in the last 30 minutes.\n"
                "Deterministic Guardian protections remain active independently of Sentinel."
            )

        highest = max(int(row["score"]) for row in rows)
        severity = severity_from_score(highest)
        actors = Counter(int(row["subject_id"]) for row in rows if row["subject_id"] is not None)
        categories = Counter(str(row["category"]) for row in rows)
        high = [row for row in rows if int(row["score"]) >= 60]

        return (
            "**Guardian Sentinel live intelligence**\n"
            f"30-minute signals: {len(rows)}\n"
            f"Highest anomaly score: {highest}/100 ({severity})\n"
            f"High/critical signals: {len(high)}\n"
            f"Distinct subjects: {len(actors)}\n"
            f"Top categories: {', '.join(f'{name}={count}' for name, count in categories.most_common(5)) or 'none'}\n"
            f"Most active subjects: {', '.join(f'{actor} ({count})' for actor, count in actors.most_common(5)) or 'none'}"
        )

    async def actor_report(self, guild: discord.Guild, subject_id: int) -> str:
        profile = await self.bot.database.fetchone(
            "SELECT total_cases, weighted_score, last_action, last_seen_at "
            "FROM guardian_sentinel_subject_profile WHERE guild_id = ? AND subject_id = ?",
            (guild.id, subject_id),
        )
        rows = await self.bot.database.fetchall(
            "SELECT case_id, action, category, score, severity, created_at "
            "FROM guardian_sentinel_signals "
            "WHERE guild_id = ? AND subject_id = ? ORDER BY signal_id DESC LIMIT 12",
            (guild.id, subject_id),
        )

        if profile is None and not rows:
            return f"Sentinel has no behavioral profile for actor {subject_id} in this server."

        categories = Counter(str(row["category"]) for row in rows)
        recent_peak = max((int(row["score"]) for row in rows), default=0)

        return (
            f"**Sentinel subject profile — {subject_id}**\n"
            f"Observed cases: {int(profile['total_cases']) if profile else len(rows)}\n"
            f"Accumulated anomaly weight: {int(profile['weighted_score']) if profile else sum(int(r['score']) for r in rows)}\n"
            f"Recent peak: {recent_peak}/100 ({severity_from_score(recent_peak)})\n"
            f"Recent categories: {', '.join(f'{k}={v}' for k, v in categories.most_common()) or 'none'}\n"
            f"Last action: {profile['last_action'] if profile else rows[0]['action']}\n"
            f"Last seen: {profile['last_seen_at'] if profile else rows[0]['created_at']} UTC"
        )

    async def signals_report(self, guild_id: int, limit: int = 8) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT signal_id, case_id, subject_id, action, score, severity, explanation_json, created_at "
            "FROM guardian_sentinel_signals WHERE guild_id = ? "
            "ORDER BY signal_id DESC LIMIT ?",
            (guild_id, max(1, min(limit, 15))),
        )
        if not rows:
            return "No Sentinel signals have been recorded yet."

        lines = ["**Recent Guardian Sentinel signals**"]
        for row in rows:
            try:
                explanation = json.loads(str(row["explanation_json"]))
            except (TypeError, json.JSONDecodeError):
                explanation = {}
            lines.append(
                f"#{row['signal_id']} • case #{row['case_id']} • "
                f"{row['severity']} {row['score']}/100 • "
                f"actor {row['subject_id'] or 'unknown'} • {row['action']} • "
                f"chain {explanation.get('chain', 'unknown')}"
            )
        return "\n".join(lines)

    async def explain_signal(self, guild_id: int, signal_id: int) -> str | None:
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_sentinel_signals "
            "WHERE guild_id = ? AND signal_id = ?",
            (guild_id, signal_id),
        )
        if row is None:
            return None

        try:
            explanation = json.loads(str(row["explanation_json"]))
        except (TypeError, json.JSONDecodeError):
            explanation = {}

        return (
            f"**Sentinel signal #{signal_id}**\n"
            f"Case: #{row['case_id']}\n"
            f"Action: {row['action']} ({row['category']})\n"
            f"Actor: {row['subject_id'] or 'unknown'} • Target: {row['target_id'] or 'none'}\n"
            f"Score: {row['score']}/100 ({row['severity']})\n"
            f"5-minute burst: {explanation.get('burst_count', 'unknown')}\n"
            f"Distinct correlated categories: {explanation.get('category_count', 'unknown')}\n"
            f"Target spread: {explanation.get('target_count', 'unknown')}\n"
            f"Rare action bonus: {'yes' if explanation.get('rare_action') else 'no'}\n"
            f"Correlation chain: {explanation.get('chain', 'unknown')}\n"
            "This score is explainable advisory intelligence; Guardian's deterministic protections make enforcement decisions."
        )

    @tasks.loop(seconds=20)
    async def sentinel_loop(self) -> None:
        for guild in list(self.bot.guilds):
            try:
                await self._scan_guild(guild)
            except Exception:
                LOG.exception("Sentinel scan failed for guild %s", guild.id)

    @sentinel_loop.before_loop
    async def before_sentinel_loop(self) -> None:
        await self.bot.wait_until_ready()
        await self._initialize_state()

    @sentinel.command(name="status", description="Show Guardian Sentinel live behavioral threat intelligence.")
    @guild_only()
    @staff_only()
    async def sentinel_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await self._scan_guild(interaction.guild)
        await respond(interaction, await self.live_report(interaction.guild))

    @sentinel.command(name="signals", description="Show recent explainable Sentinel anomaly signals.")
    @guild_only()
    @staff_only()
    async def sentinel_signals(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self.signals_report(interaction.guild_id))

    @sentinel.command(name="subject", description="Show Sentinel behavioral profile for a case subject ID.")
    @guild_only()
    @staff_only()
    async def sentinel_subject(self, interaction: discord.Interaction, subject_id: str) -> None:
        assert interaction.guild is not None
        try:
            value = int(subject_id)
        except ValueError:
            await respond(interaction, "Provide a numeric Discord user or bot ID.")
            return
        await respond(interaction, await self.actor_report(interaction.guild, value))

    @sentinel.command(name="explain", description="Explain exactly why a Sentinel signal received its score.")
    @guild_only()
    @staff_only()
    async def sentinel_explain(self, interaction: discord.Interaction, signal_id: int) -> None:
        result = await self.explain_signal(interaction.guild_id, signal_id)
        await respond(
            interaction,
            result or f"Sentinel signal #{signal_id} was not found in this server.",
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecuritySentinelCog(bot))
