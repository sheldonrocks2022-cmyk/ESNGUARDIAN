from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any, Awaitable, Callable

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, guild_owner_only, log_event, respond, staff_only

LOG = logging.getLogger("esn_guardian.security_v6")

SIGNAL_WEIGHTS: dict[str, int] = {
    "channel_delete": 8,
    "channel_permissions": 5,
    "role_delete": 8,
    "permission_escalation": 9,
    "dangerous_role_assignment": 9,
    "member_ban": 4,
    "member_kick": 4,
    "webhook_change": 7,
    "integration_change": 7,
    "unapproved_bot": 10,
    "external_app": 10,
    "scam_campaign": 7,
    "credential_leak": 10,
    "raid_fingerprint": 10,
    "verification_fail": 3,
    "command_abuse": 10,
    "guardian_tamper": 12,
    "guild_settings_change": 6,
}
CRITICAL_KINDS = {
    "channel_delete",
    "role_delete",
    "permission_escalation",
    "dangerous_role_assignment",
    "webhook_change",
    "integration_change",
    "unapproved_bot",
    "external_app",
    "command_abuse",
    "guardian_tamper",
}
DANGEROUS_PERMISSION_NAMES = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
    "ban_members",
    "kick_members",
    "moderate_members",
)
SENSITIVE_COMMAND_PREFIXES = (
    "ban",
    "kick",
    "massrole",
    "role",
    "lockdown",
    "unlockdown",
    "security ",
    "antinuke ",
    "guardian panic",
    "guardian approve-bot",
    "guardian unapprove-bot",
    "verification setup",
    "protection ",
    "globalban",
    "globalunban",
    "broadcast",
    "maintenance",
)
SCAM_PHRASES = (
    "free nitro",
    "discord nitro gift",
    "steam gift",
    "verify your account",
    "scan this qr",
    "scan the qr",
    "qr code to verify",
    "claim your reward",
    "limited gift",
    "gift inventory",
    "free discord",
    "airdrop",
)
ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")
ATTACK_WINDOW = timedelta(seconds=60)
ACTOR_CONTAIN_SCORE = 18
AUTO_PANIC_SCORE = 28
RAID_WINDOW = timedelta(seconds=15)
COMMAND_WINDOW = timedelta(seconds=20)
COMMAND_LIMIT = 8
CHECKPOINT_KEEP = 12
PRIORITY_QUEUE_MAX = 2048


def adaptive_risk_score(
    *,
    account_age_days: int,
    weighted_cases: int = 0,
    dangerous_roles: int = 0,
    failed_verifications: int = 0,
    external_app_events: int = 0,
    raid_cluster_score: int = 0,
) -> int:
    score = 0
    if account_age_days < 1:
        score += 28
    elif account_age_days < 3:
        score += 20
    elif account_age_days < 7:
        score += 12
    elif account_age_days < 30:
        score += 5
    score += min(30, max(0, weighted_cases))
    score += min(20, max(0, dangerous_roles) * 8)
    score += min(15, max(0, failed_verifications) * 5)
    score += min(25, max(0, external_app_events) * 12)
    score += min(25, max(0, raid_cluster_score))
    return max(0, min(100, score))


def attack_chain_score(kinds: list[str] | tuple[str, ...]) -> int:
    if not kinds:
        return 0
    score = sum(SIGNAL_WEIGHTS.get(kind, 2) for kind in kinds)
    unique = set(kinds)
    critical = unique & CRITICAL_KINDS
    if {"webhook_change", "permission_escalation"} <= unique:
        score += 8
    if {"permission_escalation", "channel_delete"} <= unique:
        score += 10
    if {"role_delete", "channel_delete"} <= unique:
        score += 8
    if {"unapproved_bot", "webhook_change"} <= unique:
        score += 8
    if {"command_abuse", "permission_escalation"} <= unique:
        score += 10
    if len(critical) >= 3:
        score += 12
    if len(kinds) >= 6:
        score += 8
    return min(100, score)


def scam_text_score(content: str, attachment_names: tuple[str, ...] = ()) -> int:
    text = content.casefold()
    score = 0
    score += sum(3 for phrase in SCAM_PHRASES if phrase in text)
    if "discord.gg/" in text or "discord.com/invite/" in text:
        score += 1
    if any(token in text for token in ("bit.ly/", "tinyurl.com/", "rb.gy/", "cutt.ly/")):
        score += 3
    if any(token in content for token in ZERO_WIDTH):
        score += 4
    if "http" in text and ("login" in text or "verify" in text or "gift" in text):
        score += 3
    for name in attachment_names:
        lowered = name.casefold()
        if "qr" in lowered and lowered.endswith((".png", ".jpg", ".jpeg", ".webp")):
            score += 3
    return min(20, score)


def raid_fingerprint_score(
    account_ages_days: list[int],
    name_skeletons: list[str],
) -> int:
    if not account_ages_days:
        return 0
    score = 0
    young = sum(age < 3 for age in account_ages_days)
    very_young = sum(age < 1 for age in account_ages_days)
    if young >= 4:
        score += 10 + (young - 4) * 2
    if very_young >= 3:
        score += 8
    counts = Counter(value for value in name_skeletons if value)
    if counts and max(counts.values()) >= 3:
        score += 10
    if len(account_ages_days) >= 6:
        score += 8
    return min(40, score)


class ProtectionV6Cog(commands.Cog):
    protection = app_commands.Group(
        name="protection",
        description="Guardian Protection v6 adaptive defense, recovery, and forensics.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.events: dict[int, deque[tuple[datetime, int | None, str, str, int | None]]] = defaultdict(deque)
        self.join_fingerprints: dict[int, deque[tuple[datetime, int, int, str]]] = defaultdict(deque)
        self.command_windows: dict[tuple[int, int], deque[datetime]] = defaultdict(deque)
        self._panic_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._priority_queue: asyncio.PriorityQueue[tuple[int, int, Callable[..., Awaitable[None]], tuple[Any, ...]]] = asyncio.PriorityQueue(
            maxsize=PRIORITY_QUEUE_MAX
        )
        self._sequence = count()
        self._workers: list[asyncio.Task[None]] = []
        self._previous_interaction_check: Callable[[discord.Interaction], Awaitable[bool]] | None = None
        self._failsafe_active = False
        self._last_watchdog_alert: dict[int, datetime] = {}

    async def cog_load(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS guardian_v6_config (
                guild_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                auto_panic INTEGER NOT NULL DEFAULT 1,
                adaptive_risk INTEGER NOT NULL DEFAULT 1,
                permission_firewall INTEGER NOT NULL DEFAULT 1,
                auto_heal INTEGER NOT NULL DEFAULT 1,
                command_shield INTEGER NOT NULL DEFAULT 1,
                raid_fingerprinting INTEGER NOT NULL DEFAULT 1,
                self_protection INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v6_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                actor_id INTEGER,
                kind TEXT NOT NULL,
                score INTEGER NOT NULL,
                detail TEXT NOT NULL,
                target_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_v6_events_guild
               ON guardian_v6_events(guild_id, event_id DESC)""",
            """CREATE TABLE IF NOT EXISTS guardian_v6_role_baselines (
                guild_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                permissions INTEGER NOT NULL,
                colour INTEGER NOT NULL DEFAULT 0,
                hoist INTEGER NOT NULL DEFAULT 0,
                mentionable INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, role_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v6_webhook_fingerprints (
                guild_id INTEGER NOT NULL,
                webhook_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, webhook_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_v6_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_v6_checkpoints_guild
               ON guardian_v6_checkpoints(guild_id, checkpoint_id DESC)""",
            """CREATE TABLE IF NOT EXISTS guardian_v6_incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                actor_id INTEGER,
                reason TEXT NOT NULL,
                report_json TEXT NOT NULL DEFAULT '{}',
                opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                closed_at TEXT
            )""",
        )
        for statement in statements:
            await self.bot.database.execute(statement)

        self._workers = [
            asyncio.create_task(self._priority_worker(), name=f"guardian-v6-priority-{index}")
            for index in range(4)
        ]

        self._previous_interaction_check = self.bot.tree.interaction_check
        self.bot.tree.interaction_check = self._interaction_check

        self.checkpoint_loop.start()
        self.watchdog_loop.start()
        self.incident_loop.start()

    def cog_unload(self) -> None:
        self.checkpoint_loop.cancel()
        self.watchdog_loop.cancel()
        self.incident_loop.cancel()
        for worker in self._workers:
            worker.cancel()
        if self._previous_interaction_check is not None:
            self.bot.tree.interaction_check = self._previous_interaction_check

    async def _priority_worker(self) -> None:
        while True:
            priority, _, func, args = await self._priority_queue.get()
            try:
                await func(*args)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("Protection v6 priority action failed at priority %s", priority)
            finally:
                self._priority_queue.task_done()

    async def _enqueue(
        self,
        priority: int,
        func: Callable[..., Awaitable[None]],
        *args: Any,
    ) -> None:
        item = (priority, next(self._sequence), func, args)
        try:
            self._priority_queue.put_nowait(item)
        except asyncio.QueueFull:
            if priority <= 1:
                await func(*args)
            else:
                LOG.warning("Protection v6 queue full; dropped non-critical task %s", getattr(func, "__name__", func))

    async def _config(self, guild_id: int):
        try:
            await self.bot.database.ensure_guild(guild_id)
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO guardian_config (guild_id) VALUES (?)",
                (guild_id,),
            )
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO guardian_v6_config (guild_id) VALUES (?)",
                (guild_id,),
            )
            return await self.bot.database.fetchone(
                "SELECT * FROM guardian_v6_config WHERE guild_id = ?",
                (guild_id,),
            )
        except Exception:
            self._failsafe_active = True
            LOG.exception("Protection v6 config read failed; fail-safe memory protection remains active")
            return None

    async def _case(
        self,
        guild: discord.Guild,
        actor: discord.abc.User | None,
        action: str,
        reason: str,
        *,
        target_id: int | None = None,
    ) -> None:
        try:
            security = self.bot.get_cog("SecurityCog")
            if security is not None and hasattr(security, "_security_case"):
                await security._security_case(
                    guild,
                    actor,
                    action,
                    reason,
                    None,
                )
                return
            await self.bot.database.create_case(
                guild.id,
                target_id if target_id is not None else (actor.id if actor else None),
                self.bot.user.id if self.bot.user else None,
                action,
                reason,
            )
        except Exception:
            self._failsafe_active = True
            LOG.exception("Protection v6 could not persist case %s", action)

    async def _audit_executor(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        target_id: int,
    ) -> discord.User | discord.Member | None:
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_audit_executor"):
            try:
                return await security._audit_executor(guild, action, target_id)
            except Exception:
                return None
        return None

    async def _trusted_actor(
        self,
        guild: discord.Guild,
        actor: discord.User | discord.Member | None,
    ) -> bool:
        if actor is None:
            return False
        if self.bot.user is not None and actor.id == self.bot.user.id:
            return True
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_is_trusted_executor"):
            try:
                return bool(await security._is_trusted_executor(guild, actor))
            except Exception:
                pass
        return actor.id == guild.owner_id

    @staticmethod
    def _name_skeleton(name: str) -> str:
        return re.sub(r"[^a-z]", "", name.casefold())[:12]

    @staticmethod
    def _dangerous_permissions(permissions: discord.Permissions) -> int:
        return sum(bool(getattr(permissions, name, False)) for name in DANGEROUS_PERMISSION_NAMES)

    def _prune_events(self, guild_id: int, now: datetime) -> None:
        window = self.events[guild_id]
        while window and now - window[0][0] > ATTACK_WINDOW:
            window.popleft()

    def _actor_chain_score(self, guild_id: int, actor_id: int | None) -> int:
        if actor_id is None:
            return attack_chain_score([kind for _, _, kind, _, _ in self.events[guild_id]])
        return attack_chain_score(
            [kind for _, current_actor, kind, _, _ in self.events[guild_id] if current_actor == actor_id]
        )

    async def _signal(
        self,
        guild: discord.Guild,
        actor: discord.abc.User | None,
        kind: str,
        detail: str,
        *,
        target_id: int | None = None,
        score: int | None = None,
    ) -> dict[str, int]:
        now = datetime.now(UTC)
        actor_id = actor.id if actor is not None else None
        self.events[guild.id].append((now, actor_id, kind, detail[:500], target_id))
        self._prune_events(guild.id, now)

        base_score = SIGNAL_WEIGHTS.get(kind, 2) if score is None else score
        try:
            await self.bot.database.execute(
                "INSERT INTO guardian_v6_events "
                "(guild_id, actor_id, kind, score, detail, target_id) VALUES (?, ?, ?, ?, ?, ?)",
                (guild.id, actor_id, kind, base_score, detail[:1000], target_id),
            )
        except Exception:
            self._failsafe_active = True
            LOG.exception("Protection v6 event persistence failed; continuing in fail-safe memory mode")

        actor_score = self._actor_chain_score(guild.id, actor_id)
        guild_score = attack_chain_score([item[2] for item in self.events[guild.id]])
        config = await self._config(guild.id)
        auto_panic = config is None or bool(config["auto_panic"])
        enabled = config is None or bool(config["enabled"])

        if not enabled:
            return {"actor": actor_score, "guild": guild_score}

        contain_threshold = ACTOR_CONTAIN_SCORE
        panic_threshold = AUTO_PANIC_SCORE
        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is not None and hasattr(v7, "thresholds"):
            try:
                contain_threshold, panic_threshold = v7.thresholds(guild.id)
            except Exception:
                pass

        if actor is not None and actor_id not in {guild.owner_id, self.bot.user.id if self.bot.user else 0}:
            if actor_score >= contain_threshold and kind in CRITICAL_KINDS:
                await self._enqueue(
                    1,
                    self._contain_actor,
                    guild,
                    actor,
                    f"Adaptive attack-chain score {actor_score}: {detail[:240]}",
                )

        if auto_panic and (
            guild_score >= panic_threshold
            or actor_score >= panic_threshold
            or kind == "guardian_tamper"
        ):
            await self._enqueue(
                0,
                self._activate_panic,
                guild,
                actor,
                f"Protection v6 attack-chain score actor={actor_score}, guild={guild_score}; {detail[:300]}",
            )

        return {"actor": actor_score, "guild": guild_score}

    async def _contain_actor(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        reason: str,
    ) -> None:
        if self.bot.user is not None and actor.id == self.bot.user.id:
            return
        if actor.id == guild.owner_id:
            await self._owner_safe_containment(guild, reason)
            return

        member = guild.get_member(actor.id)
        if member is None:
            try:
                member = await guild.fetch_member(actor.id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                member = None
        if member is None:
            await self._case(guild, actor, "V6_CONTAINMENT_UNRESOLVED", reason)
            return

        bot_member = guild.me
        removable = [
            role
            for role in member.roles
            if role != guild.default_role
            and not role.managed
            and self._dangerous_permissions(role.permissions) > 0
            and bot_member is not None
            and role < bot_member.top_role
        ]

        stripped = 0
        if removable:
            try:
                await member.remove_roles(
                    *removable,
                    reason=f"ESN Guardian v6 emergency privilege strip: {reason[:300]}",
                )
                stripped = len(removable)
            except (discord.Forbidden, discord.HTTPException):
                pass

        timed_out = False
        try:
            await member.timeout(
                timedelta(hours=24),
                reason=f"ESN Guardian v6 containment: {reason[:300]}",
            )
            timed_out = True
        except (discord.Forbidden, discord.HTTPException):
            pass

        if not timed_out and stripped == 0:
            try:
                await guild.ban(
                    member,
                    reason=f"ESN Guardian v6 critical containment: {reason[:300]}",
                    delete_message_seconds=0,
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

        await self._case(
            guild,
            member,
            "V6_COMPROMISED_STAFF_CONTAINED",
            f"{reason}; stripped_roles={stripped}; timeout={timed_out}",
        )

    async def _owner_safe_containment(self, guild: discord.Guild, reason: str) -> None:
        advanced = self.bot.get_cog("AdvancedSecurityCog")
        if advanced is not None:
            for method_name in (
                "_lock_external_apps",
                "_delete_unapproved_webhooks",
                "_remove_unapproved_integrations",
            ):
                method = getattr(advanced, method_name, None)
                if method is not None:
                    try:
                        await method(guild)
                    except Exception:
                        LOG.exception("Owner-safe containment step %s failed", method_name)

        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_lockdown"):
            try:
                await security._lockdown(guild, f"Guardian v6 owner-safe containment: {reason[:250]}")
            except Exception:
                LOG.exception("Owner-safe lockdown failed")

        await self._case(
            guild,
            guild.owner,
            "V6_OWNER_SAFE_CONTAINMENT",
            "Owner-originated critical activity detected. Guardian cannot ban the server owner, so it locked down manageable surfaces and preserved evidence.",
        )

    async def _activate_panic(
        self,
        guild: discord.Guild,
        actor: discord.abc.User | None,
        reason: str,
    ) -> None:
        async with self._panic_locks[guild.id]:
            try:
                row = await self.bot.database.fetchone(
                    "SELECT panic_mode FROM guardian_config WHERE guild_id = ?",
                    (guild.id,),
                )
                already_active = bool(row and row["panic_mode"])
            except Exception:
                already_active = False
                self._failsafe_active = True

            if already_active:
                return

            try:
                await self.bot.database.backup("v6-pre-containment")
            except Exception:
                self._failsafe_active = True
                LOG.exception("Could not create v6 pre-containment database backup")

            report = {
                "reason": reason,
                "actor_id": actor.id if actor else None,
                "events": [
                    {
                        "at": timestamp.isoformat(),
                        "actor_id": actor_id,
                        "kind": kind,
                        "detail": detail,
                        "target_id": target_id,
                    }
                    for timestamp, actor_id, kind, detail, target_id in list(self.events[guild.id])[-30:]
                ],
            }
            try:
                await self.bot.database.execute(
                    "INSERT INTO guardian_v6_incidents "
                    "(guild_id, severity, actor_id, reason, report_json) VALUES (?, 'CRITICAL', ?, ?, ?)",
                    (
                        guild.id,
                        actor.id if actor else None,
                        reason[:1000],
                        json.dumps(report, ensure_ascii=True),
                    ),
                )
                await self.bot.database.execute(
                    "UPDATE guardian_config SET panic_mode=1, external_app_lock=1, bot_approval=1, "
                    "webhook_guard=1, integration_guard=1, credential_guard=1, rollback_enabled=1 "
                    "WHERE guild_id=?",
                    (guild.id,),
                )
                await self.bot.database.execute(
                    "UPDATE anti_nuke_config SET enabled=1, action_limit=2, window_seconds=15 WHERE guild_id=?",
                    (guild.id,),
                )
                await self.bot.database.execute(
                    "UPDATE security_config SET automod_enabled=1, flood_limit=4, "
                    "flood_window_seconds=10, max_mentions=4, block_invites=1, strict_links=1 "
                    "WHERE guild_id=?",
                    (guild.id,),
                )
            except Exception:
                self._failsafe_active = True
                LOG.exception("V6 panic persistence failed; continuing containment in memory")

            if actor is not None:
                if actor.id == guild.owner_id:
                    await self._owner_safe_containment(guild, reason)
                elif self.bot.user is None or actor.id != self.bot.user.id:
                    await self._contain_actor(guild, actor, reason)

            advanced = self.bot.get_cog("AdvancedSecurityCog")
            if advanced is not None:
                for method_name in (
                    "_lock_external_apps",
                    "_ban_unapproved_bots",
                    "_delete_unapproved_webhooks",
                    "_remove_unapproved_integrations",
                ):
                    method = getattr(advanced, method_name, None)
                    if method is not None:
                        try:
                            await method(guild)
                        except Exception:
                            LOG.exception("Automatic panic step %s failed", method_name)

            security = self.bot.get_cog("SecurityCog")
            if security is not None and hasattr(security, "_lockdown"):
                try:
                    await security._lockdown(guild, f"Guardian v6 automatic PANIC: {reason[:250]}")
                except Exception:
                    LOG.exception("V6 automatic lockdown failed")

            await self._contain_recent_risky_joins(guild)

            try:
                await self._restore_missing_from_checkpoint(guild)
            except Exception:
                LOG.exception("V6 automatic recovery from checkpoint failed")

            await self._case(
                guild,
                actor,
                "V6_AUTO_PANIC",
                reason,
            )
            try:
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    "Guardian Protection v6 — AUTOMATIC PANIC",
                    description=reason[:3500],
                    color=discord.Color.red(),
                )
            except Exception:
                pass

    async def _interaction_check(self, interaction: discord.Interaction) -> bool:
        previous = self._previous_interaction_check
        if previous is not None:
            try:
                if not await previous(interaction):
                    return False
            except Exception:
                LOG.exception("Previous command interaction check failed")
                return False

        if interaction.guild is None or interaction.command is None:
            return True

        config = await self._config(interaction.guild.id)
        if config is not None and not config["command_shield"]:
            return True

        qualified = interaction.command.qualified_name.casefold()
        if not any(qualified == prefix or qualified.startswith(prefix) for prefix in SENSITIVE_COMMAND_PREFIXES):
            return True

        key = (interaction.guild.id, interaction.user.id)
        now = datetime.now(UTC)
        window = self.command_windows[key]
        window.append(now)
        while window and now - window[0] > COMMAND_WINDOW:
            window.popleft()

        if len(window) <= COMMAND_LIMIT:
            return True

        if not interaction.response.is_done():
            try:
                await interaction.response.send_message(
                    "Guardian Protection v6 temporarily blocked this sensitive command burst. "
                    "Wait a moment and review the security log.",
                    ephemeral=True,
                )
            except discord.HTTPException:
                pass

        await self._signal(
            interaction.guild,
            interaction.user,
            "command_abuse",
            f"{len(window)} sensitive commands inside {int(COMMAND_WINDOW.total_seconds())} seconds; latest=/{qualified}",
        )
        return False

    async def member_risk(self, guild: discord.Guild, member: discord.Member) -> dict[str, Any]:
        age_days = max(0, (datetime.now(UTC) - member.created_at).days)
        weighted_cases = 0
        failed_verifications = 0
        external_events = 0
        try:
            rows = await self.bot.database.fetchall(
                "SELECT action FROM cases WHERE guild_id=? AND target_id=? "
                "ORDER BY case_id DESC LIMIT 30",
                (guild.id, member.id),
            )
            for row in rows:
                action = str(row["action"])
                if action.startswith(("ANTINUKE_", "V6_", "EXTERNAL_APP_", "GUARDIAN_TAMPER")):
                    weighted_cases += 6
                elif action.startswith("AUTOMOD_"):
                    weighted_cases += 2
                if "VERIFY" in action and "FAILED" in action:
                    failed_verifications += 1
                if "EXTERNAL_APP" in action:
                    external_events += 1
        except Exception:
            self._failsafe_active = True

        dangerous_roles = sum(
            self._dangerous_permissions(role.permissions) > 0
            for role in member.roles
            if role != guild.default_role
        )

        raid_score = 0
        for _, member_id, age, skeleton in self.join_fingerprints[guild.id]:
            if member_id == member.id:
                peers = [
                    entry
                    for entry in self.join_fingerprints[guild.id]
                    if entry[3] == skeleton and skeleton
                ]
                if len(peers) >= 3:
                    raid_score = min(25, len(peers) * 5)
                if age < 3:
                    raid_score += 5
                break

        score = adaptive_risk_score(
            account_age_days=age_days,
            weighted_cases=weighted_cases,
            dangerous_roles=dangerous_roles,
            failed_verifications=failed_verifications,
            external_app_events=external_events,
            raid_cluster_score=raid_score,
        )
        return {
            "score": score,
            "level": "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "ELEVATED" if score >= 30 else "NORMAL",
            "account_age_days": age_days,
            "weighted_cases": weighted_cases,
            "dangerous_roles": dangerous_roles,
            "failed_verifications": failed_verifications,
            "external_app_events": external_events,
            "raid_cluster_score": raid_score,
        }

    async def highest_risk_report(self, guild: discord.Guild) -> str:
        candidate_ids: set[int] = set()
        try:
            rows = await self.bot.database.fetchall(
                "SELECT target_id FROM cases WHERE guild_id=? AND target_id IS NOT NULL "
                "ORDER BY case_id DESC LIMIT 100",
                (guild.id,),
            )
            candidate_ids.update(int(row["target_id"]) for row in rows if row["target_id"])
        except Exception:
            self._failsafe_active = True

        candidate_ids.update(member_id for _, member_id, _, _ in self.join_fingerprints[guild.id])
        if not candidate_ids:
            youngest = sorted(
                (member for member in guild.members if not member.bot),
                key=lambda member: member.created_at,
                reverse=True,
            )[:25]
            candidate_ids.update(member.id for member in youngest)

        ranked: list[tuple[int, discord.Member, dict[str, Any]]] = []
        for member_id in list(candidate_ids)[:100]:
            member = guild.get_member(member_id)
            if member is None or member.bot:
                continue
            data = await self.member_risk(guild, member)
            ranked.append((int(data["score"]), member, data))
        ranked.sort(key=lambda item: item[0], reverse=True)

        if not ranked:
            return "**Guardian Protection v6 risk board**\nNo active member risk signals are available."

        lines = ["**Guardian Protection v6 risk board**"]
        for score, member, data in ranked[:8]:
            lines.append(
                f"• {member} ({member.id}) — {score}/100 {data['level']} "
                f"• age {data['account_age_days']}d • dangerous roles {data['dangerous_roles']} "
                f"• case risk {data['weighted_cases']}"
            )
        return "\n".join(lines)[:4000]

    async def _ensure_role_baseline(self, guild: discord.Guild) -> None:
        existing = await self.bot.database.fetchone(
            "SELECT 1 FROM guardian_v6_role_baselines WHERE guild_id=? LIMIT 1",
            (guild.id,),
        )
        if existing is not None:
            return
        rows = [
            (
                guild.id,
                role.id,
                role.name,
                role.permissions.value,
                role.colour.value,
                1 if role.hoist else 0,
                1 if role.mentionable else 0,
            )
            for role in guild.roles
            if not role.is_default() and not role.managed
        ]
        if rows:
            await self.bot.database.executemany(
                "INSERT OR REPLACE INTO guardian_v6_role_baselines "
                "(guild_id, role_id, name, permissions, colour, hoist, mentionable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    async def _save_role_baseline(self, role: discord.Role) -> None:
        try:
            await self.bot.database.execute(
                "INSERT INTO guardian_v6_role_baselines "
                "(guild_id, role_id, name, permissions, colour, hoist, mentionable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(guild_id, role_id) DO UPDATE SET "
                "name=excluded.name, permissions=excluded.permissions, colour=excluded.colour, "
                "hoist=excluded.hoist, mentionable=excluded.mentionable, updated_at=CURRENT_TIMESTAMP",
                (
                    role.guild.id,
                    role.id,
                    role.name,
                    role.permissions.value,
                    role.colour.value,
                    1 if role.hoist else 0,
                    1 if role.mentionable else 0,
                ),
            )
        except Exception:
            self._failsafe_active = True

    async def _permission_firewall(
        self,
        before: discord.Role,
        after: discord.Role,
        actor: discord.User | discord.Member | None,
    ) -> None:
        config = await self._config(after.guild.id)
        if config is not None and not config["permission_firewall"]:
            return

        await self._ensure_role_baseline(after.guild)
        baseline = await self.bot.database.fetchone(
            "SELECT * FROM guardian_v6_role_baselines WHERE guild_id=? AND role_id=?",
            (after.guild.id, after.id),
        )
        actor_score = self._actor_chain_score(after.guild.id, actor.id if actor else None)
        trusted = await self._trusted_actor(after.guild, actor)

        before_danger = self._dangerous_permissions(before.permissions)
        after_danger = self._dangerous_permissions(after.permissions)
        gained_dangerous = after_danger > before_danger

        if gained_dangerous:
            scores = await self._signal(
                after.guild,
                actor,
                "permission_escalation",
                f"Role {after.name} gained high-risk permissions ({before_danger}->{after_danger})",
                target_id=after.id,
            )
            actor_score = max(actor_score, scores["actor"])

        if trusted and actor_score < ACTOR_CONTAIN_SCORE:
            await self._save_role_baseline(after)
            return

        if not gained_dangerous and actor_score < ACTOR_CONTAIN_SCORE:
            return

        permissions_value = int(baseline["permissions"]) if baseline is not None else before.permissions.value
        try:
            await after.edit(
                permissions=discord.Permissions(permissions_value),
                reason="ESN Guardian v6 permission firewall",
            )
            await self._case(
                after.guild,
                actor,
                "V6_PERMISSION_FIREWALL_REVERT",
                f"Reverted unauthorized dangerous permissions on role {after.name}",
            )
        except (discord.Forbidden, discord.HTTPException):
            await self._case(
                after.guild,
                actor,
                "V6_PERMISSION_FIREWALL_FAILED",
                f"Could not revert dangerous permissions on role {after.name}",
            )

    async def _snapshot_payload(self, guild: discord.Guild) -> dict[str, Any] | None:
        advanced = self.bot.get_cog("AdvancedSecurityCog")
        if advanced is None or not hasattr(advanced, "_snapshot_payload"):
            return None
        try:
            return await advanced._snapshot_payload(guild)
        except Exception:
            LOG.exception("V6 checkpoint snapshot failed")
            return None

    @staticmethod
    def _payload_fingerprint(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def checkpoint(self, guild: discord.Guild, label: str = "automatic") -> int | None:
        payload = await self._snapshot_payload(guild)
        if payload is None:
            return None
        fingerprint = self._payload_fingerprint(payload)
        latest = await self.bot.database.fetchone(
            "SELECT checkpoint_id, fingerprint FROM guardian_v6_checkpoints "
            "WHERE guild_id=? ORDER BY checkpoint_id DESC LIMIT 1",
            (guild.id,),
        )
        if latest is not None and latest["fingerprint"] == fingerprint and label == "automatic":
            return int(latest["checkpoint_id"])

        await self.bot.database.execute(
            "INSERT INTO guardian_v6_checkpoints (guild_id, label, fingerprint, snapshot_json) "
            "VALUES (?, ?, ?, ?)",
            (
                guild.id,
                label[:80],
                fingerprint,
                json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
            ),
        )
        row = await self.bot.database.fetchone(
            "SELECT checkpoint_id FROM guardian_v6_checkpoints "
            "WHERE guild_id=? ORDER BY checkpoint_id DESC LIMIT 1",
            (guild.id,),
        )
        old = await self.bot.database.fetchall(
            "SELECT checkpoint_id FROM guardian_v6_checkpoints "
            "WHERE guild_id=? ORDER BY checkpoint_id DESC LIMIT -1 OFFSET ?",
            (guild.id, CHECKPOINT_KEEP),
        )
        for item in old:
            await self.bot.database.execute(
                "DELETE FROM guardian_v6_checkpoints WHERE checkpoint_id=?",
                (item["checkpoint_id"],),
            )
        return int(row["checkpoint_id"]) if row is not None else None

    async def _latest_checkpoint(self, guild_id: int) -> dict[str, Any] | None:
        try:
            row = await self.bot.database.fetchone(
                "SELECT checkpoint_id, label, snapshot_json, created_at "
                "FROM guardian_v6_checkpoints WHERE guild_id=? "
                "ORDER BY checkpoint_id DESC LIMIT 1",
                (guild_id,),
            )
            if row is None:
                return None
            return {
                "checkpoint_id": int(row["checkpoint_id"]),
                "label": str(row["label"]),
                "created_at": str(row["created_at"]),
                "snapshot": json.loads(str(row["snapshot_json"])),
            }
        except Exception:
            self._failsafe_active = True
            return None

    async def _heal_channel(self, channel: discord.abc.GuildChannel) -> None:
        checkpoint = await self._latest_checkpoint(channel.guild.id)
        if checkpoint is None:
            return
        item = next(
            (
                current
                for current in checkpoint["snapshot"].get("channels", [])
                if isinstance(current, dict) and int(current.get("id", 0)) == channel.id
            ),
            None,
        )
        if item is None:
            return

        overwrites: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {}
        for entry in item.get("overwrites", []):
            if not isinstance(entry, dict):
                continue
            target_id = int(entry.get("target_id", 0) or 0)
            if entry.get("target_type") == "role":
                target = channel.guild.get_role(target_id)
            else:
                target = channel.guild.get_member(target_id)
            if target is None:
                continue
            overwrites[target] = discord.PermissionOverwrite.from_pair(
                discord.Permissions(int(entry.get("allow", 0) or 0)),
                discord.Permissions(int(entry.get("deny", 0) or 0)),
            )

        kwargs: dict[str, Any] = {
            "name": str(item.get("name", channel.name)),
            "position": int(item.get("position", channel.position)),
            "overwrites": overwrites,
            "reason": "ESN Guardian v6 automatic channel recovery",
        }
        category_id = item.get("category_id")
        if not isinstance(channel, discord.CategoryChannel):
            kwargs["category"] = channel.guild.get_channel(int(category_id)) if category_id else None
        if isinstance(channel, discord.TextChannel):
            if "topic" in item:
                kwargs["topic"] = item.get("topic")
            if "slowmode_delay" in item:
                kwargs["slowmode_delay"] = int(item.get("slowmode_delay") or 0)
            if "nsfw" in item:
                kwargs["nsfw"] = bool(item.get("nsfw"))
        if isinstance(channel, discord.VoiceChannel):
            if item.get("bitrate"):
                kwargs["bitrate"] = int(item["bitrate"])
            if "user_limit" in item:
                kwargs["user_limit"] = int(item.get("user_limit") or 0)

        try:
            await channel.edit(**kwargs)
            await self._case(
                channel.guild,
                None,
                "V6_AUTO_HEAL_CHANNEL",
                f"Restored channel {channel.name} from checkpoint #{checkpoint['checkpoint_id']}",
            )
        except (discord.Forbidden, discord.HTTPException, TypeError):
            LOG.exception("V6 could not auto-heal channel %s", channel.id)

    async def _heal_role(self, role: discord.Role) -> None:
        checkpoint = await self._latest_checkpoint(role.guild.id)
        if checkpoint is None:
            return
        item = next(
            (
                current
                for current in checkpoint["snapshot"].get("roles", [])
                if isinstance(current, dict) and int(current.get("id", 0)) == role.id
            ),
            None,
        )
        if item is None:
            return
        bot_member = role.guild.me
        if bot_member is None or role >= bot_member.top_role:
            return
        try:
            await role.edit(
                name=str(item.get("name", role.name)),
                permissions=discord.Permissions(int(item.get("permissions", role.permissions.value))),
                colour=discord.Colour(int(item.get("colour", role.colour.value))),
                hoist=bool(item.get("hoist", role.hoist)),
                mentionable=bool(item.get("mentionable", role.mentionable)),
                position=int(item.get("position", role.position)),
                reason="ESN Guardian v6 automatic role recovery",
            )
            await self._case(
                role.guild,
                None,
                "V6_AUTO_HEAL_ROLE",
                f"Restored role {role.name} from checkpoint #{checkpoint['checkpoint_id']}",
            )
        except (discord.Forbidden, discord.HTTPException):
            LOG.exception("V6 could not auto-heal role %s", role.id)

    async def _restore_missing_from_checkpoint(self, guild: discord.Guild) -> None:
        checkpoint = await self._latest_checkpoint(guild.id)
        if checkpoint is None:
            return
        snapshot = checkpoint["snapshot"]

        existing_role_names = {role.name.casefold(): role for role in guild.roles}
        role_map: dict[int, discord.Role] = {
            role.id: role for role in guild.roles
        }
        for item in snapshot.get("roles", []):
            if not isinstance(item, dict):
                continue
            old_id = int(item.get("id", 0) or 0)
            if old_id in role_map:
                continue
            by_name = existing_role_names.get(str(item.get("name", "")).casefold())
            if by_name is not None:
                role_map[old_id] = by_name
                continue
            try:
                restored = await guild.create_role(
                    name=str(item.get("name", "restored-role"))[:100],
                    permissions=discord.Permissions(int(item.get("permissions", 0) or 0)),
                    colour=discord.Colour(int(item.get("colour", 0) or 0)),
                    hoist=bool(item.get("hoist", False)),
                    mentionable=bool(item.get("mentionable", False)),
                    reason=f"Guardian v6 restore checkpoint #{checkpoint['checkpoint_id']}",
                )
                role_map[old_id] = restored
                existing_role_names[restored.name.casefold()] = restored
            except (discord.Forbidden, discord.HTTPException):
                continue

        existing_channels = {
            (channel.name.casefold(), str(channel.type)): channel
            for channel in guild.channels
        }
        category_map: dict[int, discord.CategoryChannel] = {
            channel.id: channel
            for channel in guild.categories
        }

        for item in snapshot.get("channels", []):
            if not isinstance(item, dict) or "category" not in str(item.get("type", "")):
                continue
            old_id = int(item.get("id", 0) or 0)
            if guild.get_channel(old_id) is not None:
                continue
            key = (str(item.get("name", "")).casefold(), str(item.get("type", "")))
            existing = existing_channels.get(key)
            if isinstance(existing, discord.CategoryChannel):
                category_map[old_id] = existing
                continue
            try:
                category = await guild.create_category(
                    str(item.get("name", "restored-category"))[:100],
                    reason=f"Guardian v6 restore checkpoint #{checkpoint['checkpoint_id']}",
                )
                category_map[old_id] = category
                existing_channels[(category.name.casefold(), str(category.type))] = category
            except (discord.Forbidden, discord.HTTPException):
                continue

        for item in snapshot.get("channels", []):
            if not isinstance(item, dict):
                continue
            old_id = int(item.get("id", 0) or 0)
            if guild.get_channel(old_id) is not None:
                continue
            type_name = str(item.get("type", ""))
            if "category" in type_name:
                continue
            key = (str(item.get("name", "")).casefold(), type_name)
            if key in existing_channels:
                continue
            category = category_map.get(int(item.get("category_id", 0) or 0))
            try:
                if "text" in type_name:
                    created = await guild.create_text_channel(
                        str(item.get("name", "restored-channel"))[:100],
                        category=category,
                        topic=item.get("topic"),
                        slowmode_delay=int(item.get("slowmode_delay", 0) or 0),
                        nsfw=bool(item.get("nsfw", False)),
                        reason=f"Guardian v6 restore checkpoint #{checkpoint['checkpoint_id']}",
                    )
                elif "voice" in type_name:
                    created = await guild.create_voice_channel(
                        str(item.get("name", "restored-voice"))[:100],
                        category=category,
                        bitrate=int(item.get("bitrate", 64000) or 64000),
                        user_limit=int(item.get("user_limit", 0) or 0),
                        reason=f"Guardian v6 restore checkpoint #{checkpoint['checkpoint_id']}",
                    )
                else:
                    continue
                existing_channels[(created.name.casefold(), str(created.type))] = created
            except (discord.Forbidden, discord.HTTPException, TypeError):
                continue

        await self._case(
            guild,
            None,
            "V6_CHECKPOINT_RECOVERY",
            f"Checkpoint #{checkpoint['checkpoint_id']} recovery pass completed",
        )

    @staticmethod
    def _webhook_fingerprint(webhook: discord.Webhook) -> str:
        application_id = getattr(webhook, "application_id", None)
        raw = "|".join(
            (
                str(webhook.id),
                str(getattr(webhook, "channel_id", 0) or 0),
                str(webhook.name or ""),
                str(webhook.type),
                str(application_id or 0),
            )
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def _baseline_webhooks(self, guild: discord.Guild) -> None:
        approved_rows = await self.bot.database.fetchall(
            "SELECT webhook_id FROM approved_webhooks WHERE guild_id=?",
            (guild.id,),
        )
        approved = {int(row["webhook_id"]) for row in approved_rows}
        for channel in guild.channels:
            if not hasattr(channel, "webhooks"):
                continue
            try:
                webhooks = await channel.webhooks()
            except (discord.Forbidden, discord.HTTPException):
                continue
            for webhook in webhooks:
                if webhook.id not in approved:
                    continue
                await self.bot.database.execute(
                    "INSERT OR IGNORE INTO guardian_v6_webhook_fingerprints "
                    "(guild_id, webhook_id, fingerprint) VALUES (?, ?, ?)",
                    (guild.id, webhook.id, self._webhook_fingerprint(webhook)),
                )

    async def _scan_webhooks(
        self,
        channel: discord.abc.GuildChannel,
        actor: discord.User | discord.Member | None,
    ) -> None:
        if not hasattr(channel, "webhooks"):
            return
        try:
            current = await channel.webhooks()
        except (discord.Forbidden, discord.HTTPException):
            return

        approved_rows = await self.bot.database.fetchall(
            "SELECT webhook_id FROM approved_webhooks WHERE guild_id=?",
            (channel.guild.id,),
        )
        approved = {int(row["webhook_id"]) for row in approved_rows}
        fp_rows = await self.bot.database.fetchall(
            "SELECT webhook_id, fingerprint FROM guardian_v6_webhook_fingerprints WHERE guild_id=?",
            (channel.guild.id,),
        )
        fingerprints = {int(row["webhook_id"]): str(row["fingerprint"]) for row in fp_rows}
        trusted = await self._trusted_actor(channel.guild, actor)
        actor_score = self._actor_chain_score(channel.guild.id, actor.id if actor else None)

        for webhook in current:
            fingerprint = self._webhook_fingerprint(webhook)
            if trusted and actor_score < ACTOR_CONTAIN_SCORE:
                await self.bot.database.execute(
                    "INSERT OR REPLACE INTO approved_webhooks (guild_id, webhook_id) VALUES (?, ?)",
                    (channel.guild.id, webhook.id),
                )
                await self.bot.database.execute(
                    "INSERT INTO guardian_v6_webhook_fingerprints (guild_id, webhook_id, fingerprint) "
                    "VALUES (?, ?, ?) ON CONFLICT(guild_id, webhook_id) DO UPDATE SET "
                    "fingerprint=excluded.fingerprint, updated_at=CURRENT_TIMESTAMP",
                    (channel.guild.id, webhook.id, fingerprint),
                )
                continue

            if webhook.id in approved and fingerprints.get(webhook.id) == fingerprint:
                continue

            try:
                await webhook.delete(reason="ESN Guardian v6 webhook firewall")
                await self._signal(
                    channel.guild,
                    actor,
                    "webhook_change",
                    f"Deleted unknown or fingerprint-mismatched webhook {webhook.id}",
                    target_id=webhook.id,
                )
            except (discord.Forbidden, discord.HTTPException):
                await self._case(
                    channel.guild,
                    actor,
                    "V6_WEBHOOK_FIREWALL_FAILED",
                    f"Could not delete unauthorized webhook {webhook.id}",
                )

    async def _contain_recent_risky_joins(self, guild: discord.Guild) -> None:
        security = self.bot.get_cog("SecurityCog")
        if security is None:
            return
        now = datetime.now(UTC)
        recent = [
            entry
            for entry in self.join_fingerprints[guild.id]
            if now - entry[0] <= timedelta(minutes=2)
        ]
        for _, member_id, _, _ in recent:
            member = guild.get_member(member_id)
            if member is None:
                continue
            data = await self.member_risk(guild, member)
            if int(data["score"]) < 40:
                continue
            quarantined = False
            if hasattr(security, "_quarantine"):
                try:
                    quarantined = bool(
                        await security._quarantine(
                            member,
                            f"Protection v6 panic risk score {data['score']}",
                        )
                    )
                except Exception:
                    quarantined = False
            if not quarantined and int(data["score"]) >= 70 and hasattr(security, "_enqueue_raid_kick"):
                try:
                    await security._enqueue_raid_kick(
                        member,
                        f"Protection v6 critical raid risk {data['score']}",
                    )
                except Exception:
                    pass

    async def verification_decision(self, member: discord.Member) -> dict[str, Any]:
        data = await self.member_risk(member.guild, member)
        score = int(data["score"])
        return {
            **data,
            "require_challenge": score >= 30,
            "manual_review": score >= 75,
        }

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        config = await self._config(member.guild.id)
        if config is not None and not config["enabled"]:
            return

        if member.bot:
            approved = None
            try:
                approved = await self.bot.database.fetchone(
                    "SELECT 1 FROM approved_bots WHERE guild_id=? AND bot_id=?",
                    (member.guild.id, member.id),
                )
            except Exception:
                self._failsafe_active = True
            if approved is None:
                actor = await self._audit_executor(
                    member.guild,
                    discord.AuditLogAction.bot_add,
                    member.id,
                )
                await self._signal(
                    member.guild,
                    actor,
                    "unapproved_bot",
                    f"Unapproved bot {member} ({member.id}) joined",
                    target_id=member.id,
                )
                try:
                    await member.guild.ban(
                        member,
                        reason="ESN Guardian v6 bot-installation firewall",
                        delete_message_seconds=0,
                    )
                except (discord.Forbidden, discord.HTTPException):
                    pass
            return

        now = datetime.now(UTC)
        age_days = max(0, (now - member.created_at).days)
        skeleton = self._name_skeleton(member.name)
        window = self.join_fingerprints[member.guild.id]
        window.append((now, member.id, age_days, skeleton))
        while window and now - window[0][0] > RAID_WINDOW:
            window.popleft()

        if config is not None and not config["raid_fingerprinting"]:
            return

        score = raid_fingerprint_score(
            [entry[2] for entry in window],
            [entry[3] for entry in window],
        )
        if score >= 18:
            await self._signal(
                member.guild,
                member,
                "raid_fingerprint",
                f"Coordinated join fingerprint score {score}; joins={len(window)}",
                target_id=member.id,
                score=min(15, 5 + score // 3),
            )
            await self._contain_recent_risky_joins(member.guild)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        attachments = tuple(attachment.filename for attachment in message.attachments)
        score = scam_text_score(message.content, attachments)

        if message.guild is None:
            if message.author.bot or score < 7:
                return
            try:
                await message.channel.send(
                    "ESN Guardian detected scam/phishing indicators in that message. "
                    "Do not open unknown links, scan unexpected QR codes, or enter credentials from unsolicited messages.",
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                pass
            return

        if not isinstance(message.author, discord.Member):
            return

        metadata = getattr(message, "interaction_metadata", None)
        if metadata is not None:
            try:
                is_external = bool(metadata.is_user_integration())
            except (AttributeError, TypeError):
                is_external = False
            if is_external:
                invoker = getattr(metadata, "user", None)
                actor = message.guild.get_member(invoker.id) if invoker is not None else None
                app_id = getattr(message, "application_id", None)
                await self._signal(
                    message.guild,
                    actor or invoker,
                    "external_app",
                    f"External user-installed application activity detected; application_id={app_id or 'unknown'}",
                    target_id=app_id,
                )
                if invoker is not None and invoker.id == message.guild.owner_id:
                    await self._enqueue(
                        0,
                        self._owner_safe_containment,
                        message.guild,
                        f"Server owner account invoked external application {app_id or 'unknown'}",
                    )

        if message.author.bot:
            return
        if score < 7:
            return
        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            pass
        await self._signal(
            message.guild,
            message.author,
            "scam_campaign",
            f"Scam/phishing composite score {score} in channel {message.channel.id}",
            target_id=message.author.id,
            score=min(12, score),
        )
        if score >= 12:
            await self._enqueue(
                1,
                self._contain_actor,
                message.guild,
                message.author,
                f"High-confidence scam campaign score {score}",
            )

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        actor = await self._audit_executor(
            channel.guild,
            discord.AuditLogAction.channel_delete,
            channel.id,
        )
        await self._signal(
            channel.guild,
            actor,
            "channel_delete",
            f"Channel/category deleted: {channel.name}",
            target_id=channel.id,
        )

    @commands.Cog.listener()
    async def on_guild_channel_update(
        self,
        before: discord.abc.GuildChannel,
        after: discord.abc.GuildChannel,
    ) -> None:
        changed_permissions = before.overwrites != after.overwrites
        changed_identity = (
            before.name != after.name
            or before.position != after.position
            or getattr(before, "category_id", None) != getattr(after, "category_id", None)
        )
        changed_slowmode = getattr(before, "slowmode_delay", None) != getattr(after, "slowmode_delay", None)
        if not (changed_permissions or changed_identity or changed_slowmode):
            return
        actor = await self._audit_executor(
            after.guild,
            discord.AuditLogAction.channel_update,
            after.id,
        )
        trusted = await self._trusted_actor(after.guild, actor)
        actor_score = self._actor_chain_score(after.guild.id, actor.id if actor else None)
        if changed_permissions:
            await self._signal(
                after.guild,
                actor,
                "channel_permissions",
                f"Channel permissions changed: {after.name}",
                target_id=after.id,
            )
        config = await self._config(after.guild.id)
        if config is None or bool(config["auto_heal"]):
            if not trusted or actor_score >= ACTOR_CONTAIN_SCORE:
                await self._enqueue(1, self._heal_channel, after)

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        actor = await self._audit_executor(
            role.guild,
            discord.AuditLogAction.role_delete,
            role.id,
        )
        await self._signal(
            role.guild,
            actor,
            "role_delete",
            f"Role deleted: {role.name}",
            target_id=role.id,
        )

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.permissions != after.permissions:
            await self._permission_firewall(before, after, await self._audit_executor(
                after.guild,
                discord.AuditLogAction.role_update,
                after.id,
            ))

        config = await self._config(after.guild.id)
        if config is not None and not config["auto_heal"]:
            return
        if (
            before.name == after.name
            and before.colour == after.colour
            and before.hoist == after.hoist
            and before.mentionable == after.mentionable
            and before.position == after.position
        ):
            return
        actor = await self._audit_executor(
            after.guild,
            discord.AuditLogAction.role_update,
            after.id,
        )
        trusted = await self._trusted_actor(after.guild, actor)
        actor_score = self._actor_chain_score(after.guild.id, actor.id if actor else None)
        if trusted and actor_score < ACTOR_CONTAIN_SCORE:
            await self._save_role_baseline(after)
            return
        await self._enqueue(1, self._heal_role, after)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        added = [
            role
            for role in after.roles
            if role not in before.roles and self._dangerous_permissions(role.permissions) > 0
        ]
        if not added:
            return
        actor = await self._audit_executor(
            after.guild,
            discord.AuditLogAction.member_role_update,
            after.id,
        )
        await self._signal(
            after.guild,
            actor,
            "dangerous_role_assignment",
            f"Dangerous roles added to {after}: {', '.join(role.name for role in added[:8])}",
            target_id=after.id,
        )

    @commands.Cog.listener()
    async def on_member_ban(
        self,
        guild: discord.Guild,
        user: discord.User | discord.Member,
    ) -> None:
        actor = await self._audit_executor(guild, discord.AuditLogAction.ban, user.id)
        await self._signal(
            guild,
            actor,
            "member_ban",
            f"Member banned: {user} ({user.id})",
            target_id=user.id,
        )

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel) -> None:
        actor = None
        try:
            async for entry in channel.guild.audit_logs(
                action=discord.AuditLogAction.webhook_create,
                limit=3,
                after=datetime.now(UTC) - timedelta(seconds=30),
            ):
                actor = entry.user
                break
        except (discord.Forbidden, discord.HTTPException):
            pass
        await asyncio.sleep(1)
        await self._scan_webhooks(channel, actor)

    @commands.Cog.listener()
    async def on_guild_integrations_update(self, guild: discord.Guild) -> None:
        action = getattr(discord.AuditLogAction, "integration_create", None)
        actor = None
        if action is not None:
            try:
                async for entry in guild.audit_logs(
                    action=action,
                    limit=2,
                    after=datetime.now(UTC) - timedelta(seconds=30),
                ):
                    actor = entry.user
                    break
            except (discord.Forbidden, discord.HTTPException):
                pass
        await self._signal(
            guild,
            actor,
            "integration_change",
            "Guild integration configuration changed",
        )

    @commands.Cog.listener()
    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        if (
            before.name == after.name
            and before.verification_level == after.verification_level
            and before.default_notifications == after.default_notifications
            and before.explicit_content_filter == after.explicit_content_filter
        ):
            return
        actor = await self._audit_executor(
            after,
            discord.AuditLogAction.guild_update,
            after.id,
        )
        await self._signal(
            after,
            actor,
            "guild_settings_change",
            "Core guild settings changed",
            target_id=after.id,
        )

    @tasks.loop(minutes=10)
    async def checkpoint_loop(self) -> None:
        for guild in list(self.bot.guilds):
            try:
                await self._ensure_role_baseline(guild)
                await self._baseline_webhooks(guild)
                await self.checkpoint(guild)
            except Exception:
                self._failsafe_active = True
                LOG.exception("Protection v6 checkpoint loop failed for guild %s", guild.id)

    @checkpoint_loop.before_loop
    async def before_checkpoint_loop(self) -> None:
        await self.bot.wait_until_ready()
        for guild in list(self.bot.guilds):
            try:
                await self._ensure_role_baseline(guild)
                await self._baseline_webhooks(guild)
                await self.checkpoint(guild, "v6-initial")
            except Exception:
                LOG.exception("Protection v6 initial checkpoint failed for guild %s", guild.id)

    @tasks.loop(minutes=2)
    async def watchdog_loop(self) -> None:
        required = (
            "view_audit_log",
            "manage_messages",
            "moderate_members",
            "kick_members",
            "ban_members",
            "manage_roles",
            "manage_channels",
            "manage_webhooks",
        )
        for guild in list(self.bot.guilds):
            config = await self._config(guild.id)
            if config is not None and (not config["enabled"] or not config["self_protection"]):
                continue
            bot_member = guild.me
            missing = [
                permission
                for permission in required
                if bot_member is None or not getattr(bot_member.guild_permissions, permission, False)
            ]
            tamper_details: list[str] = []
            if missing:
                tamper_details.append("missing permissions: " + ", ".join(missing))

            try:
                settings = await self.bot.database.setting(guild.id)
                for field in (
                    "security_log_channel_id",
                    "moderation_log_channel_id",
                    "command_log_channel_id",
                ):
                    channel_id = settings[field]
                    if channel_id and guild.get_channel(int(channel_id)) is None:
                        tamper_details.append(f"{field} points to missing channel {channel_id}")
            except Exception:
                self._failsafe_active = True

            try:
                guardian = await self.bot.database.fetchone(
                    "SELECT external_app_lock, bot_approval, webhook_guard, integration_guard, "
                    "credential_guard, rollback_enabled FROM guardian_config WHERE guild_id=?",
                    (guild.id,),
                )
                if guardian is not None:
                    disabled = [
                        key
                        for key in (
                            "external_app_lock",
                            "bot_approval",
                            "webhook_guard",
                            "integration_guard",
                            "credential_guard",
                            "rollback_enabled",
                        )
                        if not guardian[key]
                    ]
                    if disabled:
                        tamper_details.append("disabled core layers: " + ", ".join(disabled))
                        await self.bot.database.execute(
                            "UPDATE guardian_config SET external_app_lock=1, bot_approval=1, webhook_guard=1, "
                            "integration_guard=1, credential_guard=1, rollback_enabled=1 WHERE guild_id=?",
                            (guild.id,),
                        )
            except Exception:
                self._failsafe_active = True

            if not tamper_details:
                continue
            now = datetime.now(UTC)
            previous = self._last_watchdog_alert.get(guild.id)
            if previous is not None and now - previous < timedelta(minutes=10):
                continue
            self._last_watchdog_alert[guild.id] = now
            await self._signal(
                guild,
                None,
                "guardian_tamper",
                "; ".join(tamper_details),
            )

    @watchdog_loop.before_loop
    async def before_watchdog_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=1)
    async def incident_loop(self) -> None:
        for guild in list(self.bot.guilds):
            try:
                active = await self.bot.database.fetchone(
                    "SELECT * FROM guardian_v6_incidents WHERE guild_id=? AND closed_at IS NULL "
                    "ORDER BY incident_id DESC LIMIT 1",
                    (guild.id,),
                )
                if active is None:
                    continue
                now = datetime.now(UTC)
                self._prune_events(guild.id, now)
                recent_score = attack_chain_score([item[2] for item in self.events[guild.id]])
                opened = datetime.fromisoformat(str(active["opened_at"]).replace("Z", "+00:00"))
                if opened.tzinfo is None:
                    opened = opened.replace(tzinfo=UTC)
                if recent_score > 8 or now - opened < timedelta(minutes=10):
                    continue

                rows = await self.bot.database.fetchall(
                    "SELECT actor_id, kind, score, detail, target_id, created_at "
                    "FROM guardian_v6_events WHERE guild_id=? AND created_at>=? "
                    "ORDER BY event_id ASC LIMIT 200",
                    (guild.id, opened.strftime("%Y-%m-%d %H:%M:%S")),
                )
                kinds = Counter(str(row["kind"]) for row in rows)
                actors = Counter(
                    int(row["actor_id"])
                    for row in rows
                    if row["actor_id"] is not None
                )
                report = {
                    "incident_id": int(active["incident_id"]),
                    "severity": str(active["severity"]),
                    "reason": str(active["reason"]),
                    "event_count": len(rows),
                    "kinds": dict(kinds),
                    "actors": dict(actors),
                    "events": [
                        {
                            "actor_id": row["actor_id"],
                            "kind": row["kind"],
                            "score": row["score"],
                            "detail": row["detail"],
                            "target_id": row["target_id"],
                            "created_at": row["created_at"],
                        }
                        for row in rows[:80]
                    ],
                    "closed_at": now.isoformat(),
                }
                await self.bot.database.execute(
                    "UPDATE guardian_v6_incidents SET closed_at=CURRENT_TIMESTAMP, report_json=? "
                    "WHERE incident_id=?",
                    (json.dumps(report, ensure_ascii=True), active["incident_id"]),
                )
                await self.bot.database.backup("v6-incident-closed")
            except Exception:
                self._failsafe_active = True
                LOG.exception("Protection v6 incident finalizer failed for guild %s", guild.id)

    @incident_loop.before_loop
    async def before_incident_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def status_report(self, guild: discord.Guild) -> str:
        config = await self._config(guild.id)
        checkpoint = await self._latest_checkpoint(guild.id)
        active = None
        try:
            active = await self.bot.database.fetchone(
                "SELECT incident_id, severity, reason, opened_at FROM guardian_v6_incidents "
                "WHERE guild_id=? AND closed_at IS NULL ORDER BY incident_id DESC LIMIT 1",
                (guild.id,),
            )
        except Exception:
            self._failsafe_active = True

        now = datetime.now(UTC)
        self._prune_events(guild.id, now)
        chain = attack_chain_score([item[2] for item in self.events[guild.id]])
        queue_size = self._priority_queue.qsize()
        enabled = config is None or bool(config["enabled"])
        return (
            "**Guardian Protection v6 MAX**\n"
            f"Protection: {'ON' if enabled else 'OFF'}\n"
            f"Adaptive 60s attack-chain score: {chain}/100\n"
            f"Priority security queue: {queue_size}\n"
            f"Fail-safe memory mode: {'ACTIVE' if self._failsafe_active else 'standby'}\n"
            f"Permission firewall: {'ON' if config is None or config['permission_firewall'] else 'OFF'}\n"
            f"Automatic server healing: {'ON' if config is None or config['auto_heal'] else 'OFF'}\n"
            f"Raid fingerprinting: {'ON' if config is None or config['raid_fingerprinting'] else 'OFF'}\n"
            f"Sensitive-command shield: {'ON' if config is None or config['command_shield'] else 'OFF'}\n"
            f"Automatic PANIC: {'ON' if config is None or config['auto_panic'] else 'OFF'}\n"
            f"Latest recovery checkpoint: "
            f"{'#' + str(checkpoint['checkpoint_id']) + ' ' + checkpoint['created_at'] if checkpoint else 'none'}\n"
            f"Active incident: "
            f"{'#' + str(active['incident_id']) + ' ' + str(active['severity']) if active else 'none'}"
        )

    async def forensics_report(self, guild: discord.Guild) -> str:
        try:
            row = await self.bot.database.fetchone(
                "SELECT * FROM guardian_v6_incidents WHERE guild_id=? "
                "ORDER BY incident_id DESC LIMIT 1",
                (guild.id,),
            )
        except Exception:
            row = None
        if row is None:
            return "**Guardian v6 forensics**\nNo v6 incident has been recorded."

        try:
            report = json.loads(str(row["report_json"] or "{}"))
        except (TypeError, json.JSONDecodeError):
            report = {}
        if report.get("kinds"):
            kinds_text = ", ".join(
                f"{kind}×{amount}"
                for kind, amount in sorted(report["kinds"].items(), key=lambda item: item[1], reverse=True)[:10]
            )
        else:
            events = await self.bot.database.fetchall(
                "SELECT kind FROM guardian_v6_events WHERE guild_id=? AND created_at>=? "
                "ORDER BY event_id DESC LIMIT 100",
                (guild.id, row["opened_at"]),
            )
            counts = Counter(str(event["kind"]) for event in events)
            kinds_text = ", ".join(f"{kind}×{amount}" for kind, amount in counts.most_common(10)) or "none"

        return (
            "**Guardian v6 incident forensics**\n"
            f"Incident: #{row['incident_id']} • {row['severity']}\n"
            f"Opened: {row['opened_at']} UTC\n"
            f"Closed: {row['closed_at'] or 'ACTIVE'}\n"
            f"Primary actor: {row['actor_id'] or 'unattributed'}\n"
            f"Reason: {row['reason']}\n"
            f"Observed signals: {kinds_text}"
        )[:4000]

    @protection.command(name="status", description="Show Guardian Protection v6 MAX status.")
    @guild_only()
    @staff_only()
    async def protection_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.status_report(interaction.guild))

    @protection.command(name="risk", description="Show Guardian's adaptive risk score for a member.")
    @guild_only()
    @staff_only()
    async def protection_risk(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ) -> None:
        data = await self.member_risk(interaction.guild, member)
        await respond(
            interaction,
            (
                f"**Adaptive risk — {member}**\n"
                f"Score: {data['score']}/100 ({data['level']})\n"
                f"Account age: {data['account_age_days']} days\n"
                f"Weighted case risk: {data['weighted_cases']}\n"
                f"Dangerous roles: {data['dangerous_roles']}\n"
                f"Failed verification signals: {data['failed_verifications']}\n"
                f"External-app signals: {data['external_app_events']}\n"
                f"Raid-cluster contribution: {data['raid_cluster_score']}"
            ),
        )

    @protection.command(name="risk-board", description="Show the highest current member risk signals.")
    @guild_only()
    @staff_only()
    async def protection_risk_board(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.highest_risk_report(interaction.guild))

    @protection.command(name="checkpoint", description="Create a trusted recovery checkpoint.")
    @guild_only()
    @guild_owner_only()
    async def protection_checkpoint(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        checkpoint_id = await self.checkpoint(interaction.guild, "manual-owner")
        await respond(
            interaction,
            f"Recovery checkpoint created: #{checkpoint_id}" if checkpoint_id else "Could not create a recovery checkpoint.",
        )

    @protection.command(name="restore", description="Restore missing/modified structures from the latest checkpoint.")
    @guild_only()
    @guild_owner_only()
    async def protection_restore(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await self._restore_missing_from_checkpoint(interaction.guild)
        checkpoint = await self._latest_checkpoint(interaction.guild.id)
        await respond(
            interaction,
            f"Recovery pass completed from checkpoint #{checkpoint['checkpoint_id']}."
            if checkpoint
            else "No recovery checkpoint exists yet.",
        )

    @protection.command(name="forensics", description="Show the latest Guardian v6 incident forensics.")
    @guild_only()
    @staff_only()
    async def protection_forensics(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.forensics_report(interaction.guild))

    @protection.command(name="release", description="Release v6 panic lockdown while keeping protection enabled.")
    @guild_only()
    @guild_owner_only()
    async def protection_release(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        try:
            await self.bot.database.execute(
                "UPDATE guardian_config SET panic_mode=0 WHERE guild_id=?",
                (interaction.guild.id,),
            )
            await self.bot.database.execute(
                "UPDATE guardian_v6_incidents SET closed_at=COALESCE(closed_at, CURRENT_TIMESTAMP) "
                "WHERE guild_id=? AND closed_at IS NULL",
                (interaction.guild.id,),
            )
        except Exception:
            self._failsafe_active = True
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_unlockdown"):
            try:
                await security._unlockdown(
                    interaction.guild,
                    "Guardian v6 PANIC released by server owner",
                )
            except Exception:
                LOG.exception("V6 release could not unlock server")
        await self._case(
            interaction.guild,
            interaction.user,
            "V6_PANIC_RELEASED",
            "Server owner released v6 panic containment; protection remains enabled.",
        )
        await respond(interaction, "Protection v6 PANIC released. Core protection remains enabled.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ProtectionV6Cog(bot))
