from __future__ import annotations

import asyncio
import ipaddress
import re
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, log_event, respond, staff_only, guild_owner_only, safe_public_role, require_target

URL_RE = re.compile(r"(?:https?://|discord(?:app)?\.com/invite/|discord\.gg/)[^\s]+", re.IGNORECASE)
SUSPICIOUS_DOMAIN_TOKENS = (
    "discord-gift", "discordgift", "free-nitro", "freenitro", "nitro-gift",
    "steamcommuniity", "steamcomrnunity", "dlscord", "dicsord", "discorcl",
)
SUSPICIOUS_SHORTENERS = {"bit.ly", "tinyurl.com", "is.gd", "rb.gy", "cutt.ly"}
HIGH_RISK_PERMISSIONS = (
    "administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks",
    "ban_members", "kick_members", "moderate_members",
)

RAID_CONTAINMENT_MINUTES = 5
MESSAGE_POLICY_CACHE_SECONDS = 30
RAID_CONFIG_CACHE_SECONDS = 60
RAID_KICK_CONCURRENCY = 5


def raid_mode_active(until: datetime | None, now: datetime) -> bool:
    return until is not None and until > now


def should_activate_raid(join_count: int, join_limit: int, already_active: bool) -> bool:
    return not already_active and join_count >= join_limit


class SecurityCog(commands.Cog):
    antinuke = app_commands.Group(name="antinuke", description="Configure protection against destructive server actions.")
    security = app_commands.Group(name="security", description="Configure advanced server security and AutoMod.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.messages: dict[tuple[int, int], deque[tuple[datetime, str]]] = defaultdict(deque)
        self.joins: dict[int, deque[datetime]] = defaultdict(deque)
        self.recent_join_members: dict[int, deque[tuple[datetime, int]]] = defaultdict(deque)
        self.lockdown_locks = defaultdict(asyncio.Lock)
        self.raid_locks = defaultdict(asyncio.Lock)
        self.raid_kick_semaphores = defaultdict(lambda: asyncio.Semaphore(RAID_KICK_CONCURRENCY))
        self.audit_events: dict[tuple[int, int], deque[datetime]] = defaultdict(deque)
        self.raid_mode_until: dict[int, datetime] = {}
        self._raid_kicked_until: dict[tuple[int, int], datetime] = {}
        self._audit_access_warned_at: dict[int, datetime] = {}
        self._initialized_guilds: set[int] = set()
        self._message_policy_cache: dict[int, tuple[datetime, dict[str, object], set[str], tuple[str, ...]]] = {}
        self._raid_config_cache: dict[int, tuple[datetime, dict[str, object]]] = {}
        self._raid_case_buffer: dict[int, list[tuple[int, int | None, int | None, str, str, int | None, dict[str, object] | None]]] = defaultdict(list)
        self._raid_flush_tasks: dict[int, asyncio.Task[None]] = {}

    async def _ensure_guild_once(self, guild_id: int) -> None:
        if guild_id in self._initialized_guilds:
            return
        await self.bot.database.ensure_guild(guild_id)
        self._initialized_guilds.add(guild_id)

    async def _message_policy(
        self,
        guild_id: int,
    ) -> tuple[dict[str, object], set[str], tuple[str, ...]]:
        now = datetime.now(UTC)
        cached = self._message_policy_cache.get(guild_id)
        if cached is not None and now - cached[0] < timedelta(seconds=MESSAGE_POLICY_CACHE_SECONDS):
            return cached[1], cached[2], cached[3]

        await self._ensure_guild_once(guild_id)
        config_row = await self.bot.database.fetchone(
            "SELECT * FROM security_config WHERE guild_id = ?",
            (guild_id,),
        )
        assert config_row is not None
        allowed_rows = await self.bot.database.fetchall(
            "SELECT domain FROM allowed_domains WHERE guild_id = ?",
            (guild_id,),
        )
        bad_word_rows = await self.bot.database.fetchall(
            "SELECT word FROM bad_words WHERE guild_id = ?",
            (guild_id,),
        )
        config = dict(config_row)
        allowed_domains = {str(row["domain"]) for row in allowed_rows}
        bad_words = tuple(str(row["word"]) for row in bad_word_rows)
        self._message_policy_cache[guild_id] = (now, config, allowed_domains, bad_words)
        return config, allowed_domains, bad_words

    async def _raid_config(self, guild_id: int) -> dict[str, object]:
        now = datetime.now(UTC)
        cached = self._raid_config_cache.get(guild_id)
        if cached is not None and now - cached[0] < timedelta(seconds=RAID_CONFIG_CACHE_SECONDS):
            return cached[1]
        row = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (guild_id,))
        assert row is not None
        config = dict(row)
        self._raid_config_cache[guild_id] = (now, config)
        return config

    def _queue_raid_case(self, member: discord.Member, reason: str) -> None:
        guild_id = member.guild.id
        self._raid_case_buffer[guild_id].append((
            guild_id,
            member.id,
            self.bot.user.id if self.bot.user else None,
            "RAID_JOIN_BLOCKED",
            reason,
            None,
            None,
        ))
        task = self._raid_flush_tasks.get(guild_id)
        if task is None or task.done():
            self._raid_flush_tasks[guild_id] = asyncio.create_task(self._flush_raid_cases(guild_id))

    async def _flush_raid_cases(self, guild_id: int) -> None:
        await asyncio.sleep(0.75)
        rows = self._raid_case_buffer.pop(guild_id, [])
        if rows:
            await self.bot.database.create_cases_bulk(rows)

    async def _kick_for_raid(self, member: discord.Member, reason: str) -> bool:
        if member.bot or member.id == member.guild.owner_id:
            return False
        async with self.raid_kick_semaphores[member.guild.id]:
            self._raid_kicked_until[(member.guild.id, member.id)] = datetime.now(UTC) + timedelta(minutes=2)
            try:
                await member.kick(reason=f"ESN Guardian raid containment: {reason}"[:512])
                self._queue_raid_case(member, reason)
                return True
            except (discord.Forbidden, discord.HTTPException):
                self._raid_kicked_until.pop((member.guild.id, member.id), None)
                await self._security_case(
                    member.guild,
                    member,
                    "RAID_CONTAINMENT_FAILED",
                    f"Could not remove member during raid containment: {reason}",
                )
                return False

    async def _contain_recent_raid_joiners(
        self,
        guild: discord.Guild,
        member_ids: list[int],
        reason: str,
    ) -> int:
        semaphore = asyncio.Semaphore(RAID_KICK_CONCURRENCY)

        async def remove(member_id: int) -> bool:
            member = guild.get_member(member_id)
            if member is None or member.bot or member.id == guild.owner_id:
                return False
            async with semaphore:
                return await self._kick_for_raid(member, reason)

        results = await asyncio.gather(
            *(remove(member_id) for member_id in member_ids[-25:]),
            return_exceptions=True,
        )
        return sum(result is True for result in results)

    async def _security_case(self, guild: discord.Guild, target: discord.abc.User | None, action: str, reason: str, channel_id: int | None = None) -> int:
        case_id = await self.bot.database.create_case(guild.id, target.id if target else None, self.bot.user.id if self.bot.user else None, action, reason, channel_id)
        await log_event(self.bot, guild, "security_log_channel_id", f"Security: {action} | Case #{case_id}", description=f"Target: {target.mention if target else 'N/A'}\nReason: {reason}", color=discord.Color.red())
        if guild.owner is not None:
            target_text = f"{target} ({target.id})" if target else "N/A"
            try:
                await guild.owner.send(
                    f"Security alert in **{guild.name}** (`{guild.id}`)\n"
                    f"Case #{case_id}: {action}\n"
                    f"Target: {target_text}\n"
                    f"Reason: {reason}",
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                pass
        return case_id

    async def _audit_executor(self, guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> discord.User | discord.Member | None:
        for delay in (0.6, 1.2, 2.0):
            await asyncio.sleep(delay)
            try:
                async for entry in guild.audit_logs(action=action, limit=10, after=datetime.now(UTC) - timedelta(minutes=2)):
                    if getattr(entry.target, "id", None) == target_id and entry.user is not None:
                        return entry.user
            except discord.Forbidden:
                now = datetime.now(UTC)
                last = self._audit_access_warned_at.get(guild.id)
                if last is None or now - last >= timedelta(minutes=10):
                    self._audit_access_warned_at[guild.id] = now
                    await log_event(
                        self.bot,
                        guild,
                        "security_log_channel_id",
                        "Anti-nuke audit access unavailable",
                        description="Grant View Audit Log to attribute destructive actions.",
                        color=discord.Color.orange(),
                    )
                return None
            except discord.HTTPException:
                continue
        return None

    async def _is_trusted_executor(self, guild: discord.Guild, executor: discord.User | discord.Member | None) -> bool:
        if executor is None:
            return False
        if executor.id in {guild.owner_id, self.bot.user.id if self.bot.user else 0}:
            return True
        row = await self.bot.database.fetchone("SELECT 1 FROM anti_nuke_trusted_users WHERE guild_id = ? AND user_id = ?", (guild.id, executor.id))
        return row is not None

    @staticmethod
    def _has_high_risk_permissions(role: discord.Role) -> bool:
        return any(getattr(role.permissions, permission) for permission in HIGH_RISK_PERMISSIONS)

    @staticmethod
    def _gained_high_risk_permissions(before: discord.Role, after: discord.Role) -> bool:
        return any(
            getattr(after.permissions, permission) and not getattr(before.permissions, permission)
            for permission in HIGH_RISK_PERMISSIONS
        )

    @staticmethod
    def _normalize_domain(value: str) -> str:
        candidate = value.casefold().strip().rstrip(".")
        try:
            return candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return candidate

    @classmethod
    def _has_unallowed_url(cls, content: str, allowed_domains: set[str]) -> bool:
        normalized_allowed = {cls._normalize_domain(domain) for domain in allowed_domains}
        for value in URL_RE.findall(content):
            parsed = urlparse(value if "://" in value else f"https://{value}")
            host = cls._normalize_domain(parsed.hostname or "")
            if host and not any(host == domain or host.endswith(f".{domain}") for domain in normalized_allowed):
                return True
        return False

    @classmethod
    def _suspicious_url_reason(cls, content: str) -> str | None:
        for value in URL_RE.findall(content):
            parsed = urlparse(value if "://" in value else f"https://{value}")
            host = cls._normalize_domain(parsed.hostname or "")
            if not host:
                continue
            if parsed.username or parsed.password:
                return "Suspicious link with embedded credentials detected"
            if host in SUSPICIOUS_SHORTENERS:
                return "URL shortener detected"
            if any(token in host for token in SUSPICIOUS_DOMAIN_TOKENS):
                return "Known phishing-style domain detected"
            if host.startswith("xn--"):
                return "Punycode lookalike domain detected"
            try:
                ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                pass
            else:
                return "Direct IP link detected"
        return None

    async def _check_nuke_action(
        self,
        guild: discord.Guild,
        audit_action: discord.AuditLogAction,
        target_id: int,
        action_name: str,
        executor: discord.User | discord.Member | None = None,
        *,
        allow_unattributed: bool = False,
    ) -> None:
        config = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (guild.id,))
        if config is None or not config["enabled"]:
            return
        if executor is None:
            executor = await self._audit_executor(guild, audit_action, target_id)
        if executor is not None and await self._is_trusted_executor(guild, executor):
            return
        if executor is None and not allow_unattributed:
            return

        now = datetime.now(UTC)
        actor_id = executor.id if executor is not None else 0
        events = self.audit_events[(guild.id, actor_id)]
        events.append(now)
        while events and now - events[0] > timedelta(seconds=config["window_seconds"]):
            events.popleft()

        actor_text = str(executor) if executor is not None else "unattributed actor"
        if len(events) < config["action_limit"]:
            await self._security_case(
                guild,
                executor,
                "ANTINUKE_ALERT" if executor is not None else "ANTINUKE_UNATTRIBUTED",
                f"{action_name} by {actor_text} ({len(events)}/{config['action_limit']} actions)",
            )
            return

        events.clear()
        if executor is not None:
            try:
                await guild.ban(executor, reason=f"ESN Guardian anti-nuke: {action_name} threshold exceeded", delete_message_seconds=0)
                await self._security_case(
                    guild,
                    executor,
                    "ANTINUKE_BAN",
                    f"Banned after {config['action_limit']} destructive actions in {config['window_seconds']} seconds",
                )
            except (discord.Forbidden, discord.HTTPException):
                await self._security_case(guild, executor, "ANTINUKE_CONTAINMENT_FAILED", f"Could not ban after destructive action threshold: {action_name}")
        else:
            await self._security_case(
                guild,
                None,
                "ANTINUKE_UNATTRIBUTED",
                f"Destructive-action threshold reached for {action_name}, but Discord audit logs did not expose the actor in time.",
            )
        await self._lockdown(guild, f"Automatic anti-nuke lockdown: {action_name} threshold exceeded")

    async def _enforce_message_violation(self, message: discord.Message, reason: str, *, escalate: bool = True) -> None:
        if message.guild is None or not isinstance(message.author, discord.Member):
            return

        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            pass

        if not escalate:
            await self._security_case(message.guild, message.author, "AUTOMOD_STAFF_BLOCK", reason, message.channel.id)
            return

        prior = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM cases WHERE guild_id = ? AND target_id = ? "
            "AND action LIKE 'AUTOMOD_%' AND created_at >= datetime('now', '-30 days')",
            (message.guild.id, message.author.id),
        )
        violations = int(prior["count"]) if prior is not None else 0
        try:
            if violations == 0:
                await self._security_case(message.guild, message.author, "AUTOMOD_WARN", reason, message.channel.id)
            elif violations == 1:
                await message.author.timeout(timedelta(minutes=10), reason=f"ESN Guardian: {reason}")
                await self._security_case(message.guild, message.author, "AUTOMOD_TIMEOUT", f"{reason}; 10 minute timeout", message.channel.id)
            elif violations == 2:
                await message.author.timeout(timedelta(hours=1), reason=f"ESN Guardian: {reason}")
                await self._security_case(message.guild, message.author, "AUTOMOD_TIMEOUT", f"{reason}; 1 hour timeout", message.channel.id)
            elif violations == 3:
                await message.author.kick(reason=f"ESN Guardian: {reason}")
                await self._security_case(message.guild, message.author, "AUTOMOD_KICK", reason, message.channel.id)
            else:
                await message.guild.ban(message.author, reason=f"ESN Guardian: {reason}", delete_message_seconds=0)
                await self._security_case(message.guild, message.author, "AUTOMOD_BAN", reason, message.channel.id)
        except (discord.Forbidden, discord.HTTPException):
            await self._security_case(message.guild, message.author, "AUTOMOD_ALERT", f"Could not fully enforce: {reason}", message.channel.id)

    async def _quarantine(self, member: discord.Member, reason: str, moderator_id: int | None = None) -> bool:
        config = await self.bot.database.fetchone("SELECT quarantine_role_id FROM raid_config WHERE guild_id = ?", (member.guild.id,))
        role = member.guild.get_role(config["quarantine_role_id"]) if config and config["quarantine_role_id"] else None
        bot_member = member.guild.me
        if role is None or not safe_public_role(role, member.guild) or member.id == member.guild.owner_id:
            await self._security_case(member.guild, member, "QUARANTINE_ALERT", f"Could not quarantine member: {reason}")
            return False
        try:
            await member.add_roles(role, reason=f"ESN Guardian quarantine: {reason}")
        except (discord.Forbidden, discord.HTTPException):
            await self._security_case(member.guild, member, "QUARANTINE_ALERT", f"Could not quarantine member: {reason}")
            return False
        case_id = await self.bot.database.create_case(member.guild.id, member.id, moderator_id or (self.bot.user.id if self.bot.user else None), "QUARANTINE", reason)
        await log_event(self.bot, member.guild, "security_log_channel_id", f"Security: QUARANTINE | Case #{case_id}", description=f"Target: {member.mention}\nReason: {reason}", color=discord.Color.orange())
        return True

    async def _enforce_external_app_zero_tolerance(self, message: discord.Message) -> bool:
        guild = message.guild
        if guild is None:
            return False

        metadata = getattr(message, "interaction_metadata", None)
        if metadata is None:
            return False
        try:
            is_external_app = metadata.is_user_integration()
        except (AttributeError, TypeError):
            is_external_app = False
        if not is_external_app:
            return False

        channel_id = getattr(message.channel, "id", None)
        invoker = getattr(metadata, "user", None)
        app_id = getattr(message, "application_id", None)
        reason = f"Zero-tolerance external app use detected; application_id={app_id or 'unknown'}"

        await self._block_external_app(guild, app_id, channel_id)

        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            pass

        if invoker is None:
            await self._security_case(
                guild,
                None,
                "EXTERNAL_APP_BAN_FAILED",
                f"{reason}; Discord did not expose the invoking user",
                channel_id,
            )
            return True

        member = guild.get_member(invoker.id)
        if member is None:
            try:
                member = await guild.fetch_member(invoker.id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                member = None

        if member is None:
            await self._security_case(
                guild,
                invoker,
                "EXTERNAL_APP_BAN_FAILED",
                f"{reason}; invoking member could not be resolved",
                channel_id,
            )
            return True

        try:
            await guild.ban(
                member,
                reason=f"ESN Guardian: {reason}",
                delete_message_seconds=0,
            )
            await self._security_case(guild, member, "EXTERNAL_APP_BAN", reason, channel_id)
        except (discord.Forbidden, discord.HTTPException):
            await self._security_case(
                guild,
                member,
                "EXTERNAL_APP_BAN_FAILED",
                f"{reason}; Guardian could not ban the invoking member",
                channel_id,
            )
        return True

    async def _block_external_app(self, guild: discord.Guild, application_id: int | None, channel_id: int | None = None) -> None:
        if application_id is None:
            return

        reason = "Zero-tolerance external app policy"
        await self.bot.database.execute(
            "INSERT INTO blocked_external_apps (guild_id, application_id, reason) VALUES (?, ?, ?) "
            "ON CONFLICT(guild_id, application_id) DO UPDATE SET reason = excluded.reason, last_detected_at = CURRENT_TIMESTAMP",
            (guild.id, application_id, reason),
        )

        app_member = guild.get_member(application_id)
        if app_member is not None and getattr(app_member, "bot", False):
            try:
                await guild.ban(
                    app_member,
                    reason=f"ESN Guardian: blocked external application {application_id}",
                    delete_message_seconds=0,
                )
                await self._security_case(
                    guild,
                    app_member,
                    "EXTERNAL_APP_BOT_BAN",
                    f"Blocked external application bot {application_id}",
                    channel_id,
                )
            except (discord.Forbidden, discord.HTTPException):
                await self._security_case(
                    guild,
                    app_member,
                    "EXTERNAL_APP_BOT_BAN_FAILED",
                    f"Could not ban blocked external application bot {application_id}",
                    channel_id,
                )

        try:
            integrations = await guild.integrations()
        except (discord.Forbidden, discord.HTTPException):
            integrations = []

        for integration in integrations:
            integration_app = getattr(integration, "application", None)
            if getattr(integration_app, "id", None) != application_id:
                continue
            try:
                await integration.delete(reason=f"ESN Guardian: blocked external application {application_id}")
                await self._security_case(
                    guild,
                    getattr(integration, "user", None),
                    "EXTERNAL_APP_INTEGRATION_REMOVED",
                    f"Removed server integration for blocked application {application_id}",
                    channel_id,
                )
            except (discord.Forbidden, discord.HTTPException):
                await self._security_case(
                    guild,
                    getattr(integration, "user", None),
                    "EXTERNAL_APP_INTEGRATION_REMOVE_FAILED",
                    f"Could not remove server integration for blocked application {application_id}",
                    channel_id,
                )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        if await self._enforce_external_app_zero_tolerance(message):
            return
        if message.author.bot or not isinstance(message.author, discord.Member):
            return

        config, allowed_domains, bad_words = await self._message_policy(message.guild.id)
        if not bool(config["automod_enabled"]):
            return

        now = datetime.now(UTC)
        key = (message.guild.id, message.author.id)
        normalized = message.content.casefold().strip()
        window = self.messages[key]
        window.append((now, normalized))
        while window and now - window[0][0] > timedelta(seconds=int(config["flood_window_seconds"])):
            window.popleft()

        dangerous_violation = self._suspicious_url_reason(message.content)
        has_invite = (
            "discord.gg/" in normalized
            or "discord.com/invite/" in normalized
            or "discordapp.com/invite/" in normalized
        )
        if dangerous_violation is None and bool(config["block_invites"]) and has_invite:
            dangerous_violation = "Unauthorized invite link"
        if dangerous_violation is None and bool(config["strict_links"]) and self._has_unallowed_url(message.content, allowed_domains):
            dangerous_violation = "External link is not allowlisted"

        is_staff = (
            message.author.guild_permissions.manage_messages
            or message.author.guild_permissions.manage_guild
            or message.author.guild_permissions.administrator
        )
        if dangerous_violation is not None:
            await self._enforce_message_violation(message, dangerous_violation, escalate=not is_staff)
            return
        if is_staff:
            return

        violation = None
        if len(window) >= int(config["flood_limit"]):
            violation = "Message flood detected"
        elif len(message.mentions) + len(message.role_mentions) >= int(config["max_mentions"]):
            violation = "Mass mentions detected"
        elif (
            len(message.content) >= 12
            and sum(character.isupper() for character in message.content) * 100 / max(len(message.content), 1)
            >= int(config["caps_percentage"])
        ):
            violation = "Excessive capitals detected"
        elif sum(1 for _, prior in window if prior == normalized) >= 3:
            violation = "Repeated message detected"
        elif any(word in normalized for word in bad_words):
            violation = "Blocked word detected"

        if violation:
            await self._enforce_message_violation(message, violation)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        await self._ensure_guild_once(member.guild.id)

        if member.bot:
            blocked_app = await self.bot.database.fetchone(
                "SELECT application_id FROM blocked_external_apps WHERE guild_id = ? AND application_id = ?",
                (member.guild.id, member.id),
            )
            if blocked_app is not None:
                try:
                    await member.guild.ban(
                        member,
                        reason=f"ESN Guardian: application {member.id} is permanently blocked",
                        delete_message_seconds=0,
                    )
                    await self._security_case(
                        member.guild,
                        member,
                        "EXTERNAL_APP_REBAN",
                        f"Blocked application {member.id} attempted to join the server",
                    )
                except (discord.Forbidden, discord.HTTPException):
                    await self._security_case(
                        member.guild,
                        member,
                        "EXTERNAL_APP_REBAN_FAILED",
                        f"Could not ban blocked application {member.id} after it joined",
                    )
                return

        antinuke = await self.bot.database.fetchone(
            "SELECT enabled FROM anti_nuke_config WHERE guild_id = ?",
            (member.guild.id,),
        )
        if member.bot and antinuke is not None and antinuke["enabled"]:
            executor = await self._audit_executor(
                member.guild,
                discord.AuditLogAction.bot_add,
                member.id,
            )
            if not await self._is_trusted_executor(member.guild, executor):
                try:
                    await member.kick(reason="ESN Guardian anti-nuke: untrusted bot addition")
                    await self._security_case(
                        member.guild,
                        executor,
                        "BOT_ADD_BLOCKED",
                        f"Removed untrusted bot {member} ({member.id})",
                    )
                except (discord.Forbidden, discord.HTTPException):
                    await self._security_case(
                        member.guild,
                        executor,
                        "ANTINUKE_CONTAINMENT_FAILED",
                        f"Could not remove untrusted bot {member} ({member.id})",
                    )
                await self._check_nuke_action(
                    member.guild,
                    discord.AuditLogAction.bot_add,
                    member.id,
                    "untrusted bot addition",
                    executor,
                    allow_unattributed=True,
                )
                return

        config = await self._raid_config(member.guild.id)
        if not config["enabled"] or member.bot:
            return

        async with self.raid_locks[member.guild.id]:
            now = datetime.now(UTC)
            if len(self._raid_kicked_until) > 1000:
                self._raid_kicked_until = {
                    key: until for key, until in self._raid_kicked_until.items()
                    if until > now
                }
            if len(self.messages) > 5000:
                cutoff = now - timedelta(minutes=10)
                for key in list(self.messages)[:1000]:
                    window = self.messages.get(key)
                    if not window or window[-1][0] < cutoff:
                        self.messages.pop(key, None)
            join_window = timedelta(seconds=int(config["join_window_seconds"]))
            joins = self.joins[member.guild.id]
            recent_members = self.recent_join_members[member.guild.id]

            joins.append(now)
            recent_members.append((now, member.id))
            while joins and now - joins[0] > join_window:
                joins.popleft()
            while recent_members and now - recent_members[0][0] > join_window:
                recent_members.popleft()

            raid_until = self.raid_mode_until.get(member.guild.id)
            active = raid_mode_active(raid_until, now)
            if raid_until is not None and not active:
                self.raid_mode_until.pop(member.guild.id, None)

            activate = should_activate_raid(
                len(joins),
                int(config["join_limit"]),
                active,
            )
            surge_reason = (
                f"Join surge exceeded {config['join_limit']} members/"
                f"{config['join_window_seconds']}s"
            )

            if activate:
                self.raid_mode_until[member.guild.id] = now + timedelta(
                    minutes=RAID_CONTAINMENT_MINUTES
                )
                member_ids = [member_id for _, member_id in recent_members]
                asyncio.create_task(
                    self._contain_recent_raid_joiners(
                        member.guild,
                        member_ids,
                        surge_reason,
                    )
                )
                asyncio.create_task(
                    self._lockdown(
                        member.guild,
                        f"Automatic raid lockdown: {surge_reason}",
                    )
                )
                await self._security_case(
                    member.guild,
                    None,
                    "RAID_MODE",
                    f"Raid containment enabled for {RAID_CONTAINMENT_MINUTES} minutes; {surge_reason}",
                )
                return

            if active:
                self.raid_mode_until[member.guild.id] = now + timedelta(
                    minutes=RAID_CONTAINMENT_MINUTES
                )
                await self._kick_for_raid(
                    member,
                    "Server is in active raid containment mode",
                )
                return

            account_age = now - member.created_at
            if account_age < timedelta(days=int(config["min_account_age_days"])):
                reason = (
                    f"Account is younger than {config['min_account_age_days']} days "
                    f"(age: {account_age.days} days)"
                )
                await self._security_case(
                    member.guild,
                    member,
                    "SUSPICIOUS_JOIN",
                    reason,
                )
                await self._quarantine(member, reason)

    async def _check_webhook_change(self, channel: discord.abc.GuildChannel) -> None:
        await asyncio.sleep(0.8)
        for audit_action in (
            discord.AuditLogAction.webhook_create,
            discord.AuditLogAction.webhook_update,
            discord.AuditLogAction.webhook_delete,
        ):
            try:
                async for entry in channel.guild.audit_logs(action=audit_action, limit=5, after=datetime.now(UTC) - timedelta(minutes=1)):
                    extra_channel = getattr(entry.extra, "channel", None)
                    target_channel = getattr(entry.target, "channel", None)
                    known_ids = {
                        getattr(extra_channel, "id", None),
                        getattr(target_channel, "id", None),
                        getattr(entry.target, "channel_id", None),
                    }
                    known_ids.discard(None)
                    if known_ids and channel.id not in known_ids:
                        continue
                    target_id = getattr(entry.target, "id", channel.id)
                    await self._check_nuke_action(
                        channel.guild,
                        audit_action,
                        target_id,
                        f"webhook {audit_action.name}",
                        entry.user,
                        allow_unattributed=True,
                    )
                    return
            except (discord.Forbidden, discord.HTTPException):
                continue

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel) -> None:
        await self._security_case(channel.guild, None, "WEBHOOK_CHANGE", f"Webhook update in #{channel.name}", channel.id)
        await self._check_webhook_change(channel)

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        await self._check_nuke_action(
            channel.guild,
            discord.AuditLogAction.channel_create,
            channel.id,
            "channel creation",
            allow_unattributed=True,
        )

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        if before.overwrites != after.overwrites:
            await self._check_nuke_action(
                after.guild,
                discord.AuditLogAction.channel_update,
                after.id,
                "channel permission update",
                allow_unattributed=True,
            )

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        await self._security_case(channel.guild, None, "CHANNEL_DELETE", f"Channel deleted: {channel.name}", channel.id)
        await self._check_nuke_action(channel.guild, discord.AuditLogAction.channel_delete, channel.id, "channel deletion", allow_unattributed=True)

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role) -> None:
        await self._check_nuke_action(role.guild, discord.AuditLogAction.role_create, role.id, "role creation", allow_unattributed=True)

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        await self._security_case(role.guild, None, "ROLE_DELETE", f"Role deleted: {role.name}")
        await self._check_nuke_action(role.guild, discord.AuditLogAction.role_delete, role.id, "role deletion", allow_unattributed=True)

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.permissions != after.permissions:
            await self._security_case(after.guild, None, "ROLE_PERMISSION_CHANGE", f"Permissions changed for {after.name}")
            config = await self.bot.database.fetchone("SELECT enabled FROM anti_nuke_config WHERE guild_id = ?", (after.guild.id,))
            if config is not None and config["enabled"] and self._gained_high_risk_permissions(before, after):
                executor = await self._audit_executor(after.guild, discord.AuditLogAction.role_update, after.id)
                if not await self._is_trusted_executor(after.guild, executor):
                    try:
                        await after.edit(permissions=before.permissions, reason="ESN Guardian anti-nuke: reverted dangerous role permission escalation")
                        await self._security_case(after.guild, executor, "ANTINUKE_ROLE_REVERT", f"Reverted dangerous permissions added to {after.name}")
                    except (discord.Forbidden, discord.HTTPException):
                        await self._security_case(after.guild, executor, "ANTINUKE_ROLE_REVERT_FAILED", f"Could not revert dangerous permissions on {after.name}")
                await self._check_nuke_action(after.guild, discord.AuditLogAction.role_update, after.id, "dangerous role permission escalation", executor, allow_unattributed=True)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        added_roles = [role for role in after.roles if role not in before.roles and self._has_high_risk_permissions(role)]
        if not added_roles:
            return
        config = await self.bot.database.fetchone("SELECT enabled FROM anti_nuke_config WHERE guild_id = ?", (after.guild.id,))
        if config is None or not config["enabled"]:
            return
        executor = await self._audit_executor(after.guild, discord.AuditLogAction.member_role_update, after.id)
        if await self._is_trusted_executor(after.guild, executor):
            return
        bot_member = after.guild.me
        removable_roles = [role for role in added_roles if bot_member is not None and role < bot_member.top_role]
        try:
            if removable_roles:
                await after.remove_roles(*removable_roles, reason="ESN Guardian anti-nuke: reverted dangerous role assignment")
                await self._security_case(after.guild, executor, "ANTINUKE_ROLE_ASSIGNMENT_REVERT", f"Removed dangerous roles from {after.mention}: {', '.join(role.name for role in removable_roles)}")
            else:
                await self._security_case(after.guild, executor, "ANTINUKE_ROLE_ASSIGNMENT_UNMANAGEABLE", f"Dangerous role assigned to {after.mention}, but it is above my role")
        except (discord.Forbidden, discord.HTTPException):
            await self._security_case(after.guild, executor, "ANTINUKE_ROLE_ASSIGNMENT_REVERT_FAILED", f"Could not remove dangerous roles from {after.mention}")
        await self._check_nuke_action(after.guild, discord.AuditLogAction.member_role_update, after.id, "dangerous role assignment", executor, allow_unattributed=True)

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User | discord.Member) -> None:
        await log_event(self.bot, guild, "member_log_channel_id", "Member banned", description=f"User: {user.mention} ({user.id})", color=discord.Color.orange())
        await self._check_nuke_action(guild, discord.AuditLogAction.ban, user.id, "member ban", allow_unattributed=True)

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        key = (member.guild.id, member.id)
        raid_kick_until = self._raid_kicked_until.pop(key, None)
        if raid_kick_until is not None and raid_kick_until > datetime.now(UTC):
            return
        await log_event(
            self.bot,
            member.guild,
            "member_log_channel_id",
            "Member left",
            description=f"User: {member} ({member.id})",
        )
        await self._check_nuke_action(
            member.guild,
            discord.AuditLogAction.kick,
            member.id,
            "member kick",
        )

    @commands.Cog.listener()
    async def on_member_unban(self, guild: discord.Guild, user: discord.User) -> None:
        await self._check_nuke_action(guild, discord.AuditLogAction.unban, user.id, "member unban", allow_unattributed=True)

    async def _lockdown(self, guild: discord.Guild, reason: str):
        async with self.lockdown_locks[guild.id]:
            return await self._lockdown_locked(guild, reason)

    async def _lockdown_locked(self, guild: discord.Guild, reason: str) -> bool:
        settings = await self.bot.database.setting(guild.id)
        if settings["lockdown_active"]:
            return False

        prepared: list[tuple[discord.TextChannel, discord.PermissionOverwrite]] = []
        saved_rows: list[tuple[int, int, bool | None]] = []
        for channel in guild.text_channels:
            overwrite = channel.overwrites_for(guild.default_role)
            prepared.append((channel, overwrite))
            saved_rows.append((guild.id, channel.id, overwrite.send_messages))

        if saved_rows:
            await self.bot.database.executemany(
                "INSERT OR IGNORE INTO lockdown_overwrites "
                "(guild_id, channel_id, send_messages) VALUES (?, ?, ?)",
                saved_rows,
            )

        changed = 0
        for channel, overwrite in prepared:
            try:
                overwrite.send_messages = False
                await channel.set_permissions(
                    guild.default_role,
                    overwrite=overwrite,
                    reason=reason,
                )
                changed += 1
            except (discord.Forbidden, discord.HTTPException):
                continue

        await self.bot.database.update_setting(guild.id, "lockdown_active", 1)
        await self._security_case(
            guild,
            None,
            "LOCKDOWN",
            f"{reason}; channels secured: {changed}",
        )
        return True

    async def _unlockdown(self, guild: discord.Guild, reason: str):
        async with self.lockdown_locks[guild.id]:
            return await self._unlockdown_locked(guild, reason)

    async def _unlockdown_locked(self, guild: discord.Guild, reason: str) -> int:
        saved_rows = await self.bot.database.fetchall(
            "SELECT channel_id, send_messages FROM lockdown_overwrites WHERE guild_id = ?",
            (guild.id,),
        )
        saved = {int(row["channel_id"]): row["send_messages"] for row in saved_rows}
        restored_ids: list[tuple[int, int]] = []
        changed = 0

        for channel in guild.text_channels:
            if channel.id not in saved:
                continue
            try:
                overwrite = channel.overwrites_for(guild.default_role)
                value = saved[channel.id]
                overwrite.send_messages = None if value is None else bool(value)
                await channel.set_permissions(
                    guild.default_role,
                    overwrite=overwrite,
                    reason=reason,
                )
                restored_ids.append((guild.id, channel.id))
                changed += 1
            except (discord.Forbidden, discord.HTTPException):
                continue

        if restored_ids:
            await self.bot.database.executemany(
                "DELETE FROM lockdown_overwrites WHERE guild_id = ? AND channel_id = ?",
                restored_ids,
            )

        pending = await self.bot.database.fetchone(
            "SELECT 1 FROM lockdown_overwrites WHERE guild_id = ?",
            (guild.id,),
        )
        await self.bot.database.update_setting(
            guild.id,
            "lockdown_active",
            int(pending is not None),
        )
        await self._security_case(
            guild,
            None,
            "UNLOCKDOWN",
            f"{reason}; channels restored: {changed}",
        )
        return changed

    @app_commands.command(description="Lock the current channel for @everyone.")
    @guild_only()
    @staff_only()
    async def lock(self, interaction: discord.Interaction, reason: str = "Channel locked") -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        try:
            await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=False, reason=reason)
            case_id = await self._security_case(interaction.guild, None, "CHANNEL_LOCK", reason, interaction.channel_id)
            await respond(interaction, f"Channel locked. Case #{case_id}.")
        except discord.HTTPException:
            await respond(interaction, "I could not lock this channel.")

    @app_commands.command(description="Unlock the current channel for @everyone.")
    @guild_only()
    @staff_only()
    async def unlock(self, interaction: discord.Interaction, reason: str = "Channel unlocked") -> None:
        if not isinstance(interaction.channel, discord.TextChannel):
            await respond(interaction, "This command requires a text channel.")
            return
        try:
            await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=None, reason=reason)
            case_id = await self._security_case(interaction.guild, None, "CHANNEL_UNLOCK", reason, interaction.channel_id)
            await respond(interaction, f"Channel unlocked. Case #{case_id}.")
        except discord.HTTPException:
            await respond(interaction, "I could not unlock this channel.")

    @app_commands.command(description="Lock all text channels during an incident.")
    @guild_only()
    @staff_only()
    async def lockdown(self, interaction: discord.Interaction, reason: str = "Manual lockdown") -> None:
        await interaction.response.defer(ephemeral=True)
        changed = await self._lockdown(interaction.guild, reason)
        await respond(interaction, "Lockdown enabled." if changed else "Lockdown is already active.")

    @app_commands.command(description="Restore channels after a lockdown.")
    @guild_only()
    @staff_only()
    async def unlockdown(self, interaction: discord.Interaction, reason: str = "Manual lockdown release") -> None:
        await interaction.response.defer(ephemeral=True)
        changed = await self._unlockdown(interaction.guild, reason)
        await respond(interaction, f"Restored {changed} channels.")

    @security.command(name="automod", description="Enable or disable automatic message security enforcement.")
    @guild_only()
    @staff_only()
    async def security_automod(self, interaction: discord.Interaction, enabled: bool) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE security_config SET automod_enabled = ? WHERE guild_id = ?", (int(enabled), interaction.guild_id))
        await respond(interaction, f"AutoMod {'enabled' if enabled else 'disabled'}.")

    @security.command(name="thresholds", description="Set AutoMod flood, mention, and caps thresholds.")
    @guild_only()
    @staff_only()
    async def security_thresholds(self, interaction: discord.Interaction, flood_limit: app_commands.Range[int, 3, 20], flood_window_seconds: app_commands.Range[int, 5, 120], max_mentions: app_commands.Range[int, 2, 30], caps_percentage: app_commands.Range[int, 50, 100]) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE security_config SET flood_limit = ?, flood_window_seconds = ?, max_mentions = ?, caps_percentage = ? WHERE guild_id = ?", (flood_limit, flood_window_seconds, max_mentions, caps_percentage, interaction.guild_id))
        await respond(interaction, "AutoMod thresholds updated.")

    @security.command(name="links", description="Configure invite blocking and strict external-link allowlisting.")
    @guild_only()
    @staff_only()
    async def security_links(self, interaction: discord.Interaction, block_invites: bool, strict_links: bool) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE security_config SET block_invites = ?, strict_links = ? WHERE guild_id = ?", (int(block_invites), int(strict_links), interaction.guild_id))
        await respond(interaction, f"Invite blocking: {'enabled' if block_invites else 'disabled'}; strict link allowlisting: {'enabled' if strict_links else 'disabled'}.")

    @security.command(name="allow-domain", description="Allow an exact domain and its subdomains in strict link mode.")
    @guild_only()
    @staff_only()
    async def security_allow_domain(self, interaction: discord.Interaction, domain: str) -> None:
        normalized = domain.casefold().strip().removeprefix("https://").removeprefix("http://").split("/", 1)[0]
        if not normalized or "." not in normalized or " " in normalized:
            await respond(interaction, "Provide a valid domain, such as `example.com`.")
            return
        await self.bot.database.execute("INSERT OR IGNORE INTO allowed_domains (guild_id, domain) VALUES (?, ?)", (interaction.guild_id, normalized))
        await respond(interaction, f"Allowed `{normalized}` and its subdomains in strict link mode.")

    @security.command(name="remove-domain", description="Remove a domain from the strict link allowlist.")
    @guild_only()
    @staff_only()
    async def security_remove_domain(self, interaction: discord.Interaction, domain: str) -> None:
        normalized = domain.casefold().strip().removeprefix("https://").removeprefix("http://").split("/", 1)[0]
        await self.bot.database.execute("DELETE FROM allowed_domains WHERE guild_id = ? AND domain = ?", (interaction.guild_id, normalized))
        await respond(interaction, f"Removed `{normalized}` from the strict link allowlist.")

    @security.command(name="add-word", description="Add a word or phrase to the AutoMod blocked-word filter.")
    @guild_only()
    @staff_only()
    async def security_add_word(self, interaction: discord.Interaction, word: str) -> None:
        normalized = word.casefold().strip()
        if not 2 <= len(normalized) <= 100:
            await respond(interaction, "Blocked text must be between 2 and 100 characters.")
            return
        await self.bot.database.execute("INSERT OR IGNORE INTO bad_words (guild_id, word) VALUES (?, ?)", (interaction.guild_id, normalized))
        await respond(interaction, "Blocked word or phrase added.")

    @security.command(name="remove-word", description="Remove a word or phrase from the AutoMod blocked-word filter.")
    @guild_only()
    @staff_only()
    async def security_remove_word(self, interaction: discord.Interaction, word: str) -> None:
        await self.bot.database.execute("DELETE FROM bad_words WHERE guild_id = ? AND word = ?", (interaction.guild_id, word.casefold().strip()))
        await respond(interaction, "Blocked word or phrase removed.")

    @security.command(name="harden", description="Apply Guardian's recommended secure baseline.")
    @guild_only()
    @guild_owner_only()
    async def security_harden(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute(
            "UPDATE security_config SET automod_enabled = 1, flood_limit = 5, flood_window_seconds = 10, "
            "max_mentions = 5, caps_percentage = 80, block_invites = 1 WHERE guild_id = ?",
            (interaction.guild_id,),
        )
        await self.bot.database.execute(
            "UPDATE anti_nuke_config SET enabled = 1, action_limit = 2, window_seconds = 15 WHERE guild_id = ?",
            (interaction.guild_id,),
        )
        await self.bot.database.execute(
            "UPDATE raid_config SET enabled = 1, join_limit = 8, join_window_seconds = 30, "
            "min_account_age_days = CASE WHEN min_account_age_days < 3 THEN 3 ELSE min_account_age_days END "
            "WHERE guild_id = ?",
            (interaction.guild_id,),
        )
        advanced = self.bot.get_cog("AdvancedSecurityCog")
        if advanced is not None and interaction.guild is not None and hasattr(advanced, "harden_guild"):
            changed, failed = await advanced.harden_guild(interaction.guild)
            await respond(interaction, f"Secure baseline applied with advanced protection. External-app permission entries changed: {changed}; failed: {failed}. Current bots, webhooks, and integrations were saved as the trusted baseline.")
            return
        await respond(interaction, "Secure baseline applied. Existing strict-link allowlists and quarantine-role configuration were preserved.")

    @security.command(name="status", description="Show the current AutoMod and anti-nuke policy.")
    @guild_only()
    @staff_only()
    async def security_status(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        config = await self.bot.database.fetchone("SELECT * FROM security_config WHERE guild_id = ?", (interaction.guild_id,))
        antinuke = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (interaction.guild_id,))
        assert config is not None and antinuke is not None
        await respond(interaction, f"AutoMod: {'enabled' if config['automod_enabled'] else 'disabled'}\nFlood: {config['flood_limit']} messages / {config['flood_window_seconds']}s\nMentions: {config['max_mentions']}\nCaps: {config['caps_percentage']}%\nInvite blocking: {'enabled' if config['block_invites'] else 'disabled'}\nStrict links: {'enabled' if config['strict_links'] else 'disabled'}\nAnti-nuke: {'enabled' if antinuke['enabled'] else 'disabled'}")

    @security.command(name="scan", description="Check the bot's security permissions and role hierarchy in this server.")
    @guild_only()
    @staff_only()
    async def security_scan(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        bot_member = interaction.guild.me
        if bot_member is None:
            await respond(interaction, "I cannot inspect my server member record yet. Retry shortly.")
            return
        required = ("view_audit_log", "manage_messages", "moderate_members", "kick_members", "ban_members", "manage_roles", "manage_channels", "manage_webhooks")
        missing = [permission.replace("_", " ") for permission in required if not getattr(bot_member.guild_permissions, permission)]
        manageable = sum(1 for role in interaction.guild.roles if not role.managed and role < bot_member.top_role)
        risky_above = [
            role.name
            for role in interaction.guild.roles
            if role > bot_member.top_role and not role.managed and self._has_high_risk_permissions(role)
        ]
        await respond(
            interaction,
            f"Security scan\nMissing permissions: {', '.join(missing) if missing else 'none'}\n"
            f"Roles below bot: {manageable}\nBot top role: {bot_member.top_role.name}\n"
            f"High-risk roles above bot: {', '.join(risky_above[:10]) if risky_above else 'none'}\n"
            f"Audit attribution: {'ready' if 'view audit log' not in missing else 'unavailable'}",
        )

    @security.command(name="cases", description="Show recent AutoMod, anti-nuke, and security cases.")
    @guild_only()
    @staff_only()
    async def security_cases(self, interaction: discord.Interaction, limit: app_commands.Range[int, 1, 25] = 10) -> None:
        rows = await self.bot.database.fetchall("SELECT case_id, action, reason, created_at FROM cases WHERE guild_id = ? AND (action LIKE 'AUTOMOD_%' OR action LIKE 'ANTINUKE_%' OR action IN ('LOCKDOWN', 'UNLOCKDOWN', 'SUSPICIOUS_JOIN', 'WEBHOOK_CHANGE', 'CHANNEL_DELETE', 'ROLE_DELETE', 'ROLE_PERMISSION_CHANGE', 'QUARANTINE', 'QUARANTINE_RELEASE')) ORDER BY case_id DESC LIMIT ?", (interaction.guild_id, limit))
        text = "\n".join(f"#{row['case_id']} {row['action']}: {row['reason']}" for row in rows) or "No security cases found."
        await respond(interaction, text)

    @security.command(name="raid", description="Configure join-rate detection, suspicious-account checks, and quarantine.")
    @guild_only()
    @staff_only()
    async def security_raid(self, interaction: discord.Interaction, enabled: bool, join_limit: app_commands.Range[int, 3, 100], join_window_seconds: app_commands.Range[int, 10, 3600], minimum_account_age_days: app_commands.Range[int, 0, 365], quarantine_role: discord.Role | None = None) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        if quarantine_role is not None:
            assert interaction.guild is not None
            bot_member = interaction.guild.me
            if not safe_public_role(quarantine_role, interaction.guild):
                await respond(interaction, "The quarantine role must be below my highest role.")
                return
        await self.bot.database.execute("UPDATE raid_config SET enabled = ?, join_limit = ?, join_window_seconds = ?, min_account_age_days = ?, quarantine_role_id = ? WHERE guild_id = ?", (int(enabled), join_limit, join_window_seconds, minimum_account_age_days, quarantine_role.id if quarantine_role else None, interaction.guild_id))
        await respond(interaction, "Raid detection and quarantine policy updated.")

    @security.command(name="raid-status", description="Show join-rate, account-age, and quarantine configuration.")
    @guild_only()
    @staff_only()
    async def security_raid_status(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        config = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (interaction.guild_id,))
        assert config is not None
        await respond(interaction, f"Enabled: {'yes' if config['enabled'] else 'no'}\nJoin rate: {config['join_limit']} members / {config['join_window_seconds']}s\nMinimum account age: {config['min_account_age_days']} days\nQuarantine role: <@&{config['quarantine_role_id']}>")

    @security.command(name="quarantine", description="Assign the configured quarantine role to a member.")
    @guild_only()
    @staff_only()
    async def security_quarantine(self, interaction: discord.Interaction, member: discord.Member, reason: str = "Manual security review") -> None:
        if not await require_target(interaction, member):
            return
        if await self._quarantine(member, reason, interaction.user.id):
            await respond(interaction, f"Quarantined {member.mention}.")
        else:
            await respond(interaction, "I could not quarantine that member. Configure a role below my highest role with `/security raid`.")

    @security.command(name="release", description="Remove the configured quarantine role from a member.")
    @guild_only()
    @staff_only()
    async def security_release(self, interaction: discord.Interaction, member: discord.Member, reason: str = "Security review completed") -> None:
        if not await require_target(interaction, member):
            return
        config = await self.bot.database.fetchone("SELECT quarantine_role_id FROM raid_config WHERE guild_id = ?", (interaction.guild_id,))
        role = interaction.guild.get_role(config["quarantine_role_id"]) if config and config["quarantine_role_id"] else None
        if role is None or role not in member.roles:
            await respond(interaction, "That member is not assigned the configured quarantine role.")
            return
        try:
            await member.remove_roles(role, reason=reason)
        except (discord.Forbidden, discord.HTTPException):
            await respond(interaction, "I could not remove that quarantine role.")
            return
        case_id = await self.bot.database.create_case(interaction.guild_id, member.id, interaction.user.id, "QUARANTINE_RELEASE", reason, interaction.channel_id)
        await log_event(self.bot, interaction.guild, "security_log_channel_id", f"Security: QUARANTINE_RELEASE | Case #{case_id}", description=f"Target: {member.mention}\nModerator: {interaction.user.mention}\nReason: {reason}")
        await respond(interaction, f"Released {member.mention}. Case #{case_id}.")

    @security.command(name="member", description="Show a member's security history, account age, and high-risk roles.")
    @guild_only()
    @staff_only()
    async def security_member(self, interaction: discord.Interaction, member: discord.Member) -> None:
        count = await self.bot.database.fetchone("SELECT COUNT(*) AS count FROM cases WHERE guild_id = ? AND target_id = ?", (interaction.guild_id, member.id))
        high_risk_roles = [role.name for role in member.roles if self._has_high_risk_permissions(role)]
        age = (datetime.now(UTC) - member.created_at).days
        await respond(interaction, f"Member: {member.mention} ({member.id})\nAccount age: {age} days\nSecurity and moderation cases: {count['count'] if count else 0}\nHigh-risk roles: {', '.join(high_risk_roles) if high_risk_roles else 'none'}")

    @security.command(name="words", description="List configured blocked words and phrases.")
    @guild_only()
    @staff_only()
    async def security_words(self, interaction: discord.Interaction) -> None:
        rows = await self.bot.database.fetchall("SELECT word FROM bad_words WHERE guild_id = ? ORDER BY word LIMIT 50", (interaction.guild_id,))
        await respond(interaction, "\n".join(f"- {row['word']}" for row in rows) or "No blocked words or phrases are configured.")

    @security.command(name="domains", description="List domains allowed by strict link mode.")
    @guild_only()
    @staff_only()
    async def security_domains(self, interaction: discord.Interaction) -> None:
        rows = await self.bot.database.fetchall("SELECT domain FROM allowed_domains WHERE guild_id = ? ORDER BY domain LIMIT 50", (interaction.guild_id,))
        await respond(interaction, "\n".join(f"- {row['domain']}" for row in rows) or "No domains are allowlisted.")

    @security.command(name="trusted", description="List anti-nuke trusted users.")
    @guild_only()
    @staff_only()
    async def security_trusted(self, interaction: discord.Interaction) -> None:
        rows = await self.bot.database.fetchall("SELECT user_id FROM anti_nuke_trusted_users WHERE guild_id = ? ORDER BY created_at LIMIT 50", (interaction.guild_id,))
        await respond(interaction, "\n".join(f"- <@{row['user_id']}>" for row in rows) or "No users are trusted by anti-nuke.")

    @security.command(name="reset-automod", description="Restore this server's AutoMod thresholds and link rules to secure defaults.")
    @guild_only()
    @staff_only()
    async def security_reset_automod(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE security_config SET automod_enabled = 1, flood_limit = 6, flood_window_seconds = 10, max_mentions = 6, caps_percentage = 80, block_invites = 1, strict_links = 0 WHERE guild_id = ?", (interaction.guild_id,))
        await respond(interaction, "AutoMod defaults restored. Existing blocked words and allowed domains were retained.")

    @security.command(name="check-link", description="Check whether a URL would be allowed by this server's strict-link policy.")
    @guild_only()
    @staff_only()
    async def security_check_link(self, interaction: discord.Interaction, url: str) -> None:
        config = await self.bot.database.fetchone("SELECT strict_links FROM security_config WHERE guild_id = ?", (interaction.guild_id,))
        allowed = {row["domain"] for row in await self.bot.database.fetchall("SELECT domain FROM allowed_domains WHERE guild_id = ?", (interaction.guild_id,))}
        normalized = url if "://" in url else f"https://{url}"
        host = (urlparse(normalized).hostname or "").casefold()
        if not host:
            await respond(interaction, "Provide a valid URL or domain.")
            return
        permitted = not config or not config["strict_links"] or not self._has_unallowed_url(normalized, allowed)
        await respond(interaction, f"`{host}` would be {'allowed' if permitted else 'blocked'} by the current link policy.")

    @antinuke.command(name="setup", description="Enable anti-nuke with a destructive-action threshold.")
    @guild_only()
    @guild_owner_only()
    async def antinuke_setup(self, interaction: discord.Interaction, action_limit: app_commands.Range[int, 2, 10] = 3, window_seconds: app_commands.Range[int, 5, 120] = 15) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE anti_nuke_config SET enabled = 1, action_limit = ?, window_seconds = ? WHERE guild_id = ?", (action_limit, window_seconds, interaction.guild_id))
        await respond(interaction, f"Anti-nuke enabled: non-trusted actors are banned after {action_limit} destructive actions in {window_seconds} seconds.")

    @antinuke.command(name="enable", description="Enable previously configured anti-nuke protection.")
    @guild_only()
    @guild_owner_only()
    async def antinuke_enable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE anti_nuke_config SET enabled = 1 WHERE guild_id = ?", (interaction.guild_id,))
        await respond(interaction, "Anti-nuke enabled.")

    @antinuke.command(name="disable", description="Disable anti-nuke protection.")
    @guild_only()
    @guild_owner_only()
    async def antinuke_disable(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        await self.bot.database.execute("UPDATE anti_nuke_config SET enabled = 0 WHERE guild_id = ?", (interaction.guild_id,))
        await respond(interaction, "Anti-nuke disabled.")

    @antinuke.command(name="trust", description="Allow a trusted recovery administrator to bypass anti-nuke containment.")
    @guild_only()
    @guild_owner_only()
    async def antinuke_trust(self, interaction: discord.Interaction, user: discord.User) -> None:
        await self.bot.database.execute("INSERT OR REPLACE INTO anti_nuke_trusted_users (guild_id, user_id, added_by_id) VALUES (?, ?, ?)", (interaction.guild_id, user.id, interaction.user.id))
        await respond(interaction, f"Trusted {user.mention} for anti-nuke protection.")

    @antinuke.command(name="untrust", description="Remove a user's anti-nuke trusted status.")
    @guild_only()
    @guild_owner_only()
    async def antinuke_untrust(self, interaction: discord.Interaction, user: discord.User) -> None:
        await self.bot.database.execute("DELETE FROM anti_nuke_trusted_users WHERE guild_id = ? AND user_id = ?", (interaction.guild_id, user.id))
        await respond(interaction, f"Removed anti-nuke trust for {user.mention}.")

    @antinuke.command(name="status", description="Show anti-nuke configuration and trusted-user count.")
    @guild_only()
    @staff_only()
    async def antinuke_status(self, interaction: discord.Interaction) -> None:
        await self.bot.database.ensure_guild(interaction.guild_id)
        config = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (interaction.guild_id,))
        trusted = await self.bot.database.fetchone("SELECT COUNT(*) AS count FROM anti_nuke_trusted_users WHERE guild_id = ?", (interaction.guild_id,))
        assert config is not None and trusted is not None
        await respond(interaction, f"Enabled: {'yes' if config['enabled'] else 'no'}\nThreshold: {config['action_limit']} destructive actions in {config['window_seconds']} seconds\nTrusted users: {trusted['count']}\nRequires: View Audit Log, Ban Members, Manage Channels")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityCog(bot))