from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, guild_owner_only, respond, staff_only

USE_EXTERNAL_APPS_BIT = 1 << 50
DESTRUCTIVE_WINDOW = timedelta(seconds=10)
DESTRUCTIVE_LIMIT = 3
CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}\b"),
)


class AdvancedSecurityCog(commands.Cog):
    guardian = app_commands.Group(name="guardian", description="Emergency recovery and advanced Guardian protection.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.destructive_events: dict[tuple[int, int], deque[datetime]] = defaultdict(deque)
        self._snapshot_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._integration_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def cog_load(self) -> None:
        for statement in (
            """CREATE TABLE IF NOT EXISTS guardian_config (
                guild_id INTEGER PRIMARY KEY,
                external_app_lock INTEGER NOT NULL DEFAULT 1,
                bot_approval INTEGER NOT NULL DEFAULT 1,
                webhook_guard INTEGER NOT NULL DEFAULT 1,
                integration_guard INTEGER NOT NULL DEFAULT 1,
                credential_guard INTEGER NOT NULL DEFAULT 1,
                rollback_enabled INTEGER NOT NULL DEFAULT 1,
                panic_mode INTEGER NOT NULL DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS approved_bots (
                guild_id INTEGER NOT NULL,
                bot_id INTEGER NOT NULL,
                approved_by_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, bot_id)
            )""",
            """CREATE TABLE IF NOT EXISTS approved_webhooks (
                guild_id INTEGER NOT NULL,
                webhook_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, webhook_id)
            )""",
            """CREATE TABLE IF NOT EXISTS approved_integrations (
                guild_id INTEGER NOT NULL,
                integration_id INTEGER NOT NULL,
                application_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, integration_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_snapshots (
                guild_id INTEGER PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_baseline_state (
                guild_id INTEGER PRIMARY KEY,
                initialized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
        ):
            await self.bot.database.execute(statement)
        self.snapshot_loop.start()
        self.integration_guard_loop.start()

    def cog_unload(self) -> None:
        self.snapshot_loop.cancel()
        self.integration_guard_loop.cancel()

    async def ensure_guild(self, guild_id: int) -> None:
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_config (guild_id) VALUES (?)", (guild_id,))

    async def _case(self, guild: discord.Guild, target: discord.abc.User | None, action: str, reason: str, channel_id: int | None = None) -> None:
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_security_case"):
            await security._security_case(guild, target, action, reason, channel_id)
            return
        await self.bot.database.create_case(
            guild.id,
            target.id if target else None,
            self.bot.user.id if self.bot.user else None,
            action,
            reason,
            channel_id,
        )

    async def _audit_executor(self, guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> discord.User | discord.Member | None:
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_audit_executor"):
            return await security._audit_executor(guild, action, target_id)
        return None

    async def _trusted_change_actor(self, guild: discord.Guild, actor: discord.User | discord.Member | None) -> bool:
        if actor is None:
            return False
        if actor.id in {guild.owner_id, self.bot.user.id if self.bot.user else 0}:
            return True
        security = self.bot.get_cog("SecurityCog")
        if security is not None and hasattr(security, "_is_trusted_executor"):
            return bool(await security._is_trusted_executor(guild, actor))
        return False

    @staticmethod
    def _high_risk_role(role: discord.Role) -> bool:
        permissions = role.permissions
        return any(
            getattr(permissions, name, False)
            for name in (
                "administrator", "manage_guild", "manage_roles", "manage_channels",
                "manage_webhooks", "ban_members", "kick_members", "moderate_members",
            )
        )

    @staticmethod
    def _contains_credential(content: str) -> bool:
        return any(pattern.search(content) for pattern in CREDENTIAL_PATTERNS)

    async def _contain_actor(self, guild: discord.Guild, actor: discord.User | discord.Member | None, reason: str) -> None:
        if actor is None or actor.id in {guild.owner_id, self.bot.user.id if self.bot.user else 0}:
            return
        member = guild.get_member(actor.id)
        if member is None:
            try:
                member = await guild.fetch_member(actor.id)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                member = None
        if member is None:
            await self._case(guild, actor, "COMPROMISED_ADMIN_ALERT", reason)
            return
        bot_member = guild.me
        removable = [
            role for role in member.roles
            if role != guild.default_role and self._high_risk_role(role)
            and bot_member is not None and role < bot_member.top_role
        ]
        try:
            if removable:
                await member.remove_roles(*removable, reason=f"ESN Guardian containment: {reason}")
        except (discord.Forbidden, discord.HTTPException):
            pass
        try:
            await member.timeout(timedelta(hours=24), reason=f"ESN Guardian containment: {reason}")
        except (discord.Forbidden, discord.HTTPException):
            try:
                await guild.ban(member, reason=f"ESN Guardian emergency containment: {reason}", delete_message_seconds=0)
            except (discord.Forbidden, discord.HTTPException):
                pass
        await self._case(guild, member, "COMPROMISED_ADMIN_CONTAINED", reason)

    async def _record_destructive(self, guild: discord.Guild, actor: discord.User | discord.Member | None, action: str) -> None:
        if actor is None or actor.id in {guild.owner_id, self.bot.user.id if self.bot.user else 0}:
            return
        now = datetime.now(UTC)
        events = self.destructive_events[(guild.id, actor.id)]
        events.append(now)
        while events and now - events[0] > DESTRUCTIVE_WINDOW:
            events.popleft()
        if len(events) >= DESTRUCTIVE_LIMIT:
            events.clear()
            await self._contain_actor(
                guild,
                actor,
                f"Compromised-admin protection: {DESTRUCTIVE_LIMIT} destructive actions inside {int(DESTRUCTIVE_WINDOW.total_seconds())} seconds; latest={action}",
            )

    async def _snapshot_payload(self, guild: discord.Guild) -> dict[str, object]:
        roles: list[dict[str, object]] = []
        for role in guild.roles:
            if role.is_default() or role.managed:
                continue
            roles.append({
                "id": role.id,
                "name": role.name,
                "permissions": role.permissions.value,
                "colour": role.colour.value,
                "hoist": role.hoist,
                "mentionable": role.mentionable,
                "position": role.position,
                "members": [member.id for member in role.members],
            })
        channels: list[dict[str, object]] = []
        for channel in guild.channels:
            overwrites = []
            for target, overwrite in channel.overwrites.items():
                allow, deny = overwrite.pair()
                overwrites.append({
                    "target_id": target.id,
                    "target_type": "role" if isinstance(target, discord.Role) else "member",
                    "allow": allow.value,
                    "deny": deny.value,
                })
            item = {
                "id": channel.id,
                "name": channel.name,
                "type": str(channel.type),
                "position": channel.position,
                "category_id": channel.category_id,
                "overwrites": overwrites,
            }
            if isinstance(channel, discord.TextChannel):
                item.update({
                    "topic": channel.topic,
                    "slowmode_delay": channel.slowmode_delay,
                    "nsfw": channel.nsfw,
                })
            elif isinstance(channel, discord.VoiceChannel):
                item.update({
                    "bitrate": channel.bitrate,
                    "user_limit": channel.user_limit,
                })
            channels.append(item)
        return {"guild_id": guild.id, "roles": roles, "channels": channels}

    async def snapshot_guild(self, guild: discord.Guild, *, approve_current: bool = False) -> None:
        async with self._snapshot_locks[guild.id]:
            await self.ensure_guild(guild.id)
            payload = await self._snapshot_payload(guild)
            await self.bot.database.execute(
                "INSERT INTO guardian_snapshots (guild_id, snapshot_json, created_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(guild_id) DO UPDATE SET snapshot_json=excluded.snapshot_json, created_at=CURRENT_TIMESTAMP",
                (guild.id, json.dumps(payload, separators=(",", ":"))),
            )
            if approve_current:
                for member in guild.members:
                    if member.bot and (self.bot.user is None or member.id != self.bot.user.id):
                        await self.bot.database.execute(
                            "INSERT OR IGNORE INTO approved_bots (guild_id, bot_id, approved_by_id) VALUES (?, ?, ?)",
                            (guild.id, member.id, guild.owner_id),
                        )

                # Fetch all guild webhooks once instead of walking every channel.
                # Network calls are bounded so a slow Discord API route cannot leave
                # /guardian snapshot stuck on "thinking" indefinitely.
                try:
                    webhooks = await asyncio.wait_for(guild.webhooks(), timeout=5.0)
                except (discord.Forbidden, discord.HTTPException, TimeoutError, asyncio.TimeoutError):
                    webhooks = []
                for webhook in webhooks:
                    await self.bot.database.execute(
                        "INSERT OR IGNORE INTO approved_webhooks (guild_id, webhook_id) VALUES (?, ?)",
                        (guild.id, webhook.id),
                    )

                try:
                    integrations = await asyncio.wait_for(guild.integrations(), timeout=5.0)
                except (discord.Forbidden, discord.HTTPException, TimeoutError, asyncio.TimeoutError):
                    integrations = []
                for integration in integrations:
                    application = getattr(integration, "application", None)
                    await self.bot.database.execute(
                        "INSERT OR IGNORE INTO approved_integrations (guild_id, integration_id, application_id) VALUES (?, ?, ?)",
                        (guild.id, integration.id, getattr(application, "id", None)),
                    )

    async def _snapshot(self, guild: discord.Guild) -> dict[str, object] | None:
        row = await self.bot.database.fetchone("SELECT snapshot_json FROM guardian_snapshots WHERE guild_id = ?", (guild.id,))
        if row is None:
            return None
        try:
            return json.loads(str(row["snapshot_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    async def _restore_deleted_channel(self, channel: discord.abc.GuildChannel) -> None:
        try:
            restored = await channel.clone(reason="ESN Guardian automatic rollback of unauthorized channel deletion")
            kwargs: dict[str, object] = {"position": channel.position}
            if not isinstance(channel, discord.CategoryChannel):
                category_id = getattr(channel, "category_id", None)
                category = channel.guild.get_channel(category_id) if category_id else None
                if isinstance(category, discord.CategoryChannel):
                    kwargs["category"] = category
            try:
                await restored.edit(reason="ESN Guardian rollback positioning", **kwargs)
            except (discord.Forbidden, discord.HTTPException, TypeError):
                pass
            if isinstance(channel, discord.CategoryChannel) and isinstance(restored, discord.CategoryChannel):
                snapshot = await self._snapshot(channel.guild)
                if snapshot:
                    for item in snapshot.get("channels", []):
                        if not isinstance(item, dict) or item.get("category_id") != channel.id:
                            continue
                        child = channel.guild.get_channel(int(item.get("id", 0)))
                        if child is not None:
                            try:
                                await child.edit(category=restored, reason="ESN Guardian category rollback")
                            except (discord.Forbidden, discord.HTTPException, TypeError):
                                pass
            await self._case(channel.guild, None, "AUTO_ROLLBACK_CHANNEL", f"Recreated deleted channel/category {channel.name}")
        except (discord.Forbidden, discord.HTTPException, AttributeError):
            await self._case(channel.guild, None, "AUTO_ROLLBACK_FAILED", f"Could not recreate deleted channel/category {channel.name}")

    async def _restore_deleted_role(self, role: discord.Role) -> None:
        try:
            restored = await role.guild.create_role(
                name=role.name,
                permissions=role.permissions,
                colour=role.colour,
                hoist=role.hoist,
                mentionable=role.mentionable,
                reason="ESN Guardian automatic rollback of unauthorized role deletion",
            )
            try:
                await restored.edit(position=role.position, reason="ESN Guardian role rollback positioning")
            except (discord.Forbidden, discord.HTTPException):
                pass
            snapshot = await self._snapshot(role.guild)
            if snapshot:
                for item in snapshot.get("roles", []):
                    if not isinstance(item, dict) or item.get("id") != role.id:
                        continue
                    for member_id in item.get("members", []):
                        member = role.guild.get_member(int(member_id))
                        if member is None:
                            continue
                        try:
                            await member.add_roles(restored, reason="ESN Guardian role rollback")
                        except (discord.Forbidden, discord.HTTPException):
                            continue
                    break
            await self._case(role.guild, None, "AUTO_ROLLBACK_ROLE", f"Recreated deleted role {role.name}")
        except (discord.Forbidden, discord.HTTPException):
            await self._case(role.guild, None, "AUTO_ROLLBACK_FAILED", f"Could not recreate deleted role {role.name}")

    async def _lock_external_apps(self, guild: discord.Guild) -> tuple[int, int]:
        changed = 0
        failed = 0
        bot_member = guild.me
        for role in guild.roles:
            if role.managed or (bot_member is not None and not role.is_default() and role >= bot_member.top_role):
                continue
            if not (role.permissions.value & USE_EXTERNAL_APPS_BIT):
                continue
            permissions = discord.Permissions(role.permissions.value & ~USE_EXTERNAL_APPS_BIT)
            try:
                await role.edit(permissions=permissions, reason="ESN Guardian: external apps disabled")
                changed += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
        for channel in guild.channels:
            for target, overwrite in list(channel.overwrites.items()):
                try:
                    current = getattr(overwrite, "use_external_apps")
                except AttributeError:
                    continue
                if current is not True:
                    continue
                try:
                    overwrite.use_external_apps = False
                    await channel.set_permissions(target, overwrite=overwrite, reason="ESN Guardian: external apps disabled")
                    changed += 1
                except (discord.Forbidden, discord.HTTPException, AttributeError):
                    failed += 1
        return changed, failed

    async def _delete_unapproved_webhooks(self, guild: discord.Guild, *, channel: discord.abc.GuildChannel | None = None) -> int:
        rows = await self.bot.database.fetchall("SELECT webhook_id FROM approved_webhooks WHERE guild_id = ?", (guild.id,))
        approved = {int(row["webhook_id"]) for row in rows}
        deleted = 0
        channels = [channel] if channel is not None else list(guild.channels)
        for current in channels:
            if not hasattr(current, "webhooks"):
                continue
            try:
                webhooks = await current.webhooks()
            except (discord.Forbidden, discord.HTTPException):
                continue
            for webhook in webhooks:
                if webhook.id in approved:
                    continue
                try:
                    await webhook.delete(reason="ESN Guardian: unauthorized webhook")
                    deleted += 1
                    await self._case(guild, getattr(webhook, "user", None), "WEBHOOK_DESTROYED", f"Deleted unauthorized webhook {webhook.name or webhook.id}", getattr(current, "id", None))
                except (discord.Forbidden, discord.HTTPException):
                    await self._case(guild, getattr(webhook, "user", None), "WEBHOOK_DESTROY_FAILED", f"Could not delete unauthorized webhook {webhook.name or webhook.id}", getattr(current, "id", None))
        return deleted

    async def _ensure_safe_baseline(self, guild: discord.Guild) -> None:
        """Trust everything already present once, so a Guardian upgrade never attacks an existing server."""
        row = await self.bot.database.fetchone(
            "SELECT 1 FROM guardian_baseline_state WHERE guild_id = ?",
            (guild.id,),
        )
        if row is not None:
            return

        # Existing bots are a migration baseline. Only bots added after this point
        # are subject to the approval gate.
        for member in guild.members:
            if not member.bot or (self.bot.user is not None and member.id == self.bot.user.id):
                continue
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO approved_bots (guild_id, bot_id, approved_by_id) VALUES (?, ?, ?)",
                (guild.id, member.id, guild.owner_id),
            )

        # Existing webhooks are also preserved on first upgraded startup.
        for channel in guild.channels:
            if not hasattr(channel, "webhooks"):
                continue
            try:
                webhooks = await channel.webhooks()
            except (discord.Forbidden, discord.HTTPException):
                continue
            for webhook in webhooks:
                await self.bot.database.execute(
                    "INSERT OR IGNORE INTO approved_webhooks (guild_id, webhook_id) VALUES (?, ?)",
                    (guild.id, webhook.id),
                )

        # Most importantly: never treat pre-existing integrations as hostile.
        try:
            integrations = await guild.integrations()
        except (discord.Forbidden, discord.HTTPException):
            integrations = []
        for integration in integrations:
            application = getattr(integration, "application", None)
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO approved_integrations (guild_id, integration_id, application_id) VALUES (?, ?, ?)",
                (guild.id, integration.id, getattr(application, "id", None)),
            )

        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_baseline_state (guild_id) VALUES (?)",
            (guild.id,),
        )

    async def _remove_unapproved_integrations(self, guild: discord.Guild) -> int:
        async with self._integration_locks[guild.id]:
            await self._ensure_safe_baseline(guild)
            rows = await self.bot.database.fetchall(
                "SELECT integration_id, application_id FROM approved_integrations WHERE guild_id = ?",
                (guild.id,),
            )
            approved_ids = {int(row["integration_id"]) for row in rows}
            approved_apps = {int(row["application_id"]) for row in rows if row["application_id"] is not None}
            try:
                integrations = await guild.integrations()
            except (discord.Forbidden, discord.HTTPException):
                return 0
            removed = 0
            for integration in integrations:
                application = getattr(integration, "application", None)
                app_id = getattr(application, "id", None)
                integration_user = getattr(integration, "user", None)

                # Guardian must never delete its own Discord integration.
                if self.bot.user is not None and (
                    app_id == self.bot.user.id
                    or getattr(integration_user, "id", None) == self.bot.user.id
                ):
                    continue

                if integration.id in approved_ids or (app_id is not None and app_id in approved_apps):
                    continue
                try:
                    await integration.delete(reason="ESN Guardian: unauthorized integration")
                    removed += 1
                    await self._case(guild, getattr(integration, "user", None), "INTEGRATION_REMOVED", f"Removed unauthorized integration {getattr(integration, 'name', integration.id)}")
                except (discord.Forbidden, discord.HTTPException):
                    await self._case(guild, getattr(integration, "user", None), "INTEGRATION_REMOVE_FAILED", f"Could not remove unauthorized integration {getattr(integration, 'name', integration.id)}")
            return removed

    async def _ban_unapproved_bots(self, guild: discord.Guild) -> int:
        rows = await self.bot.database.fetchall("SELECT bot_id FROM approved_bots WHERE guild_id = ?", (guild.id,))
        approved = {int(row["bot_id"]) for row in rows}
        if self.bot.user is not None:
            approved.add(self.bot.user.id)
        removed = 0
        for member in list(guild.members):
            if not member.bot or member.id in approved:
                continue
            try:
                await guild.ban(member, reason="ESN Guardian: bot is not approved", delete_message_seconds=0)
                removed += 1
                await self._case(guild, member, "UNAPPROVED_BOT_BANNED", f"Banned unapproved bot {member} ({member.id})")
            except (discord.Forbidden, discord.HTTPException):
                await self._case(guild, member, "UNAPPROVED_BOT_BAN_FAILED", f"Could not ban unapproved bot {member} ({member.id})")
        return removed

    async def harden_guild(self, guild: discord.Guild) -> tuple[int, int]:
        await self.ensure_guild(guild.id)
        await self.snapshot_guild(guild, approve_current=True)
        changed, failed = await self._lock_external_apps(guild)
        await self.bot.database.execute(
            "UPDATE guardian_config SET external_app_lock=1, bot_approval=1, webhook_guard=1, integration_guard=1, credential_guard=1, rollback_enabled=1 WHERE guild_id=?",
            (guild.id,),
        )
        return changed, failed

    async def _guardian_config(self, guild_id: int):
        await self.ensure_guild(guild_id)
        return await self.bot.database.fetchone("SELECT * FROM guardian_config WHERE guild_id = ?", (guild_id,))

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot or not isinstance(message.author, discord.Member):
            return
        config = await self._guardian_config(message.guild.id)
        if config is None or not config["credential_guard"] or not self._contains_credential(message.content):
            return
        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            pass
        try:
            await message.author.timeout(timedelta(minutes=10), reason="ESN Guardian: possible credential leak")
        except (discord.Forbidden, discord.HTTPException):
            pass
        await self._case(message.guild, message.author, "CREDENTIAL_LEAK_BLOCKED", "Message matched a high-confidence credential/token pattern", message.channel.id)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        if not member.bot:
            return
        config = await self._guardian_config(member.guild.id)
        if config is None or not config["bot_approval"]:
            return
        row = await self.bot.database.fetchone(
            "SELECT 1 FROM approved_bots WHERE guild_id = ? AND bot_id = ?",
            (member.guild.id, member.id),
        )
        if row is not None or (self.bot.user is not None and member.id == self.bot.user.id):
            return
        actor = await self._audit_executor(member.guild, discord.AuditLogAction.bot_add, member.id)
        try:
            await member.guild.ban(member, reason="ESN Guardian: unapproved bot addition", delete_message_seconds=0)
            await self._case(member.guild, actor, "UNAPPROVED_BOT_BANNED", f"Banned unapproved bot {member} ({member.id})")
        except (discord.Forbidden, discord.HTTPException):
            await self._case(member.guild, actor, "UNAPPROVED_BOT_BAN_FAILED", f"Could not ban unapproved bot {member} ({member.id})")
        if not await self._trusted_change_actor(member.guild, actor):
            await self._contain_actor(member.guild, actor, f"Added unapproved bot {member.id}")

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        config = await self._guardian_config(channel.guild.id)
        if config is None or not config["rollback_enabled"]:
            return
        actor = await self._audit_executor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
        await self._record_destructive(channel.guild, actor, "channel deletion")
        if not await self._trusted_change_actor(channel.guild, actor):
            await self._restore_deleted_channel(channel)

    @commands.Cog.listener()
    async def on_guild_channel_update(self, before: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        config = await self._guardian_config(after.guild.id)
        if config is None or not config["rollback_enabled"]:
            return
        critical_change = before.overwrites != after.overwrites or before.name != after.name or before.position != after.position
        if not critical_change:
            return
        actor = await self._audit_executor(after.guild, discord.AuditLogAction.channel_update, after.id)
        await self._record_destructive(after.guild, actor, "channel modification")
        if await self._trusted_change_actor(after.guild, actor):
            return
        kwargs: dict[str, object] = {"name": before.name, "position": before.position, "overwrites": before.overwrites}
        if hasattr(before, "category") and not isinstance(before, discord.CategoryChannel):
            kwargs["category"] = before.category
        if isinstance(before, (discord.TextChannel, discord.ForumChannel)):
            kwargs["topic"] = before.topic
            kwargs["slowmode_delay"] = before.slowmode_delay
        try:
            await after.edit(reason="ESN Guardian automatic rollback of unauthorized channel change", **kwargs)
            await self._case(after.guild, actor, "AUTO_ROLLBACK_CHANNEL_UPDATE", f"Reverted unauthorized changes to {after.name}", after.id)
        except (discord.Forbidden, discord.HTTPException, TypeError):
            await self._case(after.guild, actor, "AUTO_ROLLBACK_FAILED", f"Could not revert unauthorized changes to {after.name}", after.id)

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        config = await self._guardian_config(role.guild.id)
        if config is None or not config["rollback_enabled"]:
            return
        actor = await self._audit_executor(role.guild, discord.AuditLogAction.role_delete, role.id)
        await self._record_destructive(role.guild, actor, "role deletion")
        if not await self._trusted_change_actor(role.guild, actor):
            await self._restore_deleted_role(role)

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        if before.permissions == after.permissions and before.position == after.position:
            return
        actor = await self._audit_executor(after.guild, discord.AuditLogAction.role_update, after.id)

        # Discord role reorders emit position updates for neighboring roles without
        # separate audit-log entries. Treating those collateral updates as attacks
        # creates a self-heal feedback loop.
        position_only = before.permissions == after.permissions and before.position != after.position
        if position_only and actor is None:
            return

        await self._record_destructive(after.guild, actor, "role permission/position change")
        bot_user_id = self.bot.user.id if self.bot.user else 0
        role_tags = getattr(after, "tags", None)
        managed_bot_id = getattr(role_tags, "bot_id", None)
        is_guardian_role = bool(after.managed and managed_bot_id == bot_user_id)
        if is_guardian_role and (actor is None or actor.id != after.guild.owner_id):
            try:
                await after.edit(permissions=before.permissions, position=before.position, reason="ESN Guardian tamper protection")
                await self._case(after.guild, actor, "GUARDIAN_TAMPER_REVERTED", f"Reverted change to Guardian role {after.name}")
            except (discord.Forbidden, discord.HTTPException):
                await self._case(after.guild, actor, "GUARDIAN_TAMPER_ALERT", f"Guardian role {after.name} was changed and could not be restored")

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        if self.bot.user is None or after.id != self.bot.user.id:
            return
        removed = [role for role in before.roles if role not in after.roles and not role.is_default()]
        if not removed:
            return
        actor = await self._audit_executor(after.guild, discord.AuditLogAction.member_role_update, after.id)
        if actor is not None and actor.id == after.guild.owner_id:
            return
        restored = 0
        for role in removed:
            try:
                await after.add_roles(role, reason="ESN Guardian tamper protection")
                restored += 1
            except (discord.Forbidden, discord.HTTPException):
                continue
        await self._case(after.guild, actor, "GUARDIAN_TAMPER_ALERT", f"Guardian roles removed; restored {restored}/{len(removed)}")

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User | discord.Member) -> None:
        actor = await self._audit_executor(guild, discord.AuditLogAction.ban, user.id)
        await self._record_destructive(guild, actor, "member ban")

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        security = self.bot.get_cog("SecurityCog")
        if (
            security is not None
            and hasattr(security, "is_internal_removal")
            and security.is_internal_removal(member.guild.id, member.id)
        ):
            return
        actor = await self._audit_executor(
            member.guild,
            discord.AuditLogAction.kick,
            member.id,
        )
        if actor is not None:
            await self._record_destructive(member.guild, actor, "member kick")

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel) -> None:
        config = await self._guardian_config(channel.guild.id)
        if config is None or not config["webhook_guard"]:
            return
        await asyncio.sleep(1)
        actor = None
        try:
            async for entry in channel.guild.audit_logs(action=discord.AuditLogAction.webhook_create, limit=3, after=datetime.now(UTC) - timedelta(seconds=30)):
                actor = entry.user
                break
        except (discord.Forbidden, discord.HTTPException):
            pass
        if await self._trusted_change_actor(channel.guild, actor):
            try:
                for webhook in await channel.webhooks():
                    await self.bot.database.execute(
                        "INSERT OR IGNORE INTO approved_webhooks (guild_id, webhook_id) VALUES (?, ?)",
                        (channel.guild.id, webhook.id),
                    )
            except (discord.Forbidden, discord.HTTPException):
                pass
            return
        deleted = await self._delete_unapproved_webhooks(channel.guild, channel=channel)
        if deleted:
            await self._record_destructive(channel.guild, actor, "unauthorized webhook creation")

    @commands.Cog.listener()
    async def on_guild_integrations_update(self, guild: discord.Guild) -> None:
        config = await self._guardian_config(guild.id)
        if config is None or not config["integration_guard"]:
            return
        action = getattr(discord.AuditLogAction, "integration_create", None)
        actor = None
        if action is not None:
            try:
                async for entry in guild.audit_logs(action=action, limit=1, after=datetime.now(UTC) - timedelta(seconds=30)):
                    actor = entry.user
                    break
            except (discord.Forbidden, discord.HTTPException):
                pass
        if await self._trusted_change_actor(guild, actor):
            try:
                integrations = await guild.integrations()
            except (discord.Forbidden, discord.HTTPException):
                integrations = []
            for integration in integrations:
                application = getattr(integration, "application", None)
                await self.bot.database.execute(
                    "INSERT OR IGNORE INTO approved_integrations (guild_id, integration_id, application_id) VALUES (?, ?, ?)",
                    (guild.id, integration.id, getattr(application, "id", None)),
                )
            return
        removed = await self._remove_unapproved_integrations(guild)
        if removed:
            await self._record_destructive(guild, actor, "unauthorized integration")

    @tasks.loop(minutes=30)
    async def snapshot_loop(self) -> None:
        for guild in self.bot.guilds:
            try:
                existing = await self.bot.database.fetchone("SELECT 1 FROM guardian_snapshots WHERE guild_id = ?", (guild.id,))
                await self.snapshot_guild(guild, approve_current=existing is None)
            except Exception:
                continue

    @snapshot_loop.before_loop
    async def before_snapshot_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=5)
    async def integration_guard_loop(self) -> None:
        for guild in self.bot.guilds:
            try:
                config = await self._guardian_config(guild.id)
                if config and config["integration_guard"]:
                    await self._remove_unapproved_integrations(guild)
            except Exception:
                continue

    @integration_guard_loop.before_loop
    async def before_integration_guard_loop(self) -> None:
        await self.bot.wait_until_ready()
        for guild in self.bot.guilds:
            try:
                await self._ensure_safe_baseline(guild)
            except Exception:
                continue

    @guardian.command(name="snapshot", description="Save a trusted recovery snapshot and approve current bots/webhooks/integrations.")
    @guild_only()
    @guild_owner_only()
    async def guardian_snapshot(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        try:
            await asyncio.wait_for(
                self.snapshot_guild(interaction.guild, approve_current=True),
                timeout=20.0,
            )
        except (TimeoutError, asyncio.TimeoutError):
            await respond(
                interaction,
                "Guardian saved the local recovery snapshot, but Discord took too long while approving current webhooks/integrations. "
                "The command was stopped safely instead of hanging indefinitely.",
            )
            return
        await respond(interaction, "Guardian recovery snapshot saved. Current bots, webhooks, and integrations are now the trusted baseline.")

    @guardian.command(name="approve-bot", description="Approve a bot ID before it joins the server.")
    @guild_only()
    @guild_owner_only()
    async def guardian_approve_bot(self, interaction: discord.Interaction, bot_id: str) -> None:
        try:
            value = int(bot_id)
        except ValueError:
            await respond(interaction, "Provide a numeric Discord bot/application ID.")
            return
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO approved_bots (guild_id, bot_id, approved_by_id) VALUES (?, ?, ?)",
            (interaction.guild_id, value, interaction.user.id),
        )
        await respond(interaction, f"Approved bot/application ID {value}.")

    @guardian.command(name="unapprove-bot", description="Remove a bot ID from Guardian's approval list.")
    @guild_only()
    @guild_owner_only()
    async def guardian_unapprove_bot(self, interaction: discord.Interaction, bot_id: str) -> None:
        try:
            value = int(bot_id)
        except ValueError:
            await respond(interaction, "Provide a numeric Discord bot/application ID.")
            return
        await self.bot.database.execute("DELETE FROM approved_bots WHERE guild_id = ? AND bot_id = ?", (interaction.guild_id, value))
        await respond(interaction, f"Removed bot/application ID {value} from the approval list.")

    @guardian.command(name="panic", description="Enable or release maximum emergency containment.")
    @guild_only()
    @guild_owner_only()
    async def guardian_panic(self, interaction: discord.Interaction, enabled: bool = True) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await self.ensure_guild(interaction.guild_id)
        security = self.bot.get_cog("SecurityCog")
        if enabled:
            await self.snapshot_guild(interaction.guild, approve_current=False)
            changed, failed = await self._lock_external_apps(interaction.guild)
            bots = await self._ban_unapproved_bots(interaction.guild)
            webhooks = await self._delete_unapproved_webhooks(interaction.guild)
            integrations = await self._remove_unapproved_integrations(interaction.guild)
            await self.bot.database.execute(
                "UPDATE guardian_config SET panic_mode=1, external_app_lock=1, bot_approval=1, webhook_guard=1, integration_guard=1, credential_guard=1, rollback_enabled=1 WHERE guild_id=?",
                (interaction.guild_id,),
            )
            await self.bot.database.execute(
                "UPDATE anti_nuke_config SET enabled=1, action_limit=2, window_seconds=15 WHERE guild_id=?",
                (interaction.guild_id,),
            )
            await self.bot.database.execute(
                "UPDATE security_config SET automod_enabled=1, flood_limit=4, flood_window_seconds=10, max_mentions=4, block_invites=1, strict_links=1 WHERE guild_id=?",
                (interaction.guild_id,),
            )
            if security is not None and hasattr(security, "_lockdown"):
                await security._lockdown(interaction.guild, "Guardian PANIC mode")
            await self._case(interaction.guild, interaction.user, "GUARDIAN_PANIC", "Maximum emergency containment enabled")
            await respond(interaction, f"PANIC enabled. External-app locks changed {changed} permission entries ({failed} failed); removed {bots} unapproved bots, {webhooks} webhooks, and {integrations} integrations.")
            return
        await self.bot.database.execute("UPDATE guardian_config SET panic_mode=0 WHERE guild_id=?", (interaction.guild_id,))
        if security is not None and hasattr(security, "_unlockdown"):
            await security._unlockdown(interaction.guild, "Guardian PANIC mode released by server owner")
        await self._case(interaction.guild, interaction.user, "GUARDIAN_PANIC_RELEASED", "Emergency containment released")
        await respond(interaction, "PANIC released. Core protections remain enabled.")

    @guardian.command(name="audit", description="Run Guardian's full security scoreboard and exposure audit.")
    async def guardian_audit(self, interaction: discord.Interaction) -> None:
        # Acknowledge this command before *any* checks, database work, or Discord API
        # calls. This avoids Discord's short initial interaction-response deadline.
        if interaction.guild is None:
            await interaction.response.send_message(
                embed=discord.Embed(title="Access denied", description="This command can only be used in a server."),
                ephemeral=True,
            )
            return
        if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
            await interaction.response.send_message(
                embed=discord.Embed(title="Access denied", description="You need Manage Server to run this audit."),
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            embed=discord.Embed(
                title="ESN Guardian",
                description="Running Guardian security audit…",
                color=discord.Color.blurple(),
            ),
            ephemeral=True,
        )

        guild = interaction.guild
        bot_member = guild.me
        required = (
            "view_audit_log", "manage_messages", "moderate_members", "kick_members",
            "ban_members", "manage_roles", "manage_channels", "manage_webhooks",
        )
        missing = [
            name for name in required
            if bot_member is None or not getattr(bot_member.guild_permissions, name, False)
        ]
        dangerous_roles = [
            role for role in guild.roles
            if not role.managed and self._high_risk_role(role) and role != guild.default_role
        ]

        approved_rows = await self.bot.database.fetchall(
            "SELECT bot_id FROM approved_bots WHERE guild_id = ?",
            (guild.id,),
        )
        approved_bots = {int(row["bot_id"]) for row in approved_rows}
        unknown_bots = [
            member for member in guild.members
            if member.bot
            and (self.bot.user is None or member.id != self.bot.user.id)
            and member.id not in approved_bots
        ]

        webhook_count: int | None
        try:
            hooks = await asyncio.wait_for(guild.webhooks(), timeout=3.0)
            webhook_count = len(hooks)
        except (discord.Forbidden, discord.HTTPException, TimeoutError, asyncio.TimeoutError):
            webhook_count = None

        external_app_roles = [
            role for role in guild.roles
            if role.permissions.value & USE_EXTERNAL_APPS_BIT
        ]
        config = await self._guardian_config(guild.id)
        deductions = min(
            100,
            len(missing) * 10
            + len(unknown_bots) * 12
            + len(external_app_roles) * 5
            + (10 if config is None or not config["rollback_enabled"] else 0)
            + (10 if config is None or not config["webhook_guard"] else 0),
        )
        score = max(0, 100 - deductions)

        content = (
            "Guardian Security Scoreboard\n"
            f"Score: {score}/100\n"
            f"Missing Guardian permissions: {', '.join(name.replace('_', ' ') for name in missing) if missing else 'none'}\n"
            f"High-risk roles: {len(dangerous_roles)}\n"
            f"Unapproved bots: {', '.join(str(member) for member in unknown_bots[:10]) if unknown_bots else 'none'}\n"
            f"Roles still allowing external apps: {len(external_app_roles)}\n"
            f"Current webhooks: {webhook_count if webhook_count is not None else 'unavailable'}\n"
            f"Rollback: {'ON' if config and config['rollback_enabled'] else 'OFF'}\n"
            f"Webhook guard: {'ON' if config and config['webhook_guard'] else 'OFF'}\n"
            f"Integration guard: {'ON' if config and config['integration_guard'] else 'OFF'}\n"
            f"Credential leak guard: {'ON' if config and config['credential_guard'] else 'OFF'}"
        )
        await interaction.edit_original_response(
            embed=discord.Embed(
                title="ESN Guardian",
                description=content[:4096],
                color=discord.Color.blurple(),
                timestamp=datetime.now(UTC),
            )
        )

    @guardian.command(name="status", description="Show advanced Guardian protection status.")
    @guild_only()
    @staff_only()
    async def guardian_status(self, interaction: discord.Interaction) -> None:
        config = await self._guardian_config(interaction.guild_id)
        assert config is not None
        bots = await self.bot.database.fetchone("SELECT COUNT(*) AS count FROM approved_bots WHERE guild_id = ?", (interaction.guild_id,))
        snapshot = await self.bot.database.fetchone("SELECT created_at FROM guardian_snapshots WHERE guild_id = ?", (interaction.guild_id,))
        await respond(
            interaction,
            f"External-app lock: {'ON' if config['external_app_lock'] else 'OFF'}\n"
            f"Bot approval: {'ON' if config['bot_approval'] else 'OFF'}\n"
            f"Webhook guard: {'ON' if config['webhook_guard'] else 'OFF'}\n"
            f"Integration guard: {'ON' if config['integration_guard'] else 'OFF'}\n"
            f"Credential leak guard: {'ON' if config['credential_guard'] else 'OFF'}\n"
            f"Automatic rollback: {'ON' if config['rollback_enabled'] else 'OFF'}\n"
            f"PANIC: {'ACTIVE' if config['panic_mode'] else 'inactive'}\n"
            f"Approved bots: {bots['count'] if bots else 0}\n"
            f"Last snapshot: {snapshot['created_at'] if snapshot else 'none'}",
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AdvancedSecurityCog(bot))
