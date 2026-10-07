"""ESN Guardian v8 ULTRA: active honeypot, human review, staff locks, and unified defense.

This is an additive Python cog.  It does not replace v7/MAX enforcement,
change existing raid thresholds, or access .env or existing member data.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import (
    defer_response,
    guild_only,
    guild_owner_only,
    log_event,
    respond,
    staff_only,
)
from esn_guardian.cogs.security import raid_trigger_reason
from esn_guardian.cogs.security_max import join_risk_score, scam_score

LOG = logging.getLogger("esn_guardian.security_ultra")
SENSITIVE_PERMISSIONS = (
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members",
)
TRIPWIRE_COOLDOWN_SECONDS = 90
ULTRA_NAME = "Guardian Vault • Honeypot"
UNLOCK_CONFIRMATION = "RESTORE"


def dangerous_role(role: discord.Role) -> bool:
    return any(bool(getattr(role.permissions, name, False)) for name in SENSITIVE_PERMISSIONS)


def reversible_roles(member: discord.Member, bot_member: discord.Member | None) -> list[discord.Role]:
    if bot_member is None or member.id == member.guild.owner_id or member.bot:
        return []
    return [
        role for role in member.roles
        if not role.is_default()
        and not role.managed
        and role < bot_member.top_role
        and dangerous_role(role)
    ]


def permission_risks(guild: discord.Guild) -> list[str]:
    problems = []
    everyone = guild.default_role
    if dangerous_role(everyone):
        problems.append("CRITICAL: @everyone has dangerous permissions.")
    me = guild.me
    if me is None:
        problems.append("CRITICAL: Guardian has no accessible guild member state.")
    else:
        needed = ("view_audit_log", "manage_roles", "manage_channels", "manage_messages")
        for permission in needed:
            if not getattr(me.guild_permissions, permission, False):
                problems.append(f"Missing Guardian permission: {permission}.")
    for role in guild.roles:
        if role.is_default() or not dangerous_role(role):
            continue
        if me is not None and role >= me.top_role:
            problems.append(f"Guardian cannot contain privileged role: {role.name} ({role.id}).")
    return problems[:18]


def raid_preview(join_count: int, fast_count: int, young_count: int, limit: int, age_days: int) -> str:
    return raid_trigger_reason(
        join_count=join_count,
        fast_count=fast_count,
        young_count=young_count,
        join_limit=max(3, limit),
        min_account_age_days=max(0, age_days),
        already_active=False,
    ) or "No existing raid threshold reached."


class VaultButton(discord.ui.View):
    """Persistent decoy control. Never contains secrets or privileged actions."""

    def __init__(self, cog: "SecurityUltraCog"):
        super().__init__(timeout=None)
        self.cog = cog

    @discord.ui.button(
        label="Restricted vault access",
        style=discord.ButtonStyle.secondary,
        custom_id="esn_guardian:v8:vault_probe",
        emoji="🔒",
    )
    async def probe(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        # Always acknowledge quickly, even while incident records are busy.
        await interaction.response.send_message(
            "This is a monitored security decoy. No credentials or private data are stored here.",
            ephemeral=True,
        )
        guild = interaction.guild
        if guild is None or interaction.user.id == guild.owner_id:
            return
        channel_id, _role_id, enabled = await self.cog._honeypot(guild.id)
        if enabled and channel_id and channel_id == interaction.channel_id:
            await self.cog._tripwire(guild, interaction.user.id, "VAULT_BUTTON", 40)


class UltraView(discord.ui.View):
    def __init__(self, cog: "SecurityUltraCog", guild_id: int, requester_id: int):
        super().__init__(timeout=150)
        self.cog = cog
        self.guild_id = guild_id
        self.requester_id = requester_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.guild_id != self.guild_id or interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                "Open your own /ultra center to use these controls.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(label="Threat radar", style=discord.ButtonStyle.primary)
    async def radar(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        await interaction.followup.send(await self.cog._radar(interaction.guild), ephemeral=True)

    @discord.ui.button(label="Security audit", style=discord.ButtonStyle.secondary)
    async def audit(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        await interaction.followup.send(
            self.cog._permission_report(interaction.guild), ephemeral=True
        )

    @discord.ui.button(label="Incident timeline", style=discord.ButtonStyle.secondary)
    async def incident(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        await interaction.followup.send(
            await self.cog._incident_report(interaction.guild.id), ephemeral=True
        )


class SecurityUltraCog(commands.Cog):
    ultra = app_commands.Group(
        name="ultra",
        description="Guardian v8 ULTRA honeypot, staff safety, recovery and incident center.",
        default_permissions=discord.Permissions(manage_guild=True),
        guild_only=True,
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._honeypots: dict[int, tuple[int | None, int | None, bool]] = {}
        self._tripwire_last: dict[tuple[int, int, str], float] = {}
        self._locks = defaultdict(asyncio.Lock)

    async def cog_load(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS ultra_honeypots (
                guild_id INTEGER PRIMARY KEY,
                channel_id INTEGER,
                role_id INTEGER,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS ultra_tripwires (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                actor_id INTEGER,
                kind TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE INDEX IF NOT EXISTS idx_ultra_tripwires
            ON ultra_tripwires (guild_id, id DESC)""",
            """CREATE TABLE IF NOT EXISTS ultra_staff_locks (
                guild_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                role_ids TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                review_after INTEGER NOT NULL,
                PRIMARY KEY(guild_id, member_id)
            )""",
            """CREATE TABLE IF NOT EXISTS ultra_appeals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                case_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                reviewed_by INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_ultra_open_appeal
            ON ultra_appeals(guild_id, member_id, case_id) WHERE status = 'open'""",
        )
        for statement in statements:
            await self.bot.database.execute(statement)
        # Re-registration makes the decoy button survive restarts.
        self.bot.add_view(VaultButton(self))
        self.lock_review_loop.start()

    def cog_unload(self) -> None:
        self.lock_review_loop.cancel()

    async def _honeypot(self, guild_id: int) -> tuple[int | None, int | None, bool]:
        if guild_id in self._honeypots:
            return self._honeypots[guild_id]
        row = await self.bot.database.fetchone(
            "SELECT channel_id, role_id, enabled FROM ultra_honeypots WHERE guild_id=?",
            (guild_id,),
        )
        value = (
            (int(row["channel_id"]) if row["channel_id"] else None,
             int(row["role_id"]) if row["role_id"] else None, bool(row["enabled"]))
            if row else (None, None, False)
        )
        self._honeypots[guild_id] = value
        return value

    async def _tripwire(
        self, guild: discord.Guild, actor_id: int | None, kind: str, confidence: int
    ) -> bool:
        if actor_id in {guild.owner_id, getattr(self.bot.user, "id", None)}:
            return False
        key = (guild.id, actor_id or 0, kind)
        now = time.monotonic()
        previous = self._tripwire_last.get(key, float("-inf"))
        if now - previous < TRIPWIRE_COOLDOWN_SECONDS:
            return False
        self._tripwire_last[key] = now
        if len(self._tripwire_last) > 4000:
            self._tripwire_last = {
                k: t for k, t in self._tripwire_last.items()
                if now - t < 600
            }
        await self.bot.database.execute(
            "INSERT INTO ultra_tripwires(guild_id,actor_id,kind,confidence) VALUES(?,?,?,?)",
            (guild.id, actor_id, kind, max(0, min(100, confidence))),
        )
        await self.bot.database.create_case(
            guild.id, actor_id, self.bot.user.id if self.bot.user else None,
            "ULTRA_HONEYPOT", f"Honeypot event: {kind} (confidence {confidence}/100)",
        )
        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is not None:
            try:
                await v7._evidence(
                    guild.id, actor_id, "ULTRA_HONEYPOT", None,
                    {"kind": kind, "confidence": confidence},
                )
            except Exception:
                LOG.exception("Could not append ULTRA honeypot evidence")
        await log_event(
            self.bot, guild, "security_log_channel_id",
            "Guardian ULTRA honeypot triggered",
            description=(
                f"Actor ID: {actor_id or 'unknown'}\n"
                f"Event: {kind}\nConfidence: {confidence}/100\n"
                "Advisory only; no automatic punishment. Review audit logs."
            ),
            color=discord.Color.orange(),
        )
        return True

    async def _setup_honeypot(self, guild: discord.Guild, created_by_id: int) -> str:
        async with self._locks[guild.id]:
            channel_id, role_id, enabled = await self._honeypot(guild.id)
            channel = guild.get_channel(channel_id) if channel_id else None
            role = guild.get_role(role_id) if role_id else None
            if channel is not None and role is not None:
                if not enabled:
                    await self.bot.database.execute(
                        "UPDATE ultra_honeypots SET enabled=1 WHERE guild_id=?", (guild.id,)
                    )
                    self._honeypots[guild.id] = (channel.id, role.id, True)
                return f"Existing honeypot rearmed: {channel.mention}. Nothing duplicated."

            if guild.me is None:
                raise ValueError("Guardian role was not available in the server.")
            perms = guild.me.guild_permissions
            if not perms.manage_channels or not perms.manage_roles:
                raise ValueError("Guardian requires Manage Channels and Manage Roles.")

            # No public exposure or actual credential material.
            if hasattr(self.bot, "suppress_security_events"):
                self.bot.suppress_security_events(
                    guild.id, seconds=90, reason="ULTRA honeypot installation"
                )
            if role is None:
                role = await guild.create_role(
                    name=ULTRA_NAME,
                    permissions=discord.Permissions.none(),
                    hoist=False, mentionable=False,
                    reason="Guardian v8 non-privileged canary role",
                )
            if channel is None:
                overwrites = {
                    guild.default_role: discord.PermissionOverwrite(view_channel=False),
                    guild.me: discord.PermissionOverwrite(
                        view_channel=True, send_messages=True,
                        manage_messages=True, read_message_history=True
                    ),
                }
                owner = guild.get_member(guild.owner_id)
                if owner is not None:
                    overwrites[owner] = discord.PermissionOverwrite(
                        view_channel=True, read_message_history=True
                    )
                channel = await guild.create_text_channel(
                    "guardian-vault-tripwire", overwrites=overwrites,
                    topic="Security decoy. No real data. Changes and access are monitored.",
                    reason="Guardian ULTRA honeypot",
                )

            # Retain the v7 Canary guard for edits and deletion.
            for kind, asset in (("channel", channel), ("role", role)):
                await self.bot.database.execute(
                    "INSERT OR REPLACE INTO guardian_v7_assets "
                    "(guild_id,asset_type,asset_id,label,canary,created_by_id) "
                    "VALUES (?,?,?,?,1,?)",
                    (guild.id, kind, asset.id, asset.name, created_by_id),
                )
            await self.bot.database.execute(
                "INSERT INTO ultra_honeypots(guild_id,channel_id,role_id,enabled) "
                "VALUES(?,?,?,1) ON CONFLICT(guild_id) DO UPDATE SET "
                "channel_id=excluded.channel_id,role_id=excluded.role_id,enabled=1",
                (guild.id, channel.id, role.id),
            )
            self._honeypots[guild.id] = (channel.id, role.id, True)
            await channel.send(
                "🔒 **GUARDIAN SECURITY CANARY**\n"
                "This is an intentionally empty decoy vault. Do not assign the decoy "
                "role, change this channel, or interact with restricted controls. "
                "There are no passwords, tokens, or credentials here.",
                view=VaultButton(self), allowed_mentions=discord.AllowedMentions.none(),
            )
            return f"Honeypot armed: {channel.mention} and {role.name}. Alerts are advisory."

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return
        channel_id, _, enabled = await self._honeypot(message.guild.id)
        if enabled and channel_id == message.channel.id:
            await self._tripwire(message.guild, message.author.id, "VAULT_MESSAGE", 45)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        if before.id == before.guild.owner_id or after.bot:
            return
        _, role_id, enabled = await self._honeypot(after.guild.id)
        if enabled and role_id and role_id not in {r.id for r in before.roles}:
            if role_id in {r.id for r in after.roles}:
                await self._tripwire(after.guild, after.id, "DECOY_ROLE_ASSIGNED", 85)

        # No DB lookup for nickname/avatar/ordinary role events.
        if before.roles == after.roles:
            return
        me = after.guild.me
        if me is None:
            return
        regranted = [
            r for r in after.roles if r not in before.roles
            and not r.managed and not r.is_default()
            and r < me.top_role and dangerous_role(r)
        ]
        if not regranted:
            return
        lock = await self.bot.database.fetchone(
            "SELECT role_ids FROM ultra_staff_locks WHERE guild_id=? AND member_id=?",
            (after.guild.id, after.id),
        )
        if lock is not None:
            try:
                await after.remove_roles(
                    *regranted, reason="Guardian ULTRA owner-approved staff lock",
                )
                await self._tripwire(
                    after.guild, after.id, "LOCK_BYPASS_REGRANT", 95
                )
            except (discord.Forbidden, discord.HTTPException):
                LOG.warning(
                    "Could not enforce ULTRA staff lock guild=%s member=%s",
                    after.guild.id, after.id,
                )

    @tasks.loop(minutes=10)
    async def lock_review_loop(self) -> None:
        now = int(datetime.now(UTC).timestamp())
        rows = await self.bot.database.fetchall(
            "SELECT guild_id,member_id FROM ultra_staff_locks "
            "WHERE review_after <= ? LIMIT 25", (now,)
        )
        for row in rows:
            guild = self.bot.get_guild(int(row["guild_id"]))
            if guild is not None:
                await log_event(
                    self.bot, guild, "security_log_channel_id",
                    "Guardian ULTRA staff lock requires owner review",
                    description=(
                        f"Member ID: {row['member_id']}\n"
                        "Lock remains active until the owner explicitly restores privileges."
                    ),
                )
            await self.bot.database.execute(
                "UPDATE ultra_staff_locks SET review_after=? "
                "WHERE guild_id=? AND member_id=?",
                (now + 3600, row["guild_id"], row["member_id"]),
            )

    @lock_review_loop.before_loop
    async def before_lock_review_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def _staff_lock(self, member: discord.Member, reason: str) -> str:
        guild = member.guild
        if member.id == guild.owner_id or member.bot:
            return "The owner and bots cannot be staff-locked."
        existing = await self.bot.database.fetchone(
            "SELECT 1 FROM ultra_staff_locks WHERE guild_id=? AND member_id=?",
            (guild.id, member.id),
        )
        if existing is not None:
            return "That staff account is already locked."
        all_dangerous = [
            role for role in member.roles if dangerous_role(role)
            and not role.is_default()
        ]
        removable = reversible_roles(member, guild.me)
        if not all_dangerous:
            return "No privileged staff roles were found."
        if len(removable) != len(all_dangerous):
            return "Cannot safely lock: managed or higher-ranked privileged roles are present."
        role_snapshots = [
            {"id": role.id, "permissions": role.permissions.value}
            for role in removable
        ]
        # Persist restoration data BEFORE modifying Discord permissions.
        await self.bot.database.execute(
            "INSERT INTO ultra_staff_locks "
            "(guild_id,member_id,role_ids,reason,review_after) VALUES(?,?,?,?,?)",
            (guild.id, member.id, json.dumps(role_snapshots), reason[:500],
             int(datetime.now(UTC).timestamp()) + 1800),
        )
        try:
            if hasattr(self.bot, "suppress_security_events"):
                self.bot.suppress_security_events(guild.id, seconds=45)
            await member.remove_roles(
                *removable, reason="Guardian ULTRA owner-approved staff lock"
            )
        except (discord.Forbidden, discord.HTTPException):
            # Preserve the saved role snapshot for owner recovery if Discord
            # partially applied the change. Never claim lock success.
            LOG.exception("Incomplete ULTRA staff lock on member %s", member.id)
            return "Discord reported a failed or partial lock. Owner recovery record retained."
        await self.bot.database.create_case(
            guild.id, member.id, guild.owner_id, "ULTRA_STAFF_LOCK",
            f"Owner-approved temporary freeze: {reason[:300]}",
        )
        return (
            f"Staff account {member.id} locked; removed {len(removable)} privileged "
            "role(s). Only the server owner can restore them."
        )

    async def _restore_staff(self, guild: discord.Guild, member: discord.Member) -> str:
        row = await self.bot.database.fetchone(
            "SELECT role_ids FROM ultra_staff_locks WHERE guild_id=? AND member_id=?",
            (guild.id, member.id),
        )
        if row is None:
            return "No saved owner-approved staff lock exists."
        me = guild.me
        if me is None:
            return "Cannot check Guardian role hierarchy."
        try:
            role_snapshots = json.loads(str(row["role_ids"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            return "Saved role record is invalid; use manual recovery."
        roles = []
        for snapshot in role_snapshots:
            # Legacy entries are intentionally not auto-restored without an
            # original permission snapshot.
            if not isinstance(snapshot, dict):
                return "Legacy role record needs manual permission review."
            role = guild.get_role(int(snapshot["id"]))
            if (role is None or role.is_default() or role.managed
                    or role >= me.top_role
                    or role.permissions.value != int(snapshot["permissions"])):
                return "Role changed, vanished, or outranks Guardian. Manual review required."
            roles.append(role)
            roles.append(role)
        try:
            if hasattr(self.bot, "suppress_security_events"):
                self.bot.suppress_security_events(guild.id, seconds=45)
            await member.add_roles(
                *roles, reason="Guardian ULTRA owner-approved role recovery"
            )
        except (discord.Forbidden, discord.HTTPException):
            return "Discord denied restoration; lock record retained."
        await self.bot.database.execute(
            "DELETE FROM ultra_staff_locks WHERE guild_id=? AND member_id=?",
            (guild.id, member.id),
        )
        await self.bot.database.create_case(
            guild.id, member.id, guild.owner_id,
            "ULTRA_STAFF_RESTORED", "Owner-approved explicit privilege restoration",
        )
        return f"Owner-approved restoration completed for {member.id}: {len(roles)} role(s)."

    def _permission_report(self, guild: discord.Guild) -> str:
        issues = permission_risks(guild)
        if not issues:
            return "ULTRA Permission Scanner: no obvious permission or hierarchy gaps."
        return "ULTRA Permission Scanner:\n" + "\n".join(
            f"• {item}" for item in issues[:15]
        )

    async def _radar(self, guild: discord.Guild) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT kind,COUNT(*) AS n FROM ultra_tripwires WHERE guild_id=? "
            "AND created_at>=datetime('now','-1 day') GROUP BY kind ORDER BY n DESC LIMIT 6",
            (guild.id,),
        )
        max_rows = await self.bot.database.fetchall(
            "SELECT kind,COUNT(*) AS n FROM guardian_max_events WHERE guild_id=? "
            "AND created_at>=datetime('now','-1 day') "
            "GROUP BY kind ORDER BY n DESC LIMIT 6",
            (guild.id,),
        )
        security = self.bot.get_cog("SecurityCog")
        active = bool(security and security.is_raid_mode_active(guild.id))
        traps = ", ".join(f"{r['kind']}={r['n']}" for r in rows) or "none"
        risks = ", ".join(f"{r['kind']}={r['n']}" for r in max_rows) or "none"
        return (
            f"Threat Radar — {guild.name}\n"
            f"Raid containment: {'ACTIVE' if active else 'standby'}\n"
            f"Honeypot alerts (24h): {traps}\nMAX threat signals (24h): {risks}"
        )[:1900]

    async def _incident_report(self, guild_id: int) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT case_id,action,target_id,reason,created_at FROM cases "
            "WHERE guild_id=? ORDER BY case_id DESC LIMIT 6", (guild_id,),
        )
        if not rows:
            return "Incident investigator: no moderation/security cases recorded."
        parts = [
            f"#{row['case_id']} {str(row['created_at'])[:19]} "
            f"{row['action']} target={row['target_id'] or 'none'} "
            f"{str(row['reason'])[:90]}" for row in rows
        ]
        return "Recent incident timeline (newest first):\n" + "\n".join(parts)

    async def _behavior(self, guild_id: int) -> str:
        rows = await self.bot.database.fetchall(
            "SELECT actor_id,COUNT(*) AS count FROM guardian_v7_staff_commands "
            "WHERE guild_id=? GROUP BY actor_id ORDER BY count DESC LIMIT 6",
            (guild_id,),
        )
        signals = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS n FROM guardian_sentinel_signals WHERE guild_id=?",
            (guild_id,),
        )
        return (
            "Behavioral intelligence (historical, not a guilt score)\n"
            + "\n".join(
                f"Staff ID {r['actor_id']}: {r['count']} recorded commands"
                for r in rows
            )
            + f"\nSentinel signals recorded: {int(signals['n']) if signals else 0}\n"
            "Anomaly review: /sentinel signals and /shield trust-graph."
        )[:1900]

    def _recovery(self) -> str:
        max_cog = self.bot.get_cog("SecurityMaxCog")
        snapshot = self.bot.database.backup_info()
        return (
            "Recovery and failover readiness\n"
            f"Local backups: {snapshot.get('count', 0)}\n"
            f"Off-host replica: {'configured' if os.getenv('GUARDIAN_BACKUP_ENDPOINT') else 'NOT CONFIGURED'}\n"
            f"External heartbeat: {'configured' if os.getenv('GUARDIAN_WATCHDOG_HEARTBEAT_URL') else 'NOT CONFIGURED'}\n"
            f"Heartbeat push: {getattr(max_cog, 'last_watchdog_push', 'unknown')}\n"
            "True automatic failover requires an independent host and tested standby. "
            "A backup on this host alone cannot provide failover."
        )

    @ultra.command(name="center", description="Interactive ULTRA threat and safety controls.")
    @guild_only()
    @staff_only()
    async def center(self, interaction: discord.Interaction) -> None:
        embed = discord.Embed(
            title="ESN Guardian v8 ULTRA",
            description=(
                "Active honeypot • staff containment • incident timeline • "
                "risk radar • policy scanning • human appeals • recovery checks\n"
                "Use the buttons below for reports; high-risk actions are owner-only."
            ), color=discord.Color.blurple(),
        )
        await interaction.response.send_message(
            embed=embed, view=UltraView(self, interaction.guild_id, interaction.user.id),
            ephemeral=True,
        )

    @ultra.command(name="honeypot", description="Create/rearm a protected, empty decoy vault and role.")
    @guild_only()
    @guild_owner_only()
    async def honeypot_cmd(self, interaction: discord.Interaction) -> None:
        await defer_response(interaction)
        try:
            message = await self._setup_honeypot(interaction.guild, interaction.user.id)
        except (discord.Forbidden, discord.HTTPException, ValueError) as exc:
            message = f"Honeypot setup failed safely: {exc}"
        await respond(interaction, message)

    @ultra.command(name="honeypot-status", description="Show ULTRA canary state and recorded tripwires.")
    @guild_only()
    @staff_only()
    async def honeypot_status(self, interaction: discord.Interaction) -> None:
        channel, role, enabled = await self._honeypot(interaction.guild_id)
        n = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS n FROM ultra_tripwires WHERE guild_id=?",
            (interaction.guild_id,),
        )
        await respond(
            interaction, f"Honeypot: {'ARMED' if enabled else 'disabled'}\n"
            f"Channel: {channel or 'unconfigured'}\n"
            f"Role: {role or 'unconfigured'}\n"
            f"Recorded tripwires: {int(n['n']) if n else 0}\n"
            "Canary events are advisory and do not auto-ban members.",
        )

    @ultra.command(name="honeypot-toggle", description="Enable/disable decoy monitoring without deleting assets.")
    @guild_only()
    @guild_owner_only()
    async def honeypot_toggle(self, interaction: discord.Interaction, enabled: bool) -> None:
        channel, role, _ = await self._honeypot(interaction.guild_id)
        if not channel or not role:
            await respond(interaction, "Run /ultra honeypot to create the decoy first.")
            return
        await self.bot.database.execute(
            "UPDATE ultra_honeypots SET enabled=? WHERE guild_id=?",
            (int(enabled), interaction.guild_id),
        )
        self._honeypots[interaction.guild_id] = (channel, role, enabled)
        await respond(
            interaction, f"ULTRA tripwire monitoring {'enabled' if enabled else 'disabled'}."
            " Existing v7 canary protection remains in place.",
        )

    @ultra.command(name="staff-lock", description="Owner-approved temporary freeze of dangerous staff roles.")
    @guild_only()
    @guild_owner_only()
    async def staff_lock(
        self, interaction: discord.Interaction, member: discord.Member, reason: str
    ) -> None:
        await defer_response(interaction)
        await respond(interaction, await self._staff_lock(member, reason))

    @ultra.command(name="undo", description="Restore a staff lock after explicit owner confirmation.")
    @guild_only()
    @guild_owner_only()
    async def undo(
        self, interaction: discord.Interaction, member: discord.Member,
        confirmation: str,
    ) -> None:
        if confirmation != UNLOCK_CONFIRMATION:
            await respond(
                interaction, "To restore dangerous permissions, type RESTORE in "
                "the confirmation field. This operation cannot revive deleted assets.",
            )
            return
        await defer_response(interaction)
        await respond(interaction, await self._restore_staff(interaction.guild, member))

    @ultra.command(name="audit", description="Scan Guardian permissions and staff hierarchy gaps.")
    @guild_only()
    @staff_only()
    async def audit_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, self._permission_report(interaction.guild))

    @ultra.command(name="radar", description="Show raid state and recent honeypot/risk activity.")
    @guild_only()
    @staff_only()
    async def radar_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self._radar(interaction.guild))

    @ultra.command(name="behavior", description="Show historical staff behavior and Sentinel observations.")
    @guild_only()
    @staff_only()
    async def behavior_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self._behavior(interaction.guild_id))

    @ultra.command(name="incidents", description="Read the recent tamper-evident incident case timeline.")
    @guild_only()
    @staff_only()
    async def incidents_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, await self._incident_report(interaction.guild_id))

    @ultra.command(name="raid-preview", description="Explain current raid threshold and simulated exposure.")
    @guild_only()
    @staff_only()
    async def raid_preview_cmd(self, interaction: discord.Interaction) -> None:
        sec = self.bot.get_cog("SecurityCog")
        if sec is None:
            await respond(interaction, "Underlying raid engine unavailable.")
            return
        config = await sec._raid_policy(interaction.guild_id)
        now = datetime.now(UTC)
        joins = sec.joins[interaction.guild_id]
        fast = sec.fast_joins[interaction.guild_id]
        young = sec.young_joins[interaction.guild_id]
        active = sec.is_raid_mode_active(interaction.guild_id)
        preview = raid_preview(
            sum((now - t).total_seconds() <= int(config["join_window_seconds"]) for t in joins),
            sum((now - t).total_seconds() <= 5 for t in fast),
            sum((now - t).total_seconds() <= 15 for t in young),
            int(config["join_limit"]), int(config["min_account_age_days"]),
        )
        await respond(
            interaction, f"Current raid mode: {'ACTIVE' if active else 'standby'}\n"
            f"Policy enabled: {bool(config['enabled'])}\n"
            f"Join limit: {config['join_limit']} in {config['join_window_seconds']}s\n"
            f"Account-age review: {config['min_account_age_days']} days\n"
            f"Threshold explanation (no actions performed): {preview}",
        )

    @ultra.command(name="recovery", description="Show backup, watchdog, and independent failover readiness.")
    @guild_only()
    @staff_only()
    async def recovery_cmd(self, interaction: discord.Interaction) -> None:
        await respond(interaction, self._recovery())

    @ultra.command(name="drill", description="Run a no-action security decision and recovery dry run.")
    @guild_only()
    @staff_only()
    async def drill(self, interaction: discord.Interaction) -> None:
        sec = self.bot.get_cog("SecurityCog")
        checks = {
            "Fast-burst detector": "Fast join burst" in raid_preview(4, 4, 0, 8, 3),
            "Young-account detector": "Young-account burst" in raid_preview(3, 2, 3, 8, 3),
            "Coordinated-name risk": join_risk_score(
                account_age_days=0, default_avatar=True,
                name_cluster=4, similar_names=3,
            ) >= 70,
            "Phishing engine": scam_score(
                "free nitro verify your account scan this QR https://bit.ly/test"
            ) >= 55,
            "Honeypot event registration": bool(self.bot.get_cog("SecurityV7Cog")),
            "Core raid engine online": bool(sec),
        }
        ok = sum(checks.values())
        await respond(
            interaction, f"ULTRA non-destructive drill: {ok}/{len(checks)} checks passed\n"
            + "\n".join(f"{'PASS' if good else 'FAIL'} {key}" for key, good in checks.items())
            + "\nNo kicks, bans, role edits or channel changes were performed.",
        )

    @ultra.command(name="appeal", description="Request human review of your own moderation case.")
    @guild_only()
    async def appeal(self, interaction: discord.Interaction, case_id: int, reason: str) -> None:
        row = await self.bot.database.fetchone(
            "SELECT case_id FROM cases WHERE guild_id=? AND case_id=? AND target_id=?",
            (interaction.guild_id, case_id, interaction.user.id),
        )
        if row is None:
            await respond(interaction, "That case does not belong to your account in this server.")
            return
        if not reason.strip():
            await respond(interaction, "Include a reason for human review.")
            return
        try:
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO ultra_appeals(guild_id,member_id,case_id,reason) "
                "VALUES(?,?,?,?)",
                (interaction.guild_id, interaction.user.id, case_id, reason[:500]),
            )
        except Exception:
            LOG.exception("Could not save ULTRA appeal")
            await respond(interaction, "The appeal database could not be updated.")
            return
        await log_event(
            self.bot, interaction.guild, "security_log_channel_id",
            "ULTRA case appeal pending",
            description=(
                f"Case #{case_id}; Member: {interaction.user.id}\n"
                "The owner must review the evidence. No automatic unban or role changes."
            ),
        )
        await respond(interaction, "Appeal recorded for human review. No punishment was reversed.")

    @ultra.command(name="appeal-review", description="Owner decision on a pending appeal (no automatic unban).")
    @guild_only()
    @guild_owner_only()
    @app_commands.choices(decision=[
        app_commands.Choice(name="Accept", value="accepted"),
        app_commands.Choice(name="Reject", value="rejected"),
    ])
    async def appeal_review(
        self, interaction: discord.Interaction,
        appeal_id: int, decision: app_commands.Choice[str],
    ) -> None:
        row = await self.bot.database.fetchone(
            "SELECT id FROM ultra_appeals WHERE id=? AND guild_id=? AND status='open'",
            (appeal_id, interaction.guild_id),
        )
        if row is None:
            await respond(interaction, "Appeal not found or already reviewed.")
            return
        await self.bot.database.execute(
            "UPDATE ultra_appeals SET status=?,reviewed_by=? WHERE id=? AND guild_id=?",
            (decision.value, interaction.user.id, appeal_id, interaction.guild_id),
        )
        await respond(
            interaction, f"Appeal #{appeal_id} marked {decision.value}. "
            "This records a human decision; restoring access requires a separate owner action.",
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityUltraCog(bot))
