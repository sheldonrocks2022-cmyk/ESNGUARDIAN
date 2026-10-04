from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import guild_only, log_event, respond, staff_only, guild_owner_only
from esn_guardian.cogs.verification import VerificationView

LOG = logging.getLogger("esn_guardian.security_max")

URL_RE = re.compile(r"(?:https?://)[^\s<>()]+", re.IGNORECASE)
ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")
DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".hta", ".lnk",
)
SCAM_PHRASES = (
    "free nitro", "nitro gift", "steam gift", "claim your gift",
    "verify your account", "account verification", "scan this qr",
    "scan the qr", "qr code", "limited time gift", "free discord",
)
SUSPICIOUS_DOMAIN_TOKENS = (
    "discord-gift", "discordgift", "free-nitro", "freenitro",
    "nitro-gift", "dlscord", "dicsord", "discorcl",
    "steamcommuniity", "steamcomrnunity", "stearncommunity",
)
SHORTENERS = {"bit.ly", "tinyurl.com", "is.gd", "rb.gy", "cutt.ly", "t.co", "shorturl.at"}
HIGH_RISK_PERMISSIONS = (
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members", "moderate_members",
)
MAX_STATUS_PATH = Path("data/guardian_max_status.json")


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def username_similarity(a: str, b: str) -> float:
    a = normalize_name(a)
    b = normalize_name(b)
    if not a or not b:
        return 0.0
    prefix = 0
    for left, right in zip(a, b):
        if left != right:
            break
        prefix += 1
    prefix_score = prefix / max(1, min(len(a), len(b)))
    common = len(set(a) & set(b)) / max(1, len(set(a) | set(b)))
    length_score = 1.0 - min(1.0, abs(len(a) - len(b)) / max(len(a), len(b)))
    return min(1.0, prefix_score * 0.55 + common * 0.25 + length_score * 0.20)


def scam_score(content: str, filenames: tuple[str, ...] = ()) -> int:
    text = content.casefold()
    score = 0

    phrase_hits = sum(1 for phrase in SCAM_PHRASES if phrase in text)
    score += min(40, phrase_hits * 15)

    if any(marker in content for marker in ZERO_WIDTH):
        score += 18
    if "password" in text or "token" in text or "seed phrase" in text:
        score += 12

    for match in URL_RE.finditer(content):
        raw = match.group(0).rstrip(".,!?;:)")
        try:
            host = (urlparse(raw).hostname or "").casefold()
        except ValueError:
            host = ""
        if not host:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            score += 30
        if host in SHORTENERS:
            score += 18
        if any(token in host for token in SUSPICIOUS_DOMAIN_TOKENS):
            score += 35
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            pass
        else:
            score += 22

    for filename in filenames:
        lower = filename.casefold()
        if lower.endswith(DANGEROUS_EXTENSIONS):
            score += 40
        if ("qr" in lower or "verify" in lower) and lower.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
            score += 18

    return max(0, min(100, score))


def join_risk_score(*, account_age_days: int, default_avatar: bool, name_cluster: int, similar_names: int) -> int:
    score = 0
    if account_age_days < 1:
        score += 42
    elif account_age_days < 3:
        score += 30
    elif account_age_days < 7:
        score += 20
    elif account_age_days < 30:
        score += 8
    if default_avatar:
        score += 12
    score += min(30, max(0, name_cluster - 1) * 10)
    score += min(25, max(0, similar_names) * 8)
    return max(0, min(100, score))


class SecurityCenterView(discord.ui.View):
    def __init__(self, cog: "SecurityMaxCog", guild_id: int) -> None:
        super().__init__(timeout=300)
        self.cog = cog
        self.guild_id = guild_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.guild_id != self.guild_id:
            return False
        return (
            isinstance(interaction.user, discord.Member)
            and interaction.user.guild_permissions.manage_guild
        )

    @discord.ui.button(label="Refresh", style=discord.ButtonStyle.primary)
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        embed = await self.cog.center_embed(interaction.guild)
        await interaction.edit_original_response(embed=embed, view=self)

    @discord.ui.button(label="Self-Test", style=discord.ButtonStyle.secondary)
    async def self_test(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.cog.self_test_report(interaction.guild))

    @discord.ui.button(label="Backup Now", style=discord.ButtonStyle.success)
    async def backup(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        backup = await self.cog.bot.database.backup("guardianmax-manual")
        offhost = "not configured"
        v7 = self.cog.bot.get_cog("SecurityV7Cog")
        if v7 is not None and hasattr(v7, "offhost_backup") and os.getenv("GUARDIAN_BACKUP_ENDPOINT", "").strip():
            try:
                offhost = await asyncio.wait_for(v7.offhost_backup(), timeout=30)
            except Exception:
                offhost = "failed safely"
        await respond(
            interaction,
            f"Local backup: {backup.name if backup else 'unavailable'}\nOff-host replication: {offhost}",
        )


class SecurityMaxCog(commands.Cog):
    """Guardian MAX integration layer: verification, quarantine, raid-v4, anti-nuke-v2 and operations."""

    guardianmax = app_commands.Group(
        name="guardianmax",
        description="Guardian MAX security center, automation, verification and recovery.",
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.recent_joins: dict[int, deque[tuple[datetime, int, str, int, bool]]] = defaultdict(deque)
        self.audit_seen: dict[int, set[int]] = defaultdict(set)
        self.audit_events: dict[tuple[int, int], deque[tuple[datetime, int, str]]] = defaultdict(deque)
        self.slow_nuke_alerted: dict[tuple[int, int], datetime] = {}
        self.session: aiohttp.ClientSession | None = None
        self.last_watchdog_push: str = "not configured"
        self.last_offhost_result: str = "not configured"

    async def cog_load(self) -> None:
        for statement in (
            """CREATE TABLE IF NOT EXISTS guardian_max_config (
                guild_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                verification_v2 INTEGER NOT NULL DEFAULT 1,
                quarantine_max INTEGER NOT NULL DEFAULT 1,
                scam_max INTEGER NOT NULL DEFAULT 1,
                raid_v4 INTEGER NOT NULL DEFAULT 1,
                antinuke_v2 INTEGER NOT NULL DEFAULT 1,
                sentinel_v2 INTEGER NOT NULL DEFAULT 1,
                quarantine_role_id INTEGER,
                verification_channel_id INTEGER,
                verified_role_id INTEGER,
                unverified_role_id INTEGER,
                quarantine_minutes INTEGER NOT NULL DEFAULT 60,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_max_quarantine (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                removed_roles_json TEXT NOT NULL DEFAULT '[]',
                expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, user_id)
            )""",
            """CREATE TABLE IF NOT EXISTS guardian_max_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER,
                kind TEXT NOT NULL,
                score INTEGER NOT NULL DEFAULT 0,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE INDEX IF NOT EXISTS idx_guardian_max_events_guild
               ON guardian_max_events(guild_id, event_id DESC)""",
        ):
            await self.bot.database.execute(statement)

        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12))
        self.quarantine_expiry_loop.start()
        self.slow_nuke_loop.start()
        self.watchdog_loop.start()
        self.offhost_backup_loop.start()
        self.daily_report_loop.start()

    def cog_unload(self) -> None:
        for loop in (
            self.quarantine_expiry_loop,
            self.slow_nuke_loop,
            self.watchdog_loop,
            self.offhost_backup_loop,
            self.daily_report_loop,
        ):
            loop.cancel()
        if self.session is not None:
            asyncio.create_task(self.session.close())

    async def _config(self, guild_id: int):
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_max_config WHERE guild_id=?",
            (guild_id,),
        )
        if row is None:
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO guardian_max_config (guild_id) VALUES (?)",
                (guild_id,),
            )
            row = await self.bot.database.fetchone(
                "SELECT * FROM guardian_max_config WHERE guild_id=?",
                (guild_id,),
            )
        return row

    async def _event(self, guild: discord.Guild, user_id: int | None, kind: str, score: int, detail: str) -> None:
        await self.bot.database.execute(
            "INSERT INTO guardian_max_events (guild_id,user_id,kind,score,detail) VALUES (?,?,?,?,?)",
            (guild.id, user_id, kind, max(0, min(100, score)), detail[:1000]),
        )

    async def _case(self, guild: discord.Guild, target: discord.abc.User | None, action: str, reason: str, channel_id: int | None = None) -> int:
        case_id = await self.bot.database.create_case(
            guild.id,
            target.id if target else None,
            self.bot.user.id if self.bot.user else None,
            action,
            reason[:1000],
            channel_id,
        )
        await log_event(
            self.bot,
            guild,
            "security_log_channel_id",
            f"Guardian MAX: {action} | Case #{case_id}",
            description=(
                f"Target: {target.mention if target and hasattr(target, 'mention') else 'none'}\n"
                f"Reason: {reason[:1500]}"
            ),
            color=discord.Color.orange(),
        )
        return case_id

    @staticmethod
    def _dangerous_role(role: discord.Role) -> bool:
        return any(getattr(role.permissions, permission, False) for permission in HIGH_RISK_PERMISSIONS)

    async def _quarantine_role(self, guild: discord.Guild) -> discord.Role | None:
        config = await self._config(guild.id)
        role_id = int(config["quarantine_role_id"] or 0) if config else 0
        if not role_id:
            raid = await self.bot.database.fetchone(
                "SELECT quarantine_role_id FROM raid_config WHERE guild_id=?",
                (guild.id,),
            )
            role_id = int(raid["quarantine_role_id"] or 0) if raid else 0
        return guild.get_role(role_id) if role_id else None

    async def quarantine_member(self, member: discord.Member, reason: str, *, minutes: int | None = None) -> bool:
        if member.id == member.guild.owner_id or member.bot:
            return False
        config = await self._config(member.guild.id)
        role = await self._quarantine_role(member.guild)
        bot_member = member.guild.me
        if role is None or bot_member is None or role >= bot_member.top_role:
            await self._case(member.guild, member, "MAX_QUARANTINE_FAILED", f"No usable quarantine role; {reason}")
            return False

        minutes = max(5, min(10080, minutes or int(config["quarantine_minutes"] or 60)))
        expires = datetime.now(UTC) + timedelta(minutes=minutes)
        removable = [
            role_item for role_item in member.roles
            if not role_item.is_default()
            and not role_item.managed
            and role_item < bot_member.top_role
            and self._dangerous_role(role_item)
            and role_item != role
        ]
        removed_ids = [role_item.id for role_item in removable]
        try:
            if removable:
                await member.remove_roles(*removable, reason=f"Guardian MAX containment: {reason}")
            if role not in member.roles:
                await member.add_roles(role, reason=f"Guardian MAX quarantine: {reason}")
            await member.timeout(timedelta(minutes=minutes), reason=f"Guardian MAX quarantine: {reason}")
        except (discord.Forbidden, discord.HTTPException):
            await self._case(member.guild, member, "MAX_QUARANTINE_FAILED", reason)
            return False

        await self.bot.database.execute(
            "INSERT OR REPLACE INTO guardian_max_quarantine "
            "(guild_id,user_id,removed_roles_json,expires_at,reason) VALUES (?,?,?,?,?)",
            (
                member.guild.id,
                member.id,
                json.dumps(removed_ids),
                expires.strftime("%Y-%m-%d %H:%M:%S"),
                reason[:1000],
            ),
        )
        await self._event(member.guild, member.id, "quarantine", 80, reason)
        await self._case(member.guild, member, "MAX_QUARANTINE", f"{reason}; expires={expires.isoformat()}")
        return True

    async def release_member(self, member: discord.Member, reason: str) -> bool:
        row = await self.bot.database.fetchone(
            "SELECT * FROM guardian_max_quarantine WHERE guild_id=? AND user_id=?",
            (member.guild.id, member.id),
        )
        role = await self._quarantine_role(member.guild)
        bot_member = member.guild.me
        try:
            if role is not None and role in member.roles:
                await member.remove_roles(role, reason=f"Guardian MAX release: {reason}")
            await member.timeout(None, reason=f"Guardian MAX release: {reason}")
        except (discord.Forbidden, discord.HTTPException):
            return False

        restored = 0
        if row is not None and bot_member is not None:
            try:
                role_ids = [int(value) for value in json.loads(str(row["removed_roles_json"] or "[]"))]
            except (TypeError, ValueError, json.JSONDecodeError):
                role_ids = []
            for role_id in role_ids:
                original = member.guild.get_role(role_id)
                if (
                    original is None
                    or original.managed
                    or original.is_default()
                    or original >= bot_member.top_role
                ):
                    continue
                try:
                    await member.add_roles(original, reason=f"Guardian MAX role restoration: {reason}")
                    restored += 1
                except (discord.Forbidden, discord.HTTPException):
                    continue

        await self.bot.database.execute(
            "DELETE FROM guardian_max_quarantine WHERE guild_id=? AND user_id=?",
            (member.guild.id, member.id),
        )
        await self._event(member.guild, member.id, "quarantine_release", 0, f"{reason}; restored_roles={restored}")
        await self._case(member.guild, member, "MAX_QUARANTINE_RELEASE", f"{reason}; restored_roles={restored}")
        return True

    async def _ensure_role(self, guild: discord.Guild, name: str) -> discord.Role:
        existing = discord.utils.get(guild.roles, name=name)
        if existing is not None and not existing.managed:
            return existing
        return await guild.create_role(
            name=name,
            permissions=discord.Permissions.none(),
            hoist=False,
            mentionable=False,
            reason="Guardian MAX automatic setup",
        )

    async def _safe_overwrite(self, channel: discord.abc.GuildChannel, role: discord.Role, overwrite: discord.PermissionOverwrite) -> bool:
        try:
            await channel.set_permissions(role, overwrite=overwrite, reason="Guardian MAX containment baseline")
            return True
        except (discord.Forbidden, discord.HTTPException, AttributeError):
            return False

    async def setup_maximum(self, guild: discord.Guild) -> dict[str, int | str]:
        await self.bot.database.ensure_guild(guild.id)
        quarantine = await self._ensure_role(guild, "Guardian Quarantine")
        unverified = await self._ensure_role(guild, "Guardian Unverified")
        verified = await self._ensure_role(guild, "Guardian Verified")

        verification_channel = discord.utils.get(guild.text_channels, name="guardian-verification")
        if verification_channel is None:
            overwrites = {
                guild.default_role: discord.PermissionOverwrite(view_channel=False),
                unverified: discord.PermissionOverwrite(
                    view_channel=True,
                    read_message_history=True,
                    send_messages=False,
                    add_reactions=False,
                    attach_files=False,
                    use_external_apps=False,
                ),
            }
            if guild.me is not None:
                overwrites[guild.me] = discord.PermissionOverwrite(
                    view_channel=True,
                    read_message_history=True,
                    send_messages=True,
                    manage_messages=True,
                )
            verification_channel = await guild.create_text_channel(
                "guardian-verification",
                overwrites=overwrites,
                reason="Guardian MAX verification v2",
            )

        deny = discord.PermissionOverwrite(
            view_channel=False,
            send_messages=False,
            add_reactions=False,
            attach_files=False,
            connect=False,
            speak=False,
            create_public_threads=False,
            create_private_threads=False,
            send_messages_in_threads=False,
            use_external_apps=False,
        )

        semaphore = asyncio.Semaphore(6)
        async def apply(channel: discord.abc.GuildChannel, role: discord.Role) -> bool:
            async with semaphore:
                return await self._safe_overwrite(channel, role, deny)

        # Always make the unverified role able to see only the verification channel,
        # including when that channel already existed before Guardian MAX setup.
        await self._safe_overwrite(
            verification_channel,
            unverified,
            discord.PermissionOverwrite(
                view_channel=True,
                read_message_history=True,
                send_messages=False,
                add_reactions=False,
                attach_files=False,
                use_external_apps=False,
            ),
        )

        jobs = []
        for channel in guild.channels:
            if channel.id == verification_channel.id:
                jobs.append(apply(channel, quarantine))
                continue
            jobs.append(apply(channel, quarantine))
            jobs.append(apply(channel, unverified))
        results = await asyncio.gather(*jobs, return_exceptions=False)
        overwrite_success = sum(1 for value in results if value)

        embed = discord.Embed(
            title="ESN Guardian Verification v2 MAX",
            description=(
                "Press **VERIFY** to pass Guardian's adaptive verification.\n"
                "Guardian can require a human challenge, account-age checks, and risk review before access is granted."
            ),
            color=discord.Color.green(),
        )
        message = await verification_channel.send(
            embed=embed,
            view=VerificationView(self.bot),
            allowed_mentions=discord.AllowedMentions.none(),
        )

        await self.bot.database.execute(
            "UPDATE verification_config SET enabled=1,channel_id=?,message_id=?,verified_role_id=?,"
            "unverified_role_id=?,min_account_age_days=3,captcha_enabled=1,cooldown_seconds=20 WHERE guild_id=?",
            (verification_channel.id, message.id, verified.id, unverified.id, guild.id),
        )
        await self.bot.database.execute(
            "INSERT OR REPLACE INTO panel_messages (guild_id,panel_type,channel_id,message_id) "
            "VALUES (?,'verification',?,?)",
            (guild.id, verification_channel.id, message.id),
        )
        await self.bot.database.execute(
            "UPDATE raid_config SET enabled=1,join_limit=8,join_window_seconds=30,min_account_age_days=3,"
            "quarantine_role_id=? WHERE guild_id=?",
            (quarantine.id, guild.id),
        )
        await self.bot.database.execute(
            "UPDATE anti_nuke_config SET enabled=1,action_limit=2,window_seconds=15 WHERE guild_id=?",
            (guild.id,),
        )
        await self.bot.database.execute(
            "UPDATE security_config SET automod_enabled=1,flood_limit=4,flood_window_seconds=10,"
            "max_mentions=4,caps_percentage=80,block_invites=1,strict_links=1 WHERE guild_id=?",
            (guild.id,),
        )
        for domain in (
            "discord.com", "discordapp.com", "discord.gg", "github.com",
            "youtube.com", "youtu.be", "minecraft.net", "esnoffical.com",
        ):
            await self.bot.database.execute(
                "INSERT OR IGNORE INTO allowed_domains (guild_id,domain) VALUES (?,?)",
                (guild.id, domain),
            )

        await self.bot.database.execute(
            "INSERT INTO guardian_max_config "
            "(guild_id,enabled,verification_v2,quarantine_max,scam_max,raid_v4,antinuke_v2,sentinel_v2,"
            "quarantine_role_id,verification_channel_id,verified_role_id,unverified_role_id,quarantine_minutes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(guild_id) DO UPDATE SET enabled=1,verification_v2=1,quarantine_max=1,scam_max=1,"
            "raid_v4=1,antinuke_v2=1,sentinel_v2=1,quarantine_role_id=excluded.quarantine_role_id,"
            "verification_channel_id=excluded.verification_channel_id,verified_role_id=excluded.verified_role_id,"
            "unverified_role_id=excluded.unverified_role_id,quarantine_minutes=excluded.quarantine_minutes,"
            "updated_at=CURRENT_TIMESTAMP",
            (
                guild.id, 1, 1, 1, 1, 1, 1, 1,
                quarantine.id, verification_channel.id, verified.id, unverified.id, 60,
            ),
        )

        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is not None and hasattr(v7, "_config"):
            await self.bot.database.execute(
                "UPDATE guardian_v7_config SET profile='maximum',two_person=1,protected_assets=1,"
                "behavior_baselines=1,privilege_paths=1,evidence_chain=1,offhost_replication=1,"
                "predictive_alerts=1,emergency_minimal=1,updated_at=CURRENT_TIMESTAMP WHERE guild_id=?",
                (guild.id,),
            )

        v6 = self.bot.get_cog("ProtectionV6Cog")
        checkpoint_id = 0
        if v6 is not None and hasattr(v6, "checkpoint"):
            try:
                checkpoint_id = int(await v6.checkpoint(guild, "guardianmax-setup") or 0)
            except Exception:
                checkpoint_id = 0

        return {
            "quarantine_role": quarantine.id,
            "unverified_role": unverified.id,
            "verified_role": verified.id,
            "verification_channel": verification_channel.id,
            "overwrites": overwrite_success,
            "checkpoint": checkpoint_id,
        }

    async def _verification_on_join(self, member: discord.Member, config) -> None:
        if not bool(config["verification_v2"]):
            return
        verified = await self.bot.database.fetchone(
            "SELECT 1 FROM verified_members WHERE guild_id=? AND user_id=?",
            (member.guild.id, member.id),
        )
        if verified is not None:
            return
        role_id = int(config["unverified_role_id"] or 0)
        role = member.guild.get_role(role_id) if role_id else None
        if role is not None:
            try:
                await member.add_roles(role, reason="Guardian Verification v2 MAX: new member gate")
            except (discord.Forbidden, discord.HTTPException):
                pass

    async def _join_risk(self, member: discord.Member) -> tuple[int, int, int]:
        now = datetime.now(UTC)
        recent = self.recent_joins[member.guild.id]
        while recent and now - recent[0][0] > timedelta(seconds=60):
            recent.popleft()

        name = member.name
        cluster = 0
        similar = 0
        for created, _member_id, prior_name, _age, _default_avatar in recent:
            if now - created > timedelta(seconds=20):
                continue
            similarity = username_similarity(name, prior_name)
            if similarity >= 0.72:
                similar += 1
            if normalize_name(name)[:5] and normalize_name(name)[:5] == normalize_name(prior_name)[:5]:
                cluster += 1

        age_days = max(0, (now - member.created_at).days)
        default_avatar = member.avatar is None
        score = join_risk_score(
            account_age_days=age_days,
            default_avatar=default_avatar,
            name_cluster=cluster + 1,
            similar_names=similar,
        )
        recent.append((now, member.id, name, age_days, default_avatar))
        return score, cluster + 1, similar

    async def _activate_raid_v4(self, guild: discord.Guild, reason: str) -> None:
        security = self.bot.get_cog("SecurityCog")
        if security is not None:
            try:
                security.raid_mode_until[guild.id] = datetime.now(UTC) + timedelta(minutes=5)
                security._raid_trigger_count[guild.id] += 1
                security._schedule_raid_persist(guild.id, security.raid_mode_until[guild.id], force=True)
                asyncio.create_task(security._lockdown(guild, f"Guardian Raid Engine v4: {reason}"))
            except Exception:
                LOG.exception("Guardian MAX could not activate underlying raid containment")
        await self._case(guild, None, "RAID_V4_CLUSTER", reason)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        if member.bot:
            return
        config = await self._config(member.guild.id)
        if config is None or not bool(config["enabled"]):
            return

        await self._verification_on_join(member, config)
        score, cluster, similar = await self._join_risk(member)
        await self._event(
            member.guild,
            member.id,
            "join_risk",
            score,
            f"cluster={cluster}; similar_names={similar}; age_days={(datetime.now(UTC)-member.created_at).days}",
        )

        if bool(config["raid_v4"]) and cluster >= 4 and similar >= 2:
            await self._activate_raid_v4(
                member.guild,
                f"Coordinated identity cluster detected: cluster={cluster}, similar_names={similar}, latest_risk={score}/100",
            )

        if bool(config["quarantine_max"]) and score >= 70:
            await self.quarantine_member(
                member,
                f"Verification v2 adaptive join risk {score}/100; name_cluster={cluster}; similar_names={similar}",
            )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot or not isinstance(message.author, discord.Member):
            return
        config = await self._config(message.guild.id)
        if config is None or not bool(config["enabled"]) or not bool(config["scam_max"]):
            return
        if message.author.id == message.guild.owner_id:
            return

        filenames = tuple(attachment.filename for attachment in message.attachments)
        score = scam_score(message.content, filenames)
        if score < 55:
            return

        await self._event(message.guild, message.author.id, "scam_score", score, message.content[:500])
        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            pass

        await self._case(
            message.guild,
            message.author,
            "SCAM_MAX_BLOCKED",
            f"Composite scam/phishing score {score}/100; attachments={', '.join(filenames[:5]) or 'none'}",
            message.channel.id,
        )

        is_staff = (
            message.author.guild_permissions.administrator
            or message.author.guild_permissions.manage_guild
            or message.author.guild_permissions.manage_messages
        )
        if score >= 82 and not is_staff:
            await self.quarantine_member(
                message.author,
                f"Link & Scam Protection MAX score {score}/100",
            )

    async def _contain_slow_nuke_actor(self, guild: discord.Guild, actor_id: int, score: int, categories: set[str]) -> None:
        key = (guild.id, actor_id)
        now = datetime.now(UTC)
        previous = self.slow_nuke_alerted.get(key)
        if previous is not None and now - previous < timedelta(minutes=10):
            return
        self.slow_nuke_alerted[key] = now

        member = guild.get_member(actor_id)
        detail = f"Slow-nuke chain score={score}; categories={','.join(sorted(categories))}"
        await self._event(guild, actor_id, "slow_nuke", min(100, score * 10), detail)
        if member is not None:
            await self.quarantine_member(member, f"Anti-Nuke v2 detected a slow destructive chain: {detail}", minutes=1440)
        else:
            await self._case(guild, None, "ANTINUKE_V2_ALERT", f"Actor {actor_id}; {detail}")

    @tasks.loop(seconds=15)
    async def slow_nuke_loop(self) -> None:
        destructive_weights = {
            discord.AuditLogAction.channel_delete: (3, "channel"),
            discord.AuditLogAction.role_delete: (3, "role"),
            discord.AuditLogAction.role_update: (2, "privilege"),
            discord.AuditLogAction.member_role_update: (2, "privilege"),
            discord.AuditLogAction.webhook_create: (2, "webhook"),
            discord.AuditLogAction.webhook_update: (2, "webhook"),
            discord.AuditLogAction.webhook_delete: (2, "webhook"),
            discord.AuditLogAction.bot_add: (5, "automation"),
            discord.AuditLogAction.ban: (1, "moderation"),
            discord.AuditLogAction.kick: (1, "moderation"),
            discord.AuditLogAction.guild_update: (3, "settings"),
        }
        now = datetime.now(UTC)
        cutoff = now - timedelta(minutes=5)
        for guild in list(self.bot.guilds):
            config = await self._config(guild.id)
            if config is None or not bool(config["enabled"]) or not bool(config["antinuke_v2"]):
                continue
            try:
                async for entry in guild.audit_logs(limit=100, after=cutoff):
                    if entry.id in self.audit_seen[guild.id]:
                        continue
                    self.audit_seen[guild.id].add(entry.id)
                    if len(self.audit_seen[guild.id]) > 5000:
                        self.audit_seen[guild.id] = set(list(self.audit_seen[guild.id])[-2500:])

                    mapped = destructive_weights.get(entry.action)
                    actor = entry.user
                    if mapped is None or actor is None:
                        continue
                    if actor.id in {guild.owner_id, self.bot.user.id if self.bot.user else 0} or getattr(actor, "bot", False):
                        continue
                    weight, category = mapped
                    events = self.audit_events[(guild.id, actor.id)]
                    events.append((entry.created_at, weight, category))
                    while events and events[0][0] < cutoff:
                        events.popleft()
                    total = sum(item[1] for item in events)
                    categories = {item[2] for item in events}
                    if total >= 8 and len(categories) >= 2:
                        await self._contain_slow_nuke_actor(guild, actor.id, total, categories)
            except (discord.Forbidden, discord.HTTPException):
                continue
            except Exception:
                LOG.exception("Guardian MAX slow-nuke scan failed for guild %s", guild.id)

    @slow_nuke_loop.before_loop
    async def before_slow_nuke_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(minutes=1)
    async def quarantine_expiry_loop(self) -> None:
        rows = await self.bot.database.fetchall(
            "SELECT guild_id,user_id FROM guardian_max_quarantine WHERE expires_at <= CURRENT_TIMESTAMP LIMIT 100"
        )
        for row in rows:
            guild = self.bot.get_guild(int(row["guild_id"]))
            if guild is None:
                continue
            member = guild.get_member(int(row["user_id"]))
            if member is None:
                await self.bot.database.execute(
                    "DELETE FROM guardian_max_quarantine WHERE guild_id=? AND user_id=?",
                    (guild.id, int(row["user_id"])),
                )
                continue
            await self.release_member(member, "Automatic Guardian MAX quarantine expiry")

    @quarantine_expiry_loop.before_loop
    async def before_quarantine_expiry_loop(self) -> None:
        await self.bot.wait_until_ready()

    async def _status_payload(self) -> dict[str, object]:
        runtime = dict(getattr(self.bot, "runtime_health", {}))
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "online": bool(self.bot.is_ready()),
            "latency_ms": round(max(0.0, self.bot.latency) * 1000.0, 1),
            "event_loop_lag_ms": runtime.get("event_loop_lag_ms", 0.0),
            "database_ok": bool(runtime.get("database_ok", True)),
            "guilds": len(self.bot.guilds),
            "quarantined": int(
                (await self.bot.database.fetchone(
                    "SELECT COUNT(*) AS count FROM guardian_max_quarantine"
                ))["count"]
            ),
        }

    @tasks.loop(minutes=1)
    async def watchdog_loop(self) -> None:
        payload = await self._status_payload()
        MAX_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(
            MAX_STATUS_PATH.write_text,
            json.dumps(payload, indent=2, sort_keys=True),
            "utf-8",
        )

        endpoint = os.getenv("GUARDIAN_WATCHDOG_HEARTBEAT_URL", "").strip()
        if not endpoint or self.session is None:
            self.last_watchdog_push = "status-file only"
            return
        headers = {"Content-Type": "application/json"}
        token = os.getenv("GUARDIAN_WATCHDOG_HEARTBEAT_TOKEN", "").strip()
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            async with self.session.post(endpoint, json=payload, headers=headers) as response:
                self.last_watchdog_push = "online" if response.status < 400 else f"HTTP {response.status}"
        except Exception:
            self.last_watchdog_push = "failed"

    @watchdog_loop.before_loop
    async def before_watchdog_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(hours=6)
    async def offhost_backup_loop(self) -> None:
        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is None or not hasattr(v7, "offhost_backup"):
            self.last_offhost_result = "v7 unavailable"
            return
        if not os.getenv("GUARDIAN_BACKUP_ENDPOINT", "").strip():
            self.last_offhost_result = "not configured"
            return
        try:
            self.last_offhost_result = await asyncio.wait_for(v7.offhost_backup(), timeout=45)
        except Exception:
            self.last_offhost_result = "failed safely"

    @offhost_backup_loop.before_loop
    async def before_offhost_backup_loop(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(hours=24)
    async def daily_report_loop(self) -> None:
        for guild in list(self.bot.guilds):
            try:
                report = await self.analyst_report(guild)
                await log_event(
                    self.bot,
                    guild,
                    "security_log_channel_id",
                    "Guardian MAX Daily Security Report",
                    description=report[:4000],
                    color=discord.Color.blue(),
                )
            except Exception:
                LOG.exception("Guardian MAX daily report failed for guild %s", guild.id)

    @daily_report_loop.before_loop
    async def before_daily_report_loop(self) -> None:
        await self.bot.wait_until_ready()
        await asyncio.sleep(300)

    async def self_test_report(self, guild: discord.Guild) -> str:
        checks: list[tuple[str, bool]] = []
        bot_member = guild.me
        for permission in (
            "view_audit_log", "manage_messages", "moderate_members", "kick_members",
            "ban_members", "manage_roles", "manage_channels", "manage_webhooks",
        ):
            checks.append((permission, bool(bot_member and getattr(bot_member.guild_permissions, permission, False))))

        for cog_name in (
            "SecurityCog", "AdvancedSecurityCog", "SecuritySentinelCog", "SecurityOverwatchCog",
            "SecurityResilienceCog", "ProtectionV6Cog", "SecurityV7Cog", "SecurityMaxCog",
            "VerificationCog",
        ):
            checks.append((cog_name, self.bot.get_cog(cog_name) is not None))

        try:
            checks.append(("database_integrity", await self.bot.database.quick_check()))
        except Exception:
            checks.append(("database_integrity", False))

        config = await self._config(guild.id)
        verification = await self.bot.database.fetchone(
            "SELECT * FROM verification_config WHERE guild_id=?",
            (guild.id,),
        )
        security = await self.bot.database.fetchone(
            "SELECT strict_links FROM security_config WHERE guild_id=?",
            (guild.id,),
        )
        antinuke = await self.bot.database.fetchone(
            "SELECT enabled FROM anti_nuke_config WHERE guild_id=?",
            (guild.id,),
        )
        checks.extend(
            (
                ("verification_v2", bool(verification and verification["enabled"] and verification["captcha_enabled"])),
                ("quarantine_role", bool(config and config["quarantine_role_id"] and guild.get_role(int(config["quarantine_role_id"])))),
                ("strict_link_protection", bool(security and security["strict_links"])),
                ("anti_nuke", bool(antinuke and antinuke["enabled"])),
                ("local_backup", int(self.bot.database.backup_info().get("count", 0) or 0) > 0),
            )
        )

        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is not None and hasattr(v7, "verify_chain"):
            chain = await v7.verify_chain(guild.id)
            checks.append(("evidence_chain", bool(chain["ok"])))

        passed = sum(1 for _name, ok in checks if ok)
        score = round(100 * passed / max(1, len(checks)))
        failed = [name for name, ok in checks if not ok]
        external = (
            f"Off-host backup: {'configured' if os.getenv('GUARDIAN_BACKUP_ENDPOINT') else 'not configured'}\n"
            f"External watchdog push: {'configured' if os.getenv('GUARDIAN_WATCHDOG_HEARTBEAT_URL') else 'status-file only'}"
        )
        return (
            "**Guardian MAX self-test**\n"
            f"Core score: {score}/100\n"
            f"Passed: {passed}/{len(checks)}\n"
            f"Failed: {', '.join(failed) if failed else 'none'}\n"
            f"{external}"
        )

    async def analyst_report(self, guild: discord.Guild, member: discord.Member | None = None) -> str:
        if member is not None:
            rows = await self.bot.database.fetchall(
                "SELECT case_id,action,reason,created_at FROM cases WHERE guild_id=? AND target_id=? "
                "ORDER BY case_id DESC LIMIT 12",
                (guild.id, member.id),
            )
            protection = self.bot.get_cog("ProtectionV6Cog")
            risk_text = "Adaptive risk unavailable"
            if protection is not None and hasattr(protection, "member_risk"):
                try:
                    data = await protection.member_risk(guild, member)
                    risk_text = f"Adaptive risk: {data['score']}/100 ({data['level']})"
                except Exception:
                    pass
            recent = Counter(str(row["action"]) for row in rows)
            return (
                f"**Guardian AI Security Analyst — {member}**\n"
                f"{risk_text}\n"
                f"Recent cases: {len(rows)}\n"
                f"Top signals: {', '.join(f'{name}×{count}' for name, count in recent.most_common(5)) or 'none'}\n"
                f"Quarantined: {'yes' if await self.bot.database.fetchone('SELECT 1 FROM guardian_max_quarantine WHERE guild_id=? AND user_id=?', (guild.id, member.id)) else 'no'}\n"
                "Recommendation: keep deterministic Guardian protections in control; use analyst output as explainable context."
            )

        rows = await self.bot.database.fetchall(
            "SELECT action,COUNT(*) AS count FROM cases WHERE guild_id=? "
            "AND created_at >= datetime('now','-60 minutes') GROUP BY action ORDER BY count DESC LIMIT 8",
            (guild.id,),
        )
        signals = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM guardian_sentinel_signals WHERE guild_id=? "
            "AND created_at >= datetime('now','-60 minutes') AND score>=60",
            (guild.id,),
        )
        quarantined = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM guardian_max_quarantine WHERE guild_id=?",
            (guild.id,),
        )
        v7 = self.bot.get_cog("SecurityV7Cog")
        state = v7.state[guild.id] if v7 is not None and hasattr(v7, "state") else "unknown"
        predictive = v7.score(guild.id) if v7 is not None and hasattr(v7, "score") else 0
        return (
            "**Guardian AI Security Analyst — live assessment**\n"
            f"Predictive state: {state} • risk {predictive}/100\n"
            f"High Sentinel signals (60m): {int(signals['count']) if signals else 0}\n"
            f"Currently quarantined: {int(quarantined['count']) if quarantined else 0}\n"
            f"Recent case mix: {', '.join(str(row['action']) + '×' + str(row['count']) for row in rows) if rows else 'none'}\n"
            "Assessment: Guardian enforcement remains deterministic; this analyst correlates evidence and explains the current posture."
        )

    async def center_embed(self, guild: discord.Guild) -> discord.Embed:
        config = await self._config(guild.id)
        verification = await self.bot.database.fetchone(
            "SELECT enabled,captcha_enabled,min_account_age_days FROM verification_config WHERE guild_id=?",
            (guild.id,),
        )
        quarantined = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM guardian_max_quarantine WHERE guild_id=?",
            (guild.id,),
        )
        cases = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM cases WHERE guild_id=? AND created_at >= datetime('now','-60 minutes')",
            (guild.id,),
        )
        sentinel = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS count FROM guardian_sentinel_signals WHERE guild_id=? "
            "AND created_at >= datetime('now','-30 minutes') AND score>=60",
            (guild.id,),
        )
        security = self.bot.get_cog("SecurityCog")
        raid_active = False
        if security is not None and hasattr(security, "is_raid_mode_active"):
            raid_active = bool(security.is_raid_mode_active(guild.id))
        v7 = self.bot.get_cog("SecurityV7Cog")
        state = v7.state[guild.id] if v7 is not None and hasattr(v7, "state") else "unknown"
        predictive = v7.score(guild.id) if v7 is not None and hasattr(v7, "score") else 0
        backups = self.bot.database.backup_info()

        embed = discord.Embed(
            title="ESN Guardian MAX Security Center",
            color=discord.Color.red() if state in {"CRITICAL", "PANIC"} else discord.Color.blue(),
            timestamp=datetime.now(UTC),
        )
        embed.add_field(name="Threat posture", value=f"{state} • predictive risk {predictive}/100", inline=False)
        embed.add_field(name="Raid Engine v4", value="ACTIVE CONTAINMENT" if raid_active else "standby", inline=True)
        embed.add_field(name="Quarantined", value=str(int(quarantined["count"]) if quarantined else 0), inline=True)
        embed.add_field(name="Recent cases", value=str(int(cases["count"]) if cases else 0), inline=True)
        embed.add_field(name="Sentinel v2 high signals", value=str(int(sentinel["count"]) if sentinel else 0), inline=True)
        embed.add_field(
            name="Verification v2",
            value=(
                f"{'ON' if verification and verification['enabled'] else 'OFF'} • "
                f"human-check {'ON' if verification and verification['captcha_enabled'] else 'OFF'} • "
                f"min age {verification['min_account_age_days'] if verification else 0}d"
            ),
            inline=False,
        )
        embed.add_field(
            name="Recovery",
            value=f"Local backups: {int(backups.get('count', 0) or 0)} • Off-host: {self.last_offhost_result}",
            inline=False,
        )
        embed.add_field(
            name="Watchdog",
            value=f"{self.last_watchdog_push} • local status: {MAX_STATUS_PATH}",
            inline=False,
        )
        embed.set_footer(text="Guardian MAX • deterministic enforcement + explainable intelligence")
        return embed

    @guardianmax.command(name="status", description="Show Guardian MAX protection status.")
    @guild_only()
    @staff_only()
    async def max_status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        config = await self._config(interaction.guild.id)
        await respond(
            interaction,
            "**Guardian MAX**\n"
            f"Verification v2: {'ON' if config['verification_v2'] else 'OFF'}\n"
            f"Quarantine MAX: {'ON' if config['quarantine_max'] else 'OFF'}\n"
            f"Link & Scam MAX: {'ON' if config['scam_max'] else 'OFF'}\n"
            f"Raid Engine v4: {'ON' if config['raid_v4'] else 'OFF'}\n"
            f"Anti-Nuke v2 slow-chain defense: {'ON' if config['antinuke_v2'] else 'OFF'}\n"
            f"Sentinel v2 correlation: {'ON' if config['sentinel_v2'] else 'OFF'}\n"
            f"Watchdog: {self.last_watchdog_push}\n"
            f"Off-host backup: {self.last_offhost_result}",
        )

    @guardianmax.command(name="setup-max", description="Safely configure Guardian's maximum protection baseline.")
    @guild_only()
    @guild_owner_only()
    async def setup_max(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        result = await self.setup_maximum(interaction.guild)
        await respond(
            interaction,
            "**Guardian MAX setup complete**\n"
            f"Verification channel: <#{result['verification_channel']}>\n"
            f"Verified role: <@&{result['verified_role']}>\n"
            f"Unverified role: <@&{result['unverified_role']}>\n"
            f"Quarantine role: <@&{result['quarantine_role']}>\n"
            f"Containment overwrites applied: {result['overwrites']}\n"
            f"Recovery checkpoint: #{result['checkpoint'] if result['checkpoint'] else 'not created'}\n"
            "Verification v2, Quarantine MAX, Strict Links, Raid v4, Anti-Nuke v2 and maximum v7 policy are enabled.",
        )

    @guardianmax.command(name="self-test", description="Run Guardian MAX's full protection self-test.")
    @guild_only()
    @staff_only()
    async def self_test(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.self_test_report(interaction.guild))

    @guardianmax.command(name="center", description="Open the Guardian MAX Security Center.")
    @guild_only()
    @staff_only()
    async def center(self, interaction: discord.Interaction) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await interaction.followup.send(
            embed=await self.center_embed(interaction.guild),
            view=SecurityCenterView(self, interaction.guild.id),
            ephemeral=True,
        )

    @guardianmax.command(name="quarantine", description="Quarantine a member with role stripping and timed containment.")
    @guild_only()
    @staff_only()
    async def quarantine(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: str = "Manual Guardian MAX security review",
        minutes: app_commands.Range[int, 5, 10080] = 60,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        if member.id in {interaction.user.id, interaction.guild.owner_id}:
            await respond(interaction, "Guardian MAX will not quarantine the server owner or the executing moderator.")
            return
        ok = await self.quarantine_member(member, reason, minutes=minutes)
        await respond(interaction, f"{'Quarantined' if ok else 'Could not quarantine'} {member.mention}.")

    @guardianmax.command(name="release", description="Release a Guardian MAX quarantine and restore safe removed roles.")
    @guild_only()
    @staff_only()
    async def release(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        reason: str = "Security review completed",
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        ok = await self.release_member(member, reason)
        await respond(interaction, f"{'Released' if ok else 'Could not release'} {member.mention}.")

    @guardianmax.command(name="analyst", description="Run the Guardian AI security analyst on the server or one member.")
    @guild_only()
    @staff_only()
    async def analyst(
        self,
        interaction: discord.Interaction,
        member: discord.Member | None = None,
    ) -> None:
        assert interaction.guild is not None
        await interaction.response.defer(ephemeral=True)
        await respond(interaction, await self.analyst_report(interaction.guild, member))

    @guardianmax.command(name="backup", description="Create a verified local backup and replicate off-host when configured.")
    @guild_only()
    @guild_owner_only()
    async def backup(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        backup = await self.bot.database.backup("guardianmax-manual")
        offhost = "not configured"
        v7 = self.bot.get_cog("SecurityV7Cog")
        if v7 is not None and hasattr(v7, "offhost_backup") and os.getenv("GUARDIAN_BACKUP_ENDPOINT", "").strip():
            try:
                offhost = await asyncio.wait_for(v7.offhost_backup(), timeout=45)
            except Exception:
                offhost = "failed safely"
        await respond(
            interaction,
            f"Local verified backup: {backup.name if backup else 'unavailable'}\nOff-host encrypted replication: {offhost}",
        )

    @guardianmax.command(name="watchdog", description="Show local and external Guardian watchdog heartbeat state.")
    @guild_only()
    @staff_only()
    async def watchdog(self, interaction: discord.Interaction) -> None:
        payload = await self._status_payload()
        await respond(
            interaction,
            "**Guardian MAX Watchdog**\n"
            f"Local status file: {MAX_STATUS_PATH}\n"
            f"External heartbeat: {self.last_watchdog_push}\n"
            f"Online: {'yes' if payload['online'] else 'no'}\n"
            f"Gateway latency: {payload['latency_ms']} ms\n"
            f"Database: {'OK' if payload['database_ok'] else 'FAILED'}\n"
            f"Quarantined: {payload['quarantined']}",
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityMaxCog(bot))
