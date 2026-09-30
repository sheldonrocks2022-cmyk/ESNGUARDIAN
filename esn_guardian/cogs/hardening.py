from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, guild_owner_only, respond, log_event

DANGEROUS = ("administrator","manage_guild","manage_roles","manage_channels","manage_webhooks","ban_members","kick_members","moderate_members")
SECRET_PATTERNS = (
    re.compile(r"(?i)(?:token|api[_ -]?key|secret|password)\\s*[:=]\\s*[\"']?[A-Za-z0-9_\\-.]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

class HardeningCog(commands.Cog):
    securityplus = app_commands.Group(name="guardian", description="ESN Guardian emergency security and recovery.")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        await self.bot.database.execute("""CREATE TABLE IF NOT EXISTS guardian_approved_bots (
            guild_id INTEGER NOT NULL, bot_id INTEGER NOT NULL, approved_by_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(guild_id, bot_id))""")
        await self.bot.database.execute("""CREATE TABLE IF NOT EXISTS guardian_approved_webhooks (
            guild_id INTEGER NOT NULL, webhook_id INTEGER NOT NULL, approved_by_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(guild_id, webhook_id))""")
        await self.bot.database.execute("""CREATE TABLE IF NOT EXISTS guardian_snapshots (
            guild_id INTEGER PRIMARY KEY, snapshot_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")

    async def _case(self, guild: discord.Guild, target, action: str, reason: str) -> None:
        await self.bot.database.create_case(guild.id, getattr(target,"id",None), self.bot.user.id if self.bot.user else None, action, reason)
        await log_event(self.bot, guild, "security_log_channel_id", action, description=reason, color=discord.Color.red())

    async def _approved_bot(self, guild_id: int, bot_id: int) -> bool:
        row = await self.bot.database.fetchone("SELECT 1 FROM guardian_approved_bots WHERE guild_id=? AND bot_id=?", (guild_id,bot_id))
        return row is not None

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        if not member.bot or (self.bot.user and member.id == self.bot.user.id):
            return
        if await self._approved_bot(member.guild.id, member.id):
            return
        try:
            await member.guild.ban(member, reason="ESN Guardian: unapproved bot", delete_message_seconds=0)
            await self._case(member.guild, member, "UNAPPROVED_BOT_BAN", f"Unapproved bot {member.id} was automatically banned.")
        except discord.HTTPException:
            await self._case(member.guild, member, "UNAPPROVED_BOT_BAN_FAILED", f"Could not ban unapproved bot {member.id}.")

    @commands.Cog.listener()
    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        gained = [p for p in DANGEROUS if getattr(after.permissions,p) and not getattr(before.permissions,p)]
        if not gained:
            return
        actor = None
        try:
            async for entry in after.guild.audit_logs(action=discord.AuditLogAction.role_update, limit=5):
                if getattr(entry.target,"id",None) == after.id:
                    actor = entry.user; break
        except discord.HTTPException:
            pass
        if actor and actor.id == after.guild.owner_id:
            return
        try:
            await after.edit(permissions=before.permissions, reason="ESN Guardian: blocked dangerous permission escalation")
            await self._case(after.guild, actor, "PERMISSION_ESCALATION_REVERTED", f"Reverted {after.name}; attempted permissions: {', '.join(gained)}")
        except discord.HTTPException:
            await self._case(after.guild, actor, "PERMISSION_ESCALATION_REVERT_FAILED", f"Could not revert {after.name}: {', '.join(gained)}")

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel) -> None:
        try:
            hooks = await channel.webhooks()
        except discord.HTTPException:
            return
        for hook in hooks:
            row = await self.bot.database.fetchone("SELECT 1 FROM guardian_approved_webhooks WHERE guild_id=? AND webhook_id=?", (channel.guild.id,hook.id))
            if row is not None:
                continue
            try:
                await hook.delete(reason="ESN Guardian: unauthorized webhook")
                await self._case(channel.guild, getattr(hook,"user",None), "UNAUTHORIZED_WEBHOOK_REMOVED", f"Removed webhook {hook.id}.")
            except discord.HTTPException:
                await self._case(channel.guild, getattr(hook,"user",None), "WEBHOOK_REMOVE_FAILED", f"Could not remove webhook {hook.id}.")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return
        if any(pattern.search(message.content or "") for pattern in SECRET_PATTERNS):
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            await self._case(message.guild, message.author, "CREDENTIAL_LEAK_BLOCKED", f"Potential credential removed from channel {message.channel.id}.")

    async def _snapshot(self, guild: discord.Guild) -> dict:
        return {
            "created_at": datetime.now(UTC).isoformat(),
            "roles":[{"id":r.id,"name":r.name,"permissions":r.permissions.value,"position":r.position} for r in guild.roles],
            "channels":[{"id":c.id,"name":c.name,"type":str(c.type),"position":c.position,"category_id":c.category_id,
                         "overwrites":{str(k.id):v._values for k,v in c.overwrites.items()}} for c in guild.channels],
        }

    @securityplus.command(name="snapshot", description="Save the current channel, role, permission, and overwrite security state.")
    @guild_only()
    @guild_owner_only()
    async def snapshot(self, interaction: discord.Interaction) -> None:
        data = await self._snapshot(interaction.guild)
        await self.bot.database.execute("INSERT INTO guardian_snapshots(guild_id,snapshot_json) VALUES(?,?) ON CONFLICT(guild_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,updated_at=CURRENT_TIMESTAMP",(interaction.guild_id,json.dumps(data)))
        await respond(interaction, f"Security snapshot saved: {len(data['roles'])} roles and {len(data['channels'])} channels.")

    @securityplus.command(name="approve-bot", description="Owner-only allowlist for a server bot.")
    @guild_only()
    @guild_owner_only()
    async def approve_bot(self, interaction: discord.Interaction, bot: discord.Member) -> None:
        if not bot.bot:
            await respond(interaction,"That member is not a bot."); return
        await self.bot.database.execute("INSERT OR REPLACE INTO guardian_approved_bots(guild_id,bot_id,approved_by_id) VALUES(?,?,?)",(interaction.guild_id,bot.id,interaction.user.id))
        await respond(interaction,f"Approved bot: {bot.mention}.")

    @securityplus.command(name="approve-webhook", description="Owner-only allowlist for an existing webhook ID.")
    @guild_only()
    @guild_owner_only()
    async def approve_webhook(self, interaction: discord.Interaction, webhook_id: str) -> None:
        try: wid=int(webhook_id)
        except ValueError:
            await respond(interaction,"Webhook ID must be numeric."); return
        await self.bot.database.execute("INSERT OR REPLACE INTO guardian_approved_webhooks(guild_id,webhook_id,approved_by_id) VALUES(?,?,?)",(interaction.guild_id,wid,interaction.user.id))
        await respond(interaction,f"Approved webhook {wid}.")

    @securityplus.command(name="panic", description="Owner-only emergency lockdown and unauthorized webhook purge.")
    @guild_only()
    @guild_owner_only()
    async def panic(self, interaction: discord.Interaction, reason: str="Emergency security lockdown") -> None:
        await interaction.response.defer(ephemeral=True)
        security = self.bot.get_cog("SecurityCog")
        if security is not None:
            await security._lockdown(interaction.guild, f"PANIC: {reason}")
        removed=0
        for channel in interaction.guild.text_channels:
            try: hooks=await channel.webhooks()
            except discord.HTTPException: continue
            for hook in hooks:
                row=await self.bot.database.fetchone("SELECT 1 FROM guardian_approved_webhooks WHERE guild_id=? AND webhook_id=?",(interaction.guild_id,hook.id))
                if row is None:
                    try: await hook.delete(reason="ESN Guardian panic mode"); removed+=1
                    except discord.HTTPException: pass
        await self._case(interaction.guild, interaction.user, "GUARDIAN_PANIC", f"{reason}; removed {removed} unauthorized webhooks.")
        await respond(interaction,f"Panic mode activated. Lockdown applied. Removed {removed} unauthorized webhooks.")

    @securityplus.command(name="audit", description="Owner security audit of dangerous roles, bots, webhooks, and Guardian permissions.")
    @guild_only()
    @guild_owner_only()
    async def audit(self, interaction: discord.Interaction) -> None:
        dangerous=[r for r in interaction.guild.roles if any(getattr(r.permissions,p) for p in DANGEROUS) and not r.is_default()]
        unknown=[m for m in interaction.guild.members if m.bot and (not self.bot.user or m.id != self.bot.user.id) and not await self._approved_bot(interaction.guild_id,m.id)]
        hooks=[]
        for ch in interaction.guild.text_channels:
            try: hooks.extend(await ch.webhooks())
            except discord.HTTPException: pass
        unapproved=[]
        for h in hooks:
            if not await self.bot.database.fetchone("SELECT 1 FROM guardian_approved_webhooks WHERE guild_id=? AND webhook_id=?",(interaction.guild_id,h.id)):
                unapproved.append(h)
        me=interaction.guild.me
        missing=[p for p in ("view_audit_log","ban_members","manage_roles","manage_channels","manage_webhooks","manage_messages") if not getattr(me.guild_permissions,p)]
        await respond(interaction, f"Security audit\nDangerous roles: {len(dangerous)}\nUnapproved bots: {len(unknown)}\nUnapproved webhooks: {len(unapproved)}\nMissing Guardian permissions: {', '.join(missing) or 'None'}")

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(HardeningCog(bot))
