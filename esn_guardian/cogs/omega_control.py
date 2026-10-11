"""Isolated per-guild Guardian configuration and read-only incident readiness."""
from __future__ import annotations
import json
from pathlib import Path
import discord
from discord.ext import commands

class OmegaControl(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.path = Path("data/omega_guild_settings.json")
        self.config = {}
        try:
            self.config = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(self.config, dict):
                self.config = {}
        except (OSError, ValueError):
            self.config = {}

    def settings(self, guild_id):
        return self.config.get(str(guild_id), {})

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    @commands.group(name="omega", invoke_without_command=True)
    @commands.guild_only()
    @commands.cooldown(2, 10, commands.BucketType.user)
    async def omega(self, ctx):
        await ctx.reply("**OMEGA Control**: `!omega status`, `!omega policy`, "
                        "`!omega policy strict|balanced`, `!omega scan`. "
                        "Configuration is isolated to this server.", mention_author=False)

    @omega.command(name="status")
    async def status(self, ctx):
        policy = self.settings(ctx.guild.id).get("policy", "balanced")
        await ctx.reply(f"**OMEGA** | Server: {ctx.guild.name} | Policy: {policy}\n"
                        "Existing Guardian protection remains in charge. "
                        "Policy is advisory until explicitly integrated with detection engines.", mention_author=False)

    @omega.command(name="policy")
    @commands.has_guild_permissions(manage_guild=True)
    async def policy(self, ctx, mode: str = ""):
        if not mode:
            return await ctx.reply("Policy: " + self.settings(ctx.guild.id).get("policy", "balanced"), mention_author=False)
        if mode.lower() not in ("strict", "balanced"):
            return await ctx.reply("Choose strict or balanced.", mention_author=False)
        guild_config = self.config.setdefault(str(ctx.guild.id), {})
        guild_config["policy"] = mode.lower()
        self.save()
        await ctx.reply("Saved advisory OMEGA policy for this server. Existing security thresholds are unchanged.",
                        mention_author=False)

    @omega.command(name="alerts")
    @commands.has_guild_permissions(manage_guild=True)
    async def alerts(self, ctx, enabled: str = ""):
        """Per-server preference for future OMEGA advisory notifications."""
        if not enabled:
            state = self.settings(ctx.guild.id).get("alerts", True)
            return await ctx.reply(f"OMEGA advisory alerts preference: {'on' if state else 'off'}", mention_author=False)
        if enabled.lower() not in ("on", "off"):
            return await ctx.reply("Use !omega alerts on or !omega alerts off.", mention_author=False)
        self.config.setdefault(str(ctx.guild.id), {})["alerts"] = enabled.lower() == "on"
        self.save()
        await ctx.reply("Saved advisory alert preference. Existing Guardian alerts are unchanged.", mention_author=False)

    @omega.command(name="report")
    @commands.has_guild_permissions(manage_guild=True)
    async def report(self, ctx):
        """Private guild-scoped readiness summary; never reveal other guilds."""
        health = getattr(self.bot, "runtime_health", {})
        me = ctx.guild.me
        audit_ok = bool(me and me.guild_permissions.view_audit_log)
        db_ok = bool(health.get("database_ok", False))
        policy = self.settings(ctx.guild.id).get("policy", "balanced")
        await ctx.reply(f"**OMEGA Readiness — {ctx.guild.name}**\\n"
                        f"Database: {'OK' if db_ok else 'CHECK'}\\n"
                        f"Audit log access: {'YES' if audit_ok else 'NO'}\\n"
                        f"Advisory policy: {policy}\\n"
                        "Read-only report. Existing Guardian engines remain active.", mention_author=False)

    @omega.command(name="scan")
    @commands.has_guild_permissions(manage_guild=True)
    async def scan(self, ctx):
        me = ctx.guild.me
        if not me:
            return await ctx.reply("Guardian's member record is unavailable.", mention_author=False)
        dangerous = [role for role in ctx.guild.roles if role.permissions.administrator and not role.is_default()]
        manageable = sum(1 for role in dangerous if role < me.top_role)
        await ctx.reply(f"**Read-only OMEGA scan**\nAdministrator roles: {len(dangerous)}\n"
                        f"Below Guardian's highest role: {manageable}\n"
                        "No roles or permissions were changed.", mention_author=False)

async def setup(bot):
    await bot.add_cog(OmegaControl(bot))
