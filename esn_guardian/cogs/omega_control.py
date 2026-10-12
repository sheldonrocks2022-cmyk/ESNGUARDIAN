"""Isolated per-guild Guardian configuration and read-only incident readiness."""
from __future__ import annotations
import json
from pathlib import Path
from discord.ext import commands
from esn_guardian.luxury_ui import luxury_reply

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
        await luxury_reply(ctx, "OMEGA Control Center", "Advisory security operations. Configuration is isolated to this server.",
            fields=[("Monitoring", "`!omega status` • `!omega scan` • `!omega report`", False),
                    ("Preferences", "`!omega policy` • `!omega alerts`", False)])

    @omega.command(name="status")
    async def status(self, ctx):
        policy = self.settings(ctx.guild.id).get("policy", "balanced")
        await luxury_reply(ctx, "OMEGA Status", "Existing Guardian protection remains in charge. OMEGA policy is advisory until integrated with detection engines.",
            fields=[("Server", ctx.guild.name, True), ("Advisory Policy", policy.title(), True)])

    @omega.command(name="policy")
    @commands.has_guild_permissions(manage_guild=True)
    async def policy(self, ctx, mode: str = ""):
        if not mode:
            policy = self.settings(ctx.guild.id).get("policy", "balanced")
            return await luxury_reply(ctx, "Advisory Policy", policy.title())
        if mode.lower() not in ("strict", "balanced"):
            return await luxury_reply(ctx, "Invalid Policy", "Choose `strict` or `balanced`.", level="warning")
        self.config.setdefault(str(ctx.guild.id), {})["policy"] = mode.lower()
        self.save()
        await luxury_reply(ctx, "Policy Saved", "Advisory policy updated. Existing security thresholds are unchanged.", level="success",
            fields=[("Selected Policy", mode.title(), True)])

    @omega.command(name="alerts")
    @commands.has_guild_permissions(manage_guild=True)
    async def alerts(self, ctx, enabled: str = ""):
        if not enabled:
            state = self.settings(ctx.guild.id).get("alerts", True)
            return await luxury_reply(ctx, "OMEGA Advisory Alerts", "Enabled" if state else "Disabled")
        if enabled.lower() not in ("on", "off"):
            return await luxury_reply(ctx, "Invalid Setting", "Use `!omega alerts on` or `!omega alerts off`.", level="warning")
        self.config.setdefault(str(ctx.guild.id), {})["alerts"] = enabled.lower() == "on"
        self.save()
        await luxury_reply(ctx, "Alert Preference Saved", "Existing Guardian alerts remain unchanged.", level="success")

    @omega.command(name="report")
    @commands.has_guild_permissions(manage_guild=True)
    async def report(self, ctx):
        health = getattr(self.bot, "runtime_health", {})
        me = ctx.guild.me
        audit_ok = bool(me and me.guild_permissions.view_audit_log)
        db_ok = bool(health.get("database_ok", False))
        policy = self.settings(ctx.guild.id).get("policy", "balanced")
        await luxury_reply(ctx, "OMEGA Readiness Report", "Read-only report. Existing Guardian engines remain active.",
            level="success" if db_ok and audit_ok else "warning",
            fields=[("Database", "✓ OK" if db_ok else "✕ CHECK", True),
                    ("Audit Log", "✓ Available" if audit_ok else "✕ Missing", True),
                    ("Advisory Policy", policy.title(), False)])

    @omega.command(name="scan")
    @commands.has_guild_permissions(manage_guild=True)
    async def scan(self, ctx):
        me = ctx.guild.me
        if not me:
            return await luxury_reply(ctx, "OMEGA Scan", "Guardian member record unavailable.", level="warning")
        dangerous = [role for role in ctx.guild.roles if role.permissions.administrator and not role.is_default()]
        manageable = sum(1 for role in dangerous if role < me.top_role)
        await luxury_reply(ctx, "OMEGA Security Scan", "Read-only scan completed. No roles or permissions were changed.",
            fields=[("Administrator Roles", str(len(dangerous)), True),
                    ("Below Guardian's Top Role", str(manageable), True)])

async def setup(bot):
    await bot.add_cog(OmegaControl(bot))
