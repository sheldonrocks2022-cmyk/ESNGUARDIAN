"""Free multi-server Guardian command center. Read-only commands by default."""
from __future__ import annotations
from datetime import datetime, timezone
import discord
from discord.ext import commands
from esn_guardian.luxury_ui import luxury_reply

class GuardianPublic(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.group(name="ESNG", invoke_without_command=True, case_insensitive=True)
    @commands.guild_only()
    @commands.cooldown(2, 10, commands.BucketType.user)
    async def esng(self, ctx):
        await luxury_reply(ctx, "Command Center", "Premium server security and operations. Each server keeps independent settings.",
            fields=[("◈ Operations", "`!ESNG help` • `!ESNG status` • `!ESNG uptime`", False),
                    ("◈ Diagnostics", "`!ESNG audit` • `!ESNG servers`", False),
                    ("◈ Security", "`!ESNG omega` • `!ESNG lockdown`", False),
                    ("◈ Advanced Controls", "`/ultra center` • `/guardianmax`", False)])

    @esng.command(name="help")
    async def help_cmd(self, ctx):
        await self.esng.callback(self, ctx)

    @esng.command(name="status")
    async def status(self, ctx):
        health = getattr(self.bot, "runtime_health", {})
        db = bool(health.get("database_ok"))
        await luxury_reply(ctx, "Guardian Status", "Live operational diagnostics.",
            level="success" if db else "warning",
            fields=[("Gateway", f"{round(self.bot.latency * 1000)} ms", True),
                    ("Database", "● Operational" if db else "● Check required", True),
                    ("Server", ctx.guild.name, False),
                    ("Security Controls", "`/ultra center` • `/guardianmax`", False)])

    @esng.command(name="servers")
    async def servers(self, ctx):
        await luxury_reply(ctx, "Multi-Server Operations", "● Enabled\nEach server has isolated settings. Other customers' server identities remain private.")

    @esng.command(name="audit")
    @commands.has_guild_permissions(manage_guild=True)
    async def audit(self, ctx):
        me = ctx.guild.me
        if me is None:
            return await luxury_reply(ctx, "Permission Audit", "Guardian member not found.", level="danger")
        p = me.guild_permissions
        checks = {"View Audit Log":p.view_audit_log, "Manage Roles":p.manage_roles,
                  "Manage Channels":p.manage_channels, "Kick Members":p.kick_members,
                  "Ban Members":p.ban_members, "Moderate Members":p.moderate_members}
        await luxury_reply(ctx, "Permission Audit", "This checks permissions, not full protection readiness.",
            level="success" if all(checks.values()) else "warning",
            fields=[(name, "✓ Granted" if ok else "✕ Missing", True) for name, ok in checks.items()])

    @esng.command(name="uptime")
    async def uptime(self, ctx):
        started = getattr(self.bot, "started_at", None)
        if started is None:
            return await luxury_reply(ctx, "Uptime", "Uptime unavailable.", level="warning")
        elapsed = datetime.now(timezone.utc) - started
        await luxury_reply(ctx, "Guardian Uptime", str(elapsed).split(".")[0], level="success")

    @esng.command(name="permissions")
    @commands.has_guild_permissions(manage_guild=True)
    async def permissions(self, ctx):
        await self.audit.callback(self, ctx)

    @esng.command(name="omega")
    async def omega_info(self, ctx):
        await luxury_reply(ctx, "OMEGA Operations", "Server-scoped controls and diagnostics.",
            fields=[("Read-only", "`!omega status` • `!omega scan` • `!omega report`", False),
                    ("Configuration", "`!omega policy` • `!omega alerts`", False)])

    @esng.command(name="lockdown")
    @commands.has_guild_permissions(administrator=True)
    async def lockdown(self, ctx):
        await luxury_reply(ctx, "Lockdown Safety", "This prefix command never triggers a lockdown. Use existing slash-command controls and their confirmation safeguards.", level="warning")

    @commands.Cog.listener()
    async def on_command_error(self, ctx, error):
        if ctx.command is None or not ctx.command.qualified_name.lower().startswith("esng"):
            return
        if isinstance(error, commands.MissingPermissions):
            await luxury_reply(ctx, "Access Denied", "You need server management permissions.", level="danger")
        elif isinstance(error, commands.CommandOnCooldown):
            await luxury_reply(ctx, "Cooldown Active", "Try again shortly.", level="warning")
        elif isinstance(error, commands.NoPrivateMessage):
            await luxury_reply(ctx, "Server Only", "Use this command inside a Discord server.", level="warning")

async def setup(bot):
    await bot.add_cog(GuardianPublic(bot))
