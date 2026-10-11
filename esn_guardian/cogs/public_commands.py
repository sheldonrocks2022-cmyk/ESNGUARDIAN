"""Free multi-server Guardian command center. Read-only commands by default."""
from __future__ import annotations
import discord
from discord.ext import commands

class GuardianPublic(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.group(name="ESNG", invoke_without_command=True, case_insensitive=True)
    @commands.guild_only()
    @commands.cooldown(2, 10, commands.BucketType.user)
    async def esng(self, ctx: commands.Context):
        """Public Guardian prefix command directory."""
        await ctx.reply("**ESN Guardian | Free Command Center**\n"
            "\`!ESNG help\` • \`!ESNG status\` • \`!ESNG audit\` • \`!ESNG servers\` • \`!ESNG lockdown\`\n"
            "Each Discord server has separate settings. Slash-command security controls remain available.",
            mention_author=False)

    @esng.command(name="help")
    async def help_cmd(self, ctx: commands.Context):
        await ctx.invoke(self.esng)

    @esng.command(name="status")
    async def status(self, ctx: commands.Context):
        health = getattr(self.bot, "runtime_health", {})
        db = "OK" if health.get("database_ok") else "CHECK"
        latency = round(self.bot.latency * 1000)
        await ctx.reply(f"**Guardian Status** | Gateway: {latency} ms | Database: {db} | Server: {ctx.guild.name}\n"
                        "Security controls: use \`/ultra center\` or \`/guardianmax\`.", mention_author=False)

    @esng.command(name="servers")
    async def servers(self, ctx: commands.Context):
        # Never disclose other customers' server identities or names.
        await ctx.reply("**Multi-server mode:** enabled. Each guild is configured independently. "
                        "Other customers' server details are private.", mention_author=False)

    @esng.command(name="audit")
    @commands.has_guild_permissions(manage_guild=True)
    async def audit(self, ctx: commands.Context):
        me = ctx.guild.me
        if me is None:
            return await ctx.reply("Guardian member not found.", mention_author=False)
        p = me.guild_permissions
        checks = {"View audit log":p.view_audit_log, "Manage roles":p.manage_roles,
                  "Manage channels":p.manage_channels, "Kick members":p.kick_members,
                  "Ban members":p.ban_members, "Moderate members":p.moderate_members}
        summary = "\n".join(f"{'PASS' if ok else 'MISSING'} — {name}" for name,ok in checks.items())
        await ctx.reply(f"**Guardian Permission Audit**\n{summary}\n"
                        "This checks permissions, not full protection readiness.", mention_author=False)

    @esng.command(name="lockdown")
    @commands.has_guild_permissions(administrator=True)
    async def lockdown(self, ctx: commands.Context):
        await ctx.reply("**Safety first:** lockdown is not executed by this prefix command. "
                        "Use the existing Guardian slash-command controls with their confirmation safeguards.",
                        mention_author=False)

    @commands.Cog.listener()
    async def on_command_error(self, ctx: commands.Context, error: commands.CommandError):
        if ctx.command is None or not ctx.command.qualified_name.lower().startswith("esng"):
            return
        if isinstance(error, commands.MissingPermissions):
            await ctx.reply("You need server management permissions for that Guardian command.", mention_author=False)
        elif isinstance(error, commands.CommandOnCooldown):
            await ctx.reply("Guardian command cooldown is active. Try again shortly.", mention_author=False)
        elif isinstance(error, commands.NoPrivateMessage):
            await ctx.reply("Use this command inside a Discord server.", mention_author=False)

async def setup(bot: commands.Bot):
    await bot.add_cog(GuardianPublic(bot))
