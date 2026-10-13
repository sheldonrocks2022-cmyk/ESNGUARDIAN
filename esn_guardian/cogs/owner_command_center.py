"""Bot-owner-only ESNG command center and fleet diagnostics."""
from __future__ import annotations
import io
import discord
from discord.ext import commands
from esn_guardian.cogs.network_operations import luxury

class OwnerCommandCenter(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def _owner(self, user_id: int) -> bool:
        configured = getattr(self.bot.settings, "owner_id", None)
        return configured is not None and int(configured) == int(user_id)

    @commands.group(name="ownercenter", aliases=["esngowner"], invoke_without_command=True)
    @commands.dm_only()
    async def ownercenter(self, ctx):
        if not self._owner(ctx.author.id):
            return
        health = getattr(self.bot, "runtime_health", {})
        await ctx.reply(embed=luxury("OWNER COMMAND CENTER",f"**Servers:** {len(self.bot.guilds)}\n**Gateway:** {round(self.bot.latency * 1000)} ms\n**Database:** {'Operational' if health.get('database_ok', True) else 'Check required'}\n\n`!ownercenter fleet`\n`!ownercenter server <SERVER_ID>`\n`!ownercenter health`"),mention_author=False)

    @ownercenter.command(name="health")
    async def health(self, ctx):
        if not self._owner(ctx.author.id):
            return
        h = getattr(self.bot, "runtime_health", {})
        await ctx.reply(embed=luxury("ESNG FLEET HEALTH",f"**Gateway:** {h.get('gateway_latency_ms', round(self.bot.latency*1000,1))} ms\n**Event loop:** {h.get('event_loop_lag_ms', 'unknown')} ms\n**Database:** {'OK' if h.get('database_ok', True) else 'FAILED'}\n**Guilds:** {len(self.bot.guilds)}","success" if h.get("database_ok", True) else "danger"),mention_author=False)

    @ownercenter.command(name="fleet")
    async def fleet(self, ctx):
        if not self._owner(ctx.author.id):
            return
        lines=[]
        for g in sorted(self.bot.guilds, key=lambda x: x.name.casefold()):
            p=g.me.guild_permissions if g.me else None
            lines.append(f"{g.name} | {g.id} | members={g.member_count or 0} | audit={bool(p and p.view_audit_log)} | ban={bool(p and p.ban_members)}")
        payload=("\n".join(lines) or "No connected servers.").encode("utf-8")
        await ctx.reply(embed=luxury("GUARDIAN FLEET EXPORT",f"**Servers:** {len(self.bot.guilds)}\nFull fleet diagnostics attached."),file=discord.File(io.BytesIO(payload), filename="esng-fleet.txt"), mention_author=False)

    @ownercenter.command(name="server")
    async def server(self, ctx, server_id: int):
        if not self._owner(ctx.author.id):
            return
        g=self.bot.get_guild(server_id)
        if g is None:
            return await ctx.reply(embed=luxury("SERVER NOT FOUND","Guardian is not connected to that server.","warning"), mention_author=False)
        p=g.me.guild_permissions if g.me else None
        await ctx.reply(embed=luxury("GUARDIAN SERVER DIAGNOSTICS",f"**Server:** {discord.utils.escape_markdown(g.name)} (`{g.id}`)\n**Owner:** `{g.owner_id}`\n**Members:** {g.member_count or 0}\n**Audit log:** {bool(p and p.view_audit_log)}\n**Ban members:** {bool(p and p.ban_members)}\n**Manage roles:** {bool(p and p.manage_roles)}\n**Manage channels:** {bool(p and p.manage_channels)}"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

async def setup(bot):
    await bot.add_cog(OwnerCommandCenter(bot))
