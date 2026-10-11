"""OMEGA fleet overview and safe, versioned configuration snapshots.

This module does not restore deleted resources or automatically moderate users.
"""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
import discord
from discord.ext import commands


class OmegaOperations(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def owner(self, ctx):
        configured = getattr(self.bot.settings, "owner_id", None)
        return configured is not None and ctx.author.id == int(configured)

    @commands.group(name="fleet", invoke_without_command=True)
    @commands.dm_only()
    @commands.cooldown(1, 8, commands.BucketType.user)
    async def fleet(self, ctx):
        if not self.owner(ctx):
            return
        guilds = list(self.bot.guilds)
        failures = sum(1 for g in guilds if not g.me or
                       not (g.me.guild_permissions.view_audit_log and g.me.guild_permissions.ban_members))
        await ctx.reply(
            f"**OMEGA Fleet Command**\\nConnected servers: {len(guilds)}\\n"
            f"Servers missing audit or ban permissions: {failures}\\n"
            "Use !fleet list for individual permission checks. No settings changed.",
            mention_author=False)

    @fleet.command(name="list")
    async def fleet_list(self, ctx):
        if not self.owner(ctx):
            return
        lines = []
        for guild in sorted(self.bot.guilds, key=lambda g: g.id):
            perms = guild.me.guild_permissions if guild.me else None
            audit = bool(perms and perms.view_audit_log)
            ban = bool(perms and perms.ban_members)
            lines.append(f"{guild.name[:80]} | {guild.id} | audit={audit} ban={ban}")
        data = ("OMEGA Fleet Permission Report\\n" + "\\n".join(lines or ["No servers."])).encode()
        await ctx.reply(file=discord.File(io.BytesIO(data), filename="omega-fleet.txt"),
                        mention_author=False)

    @commands.command(name="phoenixsnapshot")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.cooldown(1, 60, commands.BucketType.guild)
    async def phoenixsnapshot(self, ctx):
        """Export a read-only configuration snapshot to the invoking admin via DM."""
        guild = ctx.guild
        data = {
            "format": "esng-phoenix-snapshot-v1",
            "guild_id": guild.id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "roles": [
                {"id": r.id, "name": r.name, "permissions": r.permissions.value,
                 "color": r.color.value, "position": r.position,
                 "hoist": r.hoist, "mentionable": r.mentionable}
                for r in guild.roles
            ],
            "channels": [
                {"id": c.id, "name": c.name, "type": str(c.type),
                 "category_id": getattr(c, "category_id", None),
                 "position": c.position,
                 "overwrites": [
                     {"target_id": t.id, "allow": ow.pair()[0].value,
                      "deny": ow.pair()[1].value}
                     for t, ow in c.overwrites.items()
                 ]}
                for c in guild.channels
            ],
        }
        payload = json.dumps(data, indent=2).encode("utf-8")
        try:
            await ctx.author.send(
                f"**Phoenix configuration snapshot** for {discord.utils.escape_mentions(guild.name)} "
                f"({guild.id}). Contains sensitive permissions; store securely. "
                "Snapshot only: no automatic restoration is implemented.",
                file=discord.File(io.BytesIO(payload), filename=f"phoenix-{guild.id}.json"),
                allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            return await ctx.reply("I couldn't DM the snapshot. Enable DMs and try again.",
                                   mention_author=False)
        await ctx.reply("Snapshot delivered privately via DM. No server configuration changed.",
                        mention_author=False)

    @commands.command(name="omegadefense")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def omegadefense(self, ctx):
        me = ctx.guild.me
        p = me.guild_permissions if me else None
        cogs = ("SecurityV7Cog", "SecurityUltraCog", "SecuritySentinelCog")
        loaded = [name for name in cogs if self.bot.get_cog(name) is not None]
        await ctx.reply(
            "**OMEGA Defense Readiness (read-only)**\\n"
            f"Audit log access: {bool(p and p.view_audit_log)}\\n"
            f"Ban permission: {bool(p and p.ban_members)}\\n"
            f"Security cogs found: {', '.join(loaded) if loaded else 'None matched'}\\n"
            "This report does not enable new enforcement or certify attack resistance.",
            mention_author=False)


async def setup(bot):
    await bot.add_cog(OmegaOperations(bot))
