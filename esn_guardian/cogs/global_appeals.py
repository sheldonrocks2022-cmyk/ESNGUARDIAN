"""Private DM-only global-ban appeals. Never publishes appeals in guild channels."""
from __future__ import annotations
import asyncio
import discord
from discord.ext import commands

from esn_guardian.cogs.common import command_embed

class GlobalAppeals(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.lock = asyncio.Lock()

    async def cog_load(self):
        await self.bot.database.execute("""
            CREATE TABLE IF NOT EXISTS omega_global_appeals (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              statement TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              reviewed_by INTEGER,
              review_note TEXT,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              reviewed_at TEXT
            )""")
        await self.bot.database.execute("""
            CREATE TABLE IF NOT EXISTS omega_appeal_restrictions (
              user_id INTEGER PRIMARY KEY,
              blocked INTEGER NOT NULL DEFAULT 0,
              cooldown_until TEXT,
              reason TEXT,
              updated_by INTEGER NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def is_owner(self, user_id):
        owner = getattr(self.bot.settings, "owner_id", None)
        return owner is not None and user_id == int(owner)

    @commands.command(name="appeal")
    @commands.dm_only()
    @commands.cooldown(1, 120, commands.BucketType.user)
    async def appeal(self, ctx, *, statement: str = ""):
        if not 20 <= len(statement.strip()) <= 1500:
            return await ctx.reply(embed=command_embed("Submit a private explanation between **20 and 1500 characters**.\n\n`!appeal <your explanation>`", title="GUARDIAN APPEALS • SUBMISSION"), mention_author=False)
        if await self.bot.database.global_ban_reason(ctx.author.id) is None:
            return await ctx.reply(embed=command_embed("There is no active Guardian global ban for your account.", title="GUARDIAN APPEALS • NOT ELIGIBLE"), mention_author=False)
        restriction = await self.bot.database.fetchone("SELECT blocked,cooldown_until,reason FROM omega_appeal_restrictions WHERE user_id=?", (ctx.author.id,))
        if restriction and int(restriction["blocked"] or 0):
            return await ctx.reply(embed=command_embed("Your access to the Guardian appeal system has been restricted by the bot owner.\n\n**Reason:** "+discord.utils.escape_mentions(str(restriction["reason"] or "Not provided"))[:1000], title="GUARDIAN APPEALS • ACCESS RESTRICTED"), mention_author=False)
        if restriction and restriction["cooldown_until"]:
            active = await self.bot.database.fetchone("SELECT CASE WHEN datetime(?) > CURRENT_TIMESTAMP THEN 1 ELSE 0 END AS active", (restriction["cooldown_until"],))
            if active and int(active["active"]):
                return await ctx.reply(embed=command_embed(f"You cannot submit another appeal until **{restriction['cooldown_until']} UTC**.\n\n**Reason:** {discord.utils.escape_mentions(str(restriction['reason'] or 'Owner cooldown'))[:1000]}", title="GUARDIAN APPEALS • COOLDOWN"), mention_author=False)
        async with self.lock:
            existing = await self.bot.database.fetchone(
                "SELECT id FROM omega_global_appeals WHERE user_id=? AND status='pending'",
                (ctx.author.id,))
            if existing:
                return await ctx.reply(embed=command_embed("You already have an appeal waiting for bot-owner review.", title="GUARDIAN APPEALS • ALREADY PENDING"), mention_author=False)
            await self.bot.database.execute(
                "INSERT INTO omega_global_appeals (user_id, statement) VALUES (?,?)",
                (ctx.author.id, statement.strip()))
            row = await self.bot.database.fetchone(
                "SELECT id FROM omega_global_appeals WHERE user_id=? ORDER BY id DESC LIMIT 1",
                (ctx.author.id,))
        await ctx.reply(embed=command_embed(f"**Appeal:** #{row['id']}\n**Status:** Pending owner review\n**Privacy:** Private — not broadcast to servers", title="GUARDIAN APPEALS • SUBMITTED"), mention_author=False)
        owner_id = self.bot.settings.owner_id
        if owner_id:
            try:
                owner = self.bot.get_user(owner_id) or await self.bot.fetch_user(owner_id)
                await owner.send(embed=command_embed(f"**Appeal:** #{row['id']}\n**User:** {ctx.author} (`{ctx.author.id}`)\n**Status:** Pending\n\nDM Guardian with `!appeals` to review.", title="GUARDIAN APPEALS • NEW CASE"), allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:
                pass

    @commands.command(name="appeals")
    @commands.dm_only()
    async def appeals(self, ctx):
        if not self.is_owner(ctx.author.id):
            return
        rows = await self.bot.database.fetchall(
            "SELECT id,user_id,statement FROM omega_global_appeals WHERE status='pending' ORDER BY id LIMIT 10")
        if not rows:
            return await ctx.reply(embed=command_embed("There are currently no pending global-ban appeals.", title="GUARDIAN APPEALS • OWNER QUEUE"), mention_author=False)
        for row in rows:
            await ctx.author.send(embed=command_embed(f"**Appeal:** #{row['id']}\n**User:** `{row['user_id']}`\n\n**Statement**\n{discord.utils.escape_mentions(str(row['statement']))[:1500]}\n\n**Review**\n`!appealreview {row['id']} approve|deny <reason>`", title="GUARDIAN APPEALS • OWNER REVIEW"), allowed_mentions=discord.AllowedMentions.none())

    @commands.command(name="globalbanlist", aliases=["bannedusers"])
    @commands.dm_only()
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def globalbanlist(self, ctx, page: int = 1):
        """Bot-owner-only private list of globally banned accounts and Discord IDs."""
        if not self.is_owner(ctx.author.id):
            return
        page = max(1, page)
        count = await self.bot.database.fetchone("SELECT COUNT(*) AS total FROM global_bans")
        total = int(count["total"])
        rows = await self.bot.database.fetchall(
            "SELECT user_id, reason FROM global_bans ORDER BY user_id LIMIT 15 OFFSET ?",
            ((page - 1) * 15,))
        if not rows:
            return await ctx.reply(f"No global bans on page {page}. Total: {total}.", mention_author=False)
        lines = []
        for row in rows:
            uid = int(row["user_id"])
            user = self.bot.get_user(uid)
            if user is None:
                try:
                    user = await self.bot.fetch_user(uid)
                except discord.HTTPException:
                    pass
            name = discord.utils.escape_markdown(str(user)) if user else "Unknown account"
            reason = discord.utils.escape_mentions(str(row["reason"]))[:110]
            lines.append(f"**{name}** — ID: `{uid}`\nReason: {reason}")
        await ctx.reply(f"**Guardian Global Ban Registry** — page {page} / {max(1, (total + 14) // 15)} "
                        f"({total} users)\n\n" + "\n\n".join(lines),
                        mention_author=False, allowed_mentions=discord.AllowedMentions.none())

    @commands.command(name="appealreview")
    @commands.dm_only()
    async def appealreview(self, ctx, appeal_id: int, decision: str, *, note: str = ""):
        if not self.is_owner(ctx.author.id):
            return
        if decision.lower() not in ("approve", "deny") or not note.strip():
            return await ctx.reply("Use `!appealreview <id> approve|deny <reason>`.", mention_author=False)
        async with self.lock:
            row = await self.bot.database.fetchone(
                "SELECT user_id FROM omega_global_appeals WHERE id=? AND status='pending'", (appeal_id,))
            if row is None:
                return await ctx.reply("Pending appeal not found.", mention_author=False)
            target_id = int(row["user_id"])
            if decision.lower() == "approve":
                # A decision does not silently unban users across servers.
                # Owner uses the existing audited /globalunban to perform enforcement.
                status = "approved_pending_unban"
            else:
                status = "denied"
            await self.bot.database.execute(
                "UPDATE omega_global_appeals SET status=?,reviewed_by=?,review_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
                (status,ctx.author.id,note[:1000],appeal_id))
        try:
            user = self.bot.get_user(target_id) or await self.bot.fetch_user(target_id)
            await user.send(embed=command_embed(f"**Appeal:** #{appeal_id}\n**Decision:** {status.replace('_',' ').upper()}\n**Owner note:** {discord.utils.escape_mentions(note[:1000])}", title="GUARDIAN APPEALS • DECISION"), allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            pass
        await ctx.reply(embed=command_embed(f"**Appeal:** #{appeal_id}\n**Decision:** {status.replace('_',' ').upper()}\n" + ("Use `/globalunban` to perform the audited unban." if status.startswith("approved") else "Decision saved and the user was notified when possible."), title="GUARDIAN APPEALS • REVIEW COMPLETE"), mention_author=False)

async def setup(bot):
    await bot.add_cog(GlobalAppeals(bot))
