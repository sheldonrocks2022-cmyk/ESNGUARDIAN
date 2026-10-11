"""Private DM-only global-ban appeals. Never publishes appeals in guild channels."""
from __future__ import annotations
import asyncio
import discord
from discord.ext import commands

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

    def is_owner(self, user_id):
        owner = getattr(self.bot.settings, "owner_id", None)
        return owner is not None and user_id == int(owner)

    @commands.command(name="appeal")
    @commands.dm_only()
    @commands.cooldown(1, 120, commands.BucketType.user)
    async def appeal(self, ctx, *, statement: str = ""):
        if not 20 <= len(statement.strip()) <= 1500:
            return await ctx.reply("DM me: `!appeal <20-1500 character explanation>`.", mention_author=False)
        if await self.bot.database.global_ban_reason(ctx.author.id) is None:
            return await ctx.reply("There is no active Guardian global ban for your account.", mention_author=False)
        async with self.lock:
            existing = await self.bot.database.fetchone(
                "SELECT id FROM omega_global_appeals WHERE user_id=? AND status='pending'",
                (ctx.author.id,))
            if existing:
                return await ctx.reply("You already have a pending appeal.", mention_author=False)
            await self.bot.database.execute(
                "INSERT INTO omega_global_appeals (user_id, statement) VALUES (?,?)",
                (ctx.author.id, statement.strip()))
            row = await self.bot.database.fetchone(
                "SELECT id FROM omega_global_appeals WHERE user_id=? ORDER BY id DESC LIMIT 1",
                (ctx.author.id,))
        await ctx.reply(f"Your private appeal #{row['id']} has been submitted for bot-owner review.", mention_author=False)
        owner_id = self.bot.settings.owner_id
        if owner_id:
            try:
                owner = self.bot.get_user(owner_id) or await self.bot.fetch_user(owner_id)
                await owner.send(f"Guardian global-ban appeal #{row['id']} from user `{ctx.author.id}`. "
                                 f"DM Guardian `!appeals` to review. No appeal text is broadcast.",
                                 allowed_mentions=discord.AllowedMentions.none())
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
            return await ctx.reply("No pending global-ban appeals.", mention_author=False)
        for row in rows:
            await ctx.author.send(f"**Appeal #{row['id']}** — User `{row['user_id']}`\n"
                                  f"{discord.utils.escape_mentions(str(row['statement']))[:1500]}\n"
                                  f"Review: `!appealreview {row['id']} approve|deny reason`",
                                  allowed_mentions=discord.AllowedMentions.none())

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
            await user.send(f"Guardian global-ban appeal #{appeal_id}: {status.replace('_',' ')}.\n"
                            f"Owner note: {discord.utils.escape_mentions(note[:1000])}",
                            allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            pass
        await ctx.reply(f"Appeal #{appeal_id}: {status}. "
                        + ("Run `/globalunban` to actually lift the ban." if status.startswith("approved") else ""),
                        mention_author=False)

async def setup(bot):
    await bot.add_cog(GlobalAppeals(bot))
