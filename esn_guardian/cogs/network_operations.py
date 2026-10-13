"""Guardian V8 Luxury batch 2: review, trust, broadcasts, alerts and contacts."""
from __future__ import annotations
import asyncio
from datetime import UTC, datetime
import discord
from discord.ext import commands

def luxury(title,description,level="info"):
    colors={"info":0xD6B46C,"success":0x35C795,"warning":0xE6A34C,"danger":0xE25B65}
    e=discord.Embed(title=title,description=description[:4096],color=colors[level],timestamp=datetime.now(UTC))
    e.set_footer(text="ESN GUARDIAN V8 LUXURY • NETWORK")
    return e

class NetworkOperations(commands.Cog):
    def __init__(self,bot):
        self.bot=bot
        self._guide_task=None

    async def cog_load(self):
        for sql in (
          """CREATE TABLE IF NOT EXISTS guardian_trust(user_id INTEGER PRIMARY KEY,substantiated INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,duplicate INTEGER NOT NULL DEFAULT 0,abuse INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
          """CREATE TABLE IF NOT EXISTS guardian_broadcasts(id INTEGER PRIMARY KEY AUTOINCREMENT,owner_id INTEGER NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL,invite TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'created',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
          """CREATE TABLE IF NOT EXISTS guardian_broadcast_delivery(broadcast_id INTEGER NOT NULL,user_id INTEGER NOT NULL,guild_id INTEGER NOT NULL,status TEXT NOT NULL,PRIMARY KEY(broadcast_id,user_id,guild_id))""",
          """CREATE TABLE IF NOT EXISTS guardian_contacts(guild_id INTEGER NOT NULL,user_id INTEGER NOT NULL,added_by INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(guild_id,user_id))""",
          """CREATE TABLE IF NOT EXISTS guardian_unban_reviews(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,requester_id INTEGER NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,reviewed_by INTEGER,reviewed_at TEXT)""",
        ): await self.bot.database.execute(sql)

    def primary(self,uid):
        oid=getattr(self.bot.settings,"owner_id",None)
        return oid is not None and int(oid)==int(uid)

    async def _owner_user(self):
        oid=getattr(self.bot.settings,"owner_id",None)
        if oid is None:return None
        try:return self.bot.get_user(int(oid)) or await self.bot.fetch_user(int(oid))
        except discord.HTTPException:return None

    async def _apply_unban(self,user_id):
        await self.bot.database.execute("DELETE FROM global_bans WHERE user_id=?",(user_id,))
        oc=self.bot.get_cog("OwnerCog")
        if oc is not None and hasattr(oc,"_global_bans"):oc._global_bans.pop(user_id,None)
        ok=failed=0
        for g in self.bot.guilds:
            try:await g.unban(discord.Object(id=user_id),reason="Guardian owner-approved network review");ok+=1
            except discord.NotFound:pass
            except (discord.Forbidden,discord.HTTPException):failed+=1
        return ok,failed

    @commands.command(name="unbanrequest")
    @commands.dm_only()
    @commands.cooldown(1,300,commands.BucketType.user)
    async def unbanrequest(self,ctx,*,reason:str):
        if await self.bot.database.global_ban_reason(ctx.author.id) is None:
            return await ctx.reply("There is no active Guardian global ban for your account.",mention_author=False)
        reason=reason.strip()
        if not 20<=len(reason)<=1500:return await ctx.reply("Use `!unbanrequest <20-1500 character reason>`.",mention_author=False)
        old=await self.bot.database.fetchone("SELECT id FROM guardian_unban_reviews WHERE user_id=? AND status='pending'",(ctx.author.id,))
        if old:return await ctx.reply(f"Review GUR-{int(old['id']):06d} is already pending.",mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_unban_reviews(user_id,requester_id,reason) VALUES(?,?,?)",(ctx.author.id,ctx.author.id,reason))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_unban_reviews WHERE user_id=? ORDER BY id DESC LIMIT 1",(ctx.author.id,))
        rid=int(row["id"]); owner=await self._owner_user()
        if owner:
            try:await owner.send(embed=luxury("GLOBAL UNBAN REVIEW",f"**Review:** `GUR-{rid:06d}`\n**User:** `{ctx.author.id}`\n**Reason:** {discord.utils.escape_mentions(reason)}","warning"))
            except discord.HTTPException:pass
        await ctx.reply(f"Guardian review `GUR-{rid:06d}` submitted.",mention_author=False)

    @commands.command(name="unbanreview")
    @commands.dm_only()
    async def unbanreview(self,ctx,review_id:int,decision:str):
        if not self.primary(ctx.author.id):return
        decision=decision.casefold()
        if decision not in {"approve","deny"}:return await ctx.reply("Use `!unbanreview <ID> approve|deny`.",mention_author=False)
        row=await self.bot.database.fetchone("SELECT * FROM guardian_unban_reviews WHERE id=? AND status='pending'",(review_id,))
        if row is None:return await ctx.reply("Pending review not found.",mention_author=False)
        status="approved" if decision=="approve" else "denied"
        await self.bot.database.execute("UPDATE guardian_unban_reviews SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(status,ctx.author.id,review_id))
        if decision=="approve":
            ok,failed=await self._apply_unban(int(row["user_id"]))
            return await ctx.reply(f"GUR-{review_id:06d} approved. Unbanned in {ok} server(s); {failed} failed.",mention_author=False)
        await ctx.reply(f"GUR-{review_id:06d} denied.",mention_author=False)

    @commands.command(name="trust")
    @commands.dm_only()
    async def trust(self,ctx,user_id:int|None=None):
        if not self.primary(ctx.author.id):return
        if user_id is None:
            return await ctx.reply(embed=luxury("GUARDIAN NETWORK TRUST","Usage: `!trust <USER_ID>`\nTrust is advisory and never auto-bans anyone."),mention_author=False)
        row=await self.bot.database.fetchone("SELECT * FROM guardian_trust WHERE user_id=?",(user_id,))
        if row is None:return await ctx.reply(embed=luxury("GUARDIAN NETWORK TRUST",f"No trust history exists for `{user_id}`."),mention_author=False)
        await ctx.reply(embed=luxury("GUARDIAN NETWORK TRUST",f"**User:** `{user_id}`\n**Substantiated:** {row['substantiated']}\n**Rejected:** {row['rejected']}\n**Duplicates:** {row['duplicate']}\n**Abuse flags:** {row['abuse']}\n\nTrust data never auto-bans anyone."),mention_author=False)

    async def _recipients(self):
        """Every connected guild owner plus administrators/manage-guild staff.

        Uses cached members first, then fetch_members when permitted so a broadcast
        is not silently limited by an incomplete member cache.
        """
        found={}
        for g in self.bot.guilds:
            owner=g.owner
            if owner is None:
                try: owner=await self.bot.fetch_user(g.owner_id)
                except discord.HTTPException: owner=None
            if owner is not None: found[(owner.id,g.id)]=owner
            members=list(g.members)
            try:
                fetched=[m async for m in g.fetch_members(limit=None)]
                if fetched: members=fetched
            except (discord.Forbidden,discord.HTTPException):
                pass
            for m in members:
                if m.bot or m.id==g.owner_id: continue
                if m.guild_permissions.administrator or m.guild_permissions.manage_guild:
                    found[(m.id,g.id)]=m
        return found

    @commands.group(name="broadcast",invoke_without_command=True)
    @commands.dm_only()
    async def broadcast(self,ctx):
        if not self.primary(ctx.author.id):return
        await ctx.reply(embed=luxury("GUARDIAN NETWORK BROADCAST","**Create** `!broadcast create <type> <message>`\n**Send** `!broadcast send <ID>`\n**Status** `!broadcast status <ID>`\n\nTypes: `normal` • `important` • `critical` • `maintenance`\nDelivery targets every connected guild owner and administrator."),mention_author=False)

    @broadcast.command(name="create")
    async def broadcast_create(self,ctx,kind:str,*,message:str):
        if not self.primary(ctx.author.id):return
        kind=kind.casefold()
        if kind not in {"normal","important","critical","maintenance"} or not 5<=len(message)<=1800:
            return await ctx.reply("Use a valid type and a 5-1800 character message.",mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_broadcasts(owner_id,kind,message) VALUES(?,?,?)",(ctx.author.id,kind,message))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_broadcasts ORDER BY id DESC LIMIT 1")
        bid=int(row["id"])
        await ctx.reply(embed=luxury("BROADCAST PREVIEW",f"**ID:** ESNG-NET-{bid:04d}\n**Type:** {kind.upper()}\n\n{discord.utils.escape_mentions(message)}\n\nSend with `!broadcast send {bid}`.","warning"),mention_author=False)

    @broadcast.command(name="send")
    async def broadcast_send(self,ctx,bid:int):
        if not self.primary(ctx.author.id):return
        row=await self.bot.database.fetchone("SELECT * FROM guardian_broadcasts WHERE id=? AND status='created'",(bid,))
        if row is None:return await ctx.reply("Unsent broadcast not found.",mention_author=False)
        await self.bot.database.execute("UPDATE guardian_broadcasts SET status='sending' WHERE id=?",(bid,))
        recipients=await self._recipients()
        for (uid,gid),user in recipients.items():
            guild=self.bot.get_guild(gid)
            e=luxury(f"GUARDIAN NETWORK • {str(row['kind']).upper()}",f"**Broadcast:** `ESNG-NET-{bid:04d}`\n**Server:** {discord.utils.escape_markdown(guild.name) if guild else gid}\n\n{discord.utils.escape_mentions(str(row['message']))}")
            status="delivered"
            try:await user.send(embed=e,allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:status="failed"
            await self.bot.database.execute("INSERT OR REPLACE INTO guardian_broadcast_delivery(broadcast_id,user_id,guild_id,status) VALUES(?,?,?,?)",(bid,uid,gid,status))
        await self.bot.database.execute("UPDATE guardian_broadcasts SET status='sent' WHERE id=?",(bid,))
        rows=await self.bot.database.fetchall("SELECT status,COUNT(*) n FROM guardian_broadcast_delivery WHERE broadcast_id=? GROUP BY status",(bid,))
        stats={str(r["status"]):int(r["n"]) for r in rows}
        await ctx.reply(embed=luxury("BROADCAST COMPLETE",f"**ID:** `ESNG-NET-{bid:04d}`\n**Guilds connected:** {len(self.bot.guilds)}\n**Delivered:** {stats.get('delivered',0)}\n**Failed:** {stats.get('failed',0)}","success"),mention_author=False)

    @broadcast.command(name="status")
    async def broadcast_status(self,ctx,bid:int):
        if not self.primary(ctx.author.id):return
        rows=await self.bot.database.fetchall("SELECT status,COUNT(*) n FROM guardian_broadcast_delivery WHERE broadcast_id=? GROUP BY status",(bid,))
        stats=", ".join(f"{r['status']}: {r['n']}" for r in rows) or "No delivery records"
        await ctx.reply(f"**ESNG-NET-{bid:04d}** • {stats}",mention_author=False)

    @commands.command(name="emergency")
    @commands.dm_only()
    async def emergency(self,ctx,severity:str|None=None,*,message:str=""):
        if not self.primary(ctx.author.id):return
        if not severity or not message.strip():
            return await ctx.reply(embed=luxury("GUARDIAN EMERGENCY ALERT","Usage: `!emergency <severity> <message>`\nTargets every connected guild owner and administrator. Nothing is sent until both values are supplied.","warning"),mention_author=False)
        severity=severity.upper()[:20]
        recipients=await self._recipients(); delivered=0
        for (uid,gid),user in recipients.items():
            guild=self.bot.get_guild(gid)
            try:
                await user.send(embed=luxury("🚨 GUARDIAN NETWORK EMERGENCY",f"**Severity:** {severity}\n**Server:** {guild.name if guild else gid}\n\n{discord.utils.escape_mentions(message)[:1800]}","danger"));delivered+=1
            except discord.HTTPException:pass
        await ctx.reply(f"Emergency alert delivered to {delivered} unique network recipient(s).",mention_author=False)

    @commands.group(name="gcontact",invoke_without_command=True)
    async def gcontact(self,ctx):
        await ctx.reply(embed=luxury("AUTHORIZED GUARDIAN CONTACTS","`!gcontact add <USER_ID>`\n`!gcontact remove <USER_ID>`\n`!gcontact list`\n\nRun contact management inside the server whose contact list you are managing."),mention_author=False)

    def contact_manager(self,ctx):
        return ctx.guild is not None and (ctx.author.id==ctx.guild.owner_id or (isinstance(ctx.author,discord.Member) and (ctx.author.guild_permissions.administrator or ctx.author.guild_permissions.manage_guild)) or self.primary(ctx.author.id))

    @gcontact.command(name="add")
    @commands.guild_only()
    async def contact_add(self,ctx,user_id:int):
        if not self.contact_manager(ctx):return
        try:user=self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
        except discord.HTTPException:return await ctx.reply("That Discord user could not be verified.",mention_author=False)
        await self.bot.database.execute("INSERT OR REPLACE INTO guardian_contacts(guild_id,user_id,added_by) VALUES(?,?,?)",(ctx.guild.id,user_id,ctx.author.id))
        await ctx.reply(f"Guardian contact added: {user} (`{user_id}`).",mention_author=False)

    @gcontact.command(name="remove")
    @commands.guild_only()
    async def contact_remove(self,ctx,user_id:int):
        if not self.contact_manager(ctx):return
        await self.bot.database.execute("DELETE FROM guardian_contacts WHERE guild_id=? AND user_id=?",(ctx.guild.id,user_id))
        await ctx.reply(f"Guardian contact removed: `{user_id}`.",mention_author=False)

    @gcontact.command(name="list")
    @commands.guild_only()
    async def contact_list(self,ctx):
        if not self.contact_manager(ctx):return
        rows=await self.bot.database.fetchall("SELECT user_id,created_at FROM guardian_contacts WHERE guild_id=? ORDER BY created_at",(ctx.guild.id,))
        body="\n".join(f"• `{r['user_id']}`" for r in rows) or "No registered contacts."
        await ctx.reply(f"**Guardian Authorized Contacts**\n{body}",mention_author=False)

async def setup(bot):await bot.add_cog(NetworkOperations(bot))
