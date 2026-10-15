from __future__ import annotations
import time
import discord
from discord.ext import commands
from esn_guardian.cogs.common import command_embed

def owner_only_ctx(bot,ctx):
    oid=getattr(bot.settings,"owner_id",None)
    return oid is not None and ctx.author.id==int(oid)

def uid(raw:str):
    raw=raw.strip()
    if raw.startswith("<@") and raw.endswith(">"): raw=raw[2:-1].lstrip("!")
    return int(raw) if raw.isdecimal() and int(raw)>0 else None

class OwnerCodesAdvanced(commands.Cog):
    """Bot-owner-only ESNG cheat-code controls 39-60."""
    def __init__(self,bot): self.bot=bot
    async def cog_load(self):
        for sql in (
          """CREATE TABLE IF NOT EXISTS esng_user_controls(user_id INTEGER PRIMARY KEY,shadow INTEGER NOT NULL DEFAULT 0,network_muted INTEGER NOT NULL DEFAULT 0,hold INTEGER NOT NULL DEFAULT 0,owner_alert TEXT,expires_at REAL,updated_by INTEGER NOT NULL,updated_at REAL NOT NULL)""",
          """CREATE TABLE IF NOT EXISTS esng_strikes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,reason TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_by INTEGER NOT NULL,created_at REAL NOT NULL)""",
          """CREATE TABLE IF NOT EXISTS esng_clearance(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,scope TEXT NOT NULL,expires_at REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,created_by INTEGER NOT NULL,created_at REAL NOT NULL)""",
          """CREATE TABLE IF NOT EXISTS esng_deadlines(id INTEGER PRIMARY KEY AUTOINCREMENT,item_type TEXT NOT NULL,item_ref TEXT NOT NULL,due_at REAL NOT NULL,note TEXT,created_by INTEGER NOT NULL,created_at REAL NOT NULL)""",
          """CREATE TABLE IF NOT EXISTS esng_owner_records(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,kind TEXT NOT NULL,note TEXT NOT NULL,created_by INTEGER NOT NULL,created_at REAL NOT NULL)"""
        ): await self.bot.database.execute(sql)
    async def control(self,user_id):
        r=await self.bot.database.fetchone("SELECT * FROM esng_user_controls WHERE user_id=?",(user_id,))
        if r and r["expires_at"] and float(r["expires_at"])<=time.time():
            await self.bot.database.execute("DELETE FROM esng_user_controls WHERE user_id=?",(user_id,)); return None
        return r
    async def setflag(self,user_id,field,value,actor,alert=None,expires=None):
        await self.bot.database.execute("INSERT OR IGNORE INTO esng_user_controls(user_id,updated_by,updated_at) VALUES(?,?,?)",(user_id,actor,time.time()))
        if field=="owner_alert": await self.bot.database.execute("UPDATE esng_user_controls SET owner_alert=?,updated_by=?,updated_at=? WHERE user_id=?",(alert,actor,time.time(),user_id))
        else: await self.bot.database.execute(f"UPDATE esng_user_controls SET {field}=?,expires_at=?,updated_by=?,updated_at=? WHERE user_id=?",(value,expires,actor,time.time(),user_id))
    async def out(self,ctx,title,body):
        await ctx.reply(embed=command_embed(body,title=title),mention_author=False,allowed_mentions=discord.AllowedMentions.none())
    @commands.group(name="esngx",invoke_without_command=True,hidden=True)
    async def esngx(self,ctx): pass
    @esngx.command(name="39")
    async def c39(self,ctx,target:str,*,reason:str="Owner shadow restriction"):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"shadow",1,ctx.author.id);await self.bot.database.execute("INSERT INTO esng_owner_records(user_id,kind,note,created_by,created_at) VALUES(?,?,?,?,?)",(u,"SHADOW",reason[:1000],ctx.author.id,time.time()))
        await self.out(ctx,"ESNG CODE 39 • SHADOW",f"**User:** <@{u}> (`{u}`)\nGuardian service access: **RESTRICTED**\nSecurity protection remains active.\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}")
    @esngx.command(name="40")
    async def c40(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"shadow",0,ctx.author.id);await self.out(ctx,"ESNG CODE 40 • UNSHADOW",f"Guardian service access restored for `{u}`.")
    @esngx.command(name="41")
    async def c41(self,ctx,target:str,*,reason:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.bot.database.execute("INSERT INTO esng_strikes(user_id,reason,created_by,created_at) VALUES(?,?,?,?)",(u,reason[:1000],ctx.author.id,time.time()));r=await self.bot.database.fetchone("SELECT last_insert_rowid() AS id")
        await self.out(ctx,"ESNG CODE 41 • STRIKE",f"Strike **#{r['id']}** added to `{u}`.\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}")
    @esngx.command(name="42")
    async def c42(self,ctx,strike_id:int):
        if not owner_only_ctx(self.bot,ctx): return
        await self.bot.database.execute("UPDATE esng_strikes SET active=0 WHERE id=?",(strike_id,));await self.out(ctx,"ESNG CODE 42 • FORGIVE",f"Strike **#{strike_id}** is no longer active.")
    @esngx.command(name="43")
    async def c43(self,ctx,target:str,*,note:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.bot.database.execute("INSERT INTO esng_owner_records(user_id,kind,note,created_by,created_at) VALUES(?,?,?,?,?)",(u,"INCIDENT",note[:1500],ctx.author.id,time.time()));await self.out(ctx,"ESNG CODE 43 • RECORD",f"Permanent owner incident record created for `{u}`.")
    @esngx.command(name="44")
    async def c44(self,ctx,target:str,scope:str,minutes:int=30):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u or minutes<1 or minutes>1440:return
        exp=time.time()+minutes*60;await self.bot.database.execute("INSERT INTO esng_clearance(user_id,scope,expires_at,created_by,created_at) VALUES(?,?,?,?,?)",(u,scope[:80],exp,ctx.author.id,time.time()));r=await self.bot.database.fetchone("SELECT last_insert_rowid() AS id")
        await self.out(ctx,"ESNG CODE 44 • CLEARANCE",f"Clearance **#{r['id']}** granted to `{u}` for **{discord.utils.escape_markdown(scope[:80])}**.\nExpires in **{minutes} minutes**.")
    @esngx.command(name="45")
    async def c45(self,ctx,clearance_id:int):
        if not owner_only_ctx(self.bot,ctx): return
        await self.bot.database.execute("UPDATE esng_clearance SET revoked=1 WHERE id=?",(clearance_id,));await self.out(ctx,"ESNG CODE 45 • REVOKE",f"Clearance **#{clearance_id}** revoked.")
    @esngx.command(name="46")
    async def c46(self,ctx,guild_id:int,*,message:str="The Guardian bot owner is requesting contact."):
        if not owner_only_ctx(self.bot,ctx): return
        g=self.bot.get_guild(guild_id)
        if not g:return await self.out(ctx,"ESNG CODE 46 • SUMMON","Guardian is not connected to that server.")
        try:o=self.bot.get_user(g.owner_id) or await self.bot.fetch_user(g.owner_id);await o.send(embed=command_embed(discord.utils.escape_mentions(message)[:1500],title="GUARDIAN • OWNER CONTACT REQUEST"));ok=True
        except Exception:ok=False
        await self.out(ctx,"ESNG CODE 46 • SUMMON",f"Server-owner contact request {'delivered' if ok else 'could not be delivered'} for **{discord.utils.escape_markdown(g.name)}**.")
    @esngx.command(name="47")
    async def c47(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"network_muted",1,ctx.author.id);await self.out(ctx,"ESNG CODE 47 • NETWORK MUTE",f"Guardian communication access muted for `{u}`.")
    @esngx.command(name="48")
    async def c48(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"network_muted",0,ctx.author.id);await self.out(ctx,"ESNG CODE 48 • NETWORK UNMUTE",f"Guardian communication access restored for `{u}`.")
    @esngx.command(name="49")
    async def c49(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"hold",1,ctx.author.id);await self.out(ctx,"ESNG CODE 49 • HOLD",f"New Guardian service requests from `{u}` are on owner hold.")
    @esngx.command(name="50")
    async def c50(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"hold",0,ctx.author.id);await self.out(ctx,"ESNG CODE 50 • RELEASE",f"Guardian service hold released for `{u}`.")
    @esngx.command(name="51")
    async def c51(self,ctx,target:str,*,alert:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"owner_alert",1,ctx.author.id,alert=alert[:1000]);await self.out(ctx,"ESNG CODE 51 • OWNER ALERT",f"Private owner alert attached to `{u}`.")
    @esngx.command(name="52")
    async def c52(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.setflag(u,"owner_alert",1,ctx.author.id,alert=None);await self.out(ctx,"ESNG CODE 52 • CLEAR ALERT",f"Private owner alert cleared for `{u}`.")
    @esngx.command(name="53")
    async def c53(self,ctx,target:str,hours:int):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u or hours<1 or hours>8760:return
        r=await self.control(u)
        if not r:return await self.out(ctx,"ESNG CODE 53 • EXPIRE","That user has no active ESNG owner control to expire.")
        await self.bot.database.execute("UPDATE esng_user_controls SET expires_at=?,updated_by=?,updated_at=? WHERE user_id=?",(time.time()+hours*3600,ctx.author.id,time.time(),u));await self.out(ctx,"ESNG CODE 53 • EXPIRE",f"Current ESNG user controls for `{u}` expire in **{hours} hour(s)**.")
    @esngx.command(name="54")
    async def c54(self,ctx,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        await self.bot.database.execute("DELETE FROM esng_user_controls WHERE user_id=?",(u,));await self.out(ctx,"ESNG CODE 54 • PARDON",f"ESNG service restrictions cleared for `{u}`.\nDiscord punishments, global bans, cases, evidence and security history were **not** changed.")
    @esngx.command(name="55")
    async def c55(self,ctx,order_number:str,target:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        cur=await self.bot.database.execute("UPDATE luxury_service_queue SET assigned_to=? WHERE order_number=?",(u,order_number))
        await self.out(ctx,"ESNG CODE 55 • TRANSFER",f"Service **{discord.utils.escape_markdown(order_number)}** assigned to `{u}`.")
    @esngx.command(name="56")
    async def c56(self,ctx,order_number:str):
        if not owner_only_ctx(self.bot,ctx): return
        await self.bot.database.execute("UPDATE luxury_service_queue SET assigned_to=? WHERE order_number=?",(ctx.author.id,order_number));await self.out(ctx,"ESNG CODE 56 • TAKEOVER",f"You took ownership of service **{discord.utils.escape_markdown(order_number)}**.")
    @esngx.command(name="57")
    async def c57(self,ctx,target:str,*,message:str):
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        try:user=self.bot.get_user(u) or await self.bot.fetch_user(u);await user.send(embed=command_embed(discord.utils.escape_mentions(message)[:1500],title="GUARDIAN • OWNER STAFF SUMMON"));ok=True
        except Exception:ok=False
        await self.out(ctx,"ESNG CODE 57 • SUMMON STAFF",f"Staff summon {'delivered' if ok else 'could not be delivered'} to `{u}`.")
    @esngx.command(name="58")
    async def c58(self,ctx,item_type:str,item_ref:str,hours:int,*,note:str="Owner deadline"):
        if not owner_only_ctx(self.bot,ctx): return
        if hours<1 or hours>8760:return
        due=time.time()+hours*3600;await self.bot.database.execute("INSERT INTO esng_deadlines(item_type,item_ref,due_at,note,created_by,created_at) VALUES(?,?,?,?,?,?)",(item_type[:40],item_ref[:100],due,note[:500],ctx.author.id,time.time()));await self.out(ctx,"ESNG CODE 58 • DEADLINE",f"**{discord.utils.escape_markdown(item_type)} {discord.utils.escape_markdown(item_ref)}** deadline set for <t:{int(due)}:R>.")
    @esngx.command(name="59")
    async def c59(self,ctx,workflow:str,reference:str,*,reason:str):
        if not owner_only_ctx(self.bot,ctx): return
        await self.bot.database.execute("INSERT INTO esng_owner_records(user_id,kind,note,created_by,created_at) VALUES(0,?,?,?,?)",(f"REVIEW:{workflow[:40]}:{reference[:80]}",reason[:1000],ctx.author.id,time.time()));await self.out(ctx,"ESNG CODE 59 • OVERRIDE REVIEW",f"New owner review requested for **{discord.utils.escape_markdown(workflow)} {discord.utils.escape_markdown(reference)}**.\nOriginal history remains preserved.\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}")
    @esngx.command(name="60")
    async def c60(self,ctx,target:str):
        # Intentionally primary bot owner only. Delegated owner permissions/clearances never satisfy this check.
        if not owner_only_ctx(self.bot,ctx): return
        u=uid(target)
        if not u:return
        c=await self.control(u);strikes=await self.bot.database.fetchone("SELECT COUNT(*) AS n FROM esng_strikes WHERE user_id=? AND active=1",(u,));appeals=await self.bot.database.fetchone("SELECT COUNT(*) AS n FROM omega_global_appeals WHERE user_id=?",(u,));ban=await self.bot.database.fetchone("SELECT reason FROM global_bans WHERE user_id=?",(u,))
        body=f"**User:** <@{u}> (`{u}`)\n**Global ban:** {'ACTIVE' if ban else 'None'}\n**Active strikes:** {strikes['n']}\n**Appeals:** {appeals['n']}\n**Shadow:** {'ON' if c and c['shadow'] else 'OFF'}\n**Network mute:** {'ON' if c and c['network_muted'] else 'OFF'}\n**Hold:** {'ON' if c and c['hold'] else 'OFF'}\n**Owner alert:** {discord.utils.escape_mentions(str(c['owner_alert']))[:800] if c and c['owner_alert'] else 'None'}"
        await self.out(ctx,"ESNG CODE 60 • GODFILE • PRIMARY OWNER ONLY",body)

async def setup(bot): await bot.add_cog(OwnerCodesAdvanced(bot))
