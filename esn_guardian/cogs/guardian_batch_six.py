from __future__ import annotations
import discord
from discord.ext import commands
from esn_guardian.owner_access import allowed

class GuardianBatchSix(commands.Cog):
    def __init__(self,bot): self.bot=bot
    async def cog_load(self):
        for sql in (
          "CREATE TABLE IF NOT EXISTS guardian_server_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,source_guild_id INTEGER NOT NULL,target_guild_id INTEGER NOT NULL,sender_id INTEGER NOT NULL,severity TEXT NOT NULL,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_contact_subscriptions(user_id INTEGER NOT NULL,guild_id INTEGER NOT NULL,topic TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(user_id,guild_id,topic))",
          "CREATE TABLE IF NOT EXISTS guardian_case_labels(case_id INTEGER NOT NULL,label TEXT NOT NULL,added_by INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(case_id,label))",
          "CREATE TABLE IF NOT EXISTS guardian_case_links(parent_case_id INTEGER NOT NULL,child_case_id INTEGER NOT NULL,linked_by INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(parent_case_id,child_case_id))",
          "CREATE TABLE IF NOT EXISTS guardian_server_enrollment(guild_id INTEGER PRIMARY KEY,enrolled_by INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'active',enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_case_watchlist(watcher_id INTEGER NOT NULL,case_id INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(watcher_id,case_id))",
        ): await self.bot.database.execute(sql)

    @commands.group(name="serveralert",invoke_without_command=True)
    @commands.dm_only()
    async def serveralert(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"): return
        await ctx.reply("Use send <SOURCE_ID> <TARGET_ID> <severity> <message>, list, or close <ID>.",mention_author=False)

    @serveralert.command(name="send")
    async def alert_send(self,ctx,source_id:int,target_id:int,severity:str,*,message:str):
        if not await allowed(self.bot,ctx.author.id,"communications"): return
        severity=severity.casefold()
        if severity not in {"info","important","critical"}: return await ctx.reply("Severity: info, important, or critical.",mention_author=False)
        if not 1<=len(message)<=1200: return await ctx.reply("Message must be 1-1200 characters.",mention_author=False)
        source,target=self.bot.get_guild(source_id),self.bot.get_guild(target_id)
        if source is None or target is None: return await ctx.reply("Guardian must be in both servers.",mention_author=False)
        enrollment=await self.bot.database.fetchall("SELECT guild_id FROM guardian_server_enrollment WHERE guild_id IN (?,?) AND status='active'",(source_id,target_id))
        if {int(row["guild_id"]) for row in enrollment}!={source_id,target_id}: return await ctx.reply("Both servers must opt in using !networkenroll join before network alerts can be sent.",mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_server_alerts(source_guild_id,target_guild_id,sender_id,severity,message) VALUES(?,?,?,?,?)",(source_id,target_id,ctx.author.id,severity,message))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_server_alerts ORDER BY id DESC LIMIT 1"); aid=int(row["id"])
        if target.owner:
            e=discord.Embed(title="Guardian Network Alert - "+severity.upper(),description=discord.utils.escape_mentions(message),color=0xE25B65 if severity=="critical" else 0xE6A34C)
            e.add_field(name="FROM",value=source.name+"\n"+str(source.id),inline=False);e.add_field(name="ALERT",value="GNA-%06d"%aid);e.set_footer(text="ESN GUARDIAN - NETWORK COORDINATION")
            if target.icon:e.set_thumbnail(url=target.icon.url)
            try: await target.owner.send(embed=e)
            except discord.HTTPException: pass
        await ctx.reply("GNA-%06d recorded and delivery attempted."%aid,mention_author=False)

    @serveralert.command(name="list")
    async def alert_list(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"): return
        rows=await self.bot.database.fetchall("SELECT id,source_guild_id,target_guild_id,severity,status FROM guardian_server_alerts ORDER BY id DESC LIMIT 15")
        await ctx.reply("\n".join("GNA-%06d | %s | %s | %s -> %s"%(r["id"],r["severity"],r["status"],r["source_guild_id"],r["target_guild_id"]) for r in rows) or "No network alerts.",mention_author=False)

    @serveralert.command(name="close")
    async def alert_close(self,ctx,alert_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"): return
        await self.bot.database.execute("UPDATE guardian_server_alerts SET status='closed' WHERE id=?",(alert_id,));await ctx.reply("GNA-%06d closed."%alert_id,mention_author=False)

    @commands.group(name="contactsub",invoke_without_command=True)
    @commands.dm_only()
    async def contactsub(self,ctx): await ctx.reply("Use add <SERVER_ID> <topic>, remove <SERVER_ID> <topic>, or list.",mention_author=False)

    @contactsub.command(name="add")
    async def sub_add(self,ctx,guild_id:int,*,topic:str):
        rows=await self.bot.database.fetchall("SELECT guild_id FROM guardian_contacts WHERE user_id=?",(ctx.author.id,))
        if guild_id not in {int(r["guild_id"]) for r in rows}: return await ctx.reply("You must be an authorized contact for that server.",mention_author=False)
        topic=topic.casefold().strip()[:40]
        if not topic:return
        await self.bot.database.execute("INSERT INTO guardian_contact_subscriptions(user_id,guild_id,topic,enabled) VALUES(?,?,?,1) ON CONFLICT(user_id,guild_id,topic) DO UPDATE SET enabled=1",(ctx.author.id,guild_id,topic));await ctx.reply("Subscription added.",mention_author=False)

    @contactsub.command(name="remove")
    async def sub_remove(self,ctx,guild_id:int,*,topic:str):
        await self.bot.database.execute("DELETE FROM guardian_contact_subscriptions WHERE user_id=? AND guild_id=? AND topic=?",(ctx.author.id,guild_id,topic.casefold().strip()[:40]));await ctx.reply("Subscription removed.",mention_author=False)

    @contactsub.command(name="list")
    async def sub_list(self,ctx):
        rows=await self.bot.database.fetchall("SELECT guild_id,topic FROM guardian_contact_subscriptions WHERE user_id=? AND enabled=1 ORDER BY guild_id,topic",(ctx.author.id,))
        await ctx.reply("\n".join(str(r["guild_id"])+" - "+r["topic"] for r in rows) or "No subscriptions.",mention_author=False)

    @commands.group(name="caselabel",invoke_without_command=True)
    @commands.dm_only()
    async def caselabel(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        await ctx.reply("Use add <CASE_ID> <label>, remove <CASE_ID> <label>, or list <CASE_ID>.",mention_author=False)

    @caselabel.command(name="add")
    async def label_add(self,ctx,case_id:int,*,label:str):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        if await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE id=?",(case_id,)) is None:return await ctx.reply("Case not found.",mention_author=False)
        label=label.casefold().strip()[:40]
        if not label:return
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_case_labels(case_id,label,added_by) VALUES(?,?,?)",(case_id,label,ctx.author.id));await ctx.reply("Label added to GNC-%06d."%case_id,mention_author=False)

    @caselabel.command(name="remove")
    async def label_remove(self,ctx,case_id:int,*,label:str):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        await self.bot.database.execute("DELETE FROM guardian_case_labels WHERE case_id=? AND label=?",(case_id,label.casefold().strip()[:40]));await ctx.reply("Label removed.",mention_author=False)

    @caselabel.command(name="list")
    async def label_list(self,ctx,case_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        rows=await self.bot.database.fetchall("SELECT label FROM guardian_case_labels WHERE case_id=? ORDER BY label",(case_id,));await ctx.reply(", ".join(r["label"] for r in rows) or "No labels.",mention_author=False)

    @commands.group(name="caselink",invoke_without_command=True)
    @commands.dm_only()
    async def caselink(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        await ctx.reply("Use add <CASE_ID> <RELATED_ID>, remove <CASE_ID> <RELATED_ID>, or list <CASE_ID>.",mention_author=False)

    @caselink.command(name="add")
    async def link_add(self,ctx,case_id:int,related_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        if case_id==related_id:return await ctx.reply("A case cannot link to itself.",mention_author=False)
        rows=await self.bot.database.fetchall("SELECT id FROM guardian_network_cases WHERE id IN (?,?)",(case_id,related_id))
        if len(rows)!=2:return await ctx.reply("Both cases must exist.",mention_author=False)
        a,b=sorted((case_id,related_id));await self.bot.database.execute("INSERT OR IGNORE INTO guardian_case_links(parent_case_id,child_case_id,linked_by) VALUES(?,?,?)",(a,b,ctx.author.id));await ctx.reply("Cases linked.",mention_author=False)

    @caselink.command(name="remove")
    async def link_remove(self,ctx,case_id:int,related_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        a,b=sorted((case_id,related_id));await self.bot.database.execute("DELETE FROM guardian_case_links WHERE parent_case_id=? AND child_case_id=?",(a,b));await ctx.reply("Case link removed.",mention_author=False)

    @caselink.command(name="list")
    async def link_list(self,ctx,case_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        rows=await self.bot.database.fetchall("SELECT parent_case_id,child_case_id FROM guardian_case_links WHERE parent_case_id=? OR child_case_id=?",(case_id,case_id))
        ids=[int(r["child_case_id"]) if int(r["parent_case_id"])==case_id else int(r["parent_case_id"]) for r in rows];await ctx.reply(", ".join("GNC-%06d"%x for x in ids) or "No linked cases.",mention_author=False)

    async def can_manage(self,ctx):
        return bool(ctx.guild and (ctx.author.id==ctx.guild.owner_id or ctx.author.guild_permissions.manage_guild or await allowed(self.bot,ctx.author.id,"communications")))

    @commands.group(name="networkenroll",invoke_without_command=True)
    @commands.guild_only()
    async def networkenroll(self,ctx): await ctx.reply("Use join, leave, or status.",mention_author=False)

    @networkenroll.command(name="join")
    async def enroll_join(self,ctx):
        if not await self.can_manage(ctx):return
        await self.bot.database.execute("INSERT INTO guardian_server_enrollment(guild_id,enrolled_by,status) VALUES(?,?,'active') ON CONFLICT(guild_id) DO UPDATE SET enrolled_by=excluded.enrolled_by,status='active'",(ctx.guild.id,ctx.author.id));await ctx.reply("Server enrolled in Guardian Network coordination.",mention_author=False)

    @networkenroll.command(name="leave")
    async def enroll_leave(self,ctx):
        if not await self.can_manage(ctx):return
        await self.bot.database.execute("UPDATE guardian_server_enrollment SET status='inactive' WHERE guild_id=?",(ctx.guild.id,));await ctx.reply("Server left Guardian Network coordination.",mention_author=False)

    @networkenroll.command(name="status")
    async def enroll_status(self,ctx):
        row=await self.bot.database.fetchone("SELECT status,enrolled_at FROM guardian_server_enrollment WHERE guild_id=?",(ctx.guild.id,));await ctx.reply(("Network enrollment: "+row["status"]+" since "+row["enrolled_at"]) if row else "Network enrollment: not enrolled.",mention_author=False)

    @commands.group(name="casewatch",invoke_without_command=True)
    @commands.dm_only()
    async def casewatch(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        await ctx.reply("Use add <CASE_ID>, remove <CASE_ID>, or list.",mention_author=False)

    @casewatch.command(name="add")
    async def watch_add(self,ctx,case_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"): return
        if await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE id=?",(case_id,)) is None:return await ctx.reply("Case not found.",mention_author=False)
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_case_watchlist(watcher_id,case_id) VALUES(?,?)",(ctx.author.id,case_id));await ctx.reply("Watching GNC-%06d."%case_id,mention_author=False)

    @casewatch.command(name="remove")
    async def watch_remove(self,ctx,case_id:int):
        await self.bot.database.execute("DELETE FROM guardian_case_watchlist WHERE watcher_id=? AND case_id=?",(ctx.author.id,case_id));await ctx.reply("Watch removed.",mention_author=False)

    @casewatch.command(name="list")
    async def watch_list(self,ctx):
        rows=await self.bot.database.fetchall("SELECT w.case_id,c.status,c.reported_user_id FROM guardian_case_watchlist w JOIN guardian_network_cases c ON c.id=w.case_id WHERE w.watcher_id=? ORDER BY w.case_id DESC",(ctx.author.id,))
        await ctx.reply("\n".join("GNC-%06d | %s | target %s"%(r["case_id"],r["status"],r["reported_user_id"]) for r in rows) or "No watched cases.",mention_author=False)

async def setup(bot): await bot.add_cog(GuardianBatchSix(bot))
