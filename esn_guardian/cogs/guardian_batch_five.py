"""Guardian V8 Luxury batch 5: case intelligence and network coordination."""
from __future__ import annotations
from datetime import UTC,datetime
import hashlib
import discord
from discord.ext import commands
from esn_guardian.owner_access import allowed
from esn_guardian.cogs.network_operations import luxury

def esc(value): return discord.utils.escape_mentions(str(value))

class GuardianBatchFive(commands.Cog):
    def __init__(self,bot): self.bot=bot
    async def cog_load(self):
        for sql in (
          "CREATE TABLE IF NOT EXISTS guardian_case_notes(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id INTEGER NOT NULL,author_id INTEGER NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_case_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id INTEGER NOT NULL,submitter_id INTEGER NOT NULL,evidence TEXT NOT NULL,evidence_hash TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_assistance(id INTEGER PRIMARY KEY AUTOINCREMENT,guild_id INTEGER NOT NULL,requester_id INTEGER NOT NULL,subject TEXT NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_incident_rooms(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created_by INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        ): await self.bot.database.execute(sql)

    @commands.group(name="caseintel",invoke_without_command=True)
    @commands.dm_only()
    async def caseintel(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        await ctx.reply(embed=luxury("GUARDIAN CASE INTELLIGENCE","Use `!caseintel timeline`, `note`, `evidence`, or `duplicates` with a case ID."),mention_author=False)

    @caseintel.command(name="timeline")
    async def timeline(self,ctx,case_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        row=await self.bot.database.fetchone("SELECT * FROM guardian_network_cases WHERE id=?",(case_id,))
        if row is None:return await ctx.reply(embed=luxury("GUARDIAN CASE NOT FOUND","Guardian case not found.","warning"),mention_author=False)
        notes=await self.bot.database.fetchall("SELECT author_id,note,created_at FROM guardian_case_notes WHERE case_id=? ORDER BY id",(case_id,))
        evidence=await self.bot.database.fetchall("SELECT submitter_id,evidence_hash,created_at FROM guardian_case_evidence WHERE case_id=? ORDER BY id",(case_id,))
        body=[f"GNC-{case_id:06d} | {row['status']} | target {row['reported_user_id']} | opened {row['created_at']}"]
        body += [f"NOTE {n['created_at']} by {n['author_id']}: {str(n['note'])[:200]}" for n in notes]
        body += [f"EVIDENCE {e['created_at']} by {e['submitter_id']} hash {str(e['evidence_hash'])[:12]}" for e in evidence]
        await ctx.reply(embed=luxury("GUARDIAN CASE TIMELINE","\n".join(body)[:3900]),mention_author=False)

    @caseintel.command(name="note")
    async def note(self,ctx,case_id:int,*,note:str):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        if not 1<=len(note)<=1500:return await ctx.reply(embed=luxury("CASE NOTE NOT ADDED","Note must be 1-1500 characters.","warning"),mention_author=False)
        row=await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE id=?",(case_id,))
        if row is None:return await ctx.reply(embed=luxury("GUARDIAN CASE NOT FOUND","Guardian case not found.","warning"),mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_case_notes(case_id,author_id,note) VALUES(?,?,?)",(case_id,ctx.author.id,note))
        await ctx.reply(embed=luxury("PRIVATE CASE NOTE ADDED",f"Owner note added to `GNC-{case_id:06d}`.","success"),mention_author=False)

    @caseintel.command(name="evidence")
    async def evidence(self,ctx,case_id:int,*,evidence:str):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        if not 3<=len(evidence)<=1800:return await ctx.reply(embed=luxury("EVIDENCE NOT ADDED","Evidence reference must be 3-1800 characters.","warning"),mention_author=False)
        row=await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE id=?",(case_id,))
        if row is None:return await ctx.reply(embed=luxury("GUARDIAN CASE NOT FOUND","Guardian case not found.","warning"),mention_author=False)
        digest=hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        await self.bot.database.execute("INSERT INTO guardian_case_evidence(case_id,submitter_id,evidence,evidence_hash) VALUES(?,?,?,?)",(case_id,ctx.author.id,evidence,digest))
        await ctx.reply(embed=luxury("EVIDENCE VAULT",f"Evidence recorded for `GNC-{case_id:06d}`.\n**SHA-256:** `{digest[:16]}...`","success"),mention_author=False)

    @caseintel.command(name="duplicates")
    async def duplicates(self,ctx,case_id:int):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        row=await self.bot.database.fetchone("SELECT reported_user_id FROM guardian_network_cases WHERE id=?",(case_id,))
        if row is None:return await ctx.reply(embed=luxury("GUARDIAN CASE NOT FOUND","Guardian case not found.","warning"),mention_author=False)
        rows=await self.bot.database.fetchall("SELECT id,status,reporter_id,guild_id,created_at FROM guardian_network_cases WHERE reported_user_id=? ORDER BY id DESC",(row["reported_user_id"],))
        body="\n".join(f"GNC-{r['id']:06d} | {r['status']} | reporter {r['reporter_id']} | server {r['guild_id']}" for r in rows[:20])
        await ctx.reply(embed=luxury("CROSS-SERVER CASE LINKS",body or "No linked cases."),mention_author=False)

    @commands.group(name="guardianassist",invoke_without_command=True)
    async def assist(self,ctx):
        await ctx.reply(embed=luxury("GUARDIAN ASSISTANCE","Use `!guardianassist request <subject> | <details>`, `status <ID>`, or `close <ID>`."),mention_author=False)

    @assist.command(name="request")
    @commands.guild_only()
    @commands.cooldown(1,300,commands.BucketType.user)
    async def assist_request(self,ctx,*,request:str):
        if "|" not in request:return await ctx.reply(embed=luxury("GUARDIAN ASSISTANCE","Use `!guardianassist request subject | details`.","warning"),mention_author=False)
        subject,details=(x.strip() for x in request.split("|",1))
        if not subject or not details or len(subject)>120 or len(details)>1500:return await ctx.reply(embed=luxury("ASSISTANCE REQUEST NOT OPENED","Subject/details length is invalid.","warning"),mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_assistance(guild_id,requester_id,subject,details) VALUES(?,?,?,?)",(ctx.guild.id,ctx.author.id,subject,details))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_assistance ORDER BY id DESC LIMIT 1");rid=int(row["id"])
        owner_id=getattr(self.bot.settings,"owner_id",None)
        if owner_id:
            try:
                owner=self.bot.get_user(int(owner_id)) or await self.bot.fetch_user(int(owner_id))
                await owner.send(embed=luxury("GUARDIAN ASSISTANCE REQUEST",f"**Request:** `GA-{rid:06d}`\n**Server:** {esc(ctx.guild.name)} (`{ctx.guild.id}`)\n**From:** `{ctx.author.id}`\n**Subject:** {esc(subject)}\n\n{esc(details)}","warning"),allowed_mentions=discord.AllowedMentions.none())
            except discord.HTTPException:pass
        await ctx.reply(embed=luxury("GUARDIAN ASSISTANCE OPENED",f"Request `GA-{rid:06d}` opened.","success"),mention_author=False)

    @assist.command(name="status")
    async def assist_status(self,ctx,request_id:int):
        row=await self.bot.database.fetchone("SELECT guild_id,requester_id,subject,status FROM guardian_assistance WHERE id=?",(request_id,))
        if row is None:return await ctx.reply(embed=luxury("ASSISTANCE REQUEST NOT FOUND","Assistance request not found.","warning"),mention_author=False)
        owner_ok=await allowed(self.bot,ctx.author.id,"communications")
        if ctx.author.id!=int(row["requester_id"]) and not owner_ok:return
        await ctx.reply(embed=luxury("GUARDIAN ASSISTANCE STATUS",f"`GA-{request_id:06d}` • **{row['status']}**\n{esc(row['subject'])}"),mention_author=False)

    @assist.command(name="close")
    async def assist_close(self,ctx,request_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        await self.bot.database.execute("UPDATE guardian_assistance SET status='closed' WHERE id=?",(request_id,))
        await ctx.reply(embed=luxury("GUARDIAN ASSISTANCE CLOSED",f"`GA-{request_id:06d}` closed.","success"),mention_author=False)

    @commands.group(name="incidentroom",invoke_without_command=True)
    @commands.dm_only()
    async def incidentroom(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        await ctx.reply(embed=luxury("GUARDIAN INCIDENT ROOMS","Use `!incidentroom open <severity> <title>`, `list`, or `close <ID>`."),mention_author=False)
    @incidentroom.command(name="open")
    async def room_open(self,ctx,severity:str,*,title:str):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        severity=severity.casefold()
        if severity not in {"low","medium","high","critical"}:return await ctx.reply(embed=luxury("INCIDENT ROOM","Severity: `low`, `medium`, `high`, or `critical`.","warning"),mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_incident_rooms(title,severity,created_by) VALUES(?,?,?)",(title[:180],severity,ctx.author.id))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_incident_rooms ORDER BY id DESC LIMIT 1")
        await ctx.reply(embed=luxury("INCIDENT ROOM OPENED",f"`GIR-{int(row['id']):05d}` opened • **{severity.upper()}**","success"),mention_author=False)
    @incidentroom.command(name="list")
    async def room_list(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        rows=await self.bot.database.fetchall("SELECT id,title,severity,status FROM guardian_incident_rooms ORDER BY id DESC LIMIT 15")
        await ctx.reply(embed=luxury("GUARDIAN INCIDENT ROOMS","\n".join(f"GIR-{r['id']:05d} | {r['severity']} | {r['status']} | {r['title']}" for r in rows) or "No incident rooms."),mention_author=False)
    @incidentroom.command(name="close")
    async def room_close(self,ctx,room_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        await self.bot.database.execute("UPDATE guardian_incident_rooms SET status='closed' WHERE id=?",(room_id,))
        await ctx.reply(embed=luxury("INCIDENT ROOM CLOSED",f"`GIR-{room_id:05d}` closed.","success"),mention_author=False)

    @commands.command(name="networkstats")
    @commands.dm_only()
    async def networkstats(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        pending=await self.bot.database.fetchone("SELECT COUNT(*) n FROM guardian_network_cases WHERE status='pending'")
        approved=await self.bot.database.fetchone("SELECT COUNT(*) n FROM guardian_network_cases WHERE status='approved_for_global_ban'")
        rejected=await self.bot.database.fetchone("SELECT COUNT(*) n FROM guardian_network_cases WHERE status='rejected'")
        contacts=await self.bot.database.fetchone("SELECT COUNT(*) n FROM guardian_contacts")
        messages=await self.bot.database.fetchone("SELECT COUNT(*) n FROM guardian_contact_messages")
        await ctx.reply(embed=luxury("GUARDIAN NETWORK STATS",f"**Pending cases:** {pending['n']}\n**Approved for review:** {approved['n']}\n**Rejected cases:** {rejected['n']}\n**Authorized contacts:** {contacts['n']}\n**Contact messages:** {messages['n']}"),mention_author=False)

async def setup(bot):await bot.add_cog(GuardianBatchFive(bot))
