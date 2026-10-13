"""Guardian Network Cases: public reports and private bot-owner decisions."""
from __future__ import annotations
import asyncio
import discord
from discord.ext import commands
from esn_guardian.cogs.network_operations import luxury

class CaseDecisionView(discord.ui.View):
    def __init__(self,cog,case_id:int):
        super().__init__(timeout=86400); self.cog=cog; self.case_id=case_id
    async def decide(self,interaction,decision):
        if not self.cog.is_owner(interaction.user.id):
            return await interaction.response.send_message("Bot-owner authorization required.",ephemeral=True)
        ok,msg=await self.cog.review(self.case_id,interaction.user.id,decision)
        await interaction.response.send_message(msg,ephemeral=True)
        if ok:
            for item in self.children: item.disabled=True
            try: await interaction.message.edit(view=self)
            except discord.HTTPException: pass
    @discord.ui.button(label="Approve for Global Ban",style=discord.ButtonStyle.danger)
    async def approve(self,interaction,button): await self.decide(interaction,"approve")
    @discord.ui.button(label="Reject Case",style=discord.ButtonStyle.secondary)
    async def deny(self,interaction,button): await self.decide(interaction,"deny")

class GuardianNetworkCases(commands.Cog):
    def __init__(self,bot): self.bot=bot; self.lock=asyncio.Lock()
    async def cog_load(self):
        await self.bot.database.execute("""CREATE TABLE IF NOT EXISTS guardian_network_cases(
          id INTEGER PRIMARY KEY AUTOINCREMENT,reporter_id INTEGER NOT NULL,
          reported_user_id INTEGER NOT NULL,guild_id INTEGER NOT NULL,reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',reviewed_by INTEGER,reviewed_at TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        await self.bot.database.execute("CREATE INDEX IF NOT EXISTS idx_gnc_target ON guardian_network_cases(reported_user_id,status)")
    def is_owner(self,uid):
        oid=getattr(self.bot.settings,"owner_id",None)
        return oid is not None and int(oid)==int(uid)
    async def review(self,case_id,reviewer,decision):
        if not self.is_owner(reviewer): return False,"Owner authorization required."
        async with self.lock:
            row=await self.bot.database.fetchone("SELECT * FROM guardian_network_cases WHERE id=? AND status='pending'",(case_id,))
            if row is None: return False,"That case is no longer pending."
            status="approved_for_global_ban" if decision=="approve" else "rejected"
            reporter_id=int(row["reporter_id"])
            metric="substantiated" if decision=="approve" else "rejected"
            await self.bot.database.execute(f"INSERT INTO guardian_trust(user_id,{metric}) VALUES(?,1) ON CONFLICT(user_id) DO UPDATE SET {metric}={metric}+1,updated_at=CURRENT_TIMESTAMP",(reporter_id,))
            await self.bot.database.execute("UPDATE guardian_network_cases SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",(status,reviewer,case_id))
            if decision=="approve":
                return True,f"GNC-{case_id:06d} approved for global-ban enforcement. Use the existing audited /globalban command with this case ID."
            return True,f"GNC-{case_id:06d} rejected. No network action performed."
    async def notify_owner(self,cid,reporter,target,guild,reason):
        oid=getattr(self.bot.settings,"owner_id",None)
        if oid is None:return
        try:
            owner=self.bot.get_user(int(oid)) or await self.bot.fetch_user(int(oid))
            e=discord.Embed(title="✦ GUARDIAN NETWORK CASE",description="A report is awaiting bot-owner review.",color=0x8B5CF6)
            if guild.icon:e.set_thumbnail(url=guild.icon.url)
            e.add_field(name="CASE",value=f"GNC-{cid:06d}",inline=True)
            e.add_field(name="SERVER",value=f"{guild.name}\n`{guild.id}`",inline=True)
            e.add_field(name="REPORTED USER",value=f"<@{target}>\n`{target}`",inline=False)
            e.add_field(name="REPORTER",value=f"{reporter}\n`{reporter.id}`",inline=False)
            e.add_field(name="SUBMITTED REASON",value=discord.utils.escape_mentions(reason)[:1024],inline=False)
            e.set_footer(text="ESN GUARDIAN • OWNER REVIEW REQUIRED • REPORT IS NOT PROOF")
            await owner.send(embed=e,view=CaseDecisionView(self,cid),allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:pass

    @commands.group(name="guardian",invoke_without_command=True,case_insensitive=True)
    async def guardian(self,ctx):
        await ctx.reply(embed=luxury("GUARDIAN NETWORK CASES","Report a user with `!guardian report <USER_ID> <reason>`\n\nReports require private owner review and never automatically punish a user."),mention_author=False)
    @guardian.command(name="report")
    @commands.guild_only()
    @commands.cooldown(1,120,commands.BucketType.user)
    async def report(self,ctx,user_id:int,*,reason:str):
        if user_id in {ctx.author.id,self.bot.user.id if self.bot.user else 0}:return await ctx.reply(embed=luxury("REPORT NOT ACCEPTED","You cannot submit yourself or Guardian as the report target.","warning"),mention_author=False)
        try:
            self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
        except (discord.NotFound,discord.Forbidden,discord.HTTPException):
            return await ctx.reply(embed=luxury("REPORT NOT ACCEPTED",f"Discord user `{user_id}` could not be verified. Check the ID and try again.","warning"),mention_author=False)
        reason=reason.strip()
        if not 10<=len(reason)<=1000:return await ctx.reply("Give a reason between 10 and 1000 characters.",mention_author=False)
        old=await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE reporter_id=? AND reported_user_id=? AND status='pending'",(ctx.author.id,user_id))
        if old:
            await self.bot.database.execute("INSERT INTO guardian_trust(user_id,duplicate) VALUES(?,1) ON CONFLICT(user_id) DO UPDATE SET duplicate=duplicate+1,updated_at=CURRENT_TIMESTAMP",(ctx.author.id,))
            return await ctx.reply(f"You already have pending case GNC-{int(old['id']):06d} for that user.",mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_network_cases(reporter_id,reported_user_id,guild_id,reason) VALUES(?,?,?,?)",(ctx.author.id,user_id,ctx.guild.id,reason))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_network_cases WHERE reporter_id=? ORDER BY id DESC LIMIT 1",(ctx.author.id,))
        cid=int(row["id"]);await self.notify_owner(cid,ctx.author,user_id,ctx.guild,reason)
        await ctx.reply(embed=luxury("REPORT SUBMITTED",f"**Case:** `GNC-{cid:06d}`\n**Target:** `{user_id}`\n\nQueued for private owner review. A report does not automatically punish anyone.","success"),mention_author=False)
    @commands.command(name="networkcase")
    @commands.dm_only()
    async def networkcase(self,ctx,action:str|None=None,case_id:int|None=None):
        if not self.is_owner(ctx.author.id):return
        if action is None or case_id is None:return await ctx.reply(embed=luxury("NETWORK CASE REVIEW","Usage: `!networkcase approve <ID>` or `!networkcase deny <ID>`."),mention_author=False)
        action=action.casefold()
        if action not in {"approve","deny"}:return await ctx.reply("Use `!networkcase approve <ID>` or `!networkcase deny <ID>`.",mention_author=False)
        ok,msg=await self.review(case_id,ctx.author.id,action);await ctx.reply(msg,mention_author=False)

async def setup(bot): await bot.add_cog(GuardianNetworkCases(bot))
