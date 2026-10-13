from __future__ import annotations
import discord
from discord.ext import commands,tasks
from esn_guardian.owner_access import LEVELS,allowed,ensure_owner_table,is_primary,owner_level
from esn_guardian.cogs.network_operations import luxury

class GuardianManagement(commands.Cog):
    def __init__(self,bot):
        self.bot=bot
        self.owner_command_guide_loop.start()

    def cog_unload(self):
        self.owner_command_guide_loop.cancel()

    def command_guide_sections(self):
        commands_all=sorted({cmd.qualified_name for cmd in self.bot.walk_commands() if not cmd.hidden})
        groups={
            "OWNER & FLEET":("ownercenter","ownersandbox","guardianowner","inbox","commandguide","fleet"),
            "NETWORK CASES":("guardian","networkcase","caseintel","appeal","appealreview","appeals","globalbanlist","unbanrequest","unbanreview","trust"),
            "BROADCAST & EMERGENCY":("broadcast","broadcastmanage","emergency"),
            "CONTACTS & MESSAGING":("gcontact","gmessage","gmsgctl","contactinfo","contactreportreview","networkdirectory"),
            "ASSISTANCE & INCIDENTS":("guardianassist","incidentroom","networkstats"),
            "OMEGA & SECURITY":("ESNG","omega","omegadefense","phoenixsnapshot"),
        }
        used=set(); result=[]
        for title,roots in groups.items():
            items=[x for x in commands_all if x.split()[0] in roots]
            used.update(items)
            if items: result.append((title,items))
        other=[x for x in commands_all if x not in used]
        if other: result.append(("OTHER COMMANDS",other))
        return result

    async def send_command_guide(self,user):
        sections=self.command_guide_sections()
        total=sum(len(items) for _,items in sections)
        for index,(title,items) in enumerate(sections,1):
            lines="\n".join(f"• `!{name}`" for name in items)
            e=luxury(f"COMMAND GUIDE • {title}",f"**Section {index}/{len(sections)}**\n{lines}")
            e.set_footer(text=f"ESN GUARDIAN V8 LUXURY • {total} PREFIX COMMANDS • AUTO GUIDE EVERY 2 HOURS")
            await user.send(embed=e,allowed_mentions=discord.AllowedMentions.none())
        slash=sorted({cmd.qualified_name for cmd in self.bot.tree.walk_commands()})
        if slash:
            body="\n".join(f"• `/{name}`" for name in slash)
            await user.send(embed=luxury("COMMAND GUIDE • SLASH COMMANDS",body),allowed_mentions=discord.AllowedMentions.none())

    @tasks.loop(hours=2)
    async def owner_command_guide_loop(self):
        owner_id=getattr(self.bot.settings,"owner_id",None)
        if owner_id is None:return
        try:
            owner=self.bot.get_user(int(owner_id)) or await self.bot.fetch_user(int(owner_id))
            await self.send_command_guide(owner)
        except discord.HTTPException:
            pass

    @owner_command_guide_loop.before_loop
    async def before_owner_command_guide_loop(self):
        await self.bot.wait_until_ready()
    async def cog_load(self):
        await ensure_owner_table(self.bot)
        for sql in (
          "CREATE TABLE IF NOT EXISTS guardian_contact_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,sender_id INTEGER NOT NULL,recipient_id INTEGER NOT NULL,sender_guild_id INTEGER NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'unread',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "CREATE TABLE IF NOT EXISTS guardian_contact_blocks(owner_id INTEGER NOT NULL,blocked_id INTEGER NOT NULL,PRIMARY KEY(owner_id,blocked_id))",
          "CREATE TABLE IF NOT EXISTS guardian_contact_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,message_id INTEGER NOT NULL,reporter_id INTEGER NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        ): await self.bot.database.execute(sql)

    @commands.group(name="guardianowner",aliases=["gowner"],invoke_without_command=True)
    @commands.dm_only()
    async def guardianowner(self,ctx):
        if not is_primary(self.bot,ctx.author.id):return
        await ctx.reply("Owner IDs: add USER_ID LEVEL, permissions USER_ID, list, revoke USER_ID.",mention_author=False)
    @guardianowner.command(name="add")
    async def owner_add(self,ctx,user_id:int,level:str):
        if not is_primary(self.bot,ctx.author.id):return
        level=level.casefold()
        if level not in LEVELS:return await ctx.reply("Level must be full, cases, or communications.",mention_author=False)
        if user_id==ctx.author.id:return await ctx.reply("The Primary Owner is permanent.",mention_author=False)
        try:self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
        except discord.HTTPException:return await ctx.reply("That Discord user could not be verified.",mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_secondary_owners(user_id,level,added_by) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET level=excluded.level,added_by=excluded.added_by",(user_id,level,ctx.author.id))
        await ctx.reply(f"Secondary owner {user_id} authorized for {level}. Secondary owners cannot grant ownership.",mention_author=False)
    @guardianowner.command(name="permissions")
    async def owner_permissions(self,ctx,user_id:int):
        if not is_primary(self.bot,ctx.author.id):return
        level=await owner_level(self.bot,user_id);await ctx.reply(f"Owner {user_id} permission level: {level or 'none'}.",mention_author=False)
    @guardianowner.command(name="list")
    async def owner_list(self,ctx):
        if not is_primary(self.bot,ctx.author.id):return
        rows=await self.bot.database.fetchall("SELECT user_id,level FROM guardian_secondary_owners ORDER BY created_at")
        body="\n".join(f"{r['user_id']} - {r['level']}" for r in rows) or "No secondary owners."
        await ctx.reply(embed=luxury("GUARDIAN OWNER ACCESS",f"**Primary:** `{self.bot.settings.owner_id}`\n\n{body}"),mention_author=False)
    @guardianowner.command(name="revoke")
    async def owner_revoke(self,ctx,user_id:int):
        if not is_primary(self.bot,ctx.author.id):return
        if user_id==int(self.bot.settings.owner_id):return await ctx.reply("The Primary Owner cannot be revoked through Discord.",mention_author=False)
        await self.bot.database.execute("DELETE FROM guardian_secondary_owners WHERE user_id=?",(user_id,));await ctx.reply(f"Secondary owner {user_id} revoked.",mention_author=False)

    @commands.command(name="inbox")
    @commands.dm_only()
    async def inbox(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        cases=await self.bot.database.fetchall("SELECT id,reported_user_id FROM guardian_network_cases WHERE status='pending' ORDER BY id DESC LIMIT 5")
        appeals=await self.bot.database.fetchall("SELECT id,user_id FROM omega_global_appeals WHERE status='pending' ORDER BY id DESC LIMIT 5")
        unbans=await self.bot.database.fetchall("SELECT id,user_id FROM guardian_unban_reviews WHERE status='pending' ORDER BY id DESC LIMIT 5")
        reports=await self.bot.database.fetchall("SELECT id,message_id FROM guardian_contact_reports WHERE status='pending' ORDER BY id DESC LIMIT 5")
        lines=[f"GNC-{r['id']:06d} user {r['reported_user_id']}" for r in cases]+[f"Appeal {r['id']} user {r['user_id']}" for r in appeals]+[f"GUR-{r['id']:06d} user {r['user_id']}" for r in unbans]+[f"Contact report {r['id']} message GMSG-{r['message_id']:06d}" for r in reports]
        await ctx.reply(embed=luxury("GUARDIAN OWNER INBOX","\n".join(lines) if lines else "No pending review items."),mention_author=False)

    @commands.command(name="commandguide")
    @commands.dm_only()
    async def commandguide(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        await self.send_command_guide(ctx.author)

    async def contacts(self,user_id):
        return await self.bot.database.fetchall("SELECT guild_id FROM guardian_contacts WHERE user_id=?",(user_id,))
    @commands.group(name="gmessage",invoke_without_command=True)
    async def gmessage(self,ctx):\n        where="**Run messaging commands in Guardian DMs.**\n\n" if ctx.guild else ""\n        await ctx.reply(embed=luxury("GUARDIAN CONTACT MESSAGING",where+"`!gmessage send <USER_ID> <message>`\n`!gmessage inbox`\n`!gmessage reply <MESSAGE_ID> <message>`\n`!gmessage block <USER_ID>`\n`!gmessage unblock <USER_ID>`\n`!gmessage report <MESSAGE_ID> <reason>`"),mention_author=False)
    @gmessage.command(name="send")\n    @commands.dm_only()
    @commands.cooldown(1,20,commands.BucketType.user)
    async def message_send(self,ctx,user_id:int,*,message:str):
        mine=await self.contacts(ctx.author.id);theirs=await self.contacts(user_id)
        if not mine or not theirs:return await ctx.reply(embed=luxury("MESSAGE NOT SENT","Both users must be registered Guardian contacts.","warning"),mention_author=False)
        if not 1<=len(message)<=1500:return await ctx.reply(embed=luxury("MESSAGE NOT SENT","Message must be 1-1500 characters.","warning"),mention_author=False)
        blocked=await self.bot.database.fetchone("SELECT 1 FROM guardian_contact_blocks WHERE owner_id=? AND blocked_id=?",(user_id,ctx.author.id))
        if blocked:return await ctx.reply(embed=luxury("MESSAGE NOT SENT","That contact is not accepting messages from you.","warning"),mention_author=False)
        pref=await self.bot.database.fetchone("SELECT muted FROM guardian_contact_preferences WHERE user_id=?",(user_id,))
        if pref and int(pref["muted"]):return await ctx.reply(embed=luxury("MESSAGE NOT SENT","That contact has Guardian network messages muted.","warning"),mention_author=False)
        gid=int(mine[0]["guild_id"]);await self.bot.database.execute("INSERT INTO guardian_contact_messages(sender_id,recipient_id,sender_guild_id,body) VALUES(?,?,?,?)",(ctx.author.id,user_id,gid,message))
        row=await self.bot.database.fetchone("SELECT id FROM guardian_contact_messages WHERE sender_id=? ORDER BY id DESC LIMIT 1",(ctx.author.id,));mid=int(row["id"])
        try:
            user=self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
            await user.send(embed=luxury("GUARDIAN CONTACT MESSAGE",f"**Message:** `GMSG-{mid:06d}`\n**From:** {ctx.author} (`{ctx.author.id}`)\n\n{discord.utils.escape_mentions(message)}"),allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:return await ctx.reply(embed=luxury("MESSAGE STORED • DELIVERY FAILED",f"`GMSG-{mid:06d}` was stored, but DM delivery failed.","warning"),mention_author=False)
        await ctx.reply(embed=luxury("MESSAGE DELIVERED",f"`GMSG-{mid:06d}` delivered successfully.","success"),mention_author=False)
    @gmessage.command(name="inbox")\n    @commands.dm_only()
    async def message_inbox(self,ctx):
        rows=await self.bot.database.fetchall("SELECT id,sender_id,body,status FROM guardian_contact_messages WHERE recipient_id=? ORDER BY id DESC LIMIT 10",(ctx.author.id,))
        body="\n".join(f"GMSG-{r['id']:06d} from {r['sender_id']} [{r['status']}] {str(r['body'])[:100]}" for r in rows) or "No Guardian contact messages."
        await ctx.reply(embed=luxury("GUARDIAN MESSAGE INBOX",body),mention_author=False)
    @gmessage.command(name="reply")\n    @commands.dm_only()
    async def message_reply(self,ctx,message_id:int,*,message:str):
        row=await self.bot.database.fetchone("SELECT sender_id FROM guardian_contact_messages WHERE id=? AND recipient_id=?",(message_id,ctx.author.id))
        if row is None:return await ctx.reply(embed=luxury("MESSAGE NOT FOUND","That Guardian contact message could not be found.","warning"),mention_author=False)
        await ctx.invoke(self.message_send,user_id=int(row["sender_id"]),message=message)
    @gmessage.command(name="block")\n    @commands.dm_only()
    async def block(self,ctx,user_id:int):
        await self.bot.database.execute("INSERT OR IGNORE INTO guardian_contact_blocks(owner_id,blocked_id) VALUES(?,?)",(ctx.author.id,user_id));await ctx.reply(embed=luxury("CONTACT BLOCKED",f"`{user_id}` can no longer message you through Guardian.","success"),mention_author=False)
    @gmessage.command(name="unblock")\n    @commands.dm_only()
    async def unblock(self,ctx,user_id:int):
        await self.bot.database.execute("DELETE FROM guardian_contact_blocks WHERE owner_id=? AND blocked_id=?",(ctx.author.id,user_id));await ctx.reply(embed=luxury("CONTACT UNBLOCKED",f"`{user_id}` may message you through Guardian again.","success"),mention_author=False)
    @gmessage.command(name="report")\n    @commands.dm_only()
    async def report(self,ctx,message_id:int,*,reason:str):
        row=await self.bot.database.fetchone("SELECT id FROM guardian_contact_messages WHERE id=? AND recipient_id=?",(message_id,ctx.author.id))
        if row is None:return await ctx.reply(embed=luxury("REPORT NOT ACCEPTED","You can only report a message sent to you.","warning"),mention_author=False)
        if not 5<=len(reason)<=1000:return await ctx.reply(embed=luxury("REPORT NOT ACCEPTED","Reason must be 5-1000 characters.","warning"),mention_author=False)
        await self.bot.database.execute("INSERT INTO guardian_contact_reports(message_id,reporter_id,reason) VALUES(?,?,?)",(message_id,ctx.author.id,reason));await ctx.reply(embed=luxury("MESSAGE REPORTED",f"`GMSG-{message_id:06d}` was sent to the Owner Inbox for review.","success"),mention_author=False)

async def setup(bot):await bot.add_cog(GuardianManagement(bot))
