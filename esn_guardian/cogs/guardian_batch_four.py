"""Guardian V8 Luxury batch 4: lifecycle, review, privacy and network utilities."""
from __future__ import annotations
import discord
from discord.ext import commands
from esn_guardian.owner_access import allowed,is_primary

class GuardianBatchFour(commands.Cog):
    def __init__(self,bot): self.bot=bot
    async def cog_load(self):
        for sql in (
          "CREATE TABLE IF NOT EXISTS guardian_broadcast_ack(broadcast_id INTEGER NOT NULL,user_id INTEGER NOT NULL,acknowledged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(broadcast_id,user_id))",
          "CREATE TABLE IF NOT EXISTS guardian_contact_preferences(user_id INTEGER PRIMARY KEY,muted INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        ): await self.bot.database.execute(sql)

    @commands.group(name="broadcastmanage",invoke_without_command=True)
    @commands.dm_only()
    async def broadcastmanage(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        await ctx.reply("Use history, cancel, resend, acknowledge, or unacknowledged.",mention_author=False)

    @broadcastmanage.command(name="history")
    async def history(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        rows=await self.bot.database.fetchall("SELECT id,kind,status,created_at FROM guardian_broadcasts ORDER BY id DESC LIMIT 15")
        body="\n".join(f"ESNG-NET-{r['id']:04d} | {r['kind']} | {r['status']} | {r['created_at']}" for r in rows) or "No broadcasts."
        await ctx.reply(body,mention_author=False)

    @broadcastmanage.command(name="cancel")
    async def cancel(self,ctx,broadcast_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        row=await self.bot.database.fetchone("SELECT status FROM guardian_broadcasts WHERE id=?",(broadcast_id,))
        if row is None:return await ctx.reply("Broadcast not found.",mention_author=False)
        if row["status"]!="created":return await ctx.reply("Only an unsent broadcast can be cancelled.",mention_author=False)
        await self.bot.database.execute("UPDATE guardian_broadcasts SET status='cancelled' WHERE id=?",(broadcast_id,))
        await ctx.reply(f"ESNG-NET-{broadcast_id:04d} cancelled.",mention_author=False)

    @broadcastmanage.command(name="resend")
    async def resend(self,ctx,broadcast_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        row=await self.bot.database.fetchone("SELECT kind,message FROM guardian_broadcasts WHERE id=? AND status='sent'",(broadcast_id,))
        if row is None:return await ctx.reply("Sent broadcast not found.",mention_author=False)
        deliveries=await self.bot.database.fetchall("SELECT user_id,guild_id,status FROM guardian_broadcast_delivery WHERE broadcast_id=?",(broadcast_id,))
        sent=0
        for d in deliveries:
            if d["status"]=="delivered":continue
            try:
                user=self.bot.get_user(int(d["user_id"])) or await self.bot.fetch_user(int(d["user_id"]))
                await user.send(f"ESN GUARDIAN NETWORK | {str(row['kind']).upper()}\nBroadcast ESNG-NET-{broadcast_id:04d}\n\n{discord.utils.escape_mentions(str(row['message']))}",allowed_mentions=discord.AllowedMentions.none())
                await self.bot.database.execute("UPDATE guardian_broadcast_delivery SET status='delivered' WHERE broadcast_id=? AND user_id=? AND guild_id=?",(broadcast_id,d["user_id"],d["guild_id"]));sent+=1
            except discord.HTTPException:pass
        await ctx.reply(f"ESNG-NET-{broadcast_id:04d}: retried undelivered recipients; delivered {sent}.",mention_author=False)

    @broadcastmanage.command(name="acknowledge")
    async def acknowledge(self,ctx,broadcast_id:int):
        row=await self.bot.database.fetchone("SELECT 1 FROM guardian_broadcast_delivery WHERE broadcast_id=? AND user_id=?",(broadcast_id,ctx.author.id))
        if row is None:return await ctx.reply("That broadcast was not addressed to you.",mention_author=False)
        await self.bot.database.execute("INSERT OR REPLACE INTO guardian_broadcast_ack(broadcast_id,user_id) VALUES(?,?)",(broadcast_id,ctx.author.id))
        await ctx.reply(f"ESNG-NET-{broadcast_id:04d} acknowledged.",mention_author=False)

    @broadcastmanage.command(name="unacknowledged")
    async def unacknowledged(self,ctx,broadcast_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        rows=await self.bot.database.fetchall("SELECT DISTINCT d.user_id FROM guardian_broadcast_delivery d LEFT JOIN guardian_broadcast_ack a ON a.broadcast_id=d.broadcast_id AND a.user_id=d.user_id WHERE d.broadcast_id=? AND d.status='delivered' AND a.user_id IS NULL",(broadcast_id,))
        await ctx.reply(f"ESNG-NET-{broadcast_id:04d}: {len(rows)} delivered recipient(s) have not acknowledged.",mention_author=False)

    @commands.group(name="gmsgctl",invoke_without_command=True)
    @commands.dm_only()
    async def gmsgctl(self,ctx):await ctx.reply("Use sent, unread, read, delete, mute, unmute, status, or blocked.",mention_author=False)
    @gmsgctl.command(name="sent")
    async def sent(self,ctx):
        rows=await self.bot.database.fetchall("SELECT id,recipient_id,status,created_at FROM guardian_contact_messages WHERE sender_id=? ORDER BY id DESC LIMIT 10",(ctx.author.id,))
        await ctx.reply("\n".join(f"GMSG-{r['id']:06d} to {r['recipient_id']} [{r['status']}]" for r in rows) or "No sent messages.",mention_author=False)
    @gmsgctl.command(name="unread")
    async def unread(self,ctx):
        rows=await self.bot.database.fetchall("SELECT id,sender_id,body FROM guardian_contact_messages WHERE recipient_id=? AND status='unread' ORDER BY id DESC LIMIT 10",(ctx.author.id,))
        await ctx.reply("\n".join(f"GMSG-{r['id']:06d} from {r['sender_id']}: {str(r['body'])[:120]}" for r in rows) or "No unread messages.",mention_author=False)
    @gmsgctl.command(name="read")
    async def read(self,ctx,message_id:int):
        await self.bot.database.execute("UPDATE guardian_contact_messages SET status='read' WHERE id=? AND recipient_id=?",(message_id,ctx.author.id));await ctx.reply(f"GMSG-{message_id:06d} marked read.",mention_author=False)
    @gmsgctl.command(name="delete")
    async def delete(self,ctx,message_id:int):
        row=await self.bot.database.fetchone("SELECT id FROM guardian_contact_messages WHERE id=? AND (sender_id=? OR recipient_id=?)",(message_id,ctx.author.id,ctx.author.id))
        if row is None:return await ctx.reply("Message not found.",mention_author=False)
        await self.bot.database.execute("UPDATE guardian_contact_messages SET body='[deleted]',status='deleted' WHERE id=?",(message_id,));await ctx.reply(f"GMSG-{message_id:06d} content deleted; audit ID retained.",mention_author=False)
    @gmsgctl.command(name="mute")
    async def mute(self,ctx):
        await self.bot.database.execute("INSERT INTO guardian_contact_preferences(user_id,muted) VALUES(?,1) ON CONFLICT(user_id) DO UPDATE SET muted=1,updated_at=CURRENT_TIMESTAMP",(ctx.author.id,));await ctx.reply("Guardian contact messages muted.",mention_author=False)
    @gmsgctl.command(name="unmute")
    async def unmute(self,ctx):
        await self.bot.database.execute("INSERT INTO guardian_contact_preferences(user_id,muted) VALUES(?,0) ON CONFLICT(user_id) DO UPDATE SET muted=0,updated_at=CURRENT_TIMESTAMP",(ctx.author.id,));await ctx.reply("Guardian contact messages unmuted.",mention_author=False)
    @gmsgctl.command(name="status")
    async def status(self,ctx):
        pref=await self.bot.database.fetchone("SELECT muted FROM guardian_contact_preferences WHERE user_id=?",(ctx.author.id,))
        contacts=await self.bot.database.fetchall("SELECT guild_id FROM guardian_contacts WHERE user_id=?",(ctx.author.id,))
        await ctx.reply(f"Registered servers: {len(contacts)} | Messaging: {'muted' if pref and pref['muted'] else 'enabled'}",mention_author=False)
    @gmsgctl.command(name="blocked")
    async def blocked(self,ctx):
        rows=await self.bot.database.fetchall("SELECT blocked_id FROM guardian_contact_blocks WHERE owner_id=?",(ctx.author.id,))
        await ctx.reply("Blocked: "+(", ".join(str(r["blocked_id"]) for r in rows) if rows else "none"),mention_author=False)

    @commands.command(name="contactinfo")
    @commands.dm_only()
    async def contactinfo(self,ctx,user_id:int):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        rows=await self.bot.database.fetchall("SELECT guild_id,added_by,created_at FROM guardian_contacts WHERE user_id=?",(user_id,))
        body="\n".join(f"Server {r['guild_id']} | added by {r['added_by']} | {r['created_at']}" for r in rows) or "Not a registered Guardian contact."
        await ctx.reply(f"Guardian contact {user_id}\n{body}",mention_author=False)

    @commands.command(name="contactreportreview")
    @commands.dm_only()
    async def contactreportreview(self,ctx,report_id:int,decision:str):
        if not await allowed(self.bot,ctx.author.id,"cases"):return
        decision=decision.casefold()
        if decision not in {"resolve","dismiss"}:return await ctx.reply("Use resolve or dismiss.",mention_author=False)
        row=await self.bot.database.fetchone("SELECT id FROM guardian_contact_reports WHERE id=? AND status='pending'",(report_id,))
        if row is None:return await ctx.reply("Pending contact report not found.",mention_author=False)
        await self.bot.database.execute("UPDATE guardian_contact_reports SET status=? WHERE id=?",(decision,report_id));await ctx.reply(f"Contact report {report_id} marked {decision}.",mention_author=False)

    @commands.command(name="networkdirectory")
    @commands.dm_only()
    async def networkdirectory(self,ctx):
        if not await allowed(self.bot,ctx.author.id,"communications"):return
        rows=await self.bot.database.fetchall("SELECT guild_id,COUNT(*) n FROM guardian_contacts GROUP BY guild_id ORDER BY guild_id")
        lines=[]
        for r in rows:
            g=self.bot.get_guild(int(r["guild_id"]));lines.append(f"{g.name if g else r['guild_id']} | {r['n']} authorized contact(s)")
        await ctx.reply("GUARDIAN NETWORK DIRECTORY\n"+("\n".join(lines) if lines else "No enrolled contact servers."),mention_author=False)

async def setup(bot):await bot.add_cog(GuardianBatchFour(bot))
