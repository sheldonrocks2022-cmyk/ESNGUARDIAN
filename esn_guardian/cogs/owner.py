from __future__ import annotations

import io

import discord
from discord import app_commands
from discord.ext import commands, tasks

from esn_guardian.cogs.common import command_embed, notify_user, respond, defer_response


def owner_only() -> app_commands.check:
    """Only the configured BOT_OWNER_ID may run privileged owner commands.

    Fail closed when the owner is not configured. Discord server ownership,
    administrator permissions and legacy hardcoded IDs never grant access.
    """
    async def predicate(interaction: discord.Interaction) -> bool:
        configured_owner = getattr(getattr(interaction.client, "settings", None), "owner_id", None)
        return configured_owner is not None and interaction.user.id == int(configured_owner)
    return app_commands.check(predicate)


class OwnerCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._global_bans: dict[int, str] = {}
        self.owner_guide_reminder.start()

    def cog_unload(self) -> None:
        self.owner_guide_reminder.cancel()

    @tasks.loop(hours=2)
    async def owner_guide_reminder(self) -> None:
        owner_id = getattr(self.bot.settings, "owner_id", None)
        if owner_id is None:
            return
        try:
            owner = self.bot.get_user(int(owner_id)) or await self.bot.fetch_user(int(owner_id))
            description = (
                "Owner commands: /esng-codex, !ESNG code <number>, and !broadcast create.\n\n"
                "Operations: /globalban, /globalunban, /globalbanpreview, /botstats, /servers, "
                "/synccommands, /maintenance, /blacklist, /unblacklist.\n\n"
                "Use /help for the live slash-command directory."
            )
            await owner.send(
                embed=command_embed(description, title="ESN Guardian • Owner Command Guide"),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    @owner_guide_reminder.before_loop
    async def before_owner_guide_reminder(self) -> None:
        await self.bot.wait_until_ready()

    async def cog_load(self) -> None:
        rows = await self.bot.database.fetchall(
            "SELECT user_id, reason FROM global_bans"
        )
        self._global_bans = {
            int(row["user_id"]): str(row["reason"])
            for row in rows
        }

    async def _notify_user_by_id(self, user_id: int, message: str) -> bool:
        user = self.bot.get_user(user_id)
        if user is None:
            try:
                user = await self.bot.fetch_user(user_id)
            except discord.HTTPException:
                return False
        return await notify_user(user, message)

    @app_commands.command(description="Show bot-wide operational statistics.")
    @owner_only()
    async def botstats(self, interaction: discord.Interaction) -> None:
        await respond(interaction, f"Servers: {len(self.bot.guilds)}\nUsers cached: {len(self.bot.users)}\nLatency: {round(self.bot.latency * 1000)}ms\nDatabase: {'online' if self.bot.database.connection else 'offline'}")

    @app_commands.command(description="Create a verified backup of Guardian's SQLite database.")
    @owner_only()
    async def backupdb(self, interaction: discord.Interaction) -> None:
        await defer_response(interaction)
        try:
            path = await self.bot.database.backup("manual")
        except Exception:
            await respond(interaction, "Database backup failed. Check the Raven console for the logged error.")
            return
        await respond(interaction, f"Database backup created: `{path.name if path else 'unavailable'}`.")

    @app_commands.command(description="Show Guardian database backup status.")
    @owner_only()
    async def backupstatus(self, interaction: discord.Interaction) -> None:
        info = self.bot.database.backup_info()
        latest = info["latest"] or "none yet"
        await respond(
            interaction,
            f"Database: `{info['database']}`\nBackups kept: {info['count']}\nLatest backup: `{latest}`",
        )

    @app_commands.command(description="List servers currently served by the bot.")
    @owner_only()
    async def servers(self, interaction: discord.Interaction) -> None:
        total_members = sum(guild.member_count or 0 for guild in self.bot.guilds)
        server_list = "\n".join(
            f"{guild.name} ({guild.id}) - {guild.member_count or 0:,} members"
            for guild in sorted(self.bot.guilds, key=lambda guild: guild.name.casefold())
        ) or "No servers."
        attachment = discord.File(io.BytesIO(server_list.encode("utf-8")), filename="servers.txt")
        if interaction.response.is_done():
            await interaction.followup.send(
                embed=command_embed(f"Servers: {len(self.bot.guilds):,}\nCombined members: {total_members:,}", title="Connected servers"),
                file=attachment,
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                embed=command_embed(f"Servers: {len(self.bot.guilds):,}\nCombined members: {total_members:,}", title="Connected servers"),
                file=attachment,
                ephemeral=True,
            )

    @app_commands.command(description="Refresh slash commands in one server or every connected server.")
    @owner_only()
    async def synccommands(self, interaction: discord.Interaction, guild_id: str | None = None) -> None:
        if guild_id is None:
            guilds = list(self.bot.guilds)
        else:
            try:
                target_id = int(guild_id)
            except ValueError:
                await respond(interaction, "Provide a numeric server ID, or leave it empty to sync every connected server.")
                return
            guild = self.bot.get_guild(target_id)
            if guild is None:
                await respond(interaction, "I am not connected to that server.")
                return
            guilds = [guild]

        await defer_response(interaction)
        synced = 0
        failed = 0
        command_count = 0
        for guild in guilds:
            try:
                commands_synced = await self.bot.sync_guild_commands(guild)
            except discord.HTTPException:
                failed += 1
            else:
                synced += 1
                command_count += len(commands_synced)
        scope = f"server `{guild_id}`" if guild_id is not None else "all connected servers"
        await respond(interaction, f"Synced {command_count} command(s) across {synced} {scope}; failed: {failed}.")

    @app_commands.command(description="Ban a user from every server served by the bot.")
    @owner_only()
    async def globalban(
        self,
        interaction: discord.Interaction,
        user_id: str,
        reason: str,
        confidence: app_commands.Range[int, 1, 100] = 100,
        evidence_case_id: int | None = None,
    ) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        configured_owner = getattr(self.bot.settings, "owner_id", None)
        protected_ids = {int(configured_owner)} if configured_owner is not None else set()
        if self.bot.user is not None:
            protected_ids.add(self.bot.user.id)
        if target_id in protected_ids:
            await respond(interaction, "Guardian cannot globally ban its configured owner or itself.")
            return

        await defer_response(interaction)
        summary = await self.execute_globalban(target_id=target_id, reason=reason, actor_id=interaction.user.id, source_guild_id=interaction.guild_id, confidence=int(confidence), evidence_case_id=evidence_case_id)
        await respond(interaction, summary)

    async def execute_globalban(self, *, target_id: int, reason: str, actor_id: int, source_guild_id: int | None, confidence: int = 100, evidence_case_id: int | None = None) -> str:
        """Shared enforcement used by /globalban and owner-confirmed prefix commands."""
        await self.bot.database.execute(
            "INSERT INTO global_bans (user_id, reason, banned_by_id) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET reason = excluded.reason, banned_by_id = excluded.banned_by_id",
            (target_id, reason, actor_id),
        )
        self._global_bans[target_id] = reason
        banned = 0
        failed = 0
        owner_notified = 0
        owner_notify_failed = 0
        target = discord.Object(id=target_id)

        for guild in self.bot.guilds:
            outcome = "failed"
            failure_reason = None
            try:
                await guild.ban(target, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
                banned += 1
                outcome = "banned"
            except discord.Forbidden:
                failed += 1
                failure_reason = "Discord denied the ban. Guardian may be missing Ban Members permission or sufficient role hierarchy."
            except discord.HTTPException as exc:
                failed += 1
                failure_reason = f"Discord API error while applying the ban (HTTP {getattr(exc, 'status', 'unknown')})."

            try:
                guild_owner = guild.owner
                if guild_owner is None:
                    guild_owner = await self.bot.fetch_user(guild.owner_id)
                status_text = (
                    "SUCCESS — Guardian applied the global ban in your server."
                    if outcome == "banned"
                    else f"FAILED — {failure_reason or 'Guardian could not apply the global ban.'}"
                )
                notice = command_embed(
                    (
                        f"**User:** <@{target_id}> (`{target_id}`)\n"
                        f"**Server:** {discord.utils.escape_markdown(guild.name)} (`{guild.id}`)\n"
                        f"**Reason:** {discord.utils.escape_mentions(reason)[:1500]}\n"
                        f"**Confidence:** {int(confidence)}%\n"
                        f"**Enforcement:** {status_text}"
                    ),
                    title="Guardian Global Ban Alert",
                )
                await guild_owner.send(embed=notice, allowed_mentions=discord.AllowedMentions.none())
                owner_notified += 1
            except (discord.Forbidden, discord.HTTPException):
                owner_notify_failed += 1

            v7 = self.bot.get_cog("SecurityV7Cog")
            if v7 is not None and hasattr(v7, "_evidence"):
                try:
                    await v7._evidence(
                        guild.id,
                        actor_id,
                        "GLOBAL_BAN_ENFORCEMENT",
                        target_id,
                        {
                            "reason": reason[:500],
                            "outcome": outcome,
                            "failure_reason": failure_reason,
                            "confidence": int(confidence),
                            "evidence_case_id": evidence_case_id,
                            "source_server_id": source_guild_id,
                            "source": "bot_owner_globalban",
                        },
                    )
                except Exception:
                    pass

        user_dm = (
            "**You have been globally banned by ESN Guardian.**\n"
            f"**Reason:** {discord.utils.escape_mentions(reason)[:1500]}\n"
            f"**Confidence:** {int(confidence)}%\n\n"
            "**Appeal:** DM this bot with `!appeal <your explanation>` using a 20–1500 character explanation. "
            "Your appeal is private and is reviewed by the Guardian bot owner."
        )
        user_notified = await self._notify_user_by_id(target_id, user_dm)
        evidence_text = f" • evidence case #{evidence_case_id}" if evidence_case_id is not None else ""
        return (
                f"Global ban saved for `{target_id}`. Confidence: {int(confidence)}%{evidence_text}.\n"
                f"Enforcement: {banned} successful • {failed} failed.\n"
                f"Server-owner notices: {owner_notified} delivered • {owner_notify_failed} failed.\n"
                f"Banned-user notice: {'delivered' if user_notified else 'failed (DM unavailable or Discord API error)'}."
            )


    @commands.group(name="esng", invoke_without_command=True)
    async def esng(self, ctx: commands.Context) -> None:
        if ctx.author.id != getattr(self.bot.settings, "owner_id", None):
            return
        await ctx.reply("Owner syntax: `!esng code 3 @user` or `!esng code 3 USER_ID`.", mention_author=False)

    @esng.group(name="code", invoke_without_command=True)
    async def esng_code(self, ctx: commands.Context) -> None:
        if ctx.author.id == getattr(self.bot.settings, "owner_id", None):
            await ctx.reply("Use `!esng code 3 @user` or `!esng code 3 USER_ID`.", mention_author=False)

    @esng_code.command(name="3")
    async def esng_code_three(self, ctx: commands.Context, target: str, *, reason: str = "Guardian owner global ban") -> None:
        owner_id = getattr(self.bot.settings, "owner_id", None)
        if owner_id is None or ctx.author.id != int(owner_id):
            return
        raw = target.strip()
        if raw.startswith("<@") and raw.endswith(">"):
            raw = raw[2:-1].lstrip("!")
        if not raw.isdecimal() or int(raw) <= 0:
            await ctx.reply("Provide a user mention or numeric Discord user ID.", mention_author=False)
            return
        target_id = int(raw)
        if target_id in {int(owner_id), self.bot.user.id if self.bot.user else -1}:
            await ctx.reply("Guardian cannot globally ban its owner or itself.", mention_author=False)
            return
        cog = self
        class ConfirmBan(discord.ui.View):
            def __init__(self) -> None:
                super().__init__(timeout=60)
                self.message: discord.Message | None = None
                self.busy = False

            async def interaction_check(self, interaction: discord.Interaction) -> bool:
                if interaction.user.id != int(owner_id):
                    await interaction.response.send_message("Only the configured Guardian owner can use this confirmation.", ephemeral=True)
                    return False
                return True

            async def on_timeout(self) -> None:
                for child in self.children:
                    child.disabled = True
                if self.message:
                    try:
                        await self.message.edit(view=self)
                    except discord.HTTPException:
                        pass

            @discord.ui.button(label="Confirm Global Ban", style=discord.ButtonStyle.danger)
            async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
                if self.busy:
                    await interaction.response.send_message("Already processing.", ephemeral=True)
                    return
                self.busy = True
                await interaction.response.defer(ephemeral=True, thinking=True)
                for child in self.children:
                    child.disabled = True
                try:
                    await interaction.message.edit(view=self)
                    summary = await cog.execute_globalban(target_id=target_id, reason=reason, actor_id=int(owner_id), source_guild_id=ctx.guild.id if ctx.guild else None)
                    await interaction.followup.send(embed=command_embed(summary, title="Guardian Global Ban • Complete"), ephemeral=True)
                except Exception:
                    import logging
                    logging.getLogger("esn_guardian").exception("Owner-confirmed global ban failed")
                    await interaction.followup.send("Global ban failed or was interrupted. Check Guardian logs before retrying.", ephemeral=True)
                self.stop()

            @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
            async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
                for child in self.children:
                    child.disabled = True
                await interaction.response.edit_message(content="Guardian global ban cancelled. No ban executed.", view=self)
                self.stop()

        view = ConfirmBan()
        embed = command_embed(f"**Target:** <@{target_id}> (`{target_id}`)\n**Reason:** {discord.utils.escape_mentions(reason)[:800]}\n**Scope:** Every connected Guardian server\n\n**No ban occurs until you confirm.**", title="ESN Guardian • Owner Global Ban Confirmation")
        view.message = await ctx.reply(embed=embed, view=view, mention_author=False, allowed_mentions=discord.AllowedMentions.none())


    async def _forward_advanced_code(self, ctx: commands.Context, number: int, *args: str) -> None:
        if ctx.author.id != int(getattr(self.bot.settings, "owner_id", 0) or 0):
            return
        cog = self.bot.get_cog("OwnerCodesAdvanced")
        group = getattr(cog, "esngx", None) if cog else None
        cmd = group.get_command(str(number)) if group else None
        if cmd is None:
            return await ctx.reply("Guardian advanced owner controls are unavailable.", mention_author=False)
        await ctx.invoke(cmd, *args)

    @esng_code.command(name="39")
    async def esng_code_39(self, ctx, target: str, *, reason: str = "Owner shadow restriction"): await self._forward_advanced_code(ctx,39,target,reason)
    @esng_code.command(name="40")
    async def esng_code_40(self, ctx, target: str): await self._forward_advanced_code(ctx,40,target)
    @esng_code.command(name="41")
    async def esng_code_41(self, ctx, target: str, *, reason: str): await self._forward_advanced_code(ctx,41,target,reason)
    @esng_code.command(name="42")
    async def esng_code_42(self, ctx, strike_id: int): await self._forward_advanced_code(ctx,42,str(strike_id))
    @esng_code.command(name="43")
    async def esng_code_43(self, ctx, target: str, *, note: str): await self._forward_advanced_code(ctx,43,target,note)
    @esng_code.command(name="44")
    async def esng_code_44(self, ctx, target: str, scope: str, minutes: int = 30): await self._forward_advanced_code(ctx,44,target,scope,str(minutes))
    @esng_code.command(name="45")
    async def esng_code_45(self, ctx, clearance_id: int): await self._forward_advanced_code(ctx,45,str(clearance_id))
    @esng_code.command(name="46")
    async def esng_code_46(self, ctx, guild_id: int, *, message: str = "The Guardian bot owner is requesting contact."): await self._forward_advanced_code(ctx,46,str(guild_id),message)
    @esng_code.command(name="47")
    async def esng_code_47(self, ctx, target: str): await self._forward_advanced_code(ctx,47,target)
    @esng_code.command(name="48")
    async def esng_code_48(self, ctx, target: str): await self._forward_advanced_code(ctx,48,target)
    @esng_code.command(name="49")
    async def esng_code_49(self, ctx, target: str): await self._forward_advanced_code(ctx,49,target)
    @esng_code.command(name="50")
    async def esng_code_50(self, ctx, target: str): await self._forward_advanced_code(ctx,50,target)
    @esng_code.command(name="51")
    async def esng_code_51(self, ctx, target: str, *, alert: str): await self._forward_advanced_code(ctx,51,target,alert)
    @esng_code.command(name="52")
    async def esng_code_52(self, ctx, target: str): await self._forward_advanced_code(ctx,52,target)
    @esng_code.command(name="53")
    async def esng_code_53(self, ctx, target: str, hours: int): await self._forward_advanced_code(ctx,53,target,str(hours))
    @esng_code.command(name="54")
    async def esng_code_54(self, ctx, target: str): await self._forward_advanced_code(ctx,54,target)
    @esng_code.command(name="55")
    async def esng_code_55(self, ctx, order_number: str, target: str): await self._forward_advanced_code(ctx,55,order_number,target)
    @esng_code.command(name="56")
    async def esng_code_56(self, ctx, order_number: str): await self._forward_advanced_code(ctx,56,order_number)
    @esng_code.command(name="57")
    async def esng_code_57(self, ctx, target: str, *, message: str): await self._forward_advanced_code(ctx,57,target,message)
    @esng_code.command(name="58")
    async def esng_code_58(self, ctx, item_type: str, item_ref: str, hours: int, *, note: str = "Owner deadline"): await self._forward_advanced_code(ctx,58,item_type,item_ref,str(hours),note)
    @esng_code.command(name="59")
    async def esng_code_59(self, ctx, workflow: str, reference: str, *, reason: str): await self._forward_advanced_code(ctx,59,workflow,reference,reason)
    @esng_code.command(name="60")
    async def esng_code_60(self, ctx, target: str): await self._forward_advanced_code(ctx,60,target)


    async def _forward_research_code(self, ctx: commands.Context, number: int, query: str) -> None:
        if ctx.author.id != int(getattr(self.bot.settings, "owner_id", 0) or 0): return
        cog=self.bot.get_cog("OwnerResearch")
        cmd=cog.esngresearch.get_command(str(number)) if cog else None
        if cmd is None: return await ctx.reply("Guardian research engine is unavailable.",mention_author=False)
        await ctx.invoke(cmd,query=query)

    @esng_code.command(name="16")
    async def esng_code_16(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 16, query)

    @esng_code.command(name="17")
    async def esng_code_17(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 17, query)

    @esng_code.command(name="18")
    async def esng_code_18(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 18, query)

    @esng_code.command(name="19")
    async def esng_code_19(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 19, query)

    @esng_code.command(name="20")
    async def esng_code_20(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 20, query)

    @esng_code.command(name="21")
    async def esng_code_21(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 21, query)

    @esng_code.command(name="22")
    async def esng_code_22(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 22, query)

    @esng_code.command(name="23")
    async def esng_code_23(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 23, query)

    @esng_code.command(name="24")
    async def esng_code_24(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 24, query)

    @esng_code.command(name="25")
    async def esng_code_25(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 25, query)

    @esng_code.command(name="26")
    async def esng_code_26(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 26, query)

    @esng_code.command(name="27")
    async def esng_code_27(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 27, query)

    @esng_code.command(name="28")
    async def esng_code_28(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 28, query)

    @esng_code.command(name="29")
    async def esng_code_29(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 29, query)

    @esng_code.command(name="30")
    async def esng_code_30(self, ctx: commands.Context, *, query: str) -> None:
        await self._forward_research_code(ctx, 30, query)


    def _owner_prefix(self, ctx: commands.Context) -> bool:
        oid=getattr(self.bot.settings,"owner_id",None)
        return oid is not None and ctx.author.id==int(oid)

    def _target_id(self, raw: str) -> int | None:
        raw=raw.strip()
        if raw.startswith("<@") and raw.endswith(">"): raw=raw[2:-1].lstrip("!")
        return int(raw) if raw.isdecimal() and int(raw)>0 else None

    async def _appeal_restriction(self, uid: int):
        return await self.bot.database.fetchone("SELECT blocked,cooldown_until,reason,updated_at FROM omega_appeal_restrictions WHERE user_id=?", (uid,))

    @esng_code.command(name="31")
    async def esng_code_31(self, ctx: commands.Context, target: str, *, reason: str="Repeated or abusive appeals") -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        await self.bot.database.execute("INSERT INTO omega_appeal_restrictions(user_id,blocked,cooldown_until,reason,updated_by) VALUES(?,1,NULL,?,?) ON CONFLICT(user_id) DO UPDATE SET blocked=1,cooldown_until=NULL,reason=excluded.reason,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP",(uid,reason[:1000],ctx.author.id))
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}> (`{uid}`)\n**Appeal access:** BLOCKED\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}",title="ESNG CODE 31 • APPEAL BAN"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="32")
    async def esng_code_32(self, ctx: commands.Context, target: str) -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        await self.bot.database.execute("DELETE FROM omega_appeal_restrictions WHERE user_id=?",(uid,))
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}> (`{uid}`)\n**Appeal access:** RESTORED",title="ESNG CODE 32 • APPEAL UNBAN"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="33")
    async def esng_code_33(self, ctx: commands.Context, target: str) -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        rr=await self._appeal_restriction(uid); pending=await self.bot.database.fetchone("SELECT id FROM omega_global_appeals WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1",(uid,))
        state="ALLOWED"
        if rr and int(rr["blocked"] or 0): state="BLOCKED"
        elif rr and rr["cooldown_until"]: state=f"COOLDOWN UNTIL {rr['cooldown_until']} UTC"
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}> (`{uid}`)\n**Appeal access:** {state}\n**Pending appeal:** "+(f"#{pending['id']}" if pending else "None"),title="ESNG CODE 33 • APPEAL STATUS"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="34")
    async def esng_code_34(self, ctx: commands.Context, appeal_id: int, *, reason: str) -> None:
        if not self._owner_prefix(ctx): return
        row=await self.bot.database.fetchone("SELECT user_id FROM omega_global_appeals WHERE id=? AND status='pending'",(appeal_id,))
        if row is None: return await ctx.reply(embed=command_embed("That pending appeal was not found.",title="ESNG CODE 34 • REJECT APPEAL"),mention_author=False)
        await self.bot.database.execute("UPDATE omega_global_appeals SET status='denied',reviewed_by=?,review_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(ctx.author.id,reason[:1000],appeal_id))
        await self._notify_user_by_id(int(row["user_id"]),f"Your Guardian global-ban appeal #{appeal_id} was denied.\nReason: {reason[:1000]}")
        await ctx.reply(embed=command_embed(f"**Appeal:** #{appeal_id}\n**Decision:** DENIED\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}",title="ESNG CODE 34 • APPEAL REJECTED"),mention_author=False)

    @esng_code.command(name="35")
    async def esng_code_35(self, ctx: commands.Context, target: str, hours: int, *, reason: str="Owner appeal cooldown") -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        await self.bot.database.execute("INSERT INTO omega_appeal_restrictions(user_id,blocked,cooldown_until,reason,updated_by) VALUES(?,0,datetime('now', ?),?,?) ON CONFLICT(user_id) DO UPDATE SET blocked=0,cooldown_until=excluded.cooldown_until,reason=excluded.reason,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP",(uid,f"+{int(hours)} hours",reason[:1000],ctx.author.id))
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}>\n**Cooldown:** {hours} hour(s)\n**Reason:** {discord.utils.escape_mentions(reason)[:1000]}",title="ESNG CODE 35 • APPEAL COOLDOWN"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="36")
    async def esng_code_36(self, ctx: commands.Context, target: str) -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        ban=await self.bot.database.fetchone("SELECT reason FROM global_bans WHERE user_id=?",(uid,)); appeals=await self.bot.database.fetchone("SELECT COUNT(*) AS n FROM omega_global_appeals WHERE user_id=?",(uid,)); pending=await self.bot.database.fetchone("SELECT COUNT(*) AS n FROM omega_global_appeals WHERE user_id=? AND status='pending'",(uid,)); rr=await self._appeal_restriction(uid)
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}> (`{uid}`)\n**Global ban:** {'ACTIVE' if ban else 'None'}\n**Ban reason:** {discord.utils.escape_mentions(str(ban['reason']))[:600] if ban else '—'}\n**Appeals:** {appeals['n']} total • {pending['n']} pending\n**Appeal restriction:** {'BLOCKED' if rr and int(rr['blocked'] or 0) else 'Configured' if rr else 'None'}",title="ESNG CODE 36 • GUARDIAN USER FILE"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="37")
    async def esng_code_37(self, ctx: commands.Context, target: str, *, reason: str) -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        cur=await self.bot.database.fetchone("SELECT user_id FROM global_bans WHERE user_id=?",(uid,))
        if cur is None: return await ctx.reply(embed=command_embed("That user does not have an active Guardian global ban.",title="ESNG CODE 37 • REASON EDIT"),mention_author=False)
        await self.bot.database.execute("UPDATE global_bans SET reason=? WHERE user_id=?",(reason[:1500],uid)); self._global_bans[uid]=reason[:1500]
        await ctx.reply(embed=command_embed(f"**User:** <@{uid}>\n**New reason:** {discord.utils.escape_mentions(reason)[:1500]}",title="ESNG CODE 37 • BAN REASON UPDATED"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @esng_code.command(name="38")
    async def esng_code_38(self, ctx: commands.Context, target: str) -> None:
        if not self._owner_prefix(ctx): return
        uid=self._target_id(target)
        if uid is None: return await ctx.reply("Provide a user mention or numeric Discord user ID.",mention_author=False)
        ban=await self.bot.database.fetchone("SELECT reason,banned_by_id FROM global_bans WHERE user_id=?",(uid,))
        body=f"**User:** <@{uid}> (`{uid}`)\n**Global ban:** "+("ACTIVE\n**Reason:** "+discord.utils.escape_mentions(str(ban["reason"]))[:1200] if ban else "NOT ACTIVE")
        await ctx.reply(embed=command_embed(body,title="ESNG CODE 38 • GLOBAL BAN STATUS"),mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @app_commands.command(name="esng-codex", description="Open Guardian's private interactive Owner Code Codex.")
    @owner_only()
    async def esng_codex(self, interaction: discord.Interaction) -> None:
        pages = [
            ("ESNG OWNER CODEX • 1/9", "**1** Guardian Status — READ ONLY\n**2** Global Investigation — READ ONLY\n**3** Global Ban — CONFIRMATION REQUIRED\n**4** Global Unban — use audited /globalunban\n**5** Server Intel — READ ONLY"),
            ("ESNG OWNER CODEX • 2/9", "**6** Emergency Lockdown — use existing audited protection controls\n**7** Release Lockdown — use /protection release\n**8** Evidence File — READ ONLY\n**9** Global Ban Preview — use /globalbanpreview\n**10** Network Pulse — READ ONLY"),
            ("ESNG OWNER CODEX • 3/9", "**11** Command Repair — use /synccommands\n**12** Trust File — READ ONLY\n**13** Case Command Center — READ ONLY\n**14** Deployment Report — READ ONLY\n**15** Network Emergency View — READ ONLY"),
            ("ESNG OWNER CODEX • 4/9", "**16** Web Hunter — public web search\n**17** Deep Research — multi-page research\n**18** Project Finder — projects, GitHub, docs, communities\n**19** GitHub Hunter — public repositories\n**20** News Scanner — recent web/news search"),
            ("ESNG OWNER CODEX • 5/9", "**21** Error Hunter — errors, docs, issues and fixes\n**22** Documentation Hunter — official docs/guides\n**23** Price Hunter — public price/listing research\n**24** Website Intel — public website/SEO research\n**25** Competitor Scan — similar public projects"),
            ("ESNG OWNER CODEX • 6/9", "**26** Resource Hunter — free/open-source resources\n**27** Source Check — supporting/contradicting sources\n**28** Update Scanner — releases and changelogs\n**29** Build Research — libraries and implementations\n**30** Research MAX — broad deep public-web research"),
            ("ESNG OWNER CODEX • 7/9", "**31** Appeal Ban — block future appeals\n**32** Appeal Unban — restore appeal access\n**33** Appeal Status — restriction + pending state\n**34** Reject Appeal — deny a pending appeal\n**35** Appeal Cooldown — temporary appeal restriction"),
            ("ESNG OWNER CODEX • 8/9", "**36** Guardian User File — ban + appeal overview\n**37** Global Ban Reason Edit — update stored reason\n**38** Global Ban Status — inspect active ban\n**39** Shadow restriction\n**40** Remove shadow restriction"),
            ("ESNG OWNER CODEX • 9/9", "**41** Add strike\n**42** Forgive strike\n**43** Permanent owner record\n**44** Temporary clearance\n**45** Revoke clearance\n**46** Summon server owner\n**47** Network mute\n**48** Network unmute\n**49** Hold requests\n**50** Release hold\n**51** Owner alert\n**52** Clear alert\n**53** Expiring restriction\n**54** Guardian pardon\n**55** Transfer assignment\n**56** Owner takeover\n**57** Summon staff\n**58** Deadline\n**59** Override review\n**60** GODFILE — primary owner only"),
        ]
        owner_id = int(self.bot.settings.owner_id)
        class CodexView(discord.ui.View):
            def __init__(self):
                super().__init__(timeout=180); self.page=0; self.refresh()
            def refresh(self):
                self.previous.disabled=self.page == 0; self.next.disabled=self.page == len(pages)-1
            def make_embed(self):
                title, body = pages[self.page]
                return command_embed(body + "\n\n**Owner syntax:** `!esng code <number> [target]`", title=title)
            async def interaction_check(self, i):
                if i.user.id != owner_id:
                    await i.response.send_message("This Owner Codex is private.", ephemeral=True); return False
                return True
            @discord.ui.button(label="Previous", emoji="◀️", style=discord.ButtonStyle.secondary)
            async def previous(self, i, button):
                self.page=max(0,self.page-1); self.refresh(); await i.response.edit_message(embed=self.make_embed(),view=self)
            @discord.ui.button(label="Next", emoji="▶️", style=discord.ButtonStyle.primary)
            async def next(self, i, button):
                self.page=min(len(pages)-1,self.page+1); self.refresh(); await i.response.edit_message(embed=self.make_embed(),view=self)
        view=CodexView()
        await interaction.response.send_message(embed=view.make_embed(), view=view, ephemeral=True)

    @app_commands.command(description="Preview global ban coverage without banning anyone.")
    @owner_only()
    async def globalbanpreview(self, interaction: discord.Interaction, user_id: str) -> None:
        try:
            target_id = int(user_id)
            if target_id <= 0:
                raise ValueError()
        except ValueError:
            await respond(interaction, "Provide a valid numeric Discord user ID.")
            return
        reachable = sum(1 for guild in self.bot.guilds if guild.me is not None and guild.me.guild_permissions.ban_members)
        await respond(interaction, f"**Global ban preview** for `{target_id}`\\n"
                      f"Connected servers: {len(self.bot.guilds)}\\n"
                      f"Servers with Ban Members permission: {reachable}\\n"
                      "Role hierarchy, rate limits and API failures may still prevent enforcement. No bans performed.")

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild) -> None:
        """Synchronize the existing global-ban list when Guardian joins a new guild."""
        if await self.bot.database.is_guild_blacklisted(guild.id):
            return
        for user_id, reason in list(self._global_bans.items()):
            try:
                await guild.ban(discord.Object(id=user_id),
                                reason=f"ESN Guardian existing global ban: {reason[:300]}",
                                delete_message_seconds=0)
            except (discord.Forbidden, discord.HTTPException):
                continue

    @app_commands.command(description="Remove a user from the global-ban list.")
    @owner_only()
    async def globalunban(self, interaction: discord.Interaction, user_id: str) -> None:
        try:
            target_id = int(user_id)
        except ValueError:
            await respond(interaction, "Provide a numeric user ID.")
            return
        await defer_response(interaction)
        await self.bot.database.execute("DELETE FROM global_bans WHERE user_id = ?", (target_id,))
        self._global_bans.pop(target_id, None)
        unbanned = 0
        failed = 0
        target = discord.Object(id=target_id)
        for guild in self.bot.guilds:
            outcome = "not_banned"
            try:
                await guild.unban(target, reason="ESN Guardian global ban removed")
                unbanned += 1
                outcome = "unbanned"
            except discord.NotFound:
                outcome = "not_banned"
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
                outcome = "failed"
            v7 = self.bot.get_cog("SecurityV7Cog")
            if v7 is not None and hasattr(v7, "_evidence"):
                try:
                    await v7._evidence(
                        guild.id,
                        interaction.user.id,
                        "GLOBAL_BAN_REMOVAL",
                        target_id,
                        {"outcome": outcome, "source": "bot_owner_globalunban"},
                    )
                except Exception:
                    pass
        await self._notify_user_by_id(target_id, "Your ESN Guardian global ban has been removed.")
        await respond(interaction, f"Removed `{target_id}` from the global-ban list. Unbanned in {unbanned} server(s); failed in {failed}.")

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        reason = self._global_bans.get(member.id)
        if reason is None:
            return
        try:
            await member.guild.ban(member, reason=f"ESN Guardian global ban: {reason}", delete_message_seconds=0)
        except (discord.Forbidden, discord.HTTPException):
            return

    @commands.group(name='broadcast', invoke_without_command=True)\n    async def broadcast_prefix(self, ctx: commands.Context) -> None:\n        if ctx.author.id != int(getattr(self.bot.settings, 'owner_id', 0) or 0): return\n        await ctx.reply('Use `!broadcast create normal <message>` or `!broadcast create important <message>`.', mention_author=False)\n\n    @broadcast_prefix.command(name='create')\n    async def broadcast_create(self, ctx: commands.Context, priority: str, *, message: str) -> None:\n        if ctx.author.id != int(getattr(self.bot.settings, 'owner_id', 0) or 0): return\n        priority=priority.lower().strip()\n        if priority not in {'normal','important'}: return await ctx.reply('Priority must be `normal` or `important`.', mention_author=False)\n        title='ESN GUARDIAN • IMPORTANT BROADCAST' if priority=='important' else 'ESN GUARDIAN • NETWORK BROADCAST'\n        embed=command_embed(discord.utils.escape_mentions(message)[:3900], title=title)\n        seen=set(); dm_ok=dm_fail=channel_ok=0\n        for guild in list(self.bot.guilds):\n            recipients=[]\n            if guild.owner: recipients.append(guild.owner)\n            recipients.extend(x for x in guild.members if not x.bot and x.guild_permissions.administrator)\n            for member in recipients:\n                if member.id in seen: continue\n                seen.add(member.id)\n                try: await member.send(embed=embed, allowed_mentions=discord.AllowedMentions.none()); dm_ok+=1\n                except (discord.Forbidden, discord.HTTPException): dm_fail+=1\n            try:\n                settings=await self.bot.database.setting(guild.id); ids=[]\n                for key in ('system_log_channel_id','command_log_channel_id'):\n                    cid=settings[key] if key in settings.keys() else None\n                    if cid and cid not in ids: ids.append(cid)\n                for cid in ids:\n                    channel=guild.get_channel(cid)\n                    if isinstance(channel, discord.TextChannel):\n                        try: await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none()); channel_ok+=1\n                        except discord.HTTPException: pass\n            except Exception: pass\n        await ctx.reply(embed=command_embed(f'Priority: **{priority.upper()}**\\nOwner/admin DMs: **{dm_ok}** delivered • **{dm_fail}** unavailable\\nConfigured channels: **{channel_ok}** delivered\\nServers scanned: **{len(self.bot.guilds)}**', title='Guardian Broadcast • Complete'), mention_author=False)\n\n    @app_commands.command(description="Send an announcement to configured system log channels.")
    @owner_only()
    async def broadcast(self, interaction: discord.Interaction, message: str) -> None:
        await defer_response(interaction)
        delivered = 0
        for guild in self.bot.guilds:
            settings = await self.bot.database.setting(guild.id)
            channel = guild.get_channel(settings["system_log_channel_id"]) if settings["system_log_channel_id"] else None
            if isinstance(channel, discord.TextChannel):
                try:
                    await channel.send(message, allowed_mentions=discord.AllowedMentions.none())
                    delivered += 1
                except discord.HTTPException:
                    continue
        await respond(interaction, f"Broadcast delivered to {delivered} configured system channels.")

    @app_commands.command(description="Enable or disable maintenance mode notice.")
    @owner_only()
    async def maintenance(self, interaction: discord.Interaction, enabled: bool) -> None:
        await self.bot.database.set_state_enabled("maintenance", enabled)
        notification = (
            "ESN Guardian maintenance has started. Normal server commands are temporarily unavailable."
            if enabled
            else "ESN Guardian maintenance has ended. Normal server commands are available again."
        )
        delivered = 0
        for user_id in await self.bot.database.status_subscriber_ids("bot"):
            if user_id == interaction.user.id:
                continue
            if await self._notify_user_by_id(user_id, notification):
                delivered += 1
        await respond(interaction, f"Maintenance mode {'enabled' if enabled else 'disabled'}. Notified {delivered} bot-status subscriber(s). Use `/broadcast` to communicate the change in servers.")


    @app_commands.command(description="Block a server from using the bot.")
    @owner_only()
    async def blacklist(self, interaction: discord.Interaction, guild_id: str, reason: str) -> None:
        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(interaction, "Provide a numeric server ID.")
            return
        await self.bot.database.blacklist_guild(target_id, reason)
        guild = self.bot.get_guild(target_id)
        if guild is not None:
            if guild.owner is not None:
                await notify_user(
                    guild.owner,
                    f"ESN Guardian has blacklisted **{guild.name}** (`{guild.id}`) and will now leave the server.\nReason: {reason}",
                )
            await guild.leave()
        await respond(interaction, f"Blacklisted server `{target_id}`.")

    @app_commands.command(description="Remove a server from the bot blacklist.")
    @owner_only()
    async def unblacklist(self, interaction: discord.Interaction, guild_id: str) -> None:
        try:
            target_id = int(guild_id)
        except ValueError:
            await respond(interaction, "Provide a numeric server ID.")
            return
        await self.bot.database.unblacklist_guild(target_id)
        await respond(interaction, f"Removed server `{target_id}` from the blacklist.")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(OwnerCog(bot))
