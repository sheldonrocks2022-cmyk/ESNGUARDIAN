"""Guardian V8 Luxury operations: configurable tickets, applications and Staff Academy."""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, staff_only

LUXURY_BLUE = discord.Color(0x0B3D91)


def luxury(title: str, body: str, guild: discord.Guild | None = None) -> discord.Embed:
    embed = discord.Embed(title=f"✦ {title}", description=body[:4096], color=LUXURY_BLUE, timestamp=datetime.now(UTC))
    if guild is not None:
        if guild.icon:
            embed.set_author(name=f"ESN GUARDIAN  •  {guild.name}", icon_url=guild.icon.url)
            embed.set_thumbnail(url=guild.icon.url)
        else:
            embed.set_author(name=f"ESN GUARDIAN  •  {guild.name}")
    embed.set_footer(text="ESN GUARDIAN  •  V8 LUXURY")
    return embed


async def respond(interaction: discord.Interaction, title: str, body: str, *, ephemeral: bool = True) -> None:
    embed = luxury(title, body, interaction.guild)
    if interaction.response.is_done():
        await interaction.followup.send(embed=embed, ephemeral=ephemeral)
    else:
        await interaction.response.send_message(embed=embed, ephemeral=ephemeral)


async def install_schema(bot: commands.Bot) -> None:
    statements = (
        """CREATE TABLE IF NOT EXISTS luxury_ticket_config (
            guild_id INTEGER PRIMARY KEY, staff_role_id INTEGER, category_id INTEGER,
            log_channel_id INTEGER, max_tickets INTEGER NOT NULL DEFAULT 3)""",
        """CREATE TABLE IF NOT EXISTS luxury_tickets (
            ticket_id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL, channel_id INTEGER UNIQUE, subject TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open', claimed_by INTEGER,
            priority TEXT NOT NULL DEFAULT 'normal', created_at REAL NOT NULL, closed_at REAL)""",
        """CREATE TABLE IF NOT EXISTS luxury_ticket_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL, note TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
        """CREATE TABLE IF NOT EXISTS luxury_application_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
            name TEXT NOT NULL, reviewer_role_id INTEGER, accepted_role_id INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1, questions_json TEXT NOT NULL DEFAULT '[]')""",
        """CREATE TABLE IF NOT EXISTS luxury_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
            type_id INTEGER NOT NULL, user_id INTEGER NOT NULL, answers_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', reviewer_id INTEGER, decision_note TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, decided_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS luxury_academy_config (
            guild_id INTEGER PRIMARY KEY, staff_role_id INTEGER,
            passing_score INTEGER NOT NULL DEFAULT 80, max_attempts INTEGER NOT NULL DEFAULT 3)""",
        """CREATE TABLE IF NOT EXISTS luxury_academy_courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
            name TEXT NOT NULL, content TEXT NOT NULL,
            published INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT 'manual')""",
    )
    for statement in statements:
        await bot.database.execute(statement)


class TicketModal(discord.ui.Modal, title="Create Guardian Ticket"):
    subject = discord.ui.TextInput(label="What do you need help with?", max_length=200)

    def __init__(self, cog: "GuardianOperations") -> None:
        super().__init__()
        self.cog = cog

    async def on_submit(self, interaction: discord.Interaction) -> None:
        await self.cog.open_ticket(interaction, str(self.subject))


class TicketPanel(discord.ui.View):
    def __init__(self, cog: "GuardianOperations") -> None:
        super().__init__(timeout=None)
        self.cog = cog

    @discord.ui.button(label="Open Ticket", emoji="🎫", style=discord.ButtonStyle.primary, custom_id="guardian:v8lux:ticket:open")
    async def open_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.send_modal(TicketModal(self.cog))


class TicketControls(discord.ui.View):
    def __init__(self, cog: "GuardianOperations") -> None:
        super().__init__(timeout=None)
        self.cog = cog

    @discord.ui.button(label="Claim", emoji="🛡️", style=discord.ButtonStyle.secondary, custom_id="guardian:v8lux:ticket:claim")
    async def claim_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self.cog.claim_ticket(interaction)

    @discord.ui.button(label="Close & Delete", emoji="🔒", style=discord.ButtonStyle.danger, custom_id="guardian:v8lux:ticket:close")
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self.cog.close_ticket(interaction)


class ApplyModal(discord.ui.Modal):
    def __init__(self, cog: "GuardianOperations", type_id: int, name: str, questions: list[str]) -> None:
        super().__init__(title=name[:45])
        self.cog = cog
        self.type_id = type_id
        self.inputs: list[discord.ui.TextInput] = []
        for question in questions[:5]:
            field = discord.ui.TextInput(label=question[:45], style=discord.TextStyle.paragraph, max_length=1000)
            self.inputs.append(field)
            self.add_item(field)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        await self.cog.save_application(interaction, self.type_id, [str(item) for item in self.inputs])


class GuardianOperations(commands.Cog):
    ticket = app_commands.Group(name="ticket", description="Guardian Luxury ticket system")
    application = app_commands.Group(name="application", description="Guardian Luxury application system")
    academy = app_commands.Group(name="academy", description="Guardian Staff Academy")

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        await install_schema(self.bot)
        self.bot.add_view(TicketPanel(self))
        self.bot.add_view(TicketControls(self))

    def is_staff(self, interaction: discord.Interaction, role_id: int | None = None) -> bool:
        member = interaction.user
        return isinstance(member, discord.Member) and (
            member.guild_permissions.manage_guild
            or bool(role_id and any(role.id == role_id for role in member.roles))
        )

    async def ticket_config(self, guild_id: int):
        return await self.bot.database.fetchone("SELECT * FROM luxury_ticket_config WHERE guild_id=?", (guild_id,))

    async def active_ticket(self, interaction: discord.Interaction):
        return await self.bot.database.fetchone(
            "SELECT * FROM luxury_tickets WHERE guild_id=? AND channel_id=? AND status='open'",
            (interaction.guild_id, interaction.channel_id),
        )

    async def open_ticket(self, interaction: discord.Interaction, subject: str) -> None:
        guild = interaction.guild
        if guild is None:
            return
        config = await self.ticket_config(guild.id)
        if config is None or not config["staff_role_id"]:
            await respond(interaction, "TICKETS", "Tickets have not been configured yet.")
            return
        count = await self.bot.database.fetchone(
            "SELECT COUNT(*) AS n FROM luxury_tickets WHERE guild_id=? AND user_id=? AND status='open'",
            (guild.id, interaction.user.id),
        )
        if count and int(count["n"]) >= int(config["max_tickets"]):
            await respond(interaction, "TICKETS", "You have reached this server's open-ticket limit.")
            return
        staff_role = guild.get_role(int(config["staff_role_id"]))
        if staff_role is None:
            await respond(interaction, "TICKETS", "The configured ticket staff role no longer exists.")
            return
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
            interaction.user: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
            staff_role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
            guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True, read_message_history=True),
        }
        category = guild.get_channel(int(config["category_id"])) if config["category_id"] else None
        try:
            channel = await guild.create_text_channel(
                f"ticket-{interaction.user.name}"[:90],
                category=category if isinstance(category, discord.CategoryChannel) else None,
                overwrites=overwrites,
                reason="Guardian V8 Luxury support ticket",
            )
        except discord.HTTPException:
            await respond(interaction, "TICKETS", "Guardian could not create the ticket. Check Manage Channels and role hierarchy.")
            return
        await self.bot.database.execute(
            "INSERT INTO luxury_tickets(guild_id,user_id,channel_id,subject,created_at) VALUES(?,?,?,?,?)",
            (guild.id, interaction.user.id, channel.id, subject, time.time()),
        )
        await channel.send(
            embed=luxury(
                "GUARDIAN SUPPORT",
                f"{interaction.user.mention}\n\n**Subject**\n{discord.utils.escape_markdown(subject)}\n\n"
                "Closing this ticket preserves its Guardian record and deletes this Discord channel.",
                guild,
            ),
            view=TicketControls(self),
        )
        await respond(interaction, "TICKET CREATED", f"Your private ticket is ready: {channel.mention}")

    async def claim_ticket(self, interaction: discord.Interaction) -> None:
        row = await self.active_ticket(interaction)
        config = await self.ticket_config(interaction.guild_id)
        if row is None or not self.is_staff(interaction, config["staff_role_id"] if config else None):
            await respond(interaction, "TICKETS", "Only configured ticket staff can claim an active ticket.")
            return
        await self.bot.database.execute("UPDATE luxury_tickets SET claimed_by=? WHERE ticket_id=?", (interaction.user.id, row["ticket_id"]))
        await respond(interaction, "TICKET CLAIMED", f"{interaction.user.mention} claimed this ticket.", ephemeral=False)

    async def close_ticket(self, interaction: discord.Interaction) -> None:
        row = await self.active_ticket(interaction)
        if row is None:
            await respond(interaction, "TICKETS", "This is not an active Guardian ticket.")
            return
        config = await self.ticket_config(interaction.guild_id)
        if interaction.user.id != row["user_id"] and not self.is_staff(interaction, config["staff_role_id"] if config else None):
            await respond(interaction, "TICKETS", "Only the ticket opener or configured staff can close this ticket.")
            return
        await self.bot.database.execute(
            "UPDATE luxury_tickets SET status='closed',channel_id=NULL,closed_at=? WHERE ticket_id=?",
            (time.time(), row["ticket_id"]),
        )
        if not interaction.response.is_done():
            await interaction.response.send_message(
                embed=luxury("TICKET CLOSED", "Ticket record preserved. Deleting this channel now.", interaction.guild),
                ephemeral=True,
            )
        try:
            await interaction.channel.delete(reason=f"Guardian ticket closed by {interaction.user.id}")
        except discord.HTTPException:
            await self.bot.database.execute(
                "UPDATE luxury_tickets SET status='open',channel_id=?,closed_at=NULL WHERE ticket_id=?",
                (interaction.channel_id, row["ticket_id"]),
            )

    @ticket.command(name="create", description="Open a private Guardian support ticket.")
    @guild_only()
    async def ticket_create(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_modal(TicketModal(self))

    @ticket.command(name="panel", description="Publish the Luxury ticket panel.")
    @guild_only()
    @staff_only()
    async def ticket_panel(self, interaction: discord.Interaction) -> None:
        await interaction.channel.send(
            embed=luxury("GUARDIAN SUPPORT CENTER", "Press **Open Ticket** for private support.", interaction.guild),
            view=TicketPanel(self),
        )
        await respond(interaction, "TICKET PANEL", "Luxury ticket panel published.")

    @ticket.command(name="configure", description="Configure Guardian tickets.")
    @guild_only()
    @staff_only()
    async def ticket_configure(
        self, interaction: discord.Interaction, staff_role: discord.Role,
        category: discord.CategoryChannel | None = None,
        log_channel: discord.TextChannel | None = None,
        max_tickets: app_commands.Range[int, 1, 10] = 3,
    ) -> None:
        await self.bot.database.execute(
            """INSERT INTO luxury_ticket_config(guild_id,staff_role_id,category_id,log_channel_id,max_tickets)
            VALUES(?,?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET
            staff_role_id=excluded.staff_role_id,category_id=excluded.category_id,
            log_channel_id=excluded.log_channel_id,max_tickets=excluded.max_tickets""",
            (interaction.guild_id, staff_role.id, category.id if category else None, log_channel.id if log_channel else None, max_tickets),
        )
        await respond(interaction, "TICKET CONFIGURATION", f"Staff: {staff_role.mention}\nMaximum open tickets: **{max_tickets}**")

    @ticket.command(name="claim", description="Claim the current ticket.")
    @guild_only()
    async def ticket_claim_command(self, interaction: discord.Interaction) -> None:
        await self.claim_ticket(interaction)

    @ticket.command(name="close", description="Close this ticket and delete its Discord channel.")
    @guild_only()
    async def ticket_close_command(self, interaction: discord.Interaction) -> None:
        await self.close_ticket(interaction)

    @ticket.command(name="note", description="Add a private staff note to this ticket.")
    @guild_only()
    async def ticket_note(self, interaction: discord.Interaction, note: app_commands.Range[str, 1, 1000]) -> None:
        row = await self.active_ticket(interaction)
        config = await self.ticket_config(interaction.guild_id)
        if row is None or not self.is_staff(interaction, config["staff_role_id"] if config else None):
            await respond(interaction, "TICKET NOTES", "Only ticket staff can add notes inside an active ticket.")
            return
        await self.bot.database.execute(
            "INSERT INTO luxury_ticket_notes(ticket_id,author_id,note) VALUES(?,?,?)",
            (row["ticket_id"], interaction.user.id, note),
        )
        await respond(interaction, "PRIVATE NOTE", "The staff note was stored in Guardian's ticket record.")

    @application.command(name="type-create", description="Create a configurable application type.")
    @guild_only()
    @staff_only()
    async def application_type_create(
        self, interaction: discord.Interaction, name: app_commands.Range[str, 1, 80],
        reviewer_role: discord.Role, accepted_role: discord.Role | None = None,
    ) -> None:
        await self.bot.database.execute(
            "INSERT INTO luxury_application_types(guild_id,name,reviewer_role_id,accepted_role_id) VALUES(?,?,?,?)",
            (interaction.guild_id, name, reviewer_role.id, accepted_role.id if accepted_role else None),
        )
        await respond(interaction, "APPLICATION TYPE CREATED", f"**{name}** is ready. Add questions with **/application question-add**.")

    @application.command(name="question-add", description="Add a question to an application type.")
    @guild_only()
    @staff_only()
    async def application_question_add(
        self, interaction: discord.Interaction, application_id: int,
        question: app_commands.Range[str, 1, 100],
    ) -> None:
        row = await self.bot.database.fetchone(
            "SELECT * FROM luxury_application_types WHERE id=? AND guild_id=?",
            (application_id, interaction.guild_id),
        )
        if row is None:
            await respond(interaction, "APPLICATIONS", "Application type not found.")
            return
        questions = json.loads(row["questions_json"] or "[]")
        if len(questions) >= 5:
            await respond(interaction, "APPLICATIONS", "This application already has five questions.")
            return
        questions.append(question)
        await self.bot.database.execute(
            "UPDATE luxury_application_types SET questions_json=? WHERE id=?",
            (json.dumps(questions), application_id),
        )
        await respond(interaction, "QUESTION ADDED", f"Question **{len(questions)}** added to **{row['name']}**.")

    @application.command(name="apply", description="Start a configured Guardian application.")
    @guild_only()
    async def application_apply(self, interaction: discord.Interaction, application_id: int) -> None:
        row = await self.bot.database.fetchone(
            "SELECT * FROM luxury_application_types WHERE id=? AND guild_id=? AND enabled=1",
            (application_id, interaction.guild_id),
        )
        if row is None:
            await respond(interaction, "APPLICATIONS", "That application is unavailable.")
            return
        questions = json.loads(row["questions_json"] or "[]")
        if not questions:
            await respond(interaction, "APPLICATIONS", "That application has no questions configured yet.")
            return
        await interaction.response.send_modal(ApplyModal(self, int(row["id"]), str(row["name"]), questions))

    async def save_application(self, interaction: discord.Interaction, type_id: int, answers: list[str]) -> None:
        pending = await self.bot.database.fetchone(
            "SELECT id FROM luxury_applications WHERE guild_id=? AND type_id=? AND user_id=? AND status='pending'",
            (interaction.guild_id, type_id, interaction.user.id),
        )
        if pending:
            await respond(interaction, "APPLICATIONS", f"You already have pending application **#{pending['id']}**.")
            return
        await self.bot.database.execute(
            "INSERT INTO luxury_applications(guild_id,type_id,user_id,answers_json) VALUES(?,?,?,?)",
            (interaction.guild_id, type_id, interaction.user.id, json.dumps(answers)),
        )
        row = await self.bot.database.fetchone(
            "SELECT id FROM luxury_applications WHERE guild_id=? AND type_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
            (interaction.guild_id, type_id, interaction.user.id),
        )
        await respond(interaction, "APPLICATION SUBMITTED", f"Application **#{row['id']}** was submitted for review.")

    @application.command(name="review", description="Review a Guardian application.")
    @guild_only()
    async def application_review(self, interaction: discord.Interaction, application_id: int) -> None:
        row = await self.bot.database.fetchone(
            """SELECT a.*,t.name,t.reviewer_role_id,t.questions_json FROM luxury_applications a
            JOIN luxury_application_types t ON t.id=a.type_id WHERE a.id=? AND a.guild_id=?""",
            (application_id, interaction.guild_id),
        )
        if row is None or not self.is_staff(interaction, row["reviewer_role_id"]):
            await respond(interaction, "APPLICATION REVIEW", "Application not found or you are not an authorized reviewer.")
            return
        questions = json.loads(row["questions_json"])
        answers = json.loads(row["answers_json"])
        details = "\n\n".join(f"**{q}**\n{a}" for q, a in zip(questions, answers))
        await respond(interaction, f"APPLICATION #{application_id}", f"Applicant: <@{row['user_id']}>\nStatus: **{row['status']}**\n\n{details}")

    async def decide_application(self, interaction: discord.Interaction, application_id: int, status: str, note: str) -> None:
        row = await self.bot.database.fetchone(
            """SELECT a.*,t.name,t.reviewer_role_id,t.accepted_role_id FROM luxury_applications a
            JOIN luxury_application_types t ON t.id=a.type_id WHERE a.id=? AND a.guild_id=?""",
            (application_id, interaction.guild_id),
        )
        if row is None or not self.is_staff(interaction, row["reviewer_role_id"]):
            await respond(interaction, "APPLICATION REVIEW", "Application not found or you are not an authorized reviewer.")
            return
        if row["status"] != "pending":
            await respond(interaction, "APPLICATION REVIEW", f"This application is already **{row['status']}**.")
            return
        await self.bot.database.execute(
            "UPDATE luxury_applications SET status=?,reviewer_id=?,decision_note=?,decided_at=CURRENT_TIMESTAMP WHERE id=?",
            (status, interaction.user.id, note, application_id),
        )
        member = interaction.guild.get_member(int(row["user_id"]))
        if status == "accepted" and member and row["accepted_role_id"]:
            role = interaction.guild.get_role(int(row["accepted_role_id"]))
            if role:
                try:
                    await member.add_roles(role, reason=f"Guardian application #{application_id} accepted")
                except discord.HTTPException:
                    pass
        if member:
            try:
                await member.send(embed=luxury(f"APPLICATION {status.upper()}", f"**{row['name']}**\n{note or 'No reviewer note.'}", interaction.guild))
            except discord.HTTPException:
                pass
        await respond(interaction, "APPLICATION DECIDED", f"Application **#{application_id}** was **{status}**.")

    @application.command(name="accept", description="Accept a pending application.")
    @guild_only()
    async def application_accept(self, interaction: discord.Interaction, application_id: int, note: str = "") -> None:
        await self.decide_application(interaction, application_id, "accepted", note)

    @application.command(name="deny", description="Deny a pending application.")
    @guild_only()
    async def application_deny(self, interaction: discord.Interaction, application_id: int, reason: app_commands.Range[str, 1, 500]) -> None:
        await self.decide_application(interaction, application_id, "denied", reason)

    @academy.command(name="configure", description="Configure Guardian Staff Academy.")
    @guild_only()
    @staff_only()
    async def academy_configure(
        self, interaction: discord.Interaction, staff_role: discord.Role,
        passing_score: app_commands.Range[int, 1, 100] = 80,
        max_attempts: app_commands.Range[int, 1, 20] = 3,
    ) -> None:
        await self.bot.database.execute(
            """INSERT INTO luxury_academy_config(guild_id,staff_role_id,passing_score,max_attempts)
            VALUES(?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET
            staff_role_id=excluded.staff_role_id,passing_score=excluded.passing_score,
            max_attempts=excluded.max_attempts""",
            (interaction.guild_id, staff_role.id, passing_score, max_attempts),
        )
        await respond(interaction, "STAFF ACADEMY CONFIGURED", f"Staff: {staff_role.mention}\nPassing score: **{passing_score}%**\nMaximum attempts: **{max_attempts}**")

    @academy.command(name="scan", description="Read server structure and propose server-specific staff training.")
    @guild_only()
    @staff_only()
    async def academy_scan(self, interaction: discord.Interaction) -> None:
        guild = interaction.guild
        relevant = [
            channel for channel in guild.text_channels
            if any(word in channel.name.lower() for word in ("rule", "staff", "info", "ticket", "support", "mod"))
        ][:12]
        roles = [role for role in reversed(guild.roles) if not role.is_default() and not role.managed][:15]
        channels_text = "\n".join(channel.mention for channel in relevant) or "None identified"
        roles_text = "\n".join(role.mention for role in roles) or "None identified"
        body = (
            f"**Read-only server training scan**\n"
            f"Channels: **{len(guild.channels)}** • Roles: **{len(guild.roles)-1}** • Members: **{guild.member_count or 0}**\n\n"
            f"**Relevant channels**\n{channels_text}\n\n**Role structure**\n{roles_text}\n\n"
            "Guardian treats this as proposed training context only. Staff must approve official course content."
        )
        await respond(interaction, "ACADEMY SCAN", body)

    @academy.command(name="course-create", description="Create a Staff Academy course.")
    @guild_only()
    @staff_only()
    async def academy_course_create(
        self, interaction: discord.Interaction,
        name: app_commands.Range[str, 1, 80], content: app_commands.Range[str, 1, 3000],
    ) -> None:
        await self.bot.database.execute(
            "INSERT INTO luxury_academy_courses(guild_id,name,content) VALUES(?,?,?)",
            (interaction.guild_id, name, content),
        )
        await respond(interaction, "COURSE CREATED", f"**{name}** was saved as an Academy draft.")

    @academy.command(name="course-publish", description="Publish a Staff Academy course.")
    @guild_only()
    @staff_only()
    async def academy_course_publish(self, interaction: discord.Interaction, course_id: int) -> None:
        row = await self.bot.database.fetchone(
            "SELECT id FROM luxury_academy_courses WHERE id=? AND guild_id=?",
            (course_id, interaction.guild_id),
        )
        if row is None:
            await respond(interaction, "STAFF ACADEMY", "Course not found.")
            return
        await self.bot.database.execute("UPDATE luxury_academy_courses SET published=1 WHERE id=?", (course_id,))
        await respond(interaction, "COURSE PUBLISHED", f"Academy course **#{course_id}** is now available.")

    @academy.command(name="train", description="Open a published Staff Academy course.")
    @guild_only()
    async def academy_train(self, interaction: discord.Interaction, course_id: int) -> None:
        config = await self.bot.database.fetchone("SELECT * FROM luxury_academy_config WHERE guild_id=?", (interaction.guild_id,))
        if config is None or not self.is_staff(interaction, config["staff_role_id"]):
            await respond(interaction, "STAFF ACADEMY", "You are not assigned to this server's Academy staff role.")
            return
        course = await self.bot.database.fetchone(
            "SELECT * FROM luxury_academy_courses WHERE id=? AND guild_id=? AND published=1",
            (course_id, interaction.guild_id),
        )
        if course is None:
            await respond(interaction, "STAFF ACADEMY", "Published course not found.")
            return
        await respond(interaction, f"ACADEMY • {course['name']}", str(course["content"]))


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(GuardianOperations(bot))
