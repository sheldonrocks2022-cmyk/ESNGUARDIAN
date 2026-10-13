"""Guardian V8 Luxury onboarding, server identity and Wrapped."""
from __future__ import annotations

import calendar
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import guild_only, staff_only

BLUE = discord.Color(0x0B3D91)


def brand(guild: discord.Guild, title: str, body: str) -> discord.Embed:
    embed = discord.Embed(title=f"✦ {title}", description=body[:4096], color=BLUE, timestamp=datetime.now(UTC))
    if guild.icon:
        embed.set_author(name=f"ESN GUARDIAN  •  {guild.name}", icon_url=guild.icon.url)
        embed.set_thumbnail(url=guild.icon.url)
    else:
        embed.set_author(name=f"ESN GUARDIAN  •  {guild.name}")
    embed.set_footer(text="ESN GUARDIAN  •  V8 LUXURY")
    return embed


async def reply(interaction: discord.Interaction, title: str, body: str, *, view: discord.ui.View | None = None) -> None:
    kwargs = {"embed": brand(interaction.guild, title, body), "ephemeral": True}
    if view is not None:
        kwargs["view"] = view
    try:
        if interaction.response.is_done():
            await interaction.followup.send(**kwargs)
        else:
            await interaction.response.send_message(**kwargs)
    except (discord.NotFound, discord.HTTPException):
        return


class SetupSelect(discord.ui.Select):
    def __init__(self, cog: "GuardianExperience") -> None:
        self.cog = cog
        super().__init__(
            placeholder="Choose a Guardian system…",
            custom_id="guardian:v8lux:journey:select",
            options=[
                discord.SelectOption(label="Support", value="support", emoji="🎫"),
                discord.SelectOption(label="Applications", value="applications", emoji="📝"),
                discord.SelectOption(label="Staff Academy", value="academy", emoji="🎓"),
                discord.SelectOption(label="Service Queue", value="service", emoji="📦"),
                discord.SelectOption(label="Reputation & Vouch Wall", value="reputation", emoji="⭐"),
            ],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        await self.cog.show_setup_step(interaction, self.values[0])


class SetupJourneyView(discord.ui.View):
    def __init__(self, cog: "GuardianExperience") -> None:
        super().__init__(timeout=None)
        self.add_item(SetupSelect(cog))

    @discord.ui.button(label="Refresh Progress", emoji="↻", style=discord.ButtonStyle.secondary, custom_id="guardian:v8lux:journey:refresh")
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self.cog.send_setup_journey(interaction)

    @discord.ui.button(label="Guardian Welcome", emoji="🛡️", style=discord.ButtonStyle.primary, custom_id="guardian:v8lux:journey:welcome")
    async def welcome(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self.cog.send_welcome(interaction)


class WelcomeView(discord.ui.View):
    def __init__(self, cog: "GuardianExperience") -> None:
        super().__init__(timeout=None)
        self.cog = cog

    @discord.ui.button(label="Start Setup Journey", emoji="🚀", style=discord.ButtonStyle.primary, custom_id="guardian:v8lux:welcome:setup")
    async def setup(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self.cog.send_setup_journey(interaction)

    @discord.ui.button(label="View Systems", emoji="✦", style=discord.ButtonStyle.secondary, custom_id="guardian:v8lux:welcome:systems")
    async def systems(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await reply(interaction, "GUARDIAN SYSTEMS", self.cog.systems_text())


class GuardianExperience(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        self.bot.add_view(WelcomeView(self))
        self.bot.add_view(SetupJourneyView(self))

    @staticmethod
    def systems_text() -> str:
        return (
            "**Protection** • Anti-raid, anti-nuke, Sentinel, verification and Guardian security layers.\n"
            "**Operations** • Support, applications, Staff Academy, services, invoices, warranties and refunds.\n"
            "**Reputation** • Community vouches, Vouch Wall and verified staff ratings.\n"
            "**Network** • Guardian cases, broadcasts, assistance and authorized owner communications.\n\n"
            "Guardian only exposes controls your server has configured and never requires public database IDs."
        )

    async def setup_state(self, guild_id: int) -> dict[str, bool]:
        async def exists(sql: str) -> bool:
            try:
                return await self.bot.database.fetchone(sql, (guild_id,)) is not None
            except Exception:
                return False
        return {
            "Support": await exists("SELECT 1 FROM luxury_ticket_config WHERE guild_id=? AND staff_role_id IS NOT NULL"),
            "Applications": await exists("SELECT 1 FROM luxury_application_types WHERE guild_id=? AND enabled=1"),
            "Staff Academy": await exists("SELECT 1 FROM luxury_academy_config WHERE guild_id=? AND staff_role_id IS NOT NULL"),
            "Service Queue": await exists("SELECT 1 FROM luxury_service_queue_config WHERE guild_id=? AND channel_id IS NOT NULL"),
            "Reputation": await exists("SELECT 1 FROM luxury_reputation_config WHERE guild_id=? AND channel_id IS NOT NULL"),
            "Vouch Wall": await exists("SELECT 1 FROM luxury_vouch_wall_config WHERE guild_id=? AND channel_id IS NOT NULL"),
        }

    async def send_welcome(self, interaction: discord.Interaction) -> None:
        state = await self.setup_state(interaction.guild_id)
        ready = sum(state.values())
        body = (
            f"Welcome to **ESN Guardian V8 Luxury** on **{interaction.guild.name}**.\n\n"
            f"Guardian recognizes **{interaction.guild.member_count or 0:,} members** and is ready to integrate with this server's identity.\n\n"
            f"**Setup progress:** {ready}/{len(state)} core experience systems ready\n\n"
            + self.systems_text()
        )
        await reply(interaction, "WELCOME TO GUARDIAN", body, view=WelcomeView(self))

    async def send_setup_journey(self, interaction: discord.Interaction) -> None:
        if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
            await reply(interaction, "SETUP JOURNEY", "You need **Manage Server** to use Guardian's setup journey.")
            return
        state = await self.setup_state(interaction.guild_id)
        lines = [f"{'✅' if value else '⬜'} **{name}**" for name, value in state.items()]
        ready = sum(state.values())
        await reply(
            interaction,
            "GUARDIAN SETUP JOURNEY",
            f"**{ready}/{len(state)} systems ready**\n\n" + "\n".join(lines) +
            "\n\nChoose an unfinished system below and Guardian will give you the exact next step.",
            view=SetupJourneyView(self),
        )

    async def show_setup_step(self, interaction: discord.Interaction, key: str) -> None:
        steps = {
            "support": ("SUPPORT SETUP", "Run **/support configure** and choose the staff role, ticket category, transcript log channel and ticket limit. Then publish **/support panel**."),
            "applications": ("APPLICATION SETUP", "Create an application with **/application type-create**, add its questions with **/application question-add**, then publish **/application panel**."),
            "academy": ("ACADEMY SETUP", "Run **/academy configure** for your staff role and training requirements. Create courses with **/academy course-create** and publish them when approved."),
            "service": ("SERVICE QUEUE SETUP", "Run **/service-queue-configure** and choose the channel Guardian should use for service/order operations."),
            "reputation": ("REPUTATION SETUP", "Run **/reputation-configure** for new vouches, then **/vouch-wall-configure** for the live Luxury Vouch Wall."),
        }
        title, body = steps.get(key, ("SETUP JOURNEY", "That setup step is unavailable."))
        await reply(interaction, title, body)

    async def wrapped_counts(self, guild_id: int, start: str, end: str) -> dict[str, int]:
        queries = {
            "Tickets opened": ("luxury_tickets", "created_at"),
            "Applications": ("luxury_applications", "created_at"),
            "Orders": ("luxury_service_queue", "created_at"),
            "Deliveries": ("luxury_delivery_receipts", "created_at"),
            "Vouches": ("luxury_vouches", "created_at"),
            "Invoices": ("luxury_invoices", "created_at"),
            "Refund requests": ("luxury_refund_requests", "created_at"),
            "Emergencies": ("luxury_emergency_requests", "created_at"),
            "Staff ratings": ("luxury_staff_ratings", "created_at"),
        }
        result: dict[str, int] = {}
        for label, (table, column) in queries.items():
            try:
                row = await self.bot.database.fetchone(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE guild_id=? AND datetime({column})>=datetime(?) AND datetime({column})<datetime(?)",
                    (guild_id, start, end),
                )
                result[label] = int(row["n"]) if row else 0
            except Exception:
                result[label] = 0
        return result

    @app_commands.command(name="guardian-welcome", description="Open this server's interactive Guardian V8 Luxury welcome.")
    @guild_only()
    async def guardian_welcome(self, interaction: discord.Interaction) -> None:
        await self.send_welcome(interaction)

    @app_commands.command(name="guardian-setup", description="Open Guardian's guided server setup journey.")
    @guild_only()
    @staff_only()
    async def guardian_setup(self, interaction: discord.Interaction) -> None:
        await self.send_setup_journey(interaction)

    @app_commands.command(name="guardian-wrapped", description="Generate this server's Guardian monthly or yearly recap.")
    @app_commands.describe(period="Choose a monthly or yearly Guardian recap")
    @app_commands.choices(period=[
        app_commands.Choice(name="This month", value="month"),
        app_commands.Choice(name="This year", value="year"),
    ])
    @guild_only()
    async def guardian_wrapped(self, interaction: discord.Interaction, period: app_commands.Choice[str]) -> None:
        now = datetime.now(UTC)
        if period.value == "year":
            start_dt = datetime(now.year, 1, 1, tzinfo=UTC)
            end_dt = datetime(now.year + 1, 1, 1, tzinfo=UTC)
            label = str(now.year)
        else:
            start_dt = datetime(now.year, now.month, 1, tzinfo=UTC)
            if now.month == 12:
                end_dt = datetime(now.year + 1, 1, 1, tzinfo=UTC)
            else:
                end_dt = datetime(now.year, now.month + 1, 1, tzinfo=UTC)
            label = f"{calendar.month_name[now.month]} {now.year}"
        counts = await self.wrapped_counts(interaction.guild_id, start_dt.isoformat(), end_dt.isoformat())
        total = sum(counts.values())
        body = (
            f"### {interaction.guild.name} • {label}\n"
            f"Guardian recorded **{total:,}** tracked V8 operational moments in this period.\n\n"
            + "\n".join(f"**{name}:** {value:,}" for name, value in counts.items())
            + f"\n\n**Community now:** {interaction.guild.member_count or 0:,} members"
        )
        await reply(interaction, "GUARDIAN WRAPPED", body)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(GuardianExperience(bot))
