from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.config import Settings
from esn_guardian.database import Database

LOG = logging.getLogger("esn_guardian")
EXTENSIONS = (
    "esn_guardian.cogs.moderation",
    "esn_guardian.cogs.security",
    "esn_guardian.cogs.verification",
    "esn_guardian.cogs.community",
    "esn_guardian.cogs.owner",
)


class GuardianBot(commands.Bot):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.moderation = True
        super().__init__(command_prefix="!", intents=intents, help_command=None)
        self.settings = settings
        self.database = Database(settings.database_path)
        self.started_at = datetime.now(UTC)

    async def setup_hook(self) -> None:
        await self.database.connect()
        for extension in EXTENSIONS:
            await self.load_extension(extension)
        await self.tree.sync()

    async def close(self) -> None:
        await self.database.close()
        await super().close()

    async def on_ready(self) -> None:
        LOG.info("Connected as %s (%s) in %s guilds", self.user, self.user.id if self.user else "unknown", len(self.guilds))
        for guild in self.guilds:
            await self.database.ensure_guild(guild.id)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        await self.database.ensure_guild(guild.id)
        if await self.database.is_guild_blacklisted(guild.id):
            await guild.leave()
            return

        if self.settings.owner_id is None:
            return
        owner = self.get_user(self.settings.owner_id)
        if owner is None:
            try:
                owner = await self.fetch_user(self.settings.owner_id)
            except discord.HTTPException:
                LOG.warning("Could not fetch bot owner %s for guild join notification", self.settings.owner_id)
                return
        try:
            await owner.send(
                f"ESN Guardian was added to **{guild.name}** (`{guild.id}`).\n"
                f"Server owner: {guild.owner} (`{guild.owner_id}`)\n"
                f"Members: {guild.member_count or 0}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            LOG.warning("Could not DM bot owner about joining guild %s (%s)", guild.name, guild.id)

    async def on_error(self, event_method: str, *args: object, **kwargs: object) -> None:
        LOG.exception("Unhandled Discord event error in %s", event_method)

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("This command is unavailable here, or you do not have permission to use it.", ephemeral=True)
            return
        if isinstance(error, app_commands.CommandOnCooldown):
            await interaction.response.send_message(f"Try again in {error.retry_after:.0f} seconds.", ephemeral=True)
            return
        LOG.exception("Application command failed", exc_info=error)
        if interaction.response.is_done():
            await interaction.followup.send("The command failed safely. Staff can check the system log.", ephemeral=True)
        else:
            await interaction.response.send_message("The command failed safely. Staff can check the system log.", ephemeral=True)


def main() -> None:
    settings = Settings.load()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    bot = GuardianBot(settings)
    try:
        bot.run(settings.token, log_handler=None)
    except discord.LoginFailure:
        LOG.critical("Discord rejected DISCORD_TOKEN.")
    except (OSError, asyncio.TimeoutError):
        LOG.exception("Fatal network or startup failure.")
    except Exception:
        LOG.exception("Fatal unexpected startup failure.")


if __name__ == "__main__":
    main()