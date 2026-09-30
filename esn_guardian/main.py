from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import command_embed, log_event
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
        super().__init__(command_prefix="!", intents=intents, help_command=None, allowed_mentions=discord.AllowedMentions.none())
        self.settings = settings
        self.database = Database(settings.database_path)
        self.started_at = datetime.now(UTC)
        self._guild_commands_synced = False
        self._global_commands_cleared = False

    async def setup_hook(self) -> None:
        await self.database.connect()
        for extension in EXTENSIONS:
            await self.load_extension(extension)

    async def close(self) -> None:
        await self.database.close()
        await super().close()

    async def sync_guild_commands(self, guild: discord.Guild) -> list[app_commands.AppCommand]:
        self.tree.copy_global_to(guild=guild)
        return await self.tree.sync(guild=guild)

    async def on_ready(self) -> None:
        LOG.info("Connected as %s (%s) in %s guilds", self.user, self.user.id if self.user else "unknown", len(self.guilds))
        for guild in self.guilds:
            await self.database.ensure_guild(guild.id)
        if not self._guild_commands_synced:
            guild_sync_succeeded = True
            for guild in self.guilds:
                try:
                    synced_commands = await self.sync_guild_commands(guild)
                except discord.HTTPException:
                    guild_sync_succeeded = False
                    LOG.exception("Could not sync application commands for guild %s (%s)", guild.name, guild.id)
                else:
                    LOG.info("Synced %s application commands for guild %s (%s)", len(synced_commands), guild.name, guild.id)
            self._guild_commands_synced = guild_sync_succeeded
        if self._guild_commands_synced and not self._global_commands_cleared:
            self.tree.clear_commands(guild=None)
            try:
                await self.tree.sync()
            except discord.HTTPException:
                LOG.exception("Could not clear legacy global application commands")
            else:
                self._global_commands_cleared = True
                LOG.info("Cleared legacy global application commands")

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

    async def _log_command_invocation(self, interaction: discord.Interaction, outcome: str) -> None:
        if interaction.guild is None or interaction.command is None:
            return
        channel = interaction.channel
        channel_text = channel.mention if isinstance(channel, (discord.TextChannel, discord.Thread, discord.VoiceChannel, discord.StageChannel)) else "Unknown"
        await log_event(
            self,
            interaction.guild,
            "command_log_channel_id",
            f"Command {outcome}",
            description=(
                f"Command: `/{interaction.command.qualified_name}`\n"
                f"Executed by: {interaction.user.mention} ({interaction.user.id})\n"
                f"Channel: {channel_text} ({interaction.channel_id or 'Unknown'})\n"
                f"Server: {interaction.guild.name} ({interaction.guild.id})\n"
                f"Interaction ID: {interaction.id}"
            ),
        )

    async def on_app_command_completion(self, interaction: discord.Interaction, command: app_commands.Command[object, ..., object]) -> None:
        await self._log_command_invocation(interaction, "completed")

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message(embed=command_embed("This command is unavailable here, or you do not have permission to use it.", title="Access denied"), ephemeral=True)
            return
        if isinstance(error, app_commands.CommandOnCooldown):
            await interaction.response.send_message(embed=command_embed(f"Try again in {error.retry_after:.0f} seconds.", title="Please wait"), ephemeral=True)
            return
        LOG.exception("Application command failed", exc_info=error)
        await self._log_command_invocation(interaction, "failed")
        if interaction.response.is_done():
            await interaction.followup.send(embed=command_embed("The command failed safely. Staff can check the system log.", title="Command unavailable"), ephemeral=True)
        else:
            await interaction.response.send_message(embed=command_embed("The command failed safely. Staff can check the system log.", title="Command unavailable"), ephemeral=True)


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