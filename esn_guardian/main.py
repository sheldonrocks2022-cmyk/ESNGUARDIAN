from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta

import discord
from discord import app_commands
from discord.ext import commands

from esn_guardian.cogs.common import command_embed, log_event
from esn_guardian.config import Settings
from esn_guardian.database import Database
from esn_guardian.release_guard import mark_healthy

LOG = logging.getLogger("esn_guardian")
EXTENSIONS = (
    "esn_guardian.cogs.moderation",
    "esn_guardian.cogs.security",
    "esn_guardian.cogs.advanced_security",
    "esn_guardian.cogs.security_intelligence",
    "esn_guardian.cogs.security_overwatch",
    "esn_guardian.cogs.security_sentinel",
    "esn_guardian.cogs.security_resilience",
    "esn_guardian.cogs.security_v6",
    "esn_guardian.cogs.security_v7",
    "esn_guardian.cogs.verification",
    "esn_guardian.cogs.security_max",
    "esn_guardian.cogs.community",
    "esn_guardian.cogs.esng_ai_v2",
    "esn_guardian.cogs.tickets",
    "esn_guardian.cogs.owner",
)


class GuardianBot(commands.Bot):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.moderation = True
        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None,
            allowed_mentions=discord.AllowedMentions.none(),
            max_messages=1000,
        )
        self.settings = settings
        self.database = Database(settings.database_path)
        self.started_at = datetime.now(UTC)
        self._guild_commands_synced = False
        self._global_commands_cleared = False
        self._backup_task: asyncio.Task[None] | None = None
        self._health_task: asyncio.Task[None] | None = None
        self._interaction_ack_tasks: set[asyncio.Task[None]] = set()
        self._security_suppression: dict[int, tuple[datetime, str]] = {}
        # v7 wraps this check later and preserves it as its previous_check.
        # This gives every slash command a universal Discord-deadline safety net.
        self.tree.interaction_check = self._universal_interaction_check
        self.runtime_health: dict[str, object] = {
            "event_loop_lag_ms": 0.0,
            "gateway_latency_ms": 0.0,
            "database_ok": True,
            "last_check": None,
            "guilds": 0,
            "members": 0,
        }

    def suppress_security_events(self, guild_id: int, *, seconds: int = 90, reason: str = "Guardian internal operation") -> None:
        """Temporarily ignore Discord audit/event echoes caused by Guardian itself."""
        until = datetime.now(UTC) + timedelta(seconds=max(1, seconds))
        current = self._security_suppression.get(guild_id)
        if current is None or current[0] < until:
            self._security_suppression[guild_id] = (until, reason)

    def security_events_suppressed(self, guild_id: int) -> bool:
        current = self._security_suppression.get(guild_id)
        if current is None:
            return False
        until, _reason = current
        if until <= datetime.now(UTC):
            self._security_suppression.pop(guild_id, None)
            return False
        return True

    def security_suppression_reason(self, guild_id: int) -> str | None:
        if not self.security_events_suppressed(guild_id):
            return None
        current = self._security_suppression.get(guild_id)
        return current[1] if current is not None else None

    def should_suppress_security_event(
        self,
        guild_id: int,
        actor: discord.abc.User | None = None,
    ) -> bool:
        """Ignore Guardian's own audit echoes while still allowing attributed outside actors through."""
        if not self.security_events_suppressed(guild_id):
            return False
        if actor is None:
            return True
        return self.user is not None and actor.id == self.user.id

    async def _universal_interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.type is not discord.InteractionType.application_command:
            return True

        command = getattr(interaction, "command", None)
        qualified_name = str(getattr(command, "qualified_name", "") or "").casefold()

        # /verify may need its *first* interaction response to be a modal.
        # Component/modal interactions do not pass through this app-command tree check.
        if qualified_name == "verify":
            return True

        async def auto_ack() -> None:
            await asyncio.sleep(1.25)
            if interaction.response.is_done():
                return
            try:
                await interaction.response.defer(ephemeral=True, thinking=True)
            except (discord.InteractionResponded, discord.NotFound, discord.HTTPException):
                return
            LOG.debug(
                "Universal interaction auto-acknowledged /%s (%s)",
                qualified_name or "unknown",
                interaction.id,
            )

        task = asyncio.create_task(
            auto_ack(),
            name=f"guardian-interaction-ack-{interaction.id}",
        )
        self._interaction_ack_tasks.add(task)
        task.add_done_callback(self._interaction_ack_tasks.discard)
        return True

    async def setup_hook(self) -> None:
        await self.database.connect()
        for extension in EXTENSIONS:
            await self.load_extension(extension)
        self._backup_task = asyncio.create_task(self._database_backup_loop(), name="guardian-database-backups")
        self._health_task = asyncio.create_task(self._runtime_health_loop(), name="guardian-runtime-health")

    async def _database_backup_loop(self) -> None:
        try:
            await self.wait_until_ready()
            while not self.is_closed():
                await asyncio.sleep(3 * 60 * 60)
                try:
                    await self.database.checkpoint()
                    backup_path = await self.database.backup("scheduled")
                except Exception:
                    LOG.exception("Automatic Guardian database backup failed")
                else:
                    if backup_path is not None:
                        LOG.info("Guardian database backup created: %s", backup_path)
        except asyncio.CancelledError:
            raise

    async def _runtime_health_loop(self) -> None:
        try:
            await self.wait_until_ready()
            checks = 0
            loop = asyncio.get_running_loop()
            while not self.is_closed():
                started = loop.time()
                await asyncio.sleep(1)
                lag_ms = max(0.0, (loop.time() - started - 1.0) * 1000.0)
                checks += 1

                database_ok = bool(self.runtime_health.get("database_ok", True))
                if checks == 1 or checks % 5 == 0:
                    try:
                        database_ok = await self.database.quick_check()
                    except Exception:
                        database_ok = False
                        LOG.exception("Guardian runtime database health check failed")

                self.runtime_health.update(
                    {
                        "event_loop_lag_ms": round(lag_ms, 1),
                        "gateway_latency_ms": round(max(0.0, self.latency) * 1000.0, 1),
                        "database_ok": database_ok,
                        "last_check": datetime.now(UTC),
                        "guilds": len(self.guilds),
                        "members": sum(guild.member_count or 0 for guild in self.guilds),
                    }
                )
                await asyncio.sleep(59)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("Guardian runtime health monitor stopped unexpectedly")

    async def close(self) -> None:
        if self._health_task is not None:
            self._health_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._health_task
            self._health_task = None
        if self._backup_task is not None:
            self._backup_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._backup_task
            self._backup_task = None
        await self.database.close()
        await super().close()

    async def sync_guild_commands(self, guild: discord.Guild) -> list[app_commands.AppCommand]:
        self.tree.copy_global_to(guild=guild)
        return await self.tree.sync(guild=guild)

    async def on_socket_response(self, payload: dict[str, object]) -> None:
        if payload.get("t") != "INTERACTION_CREATE":
            return
        data = payload.get("d")
        if not isinstance(data, dict):
            LOG.info("Gateway received INTERACTION_CREATE with unreadable payload")
            return
        command_data = data.get("data")
        command_name = command_data.get("name") if isinstance(command_data, dict) else None
        LOG.info(
            "Gateway received INTERACTION_CREATE application_id=%s guild_id=%s command=%s interaction_id=%s",
            data.get("application_id"),
            data.get("guild_id"),
            command_name,
            data.get("id"),
        )

    async def on_ready(self) -> None:
        LOG.info("Connected as %s (%s) in %s guilds", self.user, self.user.id if self.user else "unknown", len(self.guilds))
        try:
            await asyncio.to_thread(mark_healthy)
        except Exception:
            LOG.exception("Could not record Guardian release as last-known-good")
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
            embed = command_embed("This command is unavailable here, or you do not have permission to use it.", title="Access denied")
        elif isinstance(error, app_commands.CommandOnCooldown):
            embed = command_embed(f"Try again in {error.retry_after:.0f} seconds.", title="Please wait")
        else:
            LOG.exception("Application command failed", exc_info=error)
            await self._log_command_invocation(interaction, "failed")
            embed = command_embed("The command failed safely. Staff can check the system log.", title="Command unavailable")

        try:
            if interaction.response.is_done():
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(embed=embed, ephemeral=True)
        except (discord.NotFound, discord.HTTPException):
            LOG.warning(
                "Could not send application-command error response; interaction %s is no longer valid",
                interaction.id,
            )


def startup_retry_delay(error: discord.HTTPException | None, attempt: int) -> float:
    """Return a conservative startup retry delay without hammering Discord."""
    retry_after = 0.0
    if error is not None:
        response = getattr(error, "response", None)
        headers = getattr(response, "headers", None)
        if headers is not None:
            try:
                retry_after = float(headers.get("Retry-After", 0) or 0)
            except (TypeError, ValueError):
                retry_after = 0.0

    exponential = min(900.0, 60.0 * (2 ** min(max(attempt, 0), 4)))
    return max(60.0, retry_after, exponential)


async def _run_guardian(settings: Settings) -> None:
    """Own the Discord login lifecycle so startup failures cannot escape to CogitHost."""
    attempt = 0

    while True:
        bot = GuardianBot(settings)
        try:
            await bot.start(settings.token, reconnect=True)
        except discord.LoginFailure:
            LOG.critical("Discord rejected DISCORD_TOKEN. Guardian will not retry an invalid token.")
            return
        except discord.HTTPException as error:
            if getattr(error, "status", None) != 429:
                LOG.exception("Discord HTTP startup failure.")
                return

            delay = startup_retry_delay(error, attempt)
            attempt += 1
            LOG.warning(
                "Discord globally rate-limited Guardian during startup (HTTP 429). "
                "Guardian process remains alive and will retry in %.0f seconds. "
                "Do NOT restart CogitHost while this cooldown is active.",
                delay,
            )
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise
            continue
        except (OSError, asyncio.TimeoutError):
            delay = min(300.0, 30.0 * (2 ** min(attempt, 3)))
            attempt += 1
            LOG.exception(
                "Temporary network/startup failure. Guardian process remains alive and will retry in %.0f seconds.",
                delay,
            )
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise
            continue
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("Fatal unexpected Guardian runtime failure.")
            return
        finally:
            try:
                if not bot.is_closed():
                    await bot.close()
            except Exception:
                LOG.exception("Guardian cleanup after startup/runtime failure encountered an error")

        # A clean return from bot.start means Discord closed the connection without an
        # exception. Treat that as a shutdown, not a crash-loop.
        return


def main() -> None:
    settings = Settings.load()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(_run_guardian(settings))
    except KeyboardInterrupt:
        LOG.info("Guardian shutdown requested.")


if __name__ == "__main__":
    main()