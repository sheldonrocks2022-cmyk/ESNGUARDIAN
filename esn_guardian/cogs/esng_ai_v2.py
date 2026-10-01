from __future__ import annotations

import re

import discord
from discord.ext import commands

from esn_guardian.cogs.esng_ai import ESNGuardianAICog, _contains


CASE_RE = re.compile(r"\\bcase\\s*#?\\s*(\\d+)\\b", re.IGNORECASE)


class ESNGuardianAI2Cog(ESNGuardianAICog):
    """ESNG intelligence upgrade backed by live Guardian telemetry."""

    def _intel(self):
        return self.bot.get_cog("SecurityIntelligenceCog")

    async def _answer(self, guild: discord.Guild, prompt: str) -> str:
        p = prompt.casefold().strip()
        intel = self._intel()

        if intel is not None:
            case_match = CASE_RE.search(prompt)
            if case_match and _contains(p, "case", "explain", "why", "what happened", "details"):
                case_id = int(case_match.group(1))
                result = await intel.explain_case(guild.id, case_id)
                if result is None:
                    return f"I cannot find Guardian case #{case_id} in this server."
                return "**Guardian case analysis**\n" + result

            if _contains(
                p,
                "threat report",
                "threat level",
                "risk report",
                "risk level",
                "security intelligence",
                "analyze server",
                "analyse server",
                "server risk",
                "are we under attack",
                "under attack",
            ):
                return await intel.threat_report(guild)

            if _contains(
                p,
                "recent incidents",
                "recent security",
                "security timeline",
                "what happened recently",
                "latest cases",
                "latest security cases",
                "incident history",
            ):
                return await intel.timeline(guild.id)

            if _contains(
                p,
                "security health",
                "guardian health",
                "protection health",
                "security diagnostics",
                "guardian diagnostics",
                "system health",
            ):
                return await intel.health_report(guild)

            if _contains(
                p,
                "what should we do",
                "what should i do",
                "next steps",
                "security recommendations",
                "how do we secure",
                "how can we secure",
                "improve security",
                "harden this server",
            ):
                recommendations = await intel.recommendations(guild)
                return "**Guardian next actions**\n" + "\n".join(f"• {item}" for item in recommendations)

            if _contains(
                p,
                "blocked external apps",
                "blocked apps",
                "external app blocks",
                "external apps blocked",
            ):
                data = await intel.snapshot(guild)
                return (
                    "**External-app defense**\n"
                    f"External-app lock: {'ON' if data['external_app_lock'] else 'OFF'}\n"
                    f"Persistently blocked application IDs: {data['blocked_apps']}\n"
                    "Guardian keeps blocked application IDs in SQLite so they remain blocked after restarts."
                )

            if _contains(
                p,
                "why did guardian",
                "why was i banned",
                "why did it ban",
                "why did it lockdown",
                "why did it lock down",
            ):
                recent = await intel.timeline(guild.id, limit=5)
                return (
                    "**Why Guardian acted**\n"
                    "Guardian actions are recorded as server-scoped security cases. "
                    "Here are the newest cases so staff can match the action to its recorded reason:\n"
                    f"{recent}"
                )

        if _contains(p, "ai version", "esng version", "how smart are you", "what changed with ai"):
            return (
                "**ESNG Intelligence v2**\n"
                "I can answer the original ESN/Guardian/store/site questions plus live server-specific security questions. "
                "I can summarize current protection health, correlate recent incidents, explain a case number, show a 24-hour incident timeline, "
                "and generate next actions from the server's actual Guardian configuration. I do not invent live data or expose secrets."
            )

        if _contains(p, "enable panic", "turn on panic", "activate panic", "start panic"):
            return (
                "For safety, ESNG chat does not execute emergency moderation actions. "
                "The server owner can use `/guardian panic enabled:true` so Discord permission checks and the owner-only command gate are enforced."
            )

        return await super()._answer(guild, prompt)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ESNGuardianAI2Cog(bot))
