from __future__ import annotations

import re

import discord
from discord.ext import commands

from esn_guardian.cogs.esng_ai import ESNGuardianAICog, _contains


CASE_RE = re.compile(r"\bcase\s*#?\s*(\d+)\b", re.IGNORECASE)
MEMBER_RE = re.compile(
    r"(?:<@!?(\d{15,22})>|\b(?:user|member|account)\s+(\d{15,22})\b)",
    re.IGNORECASE,
)


class ESNGuardianAI2Cog(ESNGuardianAICog):
    """ESNG Intelligence v3: live Guardian reasoning over server security state."""

    def _intel(self):
        return self.bot.get_cog("SecurityIntelligenceCog")

    def _overwatch(self):
        return self.bot.get_cog("SecurityOverwatchCog")

    @staticmethod
    def _member_id(prompt: str) -> int | None:
        match = MEMBER_RE.search(prompt)
        if match is None:
            return None
        value = match.group(1) or match.group(2)
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    async def _full_security_report(self, guild: discord.Guild) -> str:
        intel = self._intel()
        overwatch = self._overwatch()
        sections: list[str] = []
        if overwatch is not None:
            sections.append(await overwatch.posture_report(guild))
            sections.append(await overwatch.integrity_report(guild))
        if intel is not None:
            sections.append(await intel.threat_report(guild))
            recommendations = await intel.recommendations(guild)
            sections.append("**Guardian next actions**\n" + "\n".join(f"• {item}" for item in recommendations))
        return "\n\n".join(sections)[:4000] if sections else "Guardian live intelligence is not ready yet."

    async def _answer(self, guild: discord.Guild, prompt: str) -> str:
        p = prompt.casefold().strip()
        intel = self._intel()
        overwatch = self._overwatch()

        if not p or _contains(p, "help", "what can you do", "what do you know"):
            return (
                "**ESNG Intelligence v3**\n"
                "I can use Guardian's live server state instead of guessing.\n"
                "Security: threat reports, attack detection, defense posture, integrity checks, incident sessions, "
                "policy-drift detection, recent cases, member security profiles, backups, anti-nuke, raids, external apps, "
                "webhooks, integrations, credential protection, and recommendations.\n"
                "ESN: products, prices, checkout, services, Website Builder, Domains, Arcade, Tools, Nexus, diagnostics, updates, and official links.\n"
                "Try: ESNG full security report • ESNG integrity check • ESNG is security getting worse • "
                "ESNG explain case #12 • ESNG analyze member 123456789012345678"
            )

        if overwatch is not None:
            member_id = self._member_id(prompt)
            if member_id is not None and _contains(
                p,
                "analyze member",
                "analyse member",
                "member risk",
                "user risk",
                "security profile",
                "check member",
                "check user",
                "is this user dangerous",
                "is this member dangerous",
            ):
                return await overwatch.member_risk_report(guild, member_id)

            if _contains(
                p,
                "full security report",
                "complete security report",
                "everything security",
                "full guardian report",
                "guardian overview",
            ):
                return await self._full_security_report(guild)

            if _contains(
                p,
                "integrity",
                "tamper",
                "tampering",
                "case ledger",
                "security ledger",
                "ledger check",
                "verify cases",
                "was the database changed",
            ):
                return await overwatch.integrity_report(guild)

            if _contains(
                p,
                "defense posture",
                "security posture",
                "guardian posture",
                "shield status",
                "protection score",
                "security score",
                "how protected are we",
                "how secure are we",
            ):
                return await overwatch.posture_report(guild)

            if _contains(
                p,
                "security trend",
                "threat trend",
                "getting worse",
                "getting better",
                "activity rising",
                "activity falling",
                "is risk increasing",
            ):
                trend = await overwatch.trend_report(guild)
                return (
                    "**Guardian threat trend**\n"
                    f"Trend: {trend['label']}\n"
                    f"Last 10 minutes: {trend['recent_cases']} cases / weighted score {trend['recent_score']}\n"
                    f"Previous 50 minutes: {trend['previous_cases']} cases / weighted score {trend['previous_score']}\n"
                    "The trend is based on Guardian's recorded security cases, not a guess."
                )

            if _contains(
                p,
                "policy drift",
                "security drift",
                "security settings changed",
                "did settings change",
                "guardian settings changed",
                "protection changed",
                "configuration changed",
            ):
                return await overwatch.drift_report(guild)

            if _contains(
                p,
                "incident sessions",
                "active incident",
                "incident report",
                "security incidents",
                "guardian incidents",
            ):
                return await overwatch.incident_report(guild.id)

            if _contains(
                p,
                "seal policy",
                "approve security baseline",
                "save security baseline",
            ):
                return (
                    "ESNG chat will not silently approve a new security baseline. "
                    "The server owner must use /overwatch seal so the approval is explicit and permission-checked."
                )

            if _contains(
                p,
                "make backup",
                "create backup",
                "security backup now",
                "incident backup",
            ):
                return (
                    "Use /overwatch backup as the server owner. "
                    "ESNG chat does not execute privileged recovery actions from normal messages."
                )

        if intel is not None:
            case_match = CASE_RE.search(prompt)
            if case_match and _contains(p, "case", "explain", "why", "what happened", "details", "analyze"):
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
                "attack happening",
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
                "what happened today",
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
                base = await intel.health_report(guild)
                if overwatch is not None:
                    base += "\n\n" + await overwatch.posture_report(guild)
                return base[:4000]

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
                "fix security",
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
                    "Guardian stores blocked application IDs in SQLite, so the block survives restarts."
                )

            if _contains(
                p,
                "why did guardian",
                "why was i banned",
                "why did it ban",
                "why did it lockdown",
                "why did it lock down",
                "why did it quarantine",
            ):
                recent = await intel.timeline(guild.id, limit=5)
                return (
                    "**Why Guardian acted**\n"
                    "Guardian records its security actions as server-scoped cases. "
                    "These are the newest recorded cases so staff can match the action to its reason:\n"
                    f"{recent}"
                )

        if _contains(p, "ai version", "esng version", "how smart are you", "what changed with ai", "new ai"):
            return (
                "**ESNG Intelligence v3**\n"
                "I now combine live Guardian configuration, threat history, tamper-evident case verification, policy drift, "
                "persistent incident sessions, threat trends, member security history, protection health, backups, and ESN knowledge. "
                "I can explain what Guardian saw and why it reacted while refusing to invent live data or reveal credentials."
            )

        if _contains(p, "enable panic", "turn on panic", "activate panic", "start panic"):
            return (
                "For safety, ESNG chat does not execute emergency moderation actions. "
                "The server owner can use /guardian panic enabled:true so Discord permission checks and the owner-only command gate are enforced."
            )

        if _contains(p, "disable security", "turn off security", "disable guardian", "remove protection"):
            return (
                "ESNG chat will not disable protection from a normal message. "
                "Security changes must go through Guardian's permission-checked slash commands so they are attributable and auditable."
            )

        return await super()._answer(guild, prompt)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ESNGuardianAI2Cog(bot))
