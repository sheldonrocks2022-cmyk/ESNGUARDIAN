from __future__ import annotations

import re

import discord
from discord.ext import commands

from esn_guardian.cogs.esng_ai import ESNGuardianAICog, _contains


CASE_RE = re.compile(r"\bcase\s*#?\s*(\d+)\b", re.IGNORECASE)
SIGNAL_RE = re.compile(r"\bsignal\s*#?\s*(\d+)\b", re.IGNORECASE)
MEMBER_RE = re.compile(
    r"(?:<@!?(\d{15,22})>|\b(?:user|member|account|actor|subject)\s+(\d{15,22})\b)",
    re.IGNORECASE,
)


class ESNGuardianAI2Cog(ESNGuardianAICog):
    """ESNG Intelligence v4: live multi-layer Guardian security reasoning."""

    def _intel(self):
        return self.bot.get_cog("SecurityIntelligenceCog")

    def _overwatch(self):
        return self.bot.get_cog("SecurityOverwatchCog")

    def _sentinel(self):
        return self.bot.get_cog("SecuritySentinelCog")

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
        sentinel = self._sentinel()
        sections: list[str] = []

        if overwatch is not None:
            sections.append(await overwatch.posture_report(guild))
            sections.append(await overwatch.integrity_report(guild))

        if sentinel is not None:
            sections.append(await sentinel.live_report(guild))

        if intel is not None:
            sections.append(await intel.threat_report(guild))
            recommendations = await intel.recommendations(guild)
            sections.append(
                "**Guardian next actions**\n"
                + "\n".join(f"• {item}" for item in recommendations)
            )

        return (
            "\n\n".join(sections)[:4000]
            if sections
            else "Guardian live intelligence is not ready yet."
        )

    async def _answer(self, guild: discord.Guild, prompt: str) -> str:
        p = prompt.casefold().strip()
        intel = self._intel()
        overwatch = self._overwatch()
        sentinel = self._sentinel()

        if not p or _contains(p, "help", "what can you do", "what do you know"):
            return (
                "**ESNG Intelligence v4**\n"
                "I can reason across Guardian's live security state instead of treating each event in isolation.\n"
                "I can combine threat reports, defense posture, integrity verification, policy drift, incident sessions, "
                "Sentinel anomaly signals, subject behavior, multi-step attack chains, member history, backups, anti-nuke, "
                "raids, external apps, webhooks, integrations, credential protection, and ESN knowledge.\n"
                "Try: ESNG full security report • ESNG sentinel status • ESNG explain signal #3 • "
                "ESNG analyze subject 123456789012345678 • ESNG are events correlated • ESNG explain case #12"
            )

        if sentinel is not None:
            signal_match = SIGNAL_RE.search(prompt)
            if signal_match and _contains(
                p,
                "signal",
                "explain",
                "why",
                "details",
                "analyze",
                "analyse",
                "score",
            ):
                signal_id = int(signal_match.group(1))
                result = await sentinel.explain_signal(guild.id, signal_id)
                if result is None:
                    return f"I cannot find Sentinel signal #{signal_id} in this server."
                return result

            member_id = self._member_id(prompt)
            if member_id is not None and _contains(
                p,
                "analyze subject",
                "analyse subject",
                "subject profile",
                "subject risk",
                "subject behavior",
                "subject behaviour",
                "check subject",
                "behavior profile",
                "behaviour profile",
            ):
                return await sentinel.subject_report(guild, member_id)

            if _contains(
                p,
                "sentinel status",
                "sentinel report",
                "anomaly report",
                "anomaly status",
                "behavioral security",
                "behavioural security",
                "behavior analysis",
                "behaviour analysis",
                "correlation report",
            ):
                return await sentinel.live_report(guild)

            if _contains(
                p,
                "sentinel signals",
                "recent anomalies",
                "latest anomalies",
                "recent signals",
                "latest signals",
                "suspicious activity",
                "high anomaly",
            ):
                return await sentinel.signals_report(guild.id)

            if _contains(
                p,
                "are events correlated",
                "attack chain",
                "correlated attack",
                "multi step attack",
                "multi-step attack",
                "is this coordinated",
                "coordinated attack",
                "behavior chain",
                "behaviour chain",
            ):
                live = await sentinel.live_report(guild)
                signals = await sentinel.signals_report(guild.id, limit=5)
                return (
                    "**Guardian correlation analysis**\n"
                    "Sentinel correlates recent Guardian cases by case subject, surface spread, action category, rarity, "
                    "and five-minute bursts. It does not auto-punish from anomaly scoring alone.\n\n"
                    f"{live}\n\n{signals}"
                )[:4000]

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
                "deep security report",
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
            if case_match and _contains(
                p,
                "case",
                "explain",
                "why",
                "what happened",
                "details",
                "analyze",
                "analyse",
            ):
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
                base = await intel.threat_report(guild)
                if sentinel is not None:
                    base += "\n\n" + await sentinel.live_report(guild)
                return base[:4000]

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
                sections = [await intel.health_report(guild)]
                if overwatch is not None:
                    sections.append(await overwatch.posture_report(guild))
                if sentinel is not None:
                    sections.append(await sentinel.live_report(guild))
                return "\n\n".join(sections)[:4000]

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
                response = (
                    "**Guardian next actions**\n"
                    + "\n".join(f"• {item}" for item in recommendations)
                )
                if sentinel is not None:
                    response += (
                        "\n\nSentinel anomaly scores are advisory. "
                        "Review the supporting cases/signals before taking manual action."
                    )
                return response[:4000]

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
                    "Guardian records security actions as server-scoped cases. "
                    "Sentinel can add explainable behavioral context, but enforcement still comes from Guardian's "
                    "deterministic rules and permission-checked controls.\n"
                    f"{recent}"
                )

        if _contains(
            p,
            "ai version",
            "esng version",
            "how smart are you",
            "what changed with ai",
            "new ai",
        ):
            return (
                "**ESNG Intelligence v4**\n"
                "I now combine live configuration, threat history, tamper-evident case verification, policy drift, "
                "persistent incident sessions, threat trends, Sentinel behavioral correlation, subject profiles, "
                "multi-step attack-chain context, member security history, protection health, backups, and ESN knowledge. "
                "I explain the evidence behind scores and do not invent live data."
            )

        if _contains(p, "enable panic", "turn on panic", "activate panic", "start panic"):
            return (
                "For safety, ESNG chat does not execute emergency moderation actions. "
                "The server owner can use /guardian panic enabled:true so Discord permission checks and the owner-only gate are enforced."
            )

        if _contains(
            p,
            "disable security",
            "turn off security",
            "disable guardian",
            "remove protection",
        ):
            return (
                "ESNG chat will not disable protection from a normal message. "
                "Security changes must go through Guardian's permission-checked slash commands so they remain attributable and auditable."
            )

        if _contains(
            p,
            "should we panic",
            "should i panic",
            "activate panic now",
            "do we need panic",
        ):
            report = await self._full_security_report(guild)
            return (
                "I can show the evidence, but I will not make the emergency-control decision for you. "
                "Review the live report below and use /guardian panic only if the owner decides emergency containment is necessary.\n\n"
                f"{report}"
            )[:4000]

        return await super()._answer(guild, prompt)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ESNGuardianAI2Cog(bot))
