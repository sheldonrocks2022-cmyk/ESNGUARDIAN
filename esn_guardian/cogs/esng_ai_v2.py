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
    """ESNG Intelligence v7 MAX: live multi-layer Guardian security reasoning."""

    def _intel(self):
        return self.bot.get_cog("SecurityIntelligenceCog")

    def _overwatch(self):
        return self.bot.get_cog("SecurityOverwatchCog")

    def _sentinel(self):
        return self.bot.get_cog("SecuritySentinelCog")

    def _resilience(self):
        return self.bot.get_cog("SecurityResilienceCog")

    def _protection_v6(self):
        return self.bot.get_cog("ProtectionV6Cog")

    def _v7(self):
        return self.bot.get_cog("SecurityV7Cog")

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
        resilience = self._resilience()
        protection_v6 = self._protection_v6()
        v7 = self._v7()
        sections: list[str] = []

        if overwatch is not None:
            sections.append(await overwatch.posture_report(guild))
            sections.append(await overwatch.integrity_report(guild))


        if sentinel is not None:
            sections.append(await sentinel.live_report(guild))

        if resilience is not None:
            sections.append(await resilience.status_report(guild))

        if protection_v6 is not None:
            sections.append(await protection_v6.status_report(guild))
            sections.append(await protection_v6.highest_risk_report(guild))

        if v7 is not None:
            chain = await v7.verify_chain(guild.id)
            sections.append(
                "**Guardian v7 predictive shield**\n"
                f"State: {v7.state[guild.id]} • Risk: {v7.score(guild.id)}/100\n"
                f"Evidence chain: {'VERIFIED' if chain['ok'] else 'FAILED'} ({chain['checked']} records)"
            )

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
        resilience = self._resilience()
        protection_v6 = self._protection_v6()
        v7 = self._v7()

        if not p or _contains(p, "help", "what can you do", "what do you know"):
            return (
                "**ESNG Intelligence v7 MAX**\n"
                "I can reason across Guardian's live security state instead of treating each event in isolation.\n"
                "I can combine threat reports, defense posture, integrity verification, policy drift, incident sessions, "
                "Protection v6 adaptive containment, Guardian v7 predictive state, trust graphs, staff behavior baselines, "
                "privilege-path analysis, protected assets, canaries, evidence-chain verification, recovery readiness, "
                "Sentinel anomaly signals, backups, anti-nuke, raids, external apps, webhooks, and integrations.\n"
                "Try: ESNG guardian v7 • ESNG trust graph • ESNG privilege paths • ESNG incident replay • "
                "ESNG protection benchmark • ESNG full security report"
            )


        if v7 is not None:
            if _contains(
                p,
                "guardian v7",
                "v7 status",
                "predictive shield",
                "predictive protection",
                "security state",
                "current security state",
            ):
                config = await v7._config(guild.id)
                chain = await v7.verify_chain(guild.id)
                return (
                    "**Guardian Protection v7 MAX**\n"
                    f"State: {v7.state[guild.id]}\n"
                    f"Predictive risk: {v7.score(guild.id)}/100\n"
                    f"Policy: {config['profile']}\n"
                    f"Evidence chain: {'VERIFIED' if chain['ok'] else 'FAILED'} ({chain['checked']} records)\n"
                    f"Emergency minimal mode: {'ACTIVE' if getattr(self.bot, 'guardian_minimal_mode', False) else 'standby'}"
                )

            if _contains(p, "trust graph", "who do we trust", "trust score", "weakest trust"):
                return await v7.trust_graph(guild)

            if _contains(
                p,
                "privilege path",
                "privilege paths",
                "privilege escalation path",
                "who can become admin",
            ):
                paths = await v7.privilege_paths(guild)
                if not paths:
                    return "Guardian v7 found no direct Manage Roles to dangerous-role escalation paths."
                return (
                    "**Guardian v7 privilege paths**\n"
                    + "\n".join(
                        f"• {item['member']} ({item['member_id']}) -> {item['target_role']} • Guardian revoke: {'yes' if item['guardian_can_revoke'] else 'NO'}"
                        for item in paths[:20]
                    )
                )[:4000]

            if _contains(p, "incident replay", "replay attack", "replay incident", "attack timeline"):
                return await v7.replay(guild.id)

            if _contains(p, "benchmark", "security benchmark", "protection benchmark", "grade our protection"):
                result = await v7.benchmark(guild)
                failed = [name for name, ok in result["checks"] if not ok]
                return (
                    "**Guardian v7 benchmark**\n"
                    f"Score: {result['score']}/100 • Grade {result['grade']}\n"
                    f"Privilege paths: {len(result['paths'])}\n"
                    f"Failed checks: {', '.join(failed) if failed else 'none'}"
                )

            if _contains(p, "chaos test", "simulate attack", "test attack scenarios"):
                return await v7.chaos_report(guild)

        if _contains(
            p,
            "runtime health",
            "guardian lag",
            "bot lag",
            "gateway latency",
        ):
            runtime = dict(getattr(self.bot, "runtime_health", {}))
            last_check = runtime.get("last_check")
            if hasattr(last_check, "isoformat"):
                last_check = last_check.isoformat()
            return (
                "**Guardian runtime health**\n"
                f"Gateway latency: {float(runtime.get('gateway_latency_ms', 0.0) or 0.0):.1f} ms\n"
                f"Event-loop lag: {float(runtime.get('event_loop_lag_ms', 0.0) or 0.0):.1f} ms\n"
                f"Database health cache: {'OK' if runtime.get('database_ok', True) else 'FAILED'}\n"
                f"Guilds: {int(runtime.get('guilds', 0) or 0)} • Members: {int(runtime.get('members', 0) or 0)}\n"
                f"Last runtime check: {last_check or 'not recorded yet'}"
            )

        if protection_v6 is not None:
            if _contains(
                p,
                "protection v6",
                "v6 status",
                "adaptive protection",
                "permission firewall",
                "auto heal",
                "auto-heal",
                "command shield",
                "automatic panic",
                "panic status",
            ):
                return await protection_v6.status_report(guild)

            if _contains(
                p,
                "highest risk",
                "highest risk member",
                "risk board",
                "who is dangerous",
                "most dangerous member",
                "top risk",
            ):
                return await protection_v6.highest_risk_report(guild)

            if _contains(
                p,
                "v6 forensics",
                "incident forensics",
                "attack report",
                "post attack report",
                "post-attack report",
                "what happened in the attack",
            ):
                return await protection_v6.forensics_report(guild)

            member_id = self._member_id(prompt)
            if member_id is not None and _contains(
                p,
                "adaptive risk",
                "v6 risk",
                "risk score",
                "member risk",
                "user risk",
            ):
                member = guild.get_member(member_id)
                if member is not None:
                    data = await protection_v6.member_risk(guild, member)
                    return (
                        f"**Protection v6 adaptive risk — {member_id}**\n"
                        f"Score: {data['score']}/100 ({data['level']})\n"
                        f"Account age: {data['account_age_days']} days\n"
                        f"Weighted case risk: {data['weighted_cases']}\n"
                        f"Dangerous roles: {data['dangerous_roles']}\n"
                        f"Verification failures: {data['failed_verifications']}\n"
                        f"External-app signals: {data['external_app_events']}\n"
                        f"Raid-cluster contribution: {data['raid_cluster_score']}"
                    )

        if resilience is not None:
            if _contains(
                p,
                "resilience status",
                "recovery readiness",
                "guardian readiness",
                "are backups ready",
                "self health",
                "self-health",
                "defense readiness",
                "runtime health",
                "guardian lag",
                "bot lag",
                "gateway latency",
                "database health",
                "sqlite health",
                "backup freshness",
            ):
                return await resilience.status_report(guild)

            if _contains(
                p,
                "security drill",
                "resilience drill",
                "run a drill",
                "test defenses",
                "test guardian",
                "readiness drill",
            ):
                return await resilience.drill_report(guild)

            if _contains(
                p,
                "recovery plan",
                "recovery steps",
                "how do we recover",
                "recovery readiness plan",
                "what if guardian fails",
            ):
                return await resilience.recovery_plan(guild)

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
                "**ESNG Intelligence v7 MAX**\n"
                "I now combine live configuration, threat history, Protection v6 adaptive containment, Guardian v7 predictive state, "
                "staff behavior baselines, trust graphs, privilege-path analysis, protected-asset/canary state, cryptographic evidence-chain integrity, "
                "signed-release health, recovery checkpoints, post-attack forensics, incident replay, application reputation, "
                "Sentinel behavioral correlation, Guardian Resilience self-health, runtime latency/event-loop health, SQLite integrity, "
                "backup freshness, member security history, verification health, and ESN knowledge. "
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
