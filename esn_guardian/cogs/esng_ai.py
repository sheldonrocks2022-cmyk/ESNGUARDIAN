from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import discord
from discord.ext import commands

TRIGGER_RE = re.compile(r"^ESNG(?:\s*[:,-]\s*|\s+|$)", re.IGNORECASE)
STORE_AI_URL = "https://esnoffical.com/store-ai"

WEBSITE_URL = "https://esnoffical.com"
DISCORD_URL = "https://discord.gg/3gxA66KZ8"

CATALOG = (
    {"name": "20 Realm 100 Keys", "kind": "SMP", "price": 1.25, "price_label": "$1.25", "checkout": "https://buy.stripe.com/4gM14o5pxgaP9Nl2dNdnW00", "status": "AVAILABLE", "tags": ("keys", "realm", "minecraft", "smp")},
    {"name": "ESN Season Pass Relic Bundle", "kind": "SMP", "price": 0.50, "price_label": "$0.50", "checkout": "https://buy.stripe.com/bJe14o8BJbUz4t1dWvdnW01", "status": "AVAILABLE", "tags": ("season", "relic", "angel", "scepter", "crystal", "tideheart", "celestial")},
    {"name": "ESN Riftwalker Bundle", "kind": "SMP", "price": 0.50, "price_label": "$0.50", "checkout": "https://buy.stripe.com/00w3cw6tB7Ej9Nl19JdnW02", "status": "AVAILABLE", "tags": ("rift", "riftwalker", "elytra", "phase", "bow", "compass")},
    {"name": "ESN Immortal Warden Bundle", "kind": "SMP", "price": 1.30, "price_label": "$1.30", "checkout": "https://buy.stripe.com/bJefZi9FN9Mr6B905FdnW03", "status": "AVAILABLE", "tags": ("warden", "immortal", "armor", "blade", "longbow", "totem")},
    {"name": "Void Warrior Bundle", "kind": "SMP", "price": 0.50, "price_label": "$0.50", "checkout": None, "status": "CHECKOUT NOT CONNECTED", "tags": ("void", "warrior", "armor", "blade")},
    {"name": "Fortnite Coaching", "kind": "SERVICE", "price": None, "price_label": "QUOTE THROUGH ESN", "checkout": None, "status": "DISCORD ORDER", "tags": ("fortnite", "coaching", "gaming")},
    {"name": "Editing Services", "kind": "SERVICE", "price": None, "price_label": "QUOTE THROUGH ESN", "checkout": None, "status": "DISCORD ORDER", "tags": ("editing", "video", "creator", "anime")},
    {"name": "Discord Server Setups", "kind": "SERVICE", "price": None, "price_label": "QUOTE THROUGH ESN", "checkout": None, "status": "DISCORD ORDER", "tags": ("discord", "setup", "roles", "channels", "moderation")},
    {"name": "Website Creation", "kind": "SERVICE", "price": None, "price_label": "ESTIMATE / QUOTE", "checkout": None, "status": "DISCORD ORDER", "tags": ("website", "web", "site", "startup", "enterprise")},
    {"name": "Memberships", "kind": "SERVICE", "price": None, "price_label": "PRICE NOT VERIFIED", "checkout": None, "status": "ASK STAFF", "tags": ("membership",)},
    {"name": "Hashtag Packs", "kind": "SERVICE", "price": None, "price_label": "PRICE NOT VERIFIED", "checkout": None, "status": "ASK STAFF", "tags": ("hashtag", "growth", "creator")},
    {"name": "Stream Branding", "kind": "SERVICE", "price": None, "price_label": "PRICE NOT VERIFIED", "checkout": None, "status": "ASK STAFF", "tags": ("stream", "branding", "creator")},
    {"name": "Custom Services", "kind": "SERVICE", "price": None, "price_label": "CUSTOM QUOTE", "checkout": None, "status": "DISCORD ORDER", "tags": ("custom", "project", "service")},
    {"name": "ESN Domains", "kind": "SERVICE", "price": None, "price_label": "PRICING NOT ACTIVATED", "checkout": None, "status": "SETUP MODE", "tags": ("domain", "domains", "subdomain", "dns")},
)

WEBSITE_ROUTES = {
    "store ai": ("/store-ai", "ESN products, services, prices, delivery, and checkout help"),
    "website builder": ("/website-builder", "Account-free ESN Website Builder"),
    "builder": ("/website-builder", "Account-free ESN Website Builder"),
    "domains": ("/domains", "ESN Domains and custom-domain controls"),
    "arcade": ("/arcade", "ESN Arcade and original browser games"),
    "tools": ("/free-browser-tools", "Free ES browser tools"),
    "status": ("/status", "ESN network status center"),
    "operations": ("/operations", "Connected ESN system operations map"),
    "diagnostics": ("/diagnostics", "Browser, cache, service worker, SMP, plugin, and Discord diagnostics"),
    "nexus": ("/nexus", "ESN Network Nexus"),
    "updates": ("/updates", "Website, SMP, Arcade, and network release center"),
    "timeline": ("/timeline", "Interactive ESN history timeline"),
    "about": ("/about", "About ES Network"),
    "leadership": ("/leadership", "ES Network leadership"),
    "faq": ("/faq", "ESN FAQ and support information"),
    "guides": ("/guides", "ESN Guides and News"),
    "smp": ("/minecraft-smp", "ESN SMP information"),
    "smp connection": ("/smpconnection", "ESN SMP connection help"),
    "support": ("/support", "Website problem reporting and diagnostics"),
    "explore": ("/explore", "ESN feature discovery"),
    "gallery": ("/gallery", "Official ESN visuals and milestones"),
}

ARCADE_GAMES = ("ES Clicker", "ES Factory", "ES Mines", "ES MOTO", "ES Tower", "ES Tower Defense")


def extract_esng_prompt(content: str) -> str | None:
    match = TRIGGER_RE.match(content.strip())
    if match is None:
        return None
    return content.strip()[match.end():].strip()


def _contains(prompt: str, *terms: str) -> bool:
    normalized = prompt.casefold()
    return any(term in normalized for term in terms)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.$ ]", " ", str(value).casefold())).strip()


def _budget_from(prompt: str) -> float | None:
    match = re.search(r"\$\s*(\d+(?:\.\d{1,2})?)|(?:under|below|less than|budget(?: of)?|for)\s*\$?\s*(\d+(?:\.\d{1,2})?)", prompt, re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1) or match.group(2))
    except (TypeError, ValueError):
        return None


def _catalog_matches(prompt: str) -> list[dict[str, object]]:
    normalized = _normalize(prompt)
    tokens = [token for token in normalized.split() if len(token) > 2]
    scored = []
    for item in CATALOG:
        text = _normalize(" ".join((str(item["name"]), str(item["kind"]), *(str(tag) for tag in item["tags"]))))
        score = sum(3 for token in tokens if token in text)
        if normalized and normalized in text:
            score += 20
        if "smp" in normalized and item["kind"] == "SMP":
            score += 5
        if "service" in normalized and item["kind"] == "SERVICE":
            score += 5
        if score:
            scored.append((score, item))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in scored]


def _catalog_line(item: dict[str, object], include_checkout: bool = False) -> str:
    line = f"**{item['name']}** — {item['price_label']} — {item['status']}"
    if include_checkout:
        if item.get("checkout"):
            line += f"\nCheckout: {item['checkout']}"
        elif item["kind"] == "SERVICE":
            line += f"\nOrder/support: {DISCORD_URL}"
        else:
            line += "\nCheckout is not connected; ESNG will not invent a payment link."
    return line


class ESNGuardianAICog(commands.Cog):
    """Local Guardian-aware assistant. It only responds to messages beginning with ESNG."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.cooldowns: dict[tuple[int, int], datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=UTC))

    async def _security_status(self, guild: discord.Guild) -> str:
        await self.bot.database.ensure_guild(guild.id)
        security = await self.bot.database.fetchone("SELECT * FROM security_config WHERE guild_id = ?", (guild.id,))
        antinuke = await self.bot.database.fetchone("SELECT * FROM anti_nuke_config WHERE guild_id = ?", (guild.id,))
        raid = await self.bot.database.fetchone("SELECT * FROM raid_config WHERE guild_id = ?", (guild.id,))
        verification = await self.bot.database.fetchone("SELECT * FROM verification_config WHERE guild_id = ?", (guild.id,))
        settings = await self.bot.database.setting(guild.id)
        return (
            "**Guardian security status**\n"
            f"AutoMod: {'ON' if security and security['automod_enabled'] else 'OFF'}\n"
            f"Anti-nuke: {'ON' if antinuke and antinuke['enabled'] else 'OFF'}\n"
            f"Raid protection: {'ON' if raid and raid['enabled'] else 'OFF'}\n"
            f"Verification: {'ON' if verification and verification['enabled'] else 'OFF'}\n"
            f"Lockdown: {'ACTIVE' if settings['lockdown_active'] else 'inactive'}"
        )

    def _store_answer(self, prompt: str) -> str | None:
        normalized = _normalize(prompt)
        matches = _catalog_matches(prompt)
        budget = _budget_from(prompt)
        purchasable = sorted(
            (item for item in CATALOG if item["price"] is not None and item["status"] == "AVAILABLE"),
            key=lambda item: float(item["price"]),
        )

        if _contains(normalized, "delivery", "minecraft username", "leading dot", "prefix"):
            return "For SMP purchases, enter the exact Minecraft Username at checkout. If the server username uses a leading period, include it. Be online on the SMP when possible for automatic delivery."

        if _contains(normalized, "all products", "catalog", "what do you sell", "show everything"):
            return "**ESN catalog**\n" + "\n".join(f"• {item['name']} — {item['price_label']} ({item['status']})" for item in CATALOG)

        if _contains(normalized, "cheapest", "lowest price", "least expensive"):
            minimum = min(float(item["price"]) for item in purchasable)
            items = [item for item in purchasable if float(item["price"]) == minimum]
            return "Cheapest verified direct-checkout items:\n" + "\n".join(_catalog_line(item, True) for item in items)

        if budget is not None:
            items = [item for item in purchasable if float(item["price"]) <= budget]
            money = "$" + f"{budget:.2f}"
            if not items:
                return f"I do not have a verified direct-checkout product at or below {money}. Some ESN services use custom quotes through Discord."
            return f"Verified products at or below {money}:\n" + "\n\n".join(_catalog_line(item, True) for item in items)

        if _contains(normalized, "compare", "versus", "difference") and len(matches) >= 2:
            return "Closest verified catalog comparison:\n" + "\n".join(_catalog_line(item) for item in matches[:3])

        if _contains(normalized, "checkout", "buy", "purchase", "order", "payment link") and matches:
            return _catalog_line(matches[0], True)

        if _contains(normalized, "services", "service", "editing", "coaching", "branding", "hashtag", "membership", "custom"):
            items = matches[:6] if matches else [item for item in CATALOG if item["kind"] == "SERVICE"]
            return "**ESN services**\n" + "\n".join(_catalog_line(item, True) for item in items[:6])

        if _contains(normalized, "smp product", "minecraft product", "bundle", "keys", "relic", "warden", "rift", "void warrior"):
            items = matches[:5] if matches else [item for item in CATALOG if item["kind"] == "SMP"]
            return "**ESN SMP catalog**\n" + "\n".join(_catalog_line(item, True) for item in items[:5])

        if matches and any(token in normalized for token in ("price", "cost", "product", "store")):
            return "\n".join(_catalog_line(item, True) for item in matches[:4])
        return None

    def _website_answer(self, prompt: str) -> str | None:
        normalized = _normalize(prompt)
        if _contains(normalized, "website links", "site links", "pages", "routes"):
            keys = ("store ai", "website builder", "domains", "arcade", "tools", "status", "diagnostics", "nexus", "updates", "guides")
            return "**Popular ESN website pages**\n" + "\n".join(
                f"• {name.title()}: {WEBSITE_URL}{WEBSITE_ROUTES[name][0]}" for name in keys
            )
        for name, (path, description) in WEBSITE_ROUTES.items():
            if _normalize(name) in normalized:
                return f"**{name.title()}**\n{description}\n{WEBSITE_URL}{path}"
        if _contains(normalized, "website", "esn site", "official site"):
            return f"Official ES Network website: {WEBSITE_URL}\nStore AI: {STORE_AI_URL}\nWebsite Builder: {WEBSITE_URL}/website-builder\nStatus: {WEBSITE_URL}/status"
        return None

    async def _answer(self, guild: discord.Guild, prompt: str) -> str:
        p = prompt.casefold().strip()

        if not p or _contains(p, "help", "what can you do", "commands"):
            return (
                "**ESNG AI** only wakes when a message starts with ESNG.\n"
                "Ask about Guardian security, anti-nuke, raids, verification, tickets, moderation, backups, "
                "ESN products, prices, checkout, services, Website Builder, Domains, Arcade, Tools, Nexus, diagnostics, updates, Discord, or website links.\n"
                "Examples: ESNG security status • ESNG what can I get for $1 • ESNG Website Builder • ESNG Warden checkout"
            )

        if _contains(p, "security status", "guardian status", "protection status"):
            return await self._security_status(guild)

        if _contains(p, "bot status", "online", "uptime", "latency"):
            uptime = datetime.now(UTC) - self.bot.started_at
            total_seconds = max(int(uptime.total_seconds()), 0)
            days, remainder = divmod(total_seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes, _ = divmod(remainder, 60)
            return (
                "**Guardian bot status**\n"
                f"Online: yes\nLatency: {round(self.bot.latency * 1000)} ms\n"
                f"Uptime: {days}d {hours}h {minutes}m\nServers: {len(self.bot.guilds)}"
            )

        if _contains(p, "anti-nuke", "antinuke", "nuke"):
            return (
                "**Anti-nuke** watches destructive Discord audit-log actions such as channel/role destruction, "
                "dangerous permission escalation, mass moderation activity, webhook abuse, and untrusted bot additions. "
                "Trusted users and the server owner are exempt. The server owner controls it with /antinuke commands."
            )

        if _contains(p, "raid", "join flood", "mass join"):
            return (
                "**Raid protection** watches rapid joins and suspiciously new accounts. "
                "It can quarantine suspicious members and trigger an emergency lockdown when the configured join threshold is exceeded. "
                "Staff configure it with /security raid."
            )

        if _contains(p, "automod", "spam", "phishing", "links", "invite"):
            return (
                "**AutoMod** checks flood spam, repeated messages, mass mentions, caps, blocked words, Discord invites, "
                "strict-link allowlists, and phishing-style links. Dangerous-link checks also apply to staff messages."
            )

        if _contains(p, "verification", "verify"):
            return (
                "**Verification** gives approved members the configured verified role after server checks. "
                "It can enforce minimum account age and safely rejects privileged or unmanageable role configurations."
            )

        if _contains(p, "ticket", "support"):
            return (
                "**Tickets** create private support channels for the member, configured support role, and Guardian. "
                "Use /ticket to open one and /ticket-close inside the ticket when the issue is resolved."
            )

        if _contains(p, "moderation", "mod commands", "ban", "kick", "timeout", "warn"):
            return (
                "**Moderation** includes warnings, timeouts, kicks, bans, unbans, role changes, nickname changes, slowmode, "
                "message clearing, cases, and member history. Guardian checks the caller's Discord permission and role hierarchy before acting."
            )

        if _contains(p, "lockdown", "lock down"):
            return (
                "**Lockdown** blocks @everyone from sending messages across text channels during an incident. "
                "Guardian stores the previous channel send permissions in SQLite and restores them when lockdown is released."
            )

        if _contains(p, "token", "bot token", "password", "secret", "staff code", "environment variable"):
            return "I will not reveal Discord tokens, passwords, staff codes, environment-variable secrets, or other private credentials."

        if _contains(p, "backup", "database save", "database persistence", "save settings"):
            return (
                "**Guardian persistence**\nServer configuration is stored in SQLite. Guardian creates verified snapshots at startup, shutdown, and every six hours, "
                "keeps recent backups, and can recover from the newest valid backup if the main database is corrupt. "
                "The bot owner can use /backupdb and /backupstatus."
            )

        if _contains(p, "who is esn", "what is esn", "ep1c", "epic services", "brand"):
            return (
                "**ES Network (ESN)** is the current brand. EP1C Services was the former name, not a separate current division. "
                "ESN connects creator services, the SMP, Arcade, free browser tools, website creation, community resources, and other network projects."
            )

        if _contains(p, "official discord", "community invite", "discord link"):
            return f"Official ES Network Discord: {DISCORD_URL}"

        if _contains(p, "arcade games", "browser games", "games"):
            return "**ESN Arcade**\n" + "\n".join(f"• {game}" for game in ARCADE_GAMES) + f"\n{WEBSITE_URL}/arcade"

        store_answer = self._store_answer(prompt)
        if store_answer is not None:
            return store_answer

        website_answer = self._website_answer(prompt)
        if website_answer is not None:
            return website_answer

        if _contains(p, "privacy", "data", "database"):
            return (
                "Guardian stores server-scoped settings, moderation/security cases, ticket state, and verification state in SQLite. "
                "Bot tokens belong in environment variables and should never be posted in Discord or committed to GitHub."
            )

        return (
            "I do not have a verified answer for that yet. Try ESNG help. "
            f"For live ESN information, use {WEBSITE_URL}. "
            "I will not invent prices, checkout links, security settings, commands, or private data."
        )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return

        prompt = extract_esng_prompt(message.content)
        if prompt is None:
            return

        key = (message.guild.id, message.author.id)
        now = datetime.now(UTC)
        if now - self.cooldowns[key] < timedelta(seconds=3):
            return
        self.cooldowns[key] = now

        answer = await self._answer(message.guild, prompt[:1000])
        embed = discord.Embed(
            title="ESNG AI",
            description=answer[:4096],
            color=discord.Color(0x0B3D91),
            timestamp=now,
        )
        embed.set_footer(text="Protected by ESN Guardian • Trigger: ESNG")
        try:
            await message.reply(embed=embed, mention_author=False, allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            return


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ESNGuardianAICog(bot))
