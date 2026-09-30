from types import SimpleNamespace as NS

import pytest

from esn_guardian.cogs.esng_ai import ESNGuardianAICog, extract_esng_prompt
from esn_guardian.cogs.owner import owner_only


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("ESNG", ""),
        ("ESNG help", "help"),
        ("esng: security status", "security status"),
        ("ESNG, tickets", "tickets"),
        ("hello ESNG", None),
        ("ESNGUARDIAN help", None),
        ("ESNGthing", None),
    ],
)
def test_esng_trigger_is_prefix_only(content, expected):
    assert extract_esng_prompt(content) == expected


def test_esng_phishing_detection():
    from esn_guardian.cogs.security import SecurityCog

    assert SecurityCog._suspicious_url_reason("https://discord-gift.example/login")
    assert SecurityCog._suspicious_url_reason("https://bit.ly/example")
    assert SecurityCog._suspicious_url_reason("http://127.0.0.1/login")
    assert SecurityCog._suspicious_url_reason("https://user:pass@example.com/")
    assert SecurityCog._suspicious_url_reason("https://xn--discrd-9za.example/")
    assert SecurityCog._suspicious_url_reason("https://discord.com/") is None


async def test_esng_help_and_unknown_are_truthful():
    bot = NS()
    cog = ESNGuardianAICog(bot)
    guild = NS(id=1)

    help_text = await cog._answer(guild, "help")
    assert "ESNG security status" in help_text

    unknown = await cog._answer(guild, "tell me tomorrow's lottery numbers")
    assert "won't invent" in unknown


async def test_owner_check_accepts_configured_bot_owner():
    check = owner_only()
    interaction = NS(
        user=NS(id=777),
        client=NS(settings=NS(owner_id=777)),
    )
    assert await check.predicate(interaction)
