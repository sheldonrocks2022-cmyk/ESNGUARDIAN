import asyncio

import pytest

from esn_guardian.esng_conversation import ESNGConversation, safe_calculate


def test_arithmetic():
    assert safe_calculate("2 + 3 * 4") == 14
    assert safe_calculate("(2 + 3) * 4") == 20


@pytest.mark.parametrize("expression", [
    "__import__('os').system('echo nope')", "2 ** 10000", "1 / 0",
    "1 + 'abc'", "[1, 2, 3]", "9" * 101,
])
def test_rejects_unsafe_expression(expression):
    with pytest.raises((ValueError, SyntaxError, ZeroDivisionError, OverflowError)):
        safe_calculate(expression)


def test_isolated_conversations_and_reset():
    async def run():
        assistant = ESNGConversation()
        assert "14" in await assistant.reply(1, 10, "calculate 2+3*4")
        assert "previous message" not in (await assistant.reply(1, 11, "what was my last question")).lower()
        assert "calculate" in (await assistant.reply(1, 10, "what was my last question")).lower()
        assert "cleared" in (await assistant.reply(1, 10, "reset conversation")).lower()
    asyncio.run(run())
