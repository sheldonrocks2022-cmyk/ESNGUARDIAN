import asyncio

from esn_guardian.esng_knowledge import retrieve
from esn_guardian.esng_conversation import ESNGConversation
from esn_guardian.localization import error_message


def test_retrieval_relevant_and_bounded():
    assert any("Discord" in item for item in retrieve("help discord bot"))
    assert retrieve("zxqvbnm gibberish") == []
    assert len(retrieve("help security", limit=1)) <= 1


def test_global_error_localization():
    title, message = error_message("denied", "es-ES")
    assert title == "Acceso denegado"
    assert "permiso" in message
    assert "5" in error_message("cooldown", "ja", seconds=5)[1]
    assert error_message("failed", "xx")[0] == "Command unavailable"


def test_conversation_local_knowledge():
    async def run():
        assistant = ESNGConversation()
        answer = await assistant.reply(4, 2, "how does Guardian security work")
        assert answer and "Guardian" in answer
    asyncio.run(run())
