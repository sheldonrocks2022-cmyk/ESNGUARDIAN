import asyncio

from esn_guardian.localization import SUPPORTED, detect_locale, normalize_locale, translate
from esn_guardian.esng_conversation import ESNGConversation


def test_locale_fallback_and_unicode():
    assert normalize_locale("es-MX") == "es"
    assert normalize_locale("unknown") == "en"
    assert detect_locale("こんにちは") == "ja"
    assert detect_locale("Hola") == "es"
    assert "ESNG" in translate("hello", "ar")
    assert len(SUPPORTED) >= 10


def test_multilingual_isolation_and_reset():
    async def run():
        ai = ESNGConversation()
        assert "Hola" in await ai.reply(1, 7, "hola")
        assert "Bonjour" in await ai.reply(1, 8, "bonjour")
        assert "Resultado" in await ai.reply(1, 7, "calculate 2+3")
        assert "cleared" in (await ai.reply(1, 8, "reset conversation")).lower() or "effacé" in (await ai.reply(1, 8, "reset conversation")).lower()
        assert "こんにちは" in await ai.reply(2, 7, "こんにちは")
    asyncio.run(run())
