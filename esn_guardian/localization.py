"""Dependency-free localization primitives for Guardian.

Unicode text works in every language. Human translations must be authored and
reviewed per locale; this module does not claim machine translation.
"""
from __future__ import annotations

import re

SUPPORTED = ("en", "es", "fr", "de", "pt", "it", "ja", "ko", "zh", "ar", "hi", "ru", "tr")
STRINGS = {
    "en": {"hello": "Hello! I'm ESNG. What can I help you with?", "reset": "Conversation context cleared.", "result": "Result: {value}", "unknown": "I don't have a verified answer yet.", "memory": "Your previous message was: {value}", "empty": "We haven't discussed anything yet."},
    "es": {"hello": "¡Hola! Soy ESNG. ¿En qué puedo ayudarte?", "reset": "Se borró el contexto de la conversación.", "result": "Resultado: {value}", "unknown": "Todavía no tengo una respuesta verificada.", "memory": "Tu mensaje anterior fue: {value}", "empty": "Todavía no hemos hablado."},
    "fr": {"hello": "Bonjour ! Je suis ESNG. Comment puis-je vous aider ?", "reset": "Contexte de conversation effacé.", "result": "Résultat : {value}", "unknown": "Je n'ai pas encore de réponse vérifiée.", "memory": "Votre message précédent était : {value}", "empty": "Nous n'avons pas encore discuté."},
    "de": {"hello": "Hallo! Ich bin ESNG. Wie kann ich helfen?", "reset": "Gesprächskontext gelöscht.", "result": "Ergebnis: {value}", "unknown": "Ich habe noch keine verifizierte Antwort.", "memory": "Deine vorherige Nachricht war: {value}", "empty": "Wir haben noch nicht gesprochen."},
    "pt": {"hello": "Olá! Sou o ESNG. Como posso ajudar?", "reset": "Contexto da conversa apagado.", "result": "Resultado: {value}", "unknown": "Ainda não tenho uma resposta verificada.", "memory": "Sua mensagem anterior foi: {value}", "empty": "Ainda não conversamos."},
    "it": {"hello": "Ciao! Sono ESNG. Come posso aiutarti?", "reset": "Contesto della conversazione cancellato.", "result": "Risultato: {value}", "unknown": "Non ho ancora una risposta verificata.", "memory": "Il tuo messaggio precedente era: {value}", "empty": "Non abbiamo ancora parlato."},
    "ja": {"hello": "こんにちは！ESNGです。何をお手伝いしましょうか？", "reset": "会話履歴を消去しました。", "result": "結果: {value}", "unknown": "確認済みの回答はまだありません。", "memory": "前のメッセージ: {value}", "empty": "まだ会話履歴がありません。"},
    "ko": {"hello": "안녕하세요! ESNG입니다. 무엇을 도와드릴까요?", "reset": "대화 기록을 지웠습니다.", "result": "결과: {value}", "unknown": "아직 확인된 답변이 없습니다.", "memory": "이전 메시지: {value}", "empty": "아직 대화 기록이 없습니다."},
    "zh": {"hello": "你好！我是 ESNG。有什么可以帮你？", "reset": "对话记录已清除。", "result": "结果：{value}", "unknown": "目前没有经过验证的答案。", "memory": "你之前的消息：{value}", "empty": "我们还没有聊过。"},
    "ar": {"hello": "مرحبًا! أنا ESNG. كيف يمكنني مساعدتك؟", "reset": "تم مسح سياق المحادثة.", "result": "النتيجة: {value}", "unknown": "ليس لدي إجابة مؤكدة بعد.", "memory": "رسالتك السابقة: {value}", "empty": "لم نتحدث بعد."},
    "hi": {"hello": "नमस्ते! मैं ESNG हूँ। कैसे मदद करूँ?", "reset": "बातचीत का संदर्भ मिटा दिया गया।", "result": "परिणाम: {value}", "unknown": "अभी मेरे पास सत्यापित उत्तर नहीं है।", "memory": "आपका पिछला संदेश: {value}", "empty": "अभी हमारी कोई बातचीत नहीं हुई है।"},
    "ru": {"hello": "Привет! Я ESNG. Чем могу помочь?", "reset": "История беседы очищена.", "result": "Результат: {value}", "unknown": "Пока нет проверенного ответа.", "memory": "Ваше предыдущее сообщение: {value}", "empty": "Мы ещё не общались."},
    "tr": {"hello": "Merhaba! Ben ESNG. Nasıl yardımcı olabilirim?", "reset": "Konuşma geçmişi temizlendi.", "result": "Sonuç: {value}", "unknown": "Henüz doğrulanmış bir yanıtım yok.", "memory": "Önceki mesajınız: {value}", "empty": "Henüz konuşmadık."},
}
HELLOS = {
    "es": ("hola", "buenas"), "fr": ("bonjour", "salut"), "de": ("hallo", "guten tag"),
    "pt": ("olá", "oi"), "it": ("ciao", "buongiorno"), "ja": ("こんにちは",),
    "ko": ("안녕하세요",), "zh": ("你好",), "ar": ("مرحبا", "مرحبًا"),
    "hi": ("नमस्ते",), "ru": ("привет", "здравствуйте"), "tr": ("merhaba", "selam"),
}
RESET = {"en": ("reset conversation", "clear my memory"), "es": ("borrar conversación",), "fr": ("effacer la conversation",), "de": ("gespräch löschen",), "pt": ("limpar conversa",), "ja": ("会話を消去",), "ko": ("대화 삭제",), "zh": ("清除对话",), "ar": ("مسح المحادثة",), "hi": ("बातचीत मिटाओ",), "ru": ("очистить диалог",), "tr": ("sohbeti temizle",)}


def normalize_locale(locale: str | None) -> str:
    language = (locale or "en").replace("_", "-").split("-", 1)[0].casefold()
    return language if language in STRINGS else "en"


def detect_locale(text: str, default: str = "en") -> str:
    lowered = text.strip().casefold()
    for locale, words in HELLOS.items():
        if any(lowered == word or lowered.startswith(word + " ") for word in words):
            return locale
    return normalize_locale(default)


def translate(key: str, locale: str | None = None, **kwargs: object) -> str:
    language = normalize_locale(locale)
    template = STRINGS[language].get(key, STRINGS["en"].get(key, key))
    return template.format(**kwargs)


def is_greeting(text: str, locale: str) -> bool:
    lowered = text.strip().casefold()
    greetings = HELLOS.get(normalize_locale(locale), ()) + ("hello", "hi", "hey")
    return any(re.fullmatch(re.escape(word) + r"[!.。！ ]*", lowered) for word in greetings)
