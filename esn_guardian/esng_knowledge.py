"""Small, auditable offline knowledge retrieval for ESNG.

Public facts only. No member data, tokens, or moderation secrets are indexed.
"""
from __future__ import annotations
import re

ARTICLES = (
    ("guardian", "Guardian is a Discord security and moderation bot. Sensitive changes must use permission-checked slash commands."),
    ("privacy", "ESNG's local conversation history is temporary, per guild and user, and cleared on restart. Never share secrets in chat."),
    ("language", "ESNG supports starter translations for 13 languages. Use ESNG language es or another supported locale code. Full bot translation is in progress."),
    ("memory", "Use ESNG reset conversation to erase your temporary chat context. Use ESNG what was my last question to recall the previous message."),
    ("math", "Use ESNG calculate (2+3)*4 for safe arithmetic. Arbitrary Python expressions and code execution are not allowed."),
    ("coding", "For Python errors, share the exception type, traceback and a minimal reproducible example with all tokens removed."),
    ("discord", "For Discord bot issues, check gateway intents, slash command synchronization, bot permissions and the error logs."),
    ("security", "ESNG cannot turn off Guardian protections through chat. Use the appropriate permission-checked Guardian command."),
)
STOPWORDS = {"what","is","the","a","an","and","or","to","for","with","can","you","me","about","how","do","i","tell","please","of"}


def retrieve(query: str, *, limit: int = 2) -> list[str]:
    tokens = set(re.findall(r"[^\W_]{2,}", query.casefold(), re.UNICODE)) - STOPWORDS
    if not tokens:
        return []
    scored = []
    for topic, article in ARTICLES:
        terms = set(re.findall(r"[^\W_]{2,}", (topic + " " + article).casefold(), re.UNICODE))
        score = len(tokens & terms) + (4 if topic in tokens else 0)
        if score:
            scored.append((score, topic, article))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [article for _, _, article in scored[:max(0, min(limit, 3))]]
