"""Optional LLM conversation backend for ESNG AI.

Requires ESNG_LLM_API_KEY, ESNG_LLM_MODEL and ESNG_LLM_BASE_URL.
Uses an OpenAI-compatible chat completions endpoint; no secret is logged.
"""
from __future__ import annotations

import os
from collections import defaultdict, deque

import aiohttp


class ESNGConversation:
    def __init__(self) -> None:
        self.history: dict[tuple[int, int], deque[dict[str, str]]] = defaultdict(lambda: deque(maxlen=12))

    @property
    def enabled(self) -> bool:
        return all(os.getenv(key, "").strip() for key in (
            "ESNG_LLM_API_KEY", "ESNG_LLM_MODEL", "ESNG_LLM_BASE_URL"
        ))

    async def reply(self, guild_id: int, user_id: int, prompt: str) -> str | None:
        if not self.enabled:
            return None
        base = os.environ["ESNG_LLM_BASE_URL"].strip().rstrip("/")
        if not base.startswith("https://"):
            return None
        key = (guild_id, user_id)
        history = list(self.history[key])
        messages = [
            {"role": "system", "content": (
                "You are ESNG AI, a helpful, accurate Discord assistant. "
                "Speak naturally and admit uncertainty. You cannot access live Guardian "
                "data unless it is supplied to you. Never claim to have executed a "
                "moderation action or changed settings. Do not reveal secrets. "
                "For security changes, direct users to permission-checked Guardian commands."
            )},
            *history,
            {"role": "user", "content": prompt[:2000]},
        ]
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                base + "/chat/completions",
                headers={"Authorization": "Bearer " + os.environ["ESNG_LLM_API_KEY"].strip()},
                json={
                    "model": os.environ["ESNG_LLM_MODEL"].strip(),
                    "messages": messages,
                    "temperature": 0.5,
                    "max_tokens": 700,
                },
            ) as response:
                response.raise_for_status()
                payload = await response.json()
        answer = str(payload["choices"][0]["message"]["content"]).strip()[:3500]
        if not answer:
            return None
        self.history[key].append({"role": "user", "content": prompt[:2000]})
        self.history[key].append({"role": "assistant", "content": answer})
        return answer
