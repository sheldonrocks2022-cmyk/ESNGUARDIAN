from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import aiohttp


async def post_alert(session: aiohttp.ClientSession, webhook: str, message: str) -> None:
    if not webhook:
        print(message)
        return
    try:
        async with session.post(webhook, json={"content": message[:1900]}) as response:
            if response.status >= 400:
                print(f"Watchdog alert webhook returned HTTP {response.status}: {message}")
    except Exception as error:
        print(f"Watchdog could not send alert: {error}: {message}")


async def main() -> None:
    status_url = os.getenv("GUARDIAN_STATUS_URL", "").strip()
    webhook = os.getenv("GUARDIAN_ALERT_WEBHOOK", "").strip()
    token = os.getenv("GUARDIAN_DASHBOARD_TOKEN", "").strip()
    expected_guilds = {
        int(value.strip())
        for value in os.getenv("GUARDIAN_EXPECTED_GUILD_IDS", "").split(",")
        if value.strip().isdigit()
    }
    if not status_url:
        raise SystemExit("GUARDIAN_STATUS_URL is required for the external Guardian watchdog.")

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    last_state: str | None = None
    failures = 0

    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            state = "offline"
            detail = ""
            try:
                async with session.get(status_url, headers=headers) as response:
                    if response.status >= 400:
                        raise RuntimeError(f"HTTP {response.status}")
                    payload = await response.json()
                    online = bool(payload.get("online"))
                    minimal = bool(payload.get("minimal_mode"))
                    guilds = payload.get("guilds", [])
                    critical = [
                        item for item in guilds
                        if str(item.get("state")) in {"CRITICAL", "PANIC"}
                    ]
                    current_guild_ids = {
                        int(item.get("guild_id"))
                        for item in guilds
                        if str(item.get("guild_id", "")).isdigit()
                    }
                    missing_guilds = sorted(expected_guilds - current_guild_ids)
                    if not online:
                        state = "offline"
                    elif missing_guilds:
                        state = "degraded"
                        detail = "Guardian is missing expected server IDs: " + ", ".join(map(str, missing_guilds))
                    elif minimal:
                        state = "degraded"
                        detail = "Guardian entered emergency minimal mode."
                    elif critical:
                        state = "critical"
                        detail = ", ".join(
                            f"{item.get('name', item.get('guild_id'))}: {item.get('state')}"
                            for item in critical[:8]
                        )
                    else:
                        state = "healthy"
                    failures = 0
            except Exception as error:
                failures += 1
                state = "offline" if failures >= 2 else "checking"
                detail = f"{type(error).__name__}: {error}"

            if state != last_state and state != "checking":
                stamp = datetime.now(UTC).isoformat()
                if state == "healthy":
                    message = f"ESN Guardian watchdog: Guardian is healthy again. {stamp}"
                elif state == "degraded":
                    message = f"ESN Guardian watchdog: Guardian is degraded. {detail} {stamp}"
                elif state == "critical":
                    message = f"ESN Guardian watchdog: Critical protection state detected. {detail} {stamp}"
                else:
                    message = f"ESN Guardian watchdog: Guardian appears OFFLINE. {detail} {stamp}"
                await post_alert(session, webhook, message)
                last_state = state

            await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main())
