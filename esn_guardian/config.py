from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True, slots=True)
class Settings:
    token: str
    owner_id: int | None
    database_path: Path
    log_level: str

    @classmethod
    def load(cls) -> "Settings":
        load_dotenv()
        token = os.getenv("DISCORD_TOKEN", "").strip()
        if not token:
            raise RuntimeError("DISCORD_TOKEN is required.")
        owner_value = os.getenv("BOT_OWNER_ID", "").strip()
        return cls(
            token=token,
            owner_id=int(owner_value) if owner_value else None,
            database_path=Path(os.getenv("DATABASE_PATH", "data/esn_guardian.db")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
