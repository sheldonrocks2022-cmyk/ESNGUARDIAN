"""Local opt-in ESNG notes. Never stores conversation transcripts automatically."""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path

class MemoryStore:
    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("ESNG_MEMORY_DB", "data/esng_memory.sqlite3"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS consent (guild INTEGER, user INTEGER, enabled INTEGER NOT NULL, PRIMARY KEY(guild,user))")
            db.execute("CREATE TABLE IF NOT EXISTS notes (guild INTEGER, user INTEGER, label TEXT, content TEXT NOT NULL, PRIMARY KEY(guild,user,label))")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def enabled(self, guild: int, user: int) -> bool:
        with self._connect() as db:
            return db.execute("SELECT enabled FROM consent WHERE guild=? AND user=?", (guild,user)).fetchone() == (1,)

    def opt_in(self, guild: int, user: int):
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO consent VALUES (?,?,1)", (guild,user))

    def forget(self, guild: int, user: int):
        with self._connect() as db:
            db.execute("DELETE FROM notes WHERE guild=? AND user=?", (guild,user))
            db.execute("DELETE FROM consent WHERE guild=? AND user=?", (guild,user))

    def remember(self, guild: int, user: int, label: str, content: str) -> bool:
        if not self.enabled(guild,user) or len(label)>40 or len(content)>500 or not label or not content:
            return False
        with self._connect() as db:
            count = db.execute("SELECT COUNT(*) FROM notes WHERE guild=? AND user=?", (guild,user)).fetchone()[0]
            existing = db.execute("SELECT 1 FROM notes WHERE guild=? AND user=? AND label=?", (guild,user,label)).fetchone()
            if count >= 20 and not existing:
                return False
            db.execute("INSERT OR REPLACE INTO notes VALUES (?,?,?,?)", (guild,user,label,content))
        return True

    def notes(self, guild: int, user: int) -> list[tuple[str,str]]:
        if not self.enabled(guild,user):
            return []
        with self._connect() as db:
            return db.execute("SELECT label, content FROM notes WHERE guild=? AND user=? ORDER BY label", (guild,user)).fetchall()
