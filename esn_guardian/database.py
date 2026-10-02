from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.connection: aiosqlite.Connection | None = None
        self.backup_dir = self.path.parent / "backups"
        self.last_backup_path: Path | None = None

    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self._recover_if_needed)
        self.connection = await aiosqlite.connect(self.path)
        self.connection.row_factory = aiosqlite.Row
        await self.connection.execute("PRAGMA journal_mode = WAL")
        await self.connection.execute("PRAGMA foreign_keys = ON")
        await self.connection.execute("PRAGMA busy_timeout = 5000")
        await self._migrate()
        await self.backup("startup")

    async def close(self) -> None:
        if self.connection is not None:
            try:
                await self.backup("shutdown")
            finally:
                await self.connection.close()
                self.connection = None

    @staticmethod
    def _backup_timestamp() -> str:
        return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")

    @staticmethod
    def _clean_backup_reason(reason: str) -> str:
        clean = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in reason.casefold())
        return clean.strip("-")[:32] or "snapshot"

    @staticmethod
    def _sqlite_file_ok(path: Path) -> bool:
        if not path.exists() or path.stat().st_size == 0:
            return False
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(str(path), timeout=5)
            row = connection.execute("PRAGMA quick_check").fetchone()
            return bool(row and row[0] == "ok")
        except sqlite3.DatabaseError:
            return False
        finally:
            if connection is not None:
                connection.close()

    def _recover_if_needed(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        if self._sqlite_file_ok(self.path):
            return

        candidates = sorted(
            self.backup_dir.glob(f"{self.path.stem}-*.db"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        source = next((candidate for candidate in candidates if self._sqlite_file_ok(candidate)), None)
        if source is None:
            raise RuntimeError(
                f"Guardian database is corrupt and no valid backup exists in {self.backup_dir}. "
                "The database was not reset automatically."
            )

        corrupt_path = self.path.with_name(f"{self.path.name}.corrupt-{self._backup_timestamp()}")
        shutil.move(self.path, corrupt_path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if sidecar.exists():
                sidecar.unlink()
        shutil.copy2(source, self.path)
        if not self._sqlite_file_ok(self.path):
            raise RuntimeError("Guardian restored a database backup, but the restored file failed SQLite integrity checking.")

    async def backup(self, reason: str = "scheduled", *, keep: int = 20) -> Path | None:
        if self.connection is None:
            return None
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        clean_reason = self._clean_backup_reason(reason)
        backup_path = self.backup_dir / f"{self.path.stem}-{self._backup_timestamp()}-{clean_reason}.db"

        async with aiosqlite.connect(backup_path) as target:
            await self.connection.backup(target)
            row = await (await target.execute("PRAGMA quick_check")).fetchone()
            if not row or row[0] != "ok":
                raise RuntimeError(f"Backup integrity check failed for {backup_path.name}")

        backups = sorted(
            self.backup_dir.glob(f"{self.path.stem}-*.db"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for stale in backups[max(keep, 3):]:
            try:
                stale.unlink()
            except FileNotFoundError:
                pass

        self.last_backup_path = backup_path
        return backup_path

    def backup_info(self) -> dict[str, Any]:
        backups = sorted(
            self.backup_dir.glob(f"{self.path.stem}-*.db"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        latest = backups[0] if backups else None
        return {
            "count": len(backups),
            "latest": latest.name if latest else None,
            "directory": str(self.backup_dir),
            "database": str(self.path),
        }

    def _require_connection(self) -> aiosqlite.Connection:
        if self.connection is None:
            raise RuntimeError("Database is not connected.")
        return self.connection

    async def _migrate(self) -> None:
        connection = self._require_connection()
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ticket_config (
                guild_id INTEGER PRIMARY KEY,
                support_role_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS tickets (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                channel_id INTEGER UNIQUE,
                opened_at REAL NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS lockdown_overwrites (
                guild_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                send_messages INTEGER,
                PRIMARY KEY (guild_id, channel_id)
            );
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                moderation_log_channel_id INTEGER,
                security_log_channel_id INTEGER,
                member_log_channel_id INTEGER,
                message_log_channel_id INTEGER,
                verification_log_channel_id INTEGER,
                system_log_channel_id INTEGER,
                guild_log_channel_id INTEGER,
                voice_log_channel_id INTEGER,
                invite_log_channel_id INTEGER,
                role_log_channel_id INTEGER,
                command_log_channel_id INTEGER,
                welcome_channel_id INTEGER,
                welcome_message TEXT,
                goodbye_channel_id INTEGER,
                goodbye_message TEXT,
                autorole_id INTEGER,
                lockdown_active INTEGER NOT NULL DEFAULT 0,
                lockdown_role_id INTEGER,
                ad_channel_id INTEGER,
                ad_enabled INTEGER NOT NULL DEFAULT 0,
                ad_cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
                ad_last_sent_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS cases (
                case_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                target_id INTEGER,
                moderator_id INTEGER,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                channel_id INTEGER,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_cases_guild_target ON cases(guild_id, target_id, case_id DESC);
            CREATE TABLE IF NOT EXISTS warnings (
                case_id INTEGER PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS verification_config (
                guild_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                channel_id INTEGER,
                message_id INTEGER,
                verified_role_id INTEGER,
                unverified_role_id INTEGER,
                min_account_age_days INTEGER NOT NULL DEFAULT 0,
                cooldown_seconds INTEGER NOT NULL DEFAULT 30,
                rules_confirmation INTEGER NOT NULL DEFAULT 1,
                captcha_enabled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS verified_members (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                verified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS panel_messages (
                guild_id INTEGER NOT NULL,
                panel_type TEXT NOT NULL,
                channel_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                PRIMARY KEY(guild_id, panel_type)
            );
            CREATE TABLE IF NOT EXISTS bad_words (
                guild_id INTEGER NOT NULL,
                word TEXT NOT NULL COLLATE NOCASE,
                PRIMARY KEY(guild_id, word)
            );
            CREATE TABLE IF NOT EXISTS guild_blacklist (
                guild_id INTEGER PRIMARY KEY,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS global_bans (
                user_id INTEGER PRIMARY KEY,
                reason TEXT NOT NULL,
                banned_by_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS anti_nuke_config (
                guild_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                action_limit INTEGER NOT NULL DEFAULT 3,
                window_seconds INTEGER NOT NULL DEFAULT 15,
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS anti_nuke_trusted_users (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                added_by_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, user_id),
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS blocked_external_apps (
                guild_id INTEGER NOT NULL,
                application_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                blocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(guild_id, application_id),
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_config (
                guild_id INTEGER PRIMARY KEY,
                automod_enabled INTEGER NOT NULL DEFAULT 1,
                flood_limit INTEGER NOT NULL DEFAULT 6,
                flood_window_seconds INTEGER NOT NULL DEFAULT 10,
                max_mentions INTEGER NOT NULL DEFAULT 6,
                caps_percentage INTEGER NOT NULL DEFAULT 80,
                block_invites INTEGER NOT NULL DEFAULT 1,
                strict_links INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS allowed_domains (
                guild_id INTEGER NOT NULL,
                domain TEXT NOT NULL COLLATE NOCASE,
                PRIMARY KEY(guild_id, domain),
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS raid_config (
                guild_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                join_limit INTEGER NOT NULL DEFAULT 10,
                join_window_seconds INTEGER NOT NULL DEFAULT 60,
                min_account_age_days INTEGER NOT NULL DEFAULT 3,
                quarantine_role_id INTEGER,
                FOREIGN KEY(guild_id) REFERENCES guild_settings(guild_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS bot_state (
                state_key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS status_subscriptions (
                user_id INTEGER NOT NULL,
                topic TEXT NOT NULL CHECK(topic IN ('smp', 'bot')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(user_id, topic)
            );
            """
        )
        cursor = await connection.execute("PRAGMA table_info(guild_settings)")
        existing_columns = {row["name"] for row in await cursor.fetchall()}
        for column_name in (
            "guild_log_channel_id",
            "voice_log_channel_id",
            "invite_log_channel_id",
            "role_log_channel_id",
            "command_log_channel_id",
        ):
            if column_name not in existing_columns:
                await connection.execute(f"ALTER TABLE guild_settings ADD COLUMN {column_name} INTEGER")
        await connection.commit()

    async def execute(self, query: str, values: Iterable[Any] = ()) -> None:
        connection = self._require_connection()
        await connection.execute(query, tuple(values))
        await connection.commit()

    async def executemany(self, query: str, rows: Iterable[Iterable[Any]]) -> None:
        connection = self._require_connection()
        await connection.executemany(query, [tuple(row) for row in rows])
        await connection.commit()

    async def fetchone(self, query: str, values: Iterable[Any] = ()) -> aiosqlite.Row | None:
        cursor = await self._require_connection().execute(query, tuple(values))
        return await cursor.fetchone()

    async def fetchall(self, query: str, values: Iterable[Any] = ()) -> list[aiosqlite.Row]:
        cursor = await self._require_connection().execute(query, tuple(values))
        return await cursor.fetchall()

    async def ensure_guild(self, guild_id: int) -> None:
        connection = self._require_connection()
        for query in (
            "INSERT OR IGNORE INTO guild_settings (guild_id) VALUES (?)",
            "INSERT OR IGNORE INTO verification_config (guild_id) VALUES (?)",
            "INSERT OR IGNORE INTO anti_nuke_config (guild_id) VALUES (?)",
            "INSERT OR IGNORE INTO security_config (guild_id) VALUES (?)",
            "INSERT OR IGNORE INTO ticket_config (guild_id) VALUES (?)",
            "INSERT OR IGNORE INTO raid_config (guild_id) VALUES (?)",
        ):
            await connection.execute(query, (guild_id,))
        await connection.commit()

    async def setting(self, guild_id: int) -> aiosqlite.Row:
        await self.ensure_guild(guild_id)
        row = await self.fetchone("SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,))
        assert row is not None
        return row

    async def update_setting(self, guild_id: int, field: str, value: Any) -> None:
        allowed = {
            "moderation_log_channel_id", "security_log_channel_id", "member_log_channel_id",
            "message_log_channel_id", "verification_log_channel_id", "system_log_channel_id",
            "guild_log_channel_id", "voice_log_channel_id", "invite_log_channel_id", "role_log_channel_id", "command_log_channel_id",
            "welcome_channel_id", "welcome_message", "goodbye_channel_id", "goodbye_message",
            "autorole_id", "lockdown_active", "lockdown_role_id", "ad_channel_id", "ad_enabled",
            "ad_cooldown_seconds", "ad_last_sent_at",
        }
        if field not in allowed:
            raise ValueError(f"Unsupported settings field: {field}")
        await self.ensure_guild(guild_id)
        await self.execute(f"UPDATE guild_settings SET {field} = ?, updated_at = CURRENT_TIMESTAMP WHERE guild_id = ?", (value, guild_id))

    async def create_case(self, guild_id: int, target_id: int | None, moderator_id: int | None, action: str, reason: str, channel_id: int | None = None, details: dict[str, Any] | None = None) -> int:
        connection = self._require_connection()
        cursor = await connection.execute(
            "INSERT INTO cases (guild_id, target_id, moderator_id, action, reason, channel_id, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (guild_id, target_id, moderator_id, action, reason, channel_id, json.dumps(details or {}, ensure_ascii=True)),
        )
        await connection.commit()
        return int(cursor.lastrowid)

    async def create_cases_bulk(
        self,
        rows: Iterable[tuple[int, int | None, int | None, str, str, int | None, dict[str, Any] | None]],
    ) -> None:
        connection = self._require_connection()
        prepared = [
            (guild_id, target_id, moderator_id, action, reason, channel_id, json.dumps(details or {}, ensure_ascii=True))
            for guild_id, target_id, moderator_id, action, reason, channel_id, details in rows
        ]
        if not prepared:
            return
        await connection.executemany(
            "INSERT INTO cases (guild_id, target_id, moderator_id, action, reason, channel_id, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            prepared,
        )
        await connection.commit()

    async def is_guild_blacklisted(self, guild_id: int) -> bool:
        row = await self.fetchone("SELECT 1 FROM guild_blacklist WHERE guild_id = ?", (guild_id,))
        return row is not None

    async def global_ban_reason(self, user_id: int) -> str | None:
        row = await self.fetchone("SELECT reason FROM global_bans WHERE user_id = ?", (user_id,))
        return str(row["reason"]) if row is not None else None

    async def state_enabled(self, state_key: str) -> bool:
        row = await self.fetchone("SELECT value FROM bot_state WHERE state_key = ?", (state_key,))
        return row is not None and row["value"] == "1"

    async def set_state_enabled(self, state_key: str, enabled: bool) -> None:
        await self.execute(
            "INSERT INTO bot_state (state_key, value) VALUES (?, ?) "
            "ON CONFLICT(state_key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            (state_key, "1" if enabled else "0"),
        )

    async def subscribe_to_status(self, user_id: int, topic: str) -> None:
        await self.execute(
            "INSERT OR IGNORE INTO status_subscriptions (user_id, topic) VALUES (?, ?)",
            (user_id, topic),
        )

    async def unsubscribe_from_status(self, user_id: int, topic: str) -> None:
        await self.execute(
            "DELETE FROM status_subscriptions WHERE user_id = ? AND topic = ?",
            (user_id, topic),
        )

    async def status_subscriptions(self, user_id: int) -> set[str]:
        rows = await self.fetchall("SELECT topic FROM status_subscriptions WHERE user_id = ?", (user_id,))
        return {str(row["topic"]) for row in rows}

    async def status_subscriber_ids(self, topic: str) -> list[int]:
        rows = await self.fetchall("SELECT user_id FROM status_subscriptions WHERE topic = ?", (topic,))
        return [int(row["user_id"]) for row in rows]
