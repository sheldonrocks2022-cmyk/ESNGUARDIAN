from __future__ import annotations

from esn_guardian.database import Database


async def test_database_backup_restores_settings_after_corruption(tmp_path):
    path = tmp_path / "data" / "esn_guardian.db"

    database = Database(path)
    await database.connect()
    await database.ensure_guild(123)
    await database.update_setting(123, "welcome_channel_id", 456)
    snapshot = await database.backup("test")
    assert snapshot is not None and snapshot.exists()
    await database.close()

    path.write_bytes(b"not-a-valid-sqlite-database")

    restored = Database(path)
    await restored.connect()
    settings = await restored.setting(123)
    assert settings["welcome_channel_id"] == 456
    info = restored.backup_info()
    assert info["count"] >= 1
    assert info["latest"] is not None
    await restored.close()


async def test_manual_backup_keeps_database_valid(tmp_path):
    path = tmp_path / "guardian.db"
    database = Database(path)
    await database.connect()
    await database.ensure_guild(55)
    await database.update_setting(55, "autorole_id", 999)

    snapshot = await database.backup("manual-test")
    assert snapshot is not None
    assert snapshot.exists()
    assert Database._sqlite_file_ok(snapshot)

    await database.close()
