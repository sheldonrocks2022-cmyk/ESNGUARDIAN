"""Central owner authorization for Guardian V8 Luxury."""
from __future__ import annotations

LEVELS={"full","cases","communications"}

async def ensure_owner_table(bot):
    await bot.database.execute("""CREATE TABLE IF NOT EXISTS guardian_secondary_owners(
      user_id INTEGER PRIMARY KEY,level TEXT NOT NULL,added_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")

def primary_owner_id(bot):
    value=getattr(bot.settings,"owner_id",None)
    return int(value) if value is not None else None

def is_primary(bot,user_id:int)->bool:
    owner=primary_owner_id(bot)
    return owner is not None and owner==int(user_id)

async def owner_level(bot,user_id:int):
    if is_primary(bot,user_id): return "primary"
    await ensure_owner_table(bot)
    row=await bot.database.fetchone("SELECT level FROM guardian_secondary_owners WHERE user_id=?",(int(user_id),))
    return str(row["level"]) if row else None

async def allowed(bot,user_id:int,permission:str)->bool:
    level=await owner_level(bot,user_id)
    if level in {"primary","full"}: return True
    return level==permission
