"""Consistent server-branded Discord embeds for Guardian responses."""
from __future__ import annotations
from datetime import datetime, timezone
import discord

COLORS = {"info": 0xD6B46C, "success": 0x35C795, "warning": 0xE6A34C, "danger": 0xE25B65}

def luxury_embed(ctx, title: str, description: str = "", *, level: str = "info", fields=()):
    guild = getattr(ctx, "guild", None)
    server = guild.name if guild else "Private Security Center"
    embed = discord.Embed(
        title=f"✦ {title}",
        description=description,
        color=COLORS.get(level, COLORS["info"]),
        timestamp=datetime.now(timezone.utc),
    )
    if guild and guild.icon:
        embed.set_author(name=f"ESN GUARDIAN  •  {server}", icon_url=guild.icon.url)
        embed.set_thumbnail(url=guild.icon.url)
    else:
        embed.set_author(name="ESN GUARDIAN  •  PRIVATE OPERATIONS")
    for name, value, inline in fields:
        embed.add_field(name=str(name), value=str(value) or "—", inline=inline)
    embed.set_footer(text="ESN GUARDIAN  •  OMEGA SECURITY OPERATIONS")
    return embed

async def luxury_reply(ctx, title, description="", *, level="info", fields=()):
    return await ctx.reply(embed=luxury_embed(ctx, title, description, level=level, fields=fields), mention_author=False)
