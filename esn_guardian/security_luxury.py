"""Luxury owner-DM embeds for Guardian security cases.
Presentation only: no security behavior is changed.
"""
from __future__ import annotations
from datetime import datetime, timezone
import discord
LEVELS={"critical":0xE5484D,"recovery":0x3CCB9A,"warning":0xF0A94A,"security":0x8B5CF6}
def _profile(action: str):
    key=(action or "").upper()
    if "RECOVERY" in key or "HEAL" in key or "RESTORE" in key: return "RECOVERY COMPLETE","Recovery protocol",LEVELS["recovery"]
    if "PANIC" in key or "LOCKDOWN" in key or "BAN" in key or "NUKE" in key: return "CRITICAL SECURITY EVENT","Maximum protection",LEVELS["critical"]
    if "ALERT" in key or "WARN" in key or "TAMPER" in key: return "SECURITY WARNING","Elevated monitoring",LEVELS["warning"]
    return "SECURITY EVENT","Guardian operations",LEVELS["security"]
def security_case_embed(guild: discord.Guild, *, case_id: int, action: str, target_text: str, reason: str) -> discord.Embed:
    heading,posture,color=_profile(action)
    embed=discord.Embed(title=f"✦ {heading}",description=f"**{guild.name}** • {posture}",color=color,timestamp=datetime.now(timezone.utc))
    if guild.icon:
        embed.set_author(name="ESN GUARDIAN  •  OMEGA SECURITY",icon_url=guild.icon.url); embed.set_thumbnail(url=guild.icon.url)
    else: embed.set_author(name="ESN GUARDIAN  •  OMEGA SECURITY")
    embed.add_field(name="CASE",value=f"#{case_id}",inline=True)
    embed.add_field(name="ACTION",value=action,inline=True)
    embed.add_field(name="SERVER",value=str(guild.id),inline=True)
    embed.add_field(name="TARGET",value=target_text or "N/A",inline=False)
    embed.add_field(name="INTELLIGENCE",value=(reason or "No additional details supplied.").strip()[:1024],inline=False)
    embed.add_field(name="GUARDIAN STATUS",value="ACTIVE • Event recorded • Existing protection policy unchanged",inline=False)
    embed.set_footer(text="ESN GUARDIAN  •  OMEGA SECURITY OPERATIONS  •  EVIDENCE LOGGED")
    return embed
