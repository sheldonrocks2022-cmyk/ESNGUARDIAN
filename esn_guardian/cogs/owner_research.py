from __future__ import annotations

import asyncio
import html
import re
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import aiohttp
import discord
from discord.ext import commands

from esn_guardian.cogs.common import command_embed

UA = "Mozilla/5.0 (compatible; ESNGuardianResearch/8.0)"
SEARCH_URL = "https://html.duckduckgo.com/html/?q={}"

class OwnerResearch(commands.Cog):
    """Owner-only public-web research codes. No external AI service is used."""
    def __init__(self, bot): self.bot=bot
    def owner(self, ctx):
        oid=getattr(self.bot.settings,"owner_id",None); return oid is not None and ctx.author.id==int(oid)
    def clean(self, text): return re.sub(r"\\s+"," ",html.unescape(re.sub(r"<[^>]+>"," ",text))).strip()
    def unwrap(self, href):
        href=html.unescape(href)
        if href.startswith("//"): href="https:"+href
        q=parse_qs(urlparse(href).query).get("uddg")
        return unquote(q[0]) if q else href
    async def search(self, query, limit=8):
        timeout=aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout,headers={"User-Agent":UA}) as session:
            async with session.get(SEARCH_URL.format(quote_plus(query)),allow_redirects=True) as resp:
                if resp.status!=200: raise RuntimeError(f"search HTTP {resp.status}")
                body=await resp.text(errors="ignore")
        links=re.findall(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',body,re.I|re.S)
        snippets=re.findall(r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div)>',body,re.I|re.S)
        out=[]; seen=set()
        for i,(href,title) in enumerate(links):
            url=self.unwrap(href); host=urlparse(url).netloc.lower()
            if not url.startswith(("http://","https://")) or url in seen: continue
            seen.add(url); out.append({"title":self.clean(title)[:180],"url":url,"host":host,"snippet":self.clean(snippets[i])[:350] if i<len(snippets) else ""})
            if len(out)>=limit: break
        return out
    async def page_text(self, url):
        timeout=aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout,headers={"User-Agent":UA}) as session:
            async with session.get(url,allow_redirects=True) as resp:
                if resp.status!=200 or "text/html" not in resp.headers.get("Content-Type",""): return ""
                body=(await resp.text(errors="ignore"))[:500000]
        body=re.sub(r"<(script|style|noscript)[^>]*>.*?</\\1>"," ",body,flags=re.I|re.S)
        return self.clean(body)[:12000]
    def embed_results(self,title,query,rows,note=""):
        lines=[]
        for i,r in enumerate(rows[:8],1):
            snip=(r.get("snippet") or "No snippet available.")[:240]
            lines.append(f"**{i}. [{discord.utils.escape_markdown(r['title'])}]({r['url']})**\n{discord.utils.escape_markdown(snip)}\n`{r['host']}`")
        body=f"**Query:** {discord.utils.escape_markdown(query)}\n\n"+("\n\n".join(lines) if lines else "No public-web results found.")
        if note: body+=f"\n\n*{note}*"
        return command_embed(body[:4000],title=title)
    async def run(self,ctx,code,query,extra="",deep=False):
        if not self.owner(ctx): return
        async with ctx.typing():
            try:
                rows=await self.search((query+" "+extra).strip(),10)
                if deep and rows:
                    texts=await asyncio.gather(*(self.page_text(r["url"]) for r in rows[:4]),return_exceptions=True)
                    words=[w.casefold() for w in re.findall(r"[A-Za-z0-9_-]{4,}",query)][:8]
                    for r,t in zip(rows,texts):
                        if isinstance(t,str): r["snippet"]=(r["snippet"]+" "+next((sent for sent in re.split(r"(?<=[.!?])\\s+",t) if any(w in sent.casefold() for w in words)),""))[:350]
                await ctx.reply(embed=self.embed_results(f"ESNG CODE {code} • WEB RESEARCH",query,rows,"Public web research • no external AI API"),mention_author=False)
            except Exception:
                await ctx.reply(embed=command_embed("Public-web research could not complete. The search source may be unavailable or rate-limiting Guardian; try again later.",title=f"ESNG CODE {code} • SEARCH UNAVAILABLE"),mention_author=False)
    @commands.group(name="esngresearch",invoke_without_command=True,hidden=True)
    async def esngresearch(self,ctx): pass
    @esngresearch.command(name="16")
    async def c16(self,ctx,*,query): await self.run(ctx,16,query)
    @esngresearch.command(name="17")
    async def c17(self,ctx,*,query): await self.run(ctx,17,query,deep=True)
    @esngresearch.command(name="18")
    async def c18(self,ctx,*,query): await self.run(ctx,18,query,"project github documentation download community",True)
    @esngresearch.command(name="19")
    async def c19(self,ctx,*,query): await self.run(ctx,19,query,"site:github.com repository")
    @esngresearch.command(name="20")
    async def c20(self,ctx,*,query): await self.run(ctx,20,query,"latest news 2026")
    @esngresearch.command(name="21")
    async def c21(self,ctx,*,query): await self.run(ctx,21,query,"error fix documentation github issue stackoverflow",True)
    @esngresearch.command(name="22")
    async def c22(self,ctx,*,query): await self.run(ctx,22,query,"official documentation docs guide")
    @esngresearch.command(name="23")
    async def c23(self,ctx,*,query): await self.run(ctx,23,query,"price buy shop")
    @esngresearch.command(name="24")
    async def c24(self,ctx,*,query): await self.run(ctx,24,query,"website SEO metadata technology")
    @esngresearch.command(name="25")
    async def c25(self,ctx,*,query): await self.run(ctx,25,query,"alternatives competitors similar")
    @esngresearch.command(name="26")
    async def c26(self,ctx,*,query): await self.run(ctx,26,query,"free open source tools resources github")
    @esngresearch.command(name="27")
    async def c27(self,ctx,*,query): await self.run(ctx,27,query,"evidence source fact check",True)
    @esngresearch.command(name="28")
    async def c28(self,ctx,*,query): await self.run(ctx,28,query,"latest release changelog update github")
    @esngresearch.command(name="29")
    async def c29(self,ctx,*,query): await self.run(ctx,29,query,"implementation library open source example github",True)
    @esngresearch.command(name="30")
    async def c30(self,ctx,*,query): await self.run(ctx,30,query,"github documentation latest",True)

async def setup(bot): await bot.add_cog(OwnerResearch(bot))
