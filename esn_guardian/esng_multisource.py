"""ESNG AI multi-source public research with DNS-pinned HTTPS fetches.

Explicit URLs only; no arbitrary private addresses, redirects, proxies or APIs.
"""
from __future__ import annotations
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit
import aiohttp
from esn_guardian.esng_capabilities import _ArticleParser
from esn_guardian.esng_intelligence import synthesize

class PublicResolver(aiohttp.abc.AbstractResolver):
    """Resolve only public addresses and return the checked IP to the connector."""
    async def resolve(self, host, port=0, family=socket.AF_INET):
        if not host or len(host)>253: raise OSError("Invalid hostname")
        results=await asyncio.to_thread(socket.getaddrinfo,host,port,family,socket.SOCK_STREAM)
        records=[]
        for fam,_,_,_,addr in results:
            ip=ipaddress.ip_address(addr[0])
            if not ip.is_global: raise OSError("Non-public address blocked")
            records.append({"hostname":host,"host":str(ip),"port":port,"family":fam,"proto":socket.IPPROTO_TCP,"flags":socket.AI_NUMERICHOST})
        if not records: raise OSError("No public address")
        return records
    async def close(self): pass

def valid_url(url: str) -> bool:
    try:
        p=urlsplit(url)
        return (len(url)<=500 and p.scheme=="https" and bool(p.hostname)
                and not p.username and not p.password and p.port in (None,443)
                and not p.hostname.endswith(".local") and not p.fragment)
    except ValueError: return False

async def fetch_public_text(url: str) -> str:
    if not valid_url(url): raise ValueError("Only public HTTPS URLs without credentials are supported")
    timeout=aiohttp.ClientTimeout(total=8,connect=4)
    connector=aiohttp.TCPConnector(resolver=PublicResolver(),use_dns_cache=False,limit=2)
    async with aiohttp.ClientSession(timeout=timeout,connector=connector,trust_env=False) as session:
        async with session.get(url,allow_redirects=False,headers={"User-Agent":"ESNGGuardian/8"}) as response:
            if response.status!=200 or "text/html" not in response.headers.get("Content-Type","").lower():
                raise ValueError("Page did not return readable HTML")
            if response.content_length and response.content_length>120000:
                raise ValueError("Page exceeds size limit")
            raw=await response.content.read(120001)
            if len(raw)>120000: raise ValueError("Page exceeds size limit")
    parser=_ArticleParser()
    parser.feed(raw.decode("utf-8","replace"))
    return " ".join(parser.parts[:40])[:12000]

async def research_many(question: str, urls: list[str]) -> str:
    if not 2<=len(urls)<=4 or len(set(urls))!=len(urls):
        return "Provide 2–4 different public HTTPS URLs."
    if any(not valid_url(u) for u in urls):
        return "Only public HTTPS URLs without credentials are supported."
    # Sequential, bounded requests: no unbounded fan-out on a shared bot.
    sources=[];failures=[]
    for url in urls:
        try:
            body=await fetch_public_text(url)
            if body: sources.append((url,body))
            else: failures.append(url+": no readable text")
        except (aiohttp.ClientError,TimeoutError,OSError,ValueError,UnicodeError) as exc:
            failures.append(url+": "+type(exc).__name__)
    if not sources: return "No readable sources could be retrieved. "+ "; ".join(failures)[:500]
    result=synthesize(question,sources)
    if failures: result+="\nUnavailable sources: "+", ".join(failures)[:300]
    return result[:1900]
