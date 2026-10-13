"""Bounded scientific calculator and optional sourced web lookup for ESNG AI."""
from __future__ import annotations
import ast
import math
import operator
import re
import aiohttp
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, unquote

BIN = {ast.Add:operator.add, ast.Sub:operator.sub, ast.Mult:operator.mul, ast.Div:operator.truediv, ast.FloorDiv:operator.floordiv, ast.Mod:operator.mod, ast.Pow:operator.pow}
UNARY = {ast.UAdd:operator.pos, ast.USub:operator.neg}
FUNCS = {"sqrt":math.sqrt,"sin":math.sin,"cos":math.cos,"tan":math.tan,"asin":math.asin,"acos":math.acos,"atan":math.atan,"log":math.log10,"ln":math.log,"exp":math.exp,"abs":abs,"floor":math.floor,"ceil":math.ceil,"factorial":math.factorial,"degrees":math.degrees,"radians":math.radians}
CONSTANTS = {"pi":math.pi,"e":math.e,"tau":math.tau}

def calculate(expression: str) -> int | float:
    expression = expression.strip().replace("×","*").replace("÷","/").replace("−","-").replace("π","pi").replace("√(","sqrt(").replace("^","**")
    expression = re.sub(r"(?<=\\d)\\s*%", "/100", expression)
    if len(expression)>180: raise ValueError("Expression too long")
    tree = ast.parse(expression,mode="eval")
    nodes = list(ast.walk(tree))
    if len(nodes)>70: raise ValueError("Too many operations")
    def run(n,depth=0):
        if depth>15: raise ValueError("Too deep")
        if isinstance(n,ast.Expression): return run(n.body,depth+1)
        if isinstance(n,ast.Constant) and type(n.value) in (int,float): result=n.value
        elif isinstance(n,ast.Name) and n.id in CONSTANTS: result=CONSTANTS[n.id]
        elif isinstance(n,ast.UnaryOp) and type(n.op) in UNARY: result=UNARY[type(n.op)](run(n.operand,depth+1))
        elif isinstance(n,ast.BinOp) and type(n.op) in BIN:
            left,right=run(n.left,depth+1),run(n.right,depth+1)
            if isinstance(n.op,ast.Pow) and (abs(right)>100 or abs(left)>1e8): raise ValueError("Power exceeds limits")
            result=BIN[type(n.op)](left,right)
        elif isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in FUNCS and not n.keywords and len(n.args)==1:
            arg=run(n.args[0],depth+1)
            if n.func.id=="factorial" and (int(arg)!=arg or arg<0 or arg>100): raise ValueError("Factorial exceeds limits")
            result=FUNCS[n.func.id](arg)
        else: raise ValueError("Unsupported expression")
        if not isinstance(result,(int,float)) or not math.isfinite(result) or abs(result)>1e30: raise ValueError("Result exceeds limits")
        return result
    return run(tree)


class _SearchParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results=[]
        self.capture=False
        self.title=[]
        self.url=""
    def handle_starttag(self,tag,attrs):
        d=dict(attrs)
        if tag=="a" and "result__a" in d.get("class","") and len(self.results)<5:
            self.capture=True
            self.title=[]
            self.url=d.get("href","")
    def handle_data(self,data):
        if self.capture: self.title.append(data)
    def handle_endtag(self,tag):
        if tag=="a" and self.capture:
            self.capture=False
            url=self.url
            if url.startswith("//"): url="https:"+url
            if "duckduckgo.com/l/" in url:
                url=parse_qs(urlparse(url).query).get("uddg",[""])[0]
            parsed=urlparse(url)
            if parsed.scheme=="https" and parsed.hostname and parsed.hostname not in ("duckduckgo.com","html.duckduckgo.com"):
                self.results.append((" ".join(self.title).strip()[:110],url[:500]))

async def search_web(query: str) -> str:
    """Search public HTML without an API or credentials; availability is not guaranteed."""
    if len(query)>200: return "Search query is too long."
    timeout=aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout,headers={"User-Agent":"Mozilla/5.0 (compatible; ESNGGuardian/8)"}) as session:
            async with session.get("https://html.duckduckgo.com/html/",params={"q":query},allow_redirects=False) as resp:
                if resp.status!=200: return "Public web search is currently unavailable."
                html=await resp.text(errors="replace")
                if len(html)>800000: return "Search page exceeds safe size limits."
        parser=_SearchParser()
        parser.feed(html)
        if not parser.results: return "No public search results were available. Some websites block automated searches."
        lines=["Public web search results (titles and links; not independently verified):"]
        for title,url in parser.results[:4]: lines.append(f"• {title}\\n{url}")
        return "\\n".join(lines)[:1800]
    except (aiohttp.ClientError,TimeoutError,ValueError):
        return "Public web search is unavailable right now. Try again later."
