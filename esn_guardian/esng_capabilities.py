"""Bounded scientific calculator and optional sourced web lookup for ESNG AI."""
from __future__ import annotations
import ast
import math
import operator
import os
import re
import aiohttp

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

async def search_web(query: str) -> str:
    key=os.getenv("BRAVE_SEARCH_API_KEY","").strip()
    if not key: return "Web search is not configured. Set BRAVE_SEARCH_API_KEY in the server environment to enable sourced results."
    if len(query)>350: return "Search query is too long."
    timeout=aiohttp.ClientTimeout(total=8)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get("https://api.search.brave.com/res/v1/web/search",params={"q":query,"count":4,"safesearch":"moderate"},headers={"X-Subscription-Token":key,"Accept":"application/json"}) as resp:
                if resp.status!=200: return f"Search unavailable (HTTP {resp.status})."
                payload=await resp.json(content_type=None)
        results=payload.get("web",{}).get("results",[])[:4]
        if not results: return "No search results found."
        lines=["Web search results (source snippets, not independently verified):"]
        for item in results:
            title=re.sub(r"[\\r\\n]+"," ",str(item.get("title","Untitled")))[:100]
            desc=re.sub(r"[\\r\\n]+"," ",str(item.get("description","")))[:200]
            url=str(item.get("url",""))
            if not url.startswith(("https://","http://")): continue
            lines.append(f"• {title} — {desc}\\n{url}")
        return "\\n".join(lines)[:1800]
    except (aiohttp.ClientError,TimeoutError,ValueError):
        return "Web search timed out or failed. Try again later."
