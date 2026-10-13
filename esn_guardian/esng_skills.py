"""ESNG AI-only deterministic skills. No external APIs or arbitrary code execution."""
from __future__ import annotations
import math
import re
import statistics
from collections import Counter
from esn_guardian.esng_capabilities import calculate

_UNITS={
    "m":("length",1.0),"km":("length",1000.0),"cm":("length",0.01),"mm":("length",0.001),
    "ft":("length",0.3048),"in":("length",0.0254),"mi":("length",1609.344),
    "kg":("mass",1.0),"g":("mass",0.001),"lb":("mass",0.45359237),"oz":("mass",0.028349523125),
    "s":("time",1.0),"min":("time",60.0),"h":("time",3600.0),"day":("time",86400.0),
    "b":("storage",1.0),"kb":("storage",1000.0),"mb":("storage",1e6),"gb":("storage",1e9),"tb":("storage",1e12),
}
def _fmt(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.9g}"

def answer_skill(prompt: str) -> str | None:
    p=prompt.strip()
    m=re.fullmatch(r"(?:esng\s+)?(?:convert\s+)?(-?\d+(?:\.\d+)?)\s*(m|km|cm|mm|ft|in|mi|kg|g|lb|oz|s|min|h|day|b|kb|mb|gb|tb|c|f|k)\s+(?:to|in)\s+(m|km|cm|mm|ft|in|mi|kg|g|lb|oz|s|min|h|day|b|kb|mb|gb|tb|c|f|k)",p,re.I)
    if m:
        val=float(m.group(1));src=m.group(2).lower();dst=m.group(3).lower()
        if src in ("c","f","k") or dst in ("c","f","k"):
            if src not in ("c","f","k") or dst not in ("c","f","k"): return "Incompatible conversion units."
            kelvin=val+273.15 if src=="c" else (val-32)*5/9+273.15 if src=="f" else val
            if kelvin<0: return "Temperature below absolute zero is invalid."
            result=kelvin-273.15 if dst=="c" else (kelvin-273.15)*9/5+32 if dst=="f" else kelvin
        else:
            kind,factor=_UNITS[src];other,other_factor=_UNITS[dst]
            if kind!=other: return "Incompatible conversion units."
            result=val*factor/other_factor
        return f"{_fmt(val)} {src} = {_fmt(result)} {dst}"
    m=re.fullmatch(r"(?:esng\s+)?(?:stats|statistics)\s*[: ]\s*(-?\d+(?:\.\d+)?(?:\s*[, ]\s*-?\d+(?:\.\d+)?){1,99})",p,re.I)
    if m:
        values=[float(x) for x in re.findall(r"-?\d+(?:\.\d+)?",m.group(1))]
        if not all(math.isfinite(x) and abs(x)<1e12 for x in values): return "Statistics input exceeds limits."
        return (f"Count: {len(values)} | Sum: {_fmt(sum(values))}\n"
                f"Mean: {_fmt(statistics.mean(values))} | Median: {_fmt(statistics.median(values))}\n"
                f"Min: {_fmt(min(values))} | Max: {_fmt(max(values))}\n"
                f"Population standard deviation: {_fmt(statistics.pstdev(values))}")
    m=re.fullmatch(r"(?:esng\s+)?(?:solve quadratic|quadratic)\s*[: ]\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)",p,re.I)
    if m:
        a,b,c=map(float,m.groups())
        if a==0: return "The first coefficient must be nonzero for a quadratic."
        d=b*b-4*a*c
        if d<0: return f"Discriminant: {_fmt(d)}. No real roots."
        root=math.sqrt(d)
        return f"Discriminant: {_fmt(d)}\nReal roots: {_fmt((-b+root)/(2*a))}, {_fmt((-b-root)/(2*a))}"
    m=re.fullmatch(r"(?:esng\s+)?(?:percent|percentage)\s+(-?\d+(?:\.\d+)?)\s+of\s+(-?\d+(?:\.\d+)?)",p,re.I)
    if m: return f"{_fmt(float(m.group(1)))}% of {_fmt(float(m.group(2)))} = {_fmt(float(m.group(1))*float(m.group(2))/100)}"
    m=re.fullmatch(r"(?:esng\s+)?(?:word count|count words)\s*[: ]\s*(.{1,1500})",p,re.I|re.S)
    if m:
        words=re.findall(r"\b[\w'-]+\b",m.group(1))
        return f"Words: {len(words)} | Characters: {len(m.group(1))} | Unique words: {len(set(w.casefold() for w in words))}"
    return None
