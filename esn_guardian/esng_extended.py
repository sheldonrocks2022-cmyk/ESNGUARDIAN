"""Additional bounded, API-free ESNG AI mathematical and text tools."""
from __future__ import annotations
import math
import re
import statistics
from collections import Counter
from datetime import date

NUM=r"(-?\d+(?:\.\d+)?)"
def fmt(x):
    if not math.isfinite(x) or abs(x)>1e15: raise ValueError("Result exceeds safe bounds")
    return str(int(x)) if x.is_integer() else f"{x:.9g}"

def extended_skill(prompt: str) -> str | None:
    p=prompt.strip()
    m=re.fullmatch(r"linear\s*[: ]\s*"+NUM+r"\s*,\s*"+NUM,p,re.I)
    if m:
        a,b=map(float,m.groups())
        return "No unique solution." if a==0 else f"For {fmt(a)}x + {fmt(b)} = 0, x = {fmt(-b/a)}"
    m=re.fullmatch(r"(?:gcd|lcm)\s*[: ]\s*(-?\d{1,12})\s*,\s*(-?\d{1,12})",p,re.I)
    if m:
        x,y=map(int,m.groups());g=math.gcd(x,y)
        return f"{m.group(0).split(':')[0].upper()}: {g if p.lower().startswith('gcd') else abs(x*y)//g if g else 0}"
    m=re.fullmatch(r"(?:factorial|n!)\s*[: ]\s*(\d{1,3})",p,re.I)
    if m:
        n=int(m.group(1))
        return f"{n}! = {math.factorial(n)}" if n<=100 else "Factorial limit is 100."
    m=re.fullmatch(r"(?:permutations|npr|combinations|ncr)\s*[: ]\s*(\d{1,3})\s*,\s*(\d{1,3})",p,re.I)
    if m:
        n,r=map(int,m.groups())
        if n>100 or r>n: return "Require 0 <= r <= n <= 100."
        value=math.comb(n,r) if p.lower().startswith(("combinations","ncr")) else math.perm(n,r)
        return f"Result: {value}"
    m=re.fullmatch(r"(?:circle area|area circle)\s*[: ]\s*"+NUM,p,re.I)
    if m:
        r=float(m.group(1))
        return "Radius must be nonnegative." if r<0 else f"Circle area: {fmt(math.pi*r*r)}"
    m=re.fullmatch(r"(?:circle circumference|circumference)\s*[: ]\s*"+NUM,p,re.I)
    if m:
        r=float(m.group(1))
        return "Radius must be nonnegative." if r<0 else f"Circumference: {fmt(2*math.pi*r)}"
    m=re.fullmatch(r"(?:rectangle area|area rectangle)\s*[: ]\s*"+NUM+r"\s*,\s*"+NUM,p,re.I)
    if m:
        w,h=map(float,m.groups())
        return "Dimensions must be nonnegative." if min(w,h)<0 else f"Rectangle area: {fmt(w*h)}"
    m=re.fullmatch(r"(?:hypotenuse|pythagorean)\s*[: ]\s*"+NUM+r"\s*,\s*"+NUM,p,re.I)
    if m:
        x,y=map(float,m.groups())
        return f"Hypotenuse: {fmt(math.hypot(x,y))}"
    m=re.fullmatch(r"(?:probability|chance)\s*[: ]\s*(\d{1,9})\s*,\s*(\d{1,9})",p,re.I)
    if m:
        good,total=map(int,m.groups())
        return "Require 0 <= favorable <= total and total > 0." if total==0 or good>total else f"Probability: {fmt(100*good/total)}%"
    m=re.fullmatch(r"(?:sort numbers|sort)\s*[: ]\s*(-?\d+(?:\.\d+)?(?:\s*[, ]\s*-?\d+(?:\.\d+)?){1,49})",p,re.I)
    if m:
        nums=sorted(float(x) for x in re.findall(r"-?\d+(?:\.\d+)?",m.group(1)))
        return "Sorted: "+", ".join(fmt(x) for x in nums)
    m=re.fullmatch(r"(?:frequency|word frequency)\s*[: ]\s*(.{1,1200})",p,re.I|re.S)
    if m:
        words=re.findall(r"[a-z0-9']+",m.group(1).lower())
        return "Top words: "+", ".join(f"{word} ({n})" for word,n in Counter(words).most_common(8)) if words else "No words found."
    m=re.fullmatch(r"(?:reverse text|reverse)\s*[: ]\s*(.{1,1200})",p,re.I|re.S)
    if m: return m.group(1)[::-1]
    m=re.fullmatch(r"(?:days between)\s*[: ]\s*(\d{4}-\d{2}-\d{2})\s*,\s*(\d{4}-\d{2}-\d{2})",p,re.I)
    if m:
        try: return f"Days between: {abs((date.fromisoformat(m.group(2))-date.fromisoformat(m.group(1))).days)}"
        except ValueError: return "Invalid ISO dates. Use YYYY-MM-DD."
    return None
