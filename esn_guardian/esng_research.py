"""Offline extractive research: transparent source-based summaries, not generative AI."""
from __future__ import annotations
import re
from collections import Counter

STOP=frozenset("the a an and or but of for to in on at from by with is are was were be been it this that these those as how what why when where who can does do i you we they their its your about into than then which will would should".split())
def tokens(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]{2,}",text.lower()) if w not in STOP]
def sentences(text: str) -> list[str]:
    return [s.strip(" •\t") for s in re.split(r"(?<=[.!?])\s+|\n+",text) if len(s.strip())>=35][:120]
def extractive_answer(question: str, passages: list[str], source: str, *, max_sentences: int=4) -> str:
    """Quote-ranked relevant passages with attribution; never fabricate missing facts."""
    corpus=sentences(" ".join(passages)[:30000])
    if not corpus: return "No readable article content was found."
    q=set(tokens(question))
    freq=Counter(w for s in corpus for w in tokens(s))
    scored=[]
    for idx,s in enumerate(corpus):
        words=set(tokens(s))
        if not words: continue
        overlap=len(q & words)
        if q and not overlap: continue
        score=(overlap*6 if q else 0)+sum(1/(1+freq[w]) for w in words)*0.3 - idx*0.012
        scored.append((score,idx,s))
    if not scored:
        return "I couldn't find a passage answering that question on this page.\nSource: "+source
    best=sorted(scored,reverse=True)[:max_sentences]
    best.sort(key=lambda x:x[1])
    heading="Relevant source passages (not independently verified):" if q else "Extractive article summary (not independently verified):"
    return (heading+"\n"+"\n".join("• "+s[:350] for _,_,s in best)+"\nSource: "+source)[:1900]
