"""ESNG AI advanced local intelligence: multi-source synthesis and short-term context.

All processing is local. Source text must be explicitly supplied or retrieved
by the existing bounded public-page reader; no provider APIs or private training.
"""
from __future__ import annotations
import re
from collections import Counter, OrderedDict
from esn_guardian.esng_research import sentences, tokens

def synthesize(question: str, sources: list[tuple[str,str]], limit: int = 3) -> str:
    """Evidence-based, source-attributed synthesis without inventing claims."""
    if not sources: return "No sources supplied."
    query = set(tokens(question[:300]))
    ranked = []
    for source_id, (url, body) in enumerate(sources[:5]):
        for position, sentence in enumerate(sentences(body[:12000])[:80]):
            terms = set(tokens(sentence))
            overlap = len(query & terms)
            if query and not overlap: continue
            score = overlap * 8 + len(terms & query) / max(len(terms),1) - position * .005
            ranked.append((score,source_id,position,sentence[:300],url))
    if not ranked: return "I couldn't find relevant evidence in the supplied sources."
    ranked.sort(key=lambda item: (-item[0],item[1],item[2]))
    selected, used = [], set()
    for _,sid,_,sentence,url in ranked:
        signature = " ".join(tokens(sentence)[:15])
        if signature in used: continue
        selected.append((sid,sentence,url));used.add(signature)
        if len(selected)>=max(1,min(limit,5)):break
    lines=["Relevant evidence from supplied sources (not independently verified):"]
    lines.extend(f"[{sid+1}] {sentence}\n{url}" for sid,sentence,url in selected)
    return "\n".join(lines)[:1850]

class ConversationContext:
    """Ephemeral per-user reference context; no disk writes or training."""
    def __init__(self, capacity: int = 1000):
        self._items: OrderedDict[tuple[int,int], tuple[str,str]] = OrderedDict()
        self.capacity = capacity

    def remember(self, key: tuple[int,int], topic: str, answer: str) -> None:
        self._items[key] = (topic[:150],answer[:1600])
        self._items.move_to_end(key)
        while len(self._items)>self.capacity:self._items.popitem(last=False)

    def forget(self, key: tuple[int,int]) -> None:
        self._items.pop(key,None)

    def followup(self, key: tuple[int,int], prompt: str) -> str | None:
        m=re.fullmatch(r"(?:what (?:was|did you say)(?: about (?:that|it))?|repeat (?:that|your answer)|show (?:that|it) again)\??",prompt.strip(),re.I)
        if m and key in self._items:
            topic,answer=self._items[key]
            return f"Earlier answer about {topic}:\n{answer}"
        return None

def explain_python_error(text: str) -> str | None:
    """Static explanation only; never execute untrusted code."""
    p=text[:1800]
    m=re.search(r"\b(SyntaxError|IndentationError|NameError|TypeError|ValueError|KeyError|IndexError|AttributeError|ModuleNotFoundError|ImportError|ZeroDivisionError|FileNotFoundError|PermissionError|TimeoutError)\b",p)
    if not m:return None
    explanations={
        "SyntaxError":"Check punctuation, parentheses, quotation marks, and the syntax at the reported line.",
        "IndentationError":"Use consistent indentation and align code blocks after colons.",
        "NameError":"Check that the variable or function exists and is spelled correctly before use.",
        "TypeError":"Check operand and argument types against what the operation expects.",
        "ValueError":"The value is inappropriate for the operation; validate input formats and ranges.",
        "KeyError":"The dictionary key is missing; check membership or use .get().",
        "IndexError":"The sequence index is outside the available range; check its length.",
        "AttributeError":"The object lacks that attribute; inspect its type and available methods.",
        "ModuleNotFoundError":"Verify the module name and installation in the active Python environment.",
        "ImportError":"Verify the imported name exists and check for circular imports.",
        "ZeroDivisionError":"Check the denominator before division.",
        "FileNotFoundError":"Verify the path and working directory.",
        "PermissionError":"Check filesystem permissions and access rights.",
        "TimeoutError":"Check the operation's timeout, connectivity, and resource limits."
    }
    return f"{m.group(1)}: {explanations[m.group(1)]}\nThis is a general diagnostic, not a verified fix."
