"""ESNG's independent, offline conversational assistant.

No external AI provider, API keys, model downloads, or network requests.
This is a bounded symbolic assistant, not a trained language model.
"""
from __future__ import annotations

import ast
import operator
import re
from collections import OrderedDict, deque

OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
}
UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_calculate(expression: str) -> int | float:
    """Evaluate basic arithmetic without eval or arbitrary code execution."""
    if len(expression) > 100:
        raise ValueError("Expression too long")
    tree = ast.parse(expression, mode="eval")

    def walk(node: ast.AST, depth: int = 0) -> int | float:
        if depth > 12:
            raise ValueError("Expression too complex")
        if isinstance(node, ast.Expression):
            return walk(node.body, depth + 1)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            value = node.value
        elif isinstance(node, ast.BinOp) and type(node.op) in OPS:
            left, right = walk(node.left, depth + 1), walk(node.right, depth + 1)
            if isinstance(node.op, ast.Pow) and (abs(right) > 8 or abs(left) > 100000):
                raise ValueError("Power too large")
            value = OPS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp) and type(node.op) in UNARY:
            value = UNARY[type(node.op)](walk(node.operand, depth + 1))
        else:
            raise ValueError("Unsupported expression")
        if abs(value) > 10**12:
            raise ValueError("Result too large")
        return value

    return walk(tree)


class ESNGConversation:
    def __init__(self) -> None:
        self.history: OrderedDict[tuple[int, int], deque[str]] = OrderedDict()

    @property
    def enabled(self) -> bool:
        return True

    async def reply(self, guild_id: int, user_id: int, prompt: str) -> str | None:
        key = (guild_id, user_id)
        if key not in self.history:
            if len(self.history) >= 2000:
                self.history.popitem(last=False)
            self.history[key] = deque(maxlen=8)
        self.history.move_to_end(key)
        history = self.history[key]
        p = prompt.strip()[:2000]
        normalized = p.casefold()
        if not p:
            return "Ask me a question, request a calculation, or tell me what you're working on."
        if re.search(r"\b(forget (this|our) (chat|conversation)|clear (my )?memory|reset conversation)\b", normalized):
            history.clear()
            return "This conversation's temporary context has been cleared."
        if re.search(r"\b(what (did i|were we) (ask|talk|discuss)|what was my last question)\b", normalized):
            return ("Your previous message was: " + history[-1]) if history else "We haven't discussed anything in this session yet."
        history.append(p)
        calc = re.fullmatch(r"(?:what is|calculate|solve|compute)?\s*([0-9+*/().%\s-]{3,100})\??", normalized)
        if calc:
            try:
                return f"Result: {safe_calculate(calc.group(1).strip())}"
            except (ValueError, SyntaxError, ZeroDivisionError, OverflowError):
                return "I couldn't calculate that safely. Try a basic arithmetic expression."
        if re.search(r"\b(hello|hi|hey|howdy)\b", normalized) and len(normalized.split()) <= 5:
            return "Hey! I'm ESNG, Guardian's independent assistant. What are you working on?"
        if "who are you" in normalized or "are you chatgpt" in normalized:
            return ("I'm ESNG AI, an independent offline assistant built into Guardian. "
                    "I can help with verified Guardian information, arithmetic and limited conversation, "
                    "but I don't have ChatGPT's general language-model abilities.")
        if re.search(r"\b(write|draft|rewrite|explain|code|program|debug|create|summarize)\b", normalized):
            return ("I can help with Guardian-specific questions, but my offline language engine "
                    "can't reliably generate arbitrary writing or code yet. "
                    "Tell me the exact task and I can identify what information is needed.")
        return None
