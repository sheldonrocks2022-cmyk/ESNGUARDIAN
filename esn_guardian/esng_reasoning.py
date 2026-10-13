"""Bounded offline diagnostics and transparent decision support."""
from __future__ import annotations
import ast
import re

ERROR_HINTS = (
    ("ModuleNotFoundError", "Install the missing dependency in the bot's active Python environment, then verify the import name and requirements file."),
    ("IndentationError", "Check indentation consistency around the reported line. Use four spaces per Python indentation level."),
    ("SyntaxError", "Inspect the reported line and the line above for missing colons, brackets, quotes or invalid syntax."),
    ("KeyError", "Check whether the key exists before indexing; inspect the incoming data shape."),
    ("AttributeError", "Check the object's actual type and whether that attribute exists in your installed library version."),
    ("TypeError", "Inspect the argument types and the function signature; do not assume a value is a string or number."),
    ("PermissionError", "Check file ownership and directory permissions. Do not run the whole bot as root to work around this."),
    ("discord.Forbidden", "Check Discord role hierarchy and the bot's permissions in the target channel."),
    ("discord.NotFound", "The Discord object may have been deleted or the ID may be wrong; handle missing resources safely."),
    ("sqlite3.OperationalError", "Check the database path, write permissions, lock contention and SQL schema."),
)

def diagnose(text: str) -> str | None:
    for name, hint in ERROR_HINTS:
        if name.casefold() in text.casefold():
            return f"**{name}** — {hint}\nRemove tokens and private data before sharing logs."
    return None

def analyze_python(source: str) -> str:
    if len(source) > 6000:
        return "Code sample too long; send a minimal reproducible example (under 6000 characters)."
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return f"Python syntax issue on line {exc.lineno}: {exc.msg}. No code was executed."
    functions = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
    classes = sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
    return f"Python syntax parses successfully. Functions: {functions}; classes: {classes}. This does not prove runtime correctness. No code was executed."

def compare_options(text: str) -> str | None:
    match = re.fullmatch(r"\s*compare\s+(.{1,80}?)\s+(?:vs\.?|versus)\s+(.{1,80})\s*", text, re.I | re.S)
    if not match:
        return None
    left, right = match.group(1).strip(), match.group(2).strip()
    return (f"Comparison framework for **{left}** and **{right}**:\n"
            "1. Define the goal and constraints.\n"
            "2. Compare cost, reliability, security, maintainability and trade-offs.\n"
            "3. Test both against the same requirements.\n"
            "I need factual details about these options before recommending one.")
