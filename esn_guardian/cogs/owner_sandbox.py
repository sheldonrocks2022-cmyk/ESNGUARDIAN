"""Owner-only safe diagnostics lab. Never executes owner-supplied Python or shell text."""
from __future__ import annotations
import ast
from pathlib import Path
from discord.ext import commands
from esn_guardian.cogs.network_operations import luxury

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "esn_guardian"

class OwnerSandboxLab(commands.Cog):
    def __init__(self, bot):
        self.bot=bot
    def _owner(self, uid: int) -> bool:
        oid=getattr(self.bot.settings, "owner_id", None)
        return oid is not None and int(oid)==int(uid)

    @commands.group(name="ownersandbox", aliases=["sandboxlab"], invoke_without_command=True)
    @commands.dm_only()
    async def sandbox(self, ctx):
        if not self._owner(ctx.author.id): return
        await ctx.reply(embed=luxury("ESNG OWNER SANDBOX LAB","Read-only diagnostics:\n`!ownersandbox syntax`\n`!ownersandbox inspect <module>`\n`!ownersandbox status`"), mention_author=False)

    @sandbox.command(name="status")
    async def status(self, ctx):
        if not self._owner(ctx.author.id): return
        files=list(PACKAGE.rglob("*.py"))
        await ctx.reply(embed=luxury("OWNER SANDBOX • STATUS",f"**Guardian Python modules:** {len(files)}\n**Mode:** Read-only\n**Production:** Unchanged","success"), mention_author=False)

    @sandbox.command(name="syntax")
    @commands.cooldown(1, 20, commands.BucketType.user)
    async def syntax(self, ctx):
        if not self._owner(ctx.author.id): return
        failures=[]; checked=0
        for path in PACKAGE.rglob("*.py"):
            checked += 1
            try: ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeError, OSError) as exc: failures.append(f"{path.relative_to(ROOT)}: {exc}")
        if failures:
            body="\n".join(failures[:15])
            return await ctx.reply(embed=luxury("OWNER SANDBOX • SYNTAX FAILED",f"**Checked:** {checked}\n```\n{body[:1500]}\n```","danger"), mention_author=False)
        await ctx.reply(embed=luxury("OWNER SANDBOX • SYNTAX PASSED",f"**Checked:** {checked} Python files\nNo production files changed.","success"), mention_author=False)

    @sandbox.command(name="inspect")
    async def inspect(self, ctx, module: str):
        if not self._owner(ctx.author.id): return
        clean=module.strip().replace(".", "/").strip("/")
        if not clean or ".." in clean or not all(c.isalnum() or c in "_/" for c in clean):
            return await ctx.reply(embed=luxury("OWNER SANDBOX • INVALID MODULE","Provide a Guardian module name, for example `network_cases`.","warning"), mention_author=False)
        candidates=[(PACKAGE / (clean + ".py")).resolve()]
        if "/" not in clean:
            candidates.extend(p.resolve() for p in PACKAGE.rglob(clean + ".py"))
        path=next((p for p in candidates if PACKAGE.resolve() in p.parents and p.is_file()),None)
        if path is None:
            return await ctx.reply(embed=luxury("OWNER SANDBOX • MODULE NOT FOUND","Try a filename such as `network_cases`.","warning"), mention_author=False)
        tree=ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        funcs=sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in ast.walk(tree))
        classes=sum(isinstance(n,ast.ClassDef) for n in ast.walk(tree))
        imports=sum(isinstance(n,(ast.Import,ast.ImportFrom)) for n in ast.walk(tree))
        await ctx.reply(embed=luxury("ESNG OWNER SANDBOX • INSPECTION",f"**Module:** `{path.relative_to(PACKAGE)}`\n**Functions:** {funcs}\n**Classes:** {classes}\n**Imports:** {imports}\n\nRead-only • Nothing executed • Production unchanged."), mention_author=False)

async def setup(bot):
    await bot.add_cog(OwnerSandboxLab(bot))
