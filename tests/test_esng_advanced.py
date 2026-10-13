import asyncio
from esn_guardian.esng_memory import MemoryStore
from esn_guardian.esng_reasoning import analyze_python, diagnose, compare_options
from esn_guardian.esng_conversation import ESNGConversation


def test_opt_in_isolation_and_erasure(tmp_path):
    store = MemoryStore(str(tmp_path / "notes.sqlite3"))
    assert not store.remember(1, 2, "project", "Guardian")
    store.opt_in(1, 2)
    assert store.remember(1, 2, "project", "Guardian")
    assert store.notes(1, 2) == [("project", "Guardian")]
    assert store.notes(1, 3) == []
    assert store.notes(2, 2) == []
    store.forget(1, 2)
    assert not store.enabled(1, 2)
    assert store.notes(1, 2) == []


def test_diagnostics_are_nonexecuting():
    assert "Syntax" in analyze_python("def broken(:")
    assert "Functions: 1" in analyze_python("def ok():\n    return 1")
    assert "ModuleNotFoundError" in diagnose("ModuleNotFoundError: No module named 'x'")
    assert "Comparison framework" in compare_options("compare Python vs JavaScript")


def test_conversation_memory_and_diagnostics(tmp_path, monkeypatch):
    monkeypatch.setenv("ESNG_MEMORY_DB", str(tmp_path / "conversation.sqlite3"))
    async def run():
        ai = ESNGConversation()
        assert "enabled" in (await ai.reply(1, 2, "memory on"))
        assert "saved" in (await ai.reply(1, 2, "remember project: ESNG"))
        assert "ESNG" in (await ai.reply(1, 2, "my notes"))
        assert "Functions: 1" in (await ai.reply(1, 2, "check python: def ok(): pass"))
        assert "deleted" in (await ai.reply(1, 2, "memory off"))
    asyncio.run(run())
