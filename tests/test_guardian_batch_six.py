"""Registration smoke tests for V8 Luxury Batch 6.

These tests do not connect to Discord or touch a production database.
"""
from __future__ import annotations

from pathlib import Path

from discord.ext import commands

from esn_guardian.cogs.guardian_batch_six import GuardianBatchSix


EXPECTED = {
    "serveralert": {"send", "list", "close"},
    "contactsub": {"add", "remove", "list"},
    "caselabel": {"add", "remove", "list"},
    "caselink": {"add", "remove", "list"},
    "networkenroll": {"join", "leave", "status"},
    "casewatch": {"add", "remove", "list"},
}


def test_batch_six_registers_all_six_command_groups():
    cog = GuardianBatchSix(bot=None)
    commands_by_name = {command.name: command for command in cog.get_commands()}
    assert EXPECTED.keys() <= commands_by_name.keys()
    for name, subcommands in EXPECTED.items():
        group = commands_by_name[name]
        assert isinstance(group, commands.Group)
        assert subcommands <= {command.name for command in group.commands}


def test_batch_six_is_loaded_by_guardian_main():
    main = Path(__file__).resolve().parents[1] / "esn_guardian" / "main.py"
    source = main.read_text(encoding="utf-8")
    assert '"esn_guardian.cogs.guardian_batch_six"' in source
