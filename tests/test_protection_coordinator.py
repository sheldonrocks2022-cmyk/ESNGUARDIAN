from __future__ import annotations

import pytest

from esn_guardian.cogs.protection_coordinator import SEVERITY


def test_incident_state_order_is_monotonic():
    assert SEVERITY["NORMAL"] < SEVERITY["WATCH"] < SEVERITY["CONTAINMENT"] < SEVERITY["LOCKDOWN"] < SEVERITY["RECOVERY"]


def test_required_states_exist():
    assert set(SEVERITY) == {"NORMAL", "WATCH", "CONTAINMENT", "LOCKDOWN", "RECOVERY"}
