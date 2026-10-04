from esn_guardian.main import EXTENSIONS


def test_security_extensions_are_registered():
    required = {
        "esn_guardian.cogs.security",
        "esn_guardian.cogs.advanced_security",
        "esn_guardian.cogs.security_intelligence",
        "esn_guardian.cogs.security_overwatch",
        "esn_guardian.cogs.security_sentinel",
        "esn_guardian.cogs.security_resilience",
        "esn_guardian.cogs.security_v6",
        "esn_guardian.cogs.security_v7",
        "esn_guardian.cogs.esng_ai_v2",
    }
    assert required.issubset(set(EXTENSIONS))
