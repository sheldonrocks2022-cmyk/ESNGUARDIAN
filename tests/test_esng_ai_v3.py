from esn_guardian.cogs.esng_ai_v2 import ESNGuardianAI2Cog


def test_esng_member_id_parser_accepts_mentions_and_words():
    assert ESNGuardianAI2Cog._member_id("analyze member 123456789012345678") == 123456789012345678
    assert ESNGuardianAI2Cog._member_id("check <@123456789012345678>") == 123456789012345678
    assert ESNGuardianAI2Cog._member_id("check <@!123456789012345678>") == 123456789012345678


def test_esng_member_id_parser_ignores_normal_numbers():
    assert ESNGuardianAI2Cog._member_id("what can I get for $1") is None
    assert ESNGuardianAI2Cog._member_id("case 123") is None
