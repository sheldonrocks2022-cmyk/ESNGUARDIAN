from types import SimpleNamespace as NS

from esn_guardian.main import startup_retry_delay


def test_startup_retry_delay_has_safe_minimum():
    assert startup_retry_delay(None, 0) == 60.0


def test_startup_retry_delay_uses_exponential_backoff():
    assert startup_retry_delay(None, 1) == 120.0
    assert startup_retry_delay(None, 2) == 240.0
    assert startup_retry_delay(None, 4) == 900.0
    assert startup_retry_delay(None, 99) == 900.0


def test_startup_retry_delay_respects_discord_retry_after():
    error = NS(response=NS(headers={"Retry-After": "420"}))
    assert startup_retry_delay(error, 1) == 420.0


def test_startup_retry_delay_ignores_bad_header():
    error = NS(response=NS(headers={"Retry-After": "not-a-number"}))
    assert startup_retry_delay(error, 0) == 60.0
