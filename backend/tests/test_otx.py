"""Unit tests for OTX rate-limit handling."""

from unittest.mock import Mock

import pytest
import requests

import integrations.otx as otx


@pytest.fixture(autouse=True)
def _reset_otx_cache(monkeypatch):
    """Keep cache and API-key state isolated between tests."""
    otx._CACHE.clear()
    monkeypatch.setattr(otx, "API_KEY", "test-key")
    yield
    otx._CACHE.clear()


def _response(status_code: int, *, headers=None, payload=None):
    response = Mock(status_code=status_code, headers=headers or {})
    response.json.return_value = payload or {"pulse_info": {"pulses": []}}
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError("OTX failure")
    return response


def test_otx_retries_429_then_returns_response(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr(otx.time, "sleep", sleep)
    monkeypatch.setattr(
        otx.requests,
        "get",
        Mock(
            side_effect=[
                _response(429, headers={"Retry-After": "3"}),
                _response(
                    200, payload={"indicator_count": 2, "pulse_info": {"pulses": []}}
                ),
            ]
        ),
    )

    result = otx.query_otx_pulses("CVE-2026-0001")

    assert result["queried"] is True
    assert result["indicators"] == 2
    assert otx.requests.get.call_count == 2
    sleep.assert_called_once_with(3.0)


def test_otx_returns_safe_result_after_rate_limit_retries(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr(otx.time, "sleep", sleep)
    monkeypatch.setattr(otx.requests, "get", Mock(return_value=_response(429)))

    result = otx.query_otx_pulses("CVE-2026-0002")

    assert result == {
        "pulse_count": 0,
        "indicators": 0,
        "targeted_countries": [],
        "pulse_names": [],
        "queried": True,
    }
    assert otx.requests.get.call_count == otx.MAX_RATE_LIMIT_RETRIES + 1
    assert sleep.call_count == otx.MAX_RATE_LIMIT_RETRIES
