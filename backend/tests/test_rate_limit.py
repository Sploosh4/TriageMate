"""
Rate limit tests for slowapi-decorated routes.

Verifies:
1. A standalone route with a low limit correctly returns 429 when exceeded
2. The shared limiter is properly configured
3. Rate-limited endpoints behave correctly (429 format)
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from middleware.rate_limit import limiter


class TestSlowapiUnit:
    """Unit tests for the slowapi limiter."""

    def test_limiter_is_configured(self):
        """The shared limiter should have a _key_func set."""
        assert limiter is not None
        assert callable(limiter._key_func)
        assert limiter._key_func is get_remote_address

    def test_rate_limit_constants_are_valid(self):
        """Each rate limit constant should be a valid slowapi string."""
        from middleware.rate_limit import (
            RATE_LIMIT_INGEST,
            RATE_LIMIT_ADMIN,
            RATE_LIMIT_NOTES,
            RATE_LIMIT_DEFAULT,
        )

        for name, val in [
            ("RATE_LIMIT_INGEST", RATE_LIMIT_INGEST),
            ("RATE_LIMIT_ADMIN", RATE_LIMIT_ADMIN),
            ("RATE_LIMIT_NOTES", RATE_LIMIT_NOTES),
            ("RATE_LIMIT_DEFAULT", RATE_LIMIT_DEFAULT),
        ]:
            assert isinstance(val, str), f"{name} should be a string, got {type(val)}"
            assert "/" in val, f"{name} should contain '/' (e.g. '10/minute')"


class TestSlowapiIntegration:
    """Integration tests with a standalone FastAPI app to verify 429 behavior."""

    @pytest.fixture
    def low_limit_app(self):
        """Create a fresh FastAPI app with a very low rate limit for testing."""
        _limiter = Limiter(key_func=get_remote_address)
        app = FastAPI()
        app.state.limiter = _limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        @app.get("/test-rate-limit")
        @_limiter.limit("2/minute")
        async def test_route(request: Request):
            return {"ok": True}

        return app

    def test_blocks_excess_requests(self, low_limit_app):
        """3 rapid requests to a 2/minute endpoint — the 3rd must return 429."""
        client = TestClient(low_limit_app)
        resp1 = client.get("/test-rate-limit")
        assert resp1.status_code == 200, f"Expected 200, got {resp1.status_code}"

        resp2 = client.get("/test-rate-limit")
        assert resp2.status_code == 200, f"Expected 200, got {resp2.status_code}"

        resp3 = client.get("/test-rate-limit")
        assert resp3.status_code == 429, (
            f"Expected 429 (rate limited), got {resp3.status_code}. Body: {resp3.text}"
        )

    def test_429_response_format(self, low_limit_app):
        """The 429 response should include an error message."""
        client = TestClient(low_limit_app)
        # Exhaust the limit
        for _ in range(2):
            client.get("/test-rate-limit")
        resp = client.get("/test-rate-limit")
        assert resp.status_code == 429
        data = resp.json()
        assert "error" in data, f"429 response must contain 'error' key. Got: {data}"
        assert "Rate limit exceeded" in data["error"], (
            f"Error message should mention rate limit. Got: {data['error']}"
        )


class TestLimiterRegistration:
    """Tests that routes are correctly registered with the limiter.

    Note: _route_limits populates only after router modules are imported
    (since @limiter.limit runs at decoration time).
    """

    @pytest.fixture(autouse=True)
    def _ensure_routes_imported(self):
        """Import key routers to trigger @limiter.limit decoration."""
        import routers.ingest  # noqa: F401
        import routers.admin  # noqa: F401
        import routers.cases  # noqa: F401
        import routers.auth  # noqa: F401
        import routers.queue  # noqa: F401
        import routers.models  # noqa: F401
        import routers.config  # noqa: F401

    def test_limiter_has_route_registrations(self):
        """The shared limiter should have route registrations after imports."""
        assert len(limiter._route_limits) > 0, (
            "Limiter has no route limits registered. "
            "Routes with @limiter.limit should populate _route_limits."
        )

    def test_ingest_route_in_limiter(self):
        """The ingest route should be registered in the limiter."""
        from routers.ingest import ingest_vulnerability

        name = f"{ingest_vulnerability.__module__}.{ingest_vulnerability.__name__}"
        registered = list(limiter._route_limits.keys())
        assert any(name in key for key in registered), (
            f"Ingest route '{name}' not found in registrations. "
            f"Registered (first 10): {registered[:10]}"
        )

    def test_admin_route_in_limiter(self):
        """The admin route should be registered."""
        from routers.admin import update_scoring_config

        name = f"{update_scoring_config.__module__}.{update_scoring_config.__name__}"
        registered = list(limiter._route_limits.keys())
        assert any(name in key for key in registered), (
            f"Admin route '{name}' not found. Registered (first 10): {registered[:10]}"
        )
