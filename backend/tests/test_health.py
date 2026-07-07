"""
Smoke test: /api/health endpoint.

Verifies the application reports its status correctly, including
version, LLM configuration, and RAG store status.
"""

import pytest

pytestmark = pytest.mark.asyncio


class TestHealthEndpoint:
    """Health endpoint smoke tests."""

    async def test_health_returns_200_and_expected_keys(self, client):
        """GET /api/health returns 200 with all required metadata keys."""
        response = await client.get("/api/health")
        assert response.status_code == 200

        data = response.json()

        # Required keys as per the health endpoint contract
        expected_keys = {
            "status",
            "version",
            "tier_2_provider",
            "llm_available",
            "rag_documents",
            "rag_store_path",
        }
        assert expected_keys.issubset(data.keys()), (
            f"Missing keys in health response. Got: {set(data.keys())}"
        )

    async def test_health_status_and_version(self, client):
        """Assert status == 'ok' and version == '0.2.0'."""
        response = await client.get("/api/health")
        data = response.json()

        assert data["status"] == "ok"
        assert data["version"] == "0.2.0"

    async def test_health_llm_disabled_in_tests(self, client):
        """LLM should be unavailable since we disable the API key for tests."""
        response = await client.get("/api/health")
        data = response.json()

        assert data["llm_available"] is False
        assert data["tier_2_provider"] == "none"

    async def test_health_rag_documents_is_integer(self, client):
        """rag_documents should be a non-negative integer or -1 if store missing."""
        response = await client.get("/api/health")
        data = response.json()

        assert isinstance(data["rag_documents"], int), (
            f"rag_documents should be int, got {type(data['rag_documents'])}"
        )
