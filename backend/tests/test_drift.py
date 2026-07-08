"""
Tests for the drift metrics endpoint.

Covers: GET /api/drift

NOTE: Response keys are camelCase because the Pydantic DriftMetricsResponse
      model uses `alias_generator = camel_case` (see backend/models.py).
"""

import pytest

pytestmark = pytest.mark.asyncio


DRIFT_RESPONSE_KEYS = {
    "scoreTrend",
    "tierRouting",
    "riskBandDistribution",
    "detectionTierTrend",
    "featureDrift",
    "totalAudited",
}


class TestDriftEndpoint:
    """GET /api/drift smoke tests."""

    async def test_drift_returns_200(self, client):
        """GET /api/drift should return HTTP 200."""
        response = await client.get("/api/drift")
        assert response.status_code == 200

    async def test_drift_returns_expected_keys(self, client):
        """Response must contain all drift metrics keys (camelCase)."""
        response = await client.get("/api/drift")
        data = response.json()

        missing = DRIFT_RESPONSE_KEYS - set(data.keys())
        assert not missing, f"Missing keys in drift response: {missing}"

    async def test_drift_total_audited_is_non_negative(self, client):
        """totalAudited must be a non-negative integer."""
        response = await client.get("/api/drift")
        data = response.json()

        assert isinstance(data["totalAudited"], int), "totalAudited must be int"
        assert data["totalAudited"] >= 0, "totalAudited must be >= 0"

    async def test_drift_tier_routing_is_dict(self, client):
        """tierRouting must be a dict."""
        response = await client.get("/api/drift")
        data = response.json()
        assert isinstance(data["tierRouting"], dict)

    async def test_drift_feature_drift_is_dict(self, client):
        """featureDrift must be a dict."""
        response = await client.get("/api/drift")
        data = response.json()
        assert isinstance(data["featureDrift"], dict)

    async def test_drift_empty_state_if_no_resolved(self, client):
        """With an empty resolved_vulnerabilities table, drift returns
        the empty/zero state."""
        response = await client.get("/api/drift")
        data = response.json()

        assert data["totalAudited"] == 0
        assert data["scoreTrend"] == []
        assert data["tierRouting"] == {"auto": 0, "escalated": 0}
        assert data["riskBandDistribution"] == {}
        assert data["detectionTierTrend"] == []
        assert data["featureDrift"] == {}
