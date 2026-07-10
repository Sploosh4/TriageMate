"""
Tests for Pre-Tier drift monitoring — PSI computation for Pre-Tier features
and GET /api/drift/pre-tier endpoint.

Covers:
- GET /api/drift/pre-tier: valid JSON, expected keys, empty state
"""

import pytest

# Expected camelCase keys from the MlDriftResponse model
PRETIER_DRIFT_RESPONSE_KEYS = {"features", "compositePsi", "status", "totalSamples"}


@pytest.mark.asyncio
class TestPretierDriftEndpoint:
    """GET /api/drift/pre-tier integration tests."""

    async def test_pretier_drift_returns_200(self, client):
        """GET /api/drift/pre-tier should return HTTP 200."""
        response = await client.get("/api/drift/pre-tier")
        assert response.status_code == 200

    async def test_pretier_drift_returns_expected_keys(self, client):
        """Response must contain all drift keys (camelCase)."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()

        missing = PRETIER_DRIFT_RESPONSE_KEYS - set(data.keys())
        assert not missing, f"Missing keys in Pre-Tier drift response: {missing}"

    async def test_pretier_drift_composite_psi_is_number(self, client):
        """compositePsi must be a number."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()
        assert isinstance(data["compositePsi"], (int, float)), (
            f"compositePsi must be numeric, got {type(data['compositePsi'])}"
        )

    async def test_pretier_drift_features_is_dict(self, client):
        """features must be a dict."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()
        assert isinstance(data["features"], dict)

    async def test_pretier_drift_status_is_string(self, client):
        """status must be a string (stable/warning/critical)."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()
        assert isinstance(data["status"], str)
        assert data["status"] in ("stable", "warning", "critical")

    async def test_pretier_drift_total_samples_is_int(self, client):
        """totalSamples must be a non-negative integer."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()
        assert isinstance(data["totalSamples"], int)
        assert data["totalSamples"] >= 0

    async def test_pretier_drift_feature_values_have_expected_structure(self, client):
        """Each feature entry must have psi (number) and status (string)."""
        response = await client.get("/api/drift/pre-tier")
        data = response.json()
        for fname, feat in data["features"].items():
            assert isinstance(feat["psi"], (int, float)), (
                f"Feature {fname} psi must be numeric"
            )
            assert isinstance(feat["status"], str), (
                f"Feature {fname} status must be string"
            )
            assert feat["status"] in ("stable", "warning", "critical"), (
                f"Feature {fname} invalid status: {feat['status']}"
            )
