"""
Tests for the drift metrics endpoint.

Covers: GET /api/drift

NOTE: Response keys are camelCase because the Pydantic DriftMetricsResponse
      model uses `alias_generator = camel_case` (see backend/models.py).
"""

from datetime import datetime, timezone

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


class TestConceptDrift:
    """Tests for GET /api/drift/concept and related endpoints."""

    CONCEPT_DRIFT_KEYS = {
        "prediction_distribution",
        "window",
        "time_series",
    }

    PREDICTION_DISTRIBUTION_KEYS = {
        "exploitation_probability",
        "confidence",
        "routing",
        "tier_routing",
    }

    DISTRIBUTION_STATS_KEYS = {"mean", "std", "p50", "p95"}

    async def test_concept_drift_endpoint(self, client):
        """GET /api/drift/concept returns 200 with expected keys."""
        response = await client.get("/api/drift/concept")
        assert response.status_code == 200
        data = response.json()

        missing = self.CONCEPT_DRIFT_KEYS - set(data.keys())
        assert not missing, f"Missing top-level keys: {missing}"

        pd = data.get("prediction_distribution", {})
        pd_missing = self.PREDICTION_DISTRIBUTION_KEYS - set(pd.keys())
        assert not pd_missing, f"Missing prediction_distribution keys: {pd_missing}"

        for stat_key in ("exploitation_probability", "confidence"):
            stats = pd.get(stat_key, {})
            stat_missing = self.DISTRIBUTION_STATS_KEYS - set(stats.keys())
            assert not stat_missing, f"Missing {stat_key} stats: {stat_missing}"

    async def test_concept_drift_window_param(self, client):
        """days parameter controls the window in the response."""
        response = await client.get("/api/drift/concept?days=7")
        assert response.status_code == 200
        data = response.json()
        assert data["window"]["days"] == 7

        response = await client.get("/api/drift/concept?days=365")
        assert response.status_code == 200
        data = response.json()
        assert data["window"]["days"] == 365

    async def test_concept_drift_empty_state(self, client):
        """Empty DB returns zeroed stats, not errors."""
        response = await client.get("/api/drift/concept?days=1")
        assert response.status_code == 200
        data = response.json()

        # Window should show 0 samples
        assert data["window"]["total_samples"] == 0
        assert data["time_series"]["daily"] == []

        # All stats should be zeroed
        pd = data["prediction_distribution"]
        for key in ("exploitation_probability", "confidence"):
            for field in ("mean", "std", "p50", "p95"):
                assert pd[key][field] == 0.0, f"{key}.{field} should be 0.0"
        assert pd["routing"]["auto_resolved"] == 0
        assert pd["routing"]["escalated"] == 0
        for key, val in pd["tier_routing"].items():
            assert val == 0, f"tier_routing.{key} should be 0"

    async def test_concept_drift_with_seeded_data(self, client):
        """When resolved_vulnerabilities has data, stats are computed.

        Directly insert test records to verify aggregation logic.
        """
        import database
        import sqlite3

        conn = sqlite3.connect(database.DB_PATH)
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                """
                INSERT INTO resolved_vulnerabilities (
                    vulnerability_id, hostname, cvss_score, priority_score, risk_band,
                    detection_tier, detection_reason,
                    tier_1_exploitation_prob, tier_1_confidence, tier_1_routing,
                    tier_0_resolution, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "CVE-TEST-CONCEPT-001",
                    "test-host-1",
                    7.5,
                    50,
                    "Medium",
                    "ML Tier",
                    "Tier 1 test",
                    0.85,
                    0.92,
                    "auto_resolved",
                    "ambiguous",
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO resolved_vulnerabilities (
                    vulnerability_id, hostname, cvss_score, priority_score, risk_band,
                    detection_tier, detection_reason,
                    tier_1_exploitation_prob, tier_1_confidence, tier_1_routing,
                    tier_0_resolution, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "CVE-TEST-CONCEPT-002",
                    "test-host-2",
                    9.0,
                    80,
                    "Critical",
                    "SLM Tier",
                    "Tier 2 test",
                    0.65,
                    0.76,
                    "escalated",
                    "ambiguous",
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO resolved_vulnerabilities (
                    vulnerability_id, hostname, cvss_score, priority_score, risk_band,
                    detection_tier, detection_reason,
                    tier_1_exploitation_prob, tier_1_confidence, tier_1_routing,
                    tier_0_resolution, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "CVE-TEST-CONCEPT-003",
                    "test-host-3",
                    8.0,
                    70,
                    "High",
                    "Deterministic",
                    "KEV match",
                    0.95,
                    0.88,
                    "auto_resolved",
                    "kev",
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        response = await client.get("/api/drift/concept")
        assert response.status_code == 200
        data = response.json()

        assert data["window"]["total_samples"] == 3

        pd = data["prediction_distribution"]
        # Check mean prob: (0.85 + 0.65 + 0.95) / 3 = 0.8167
        assert abs(pd["exploitation_probability"]["mean"] - 0.8167) < 0.01
        # Check routing counts
        assert pd["routing"]["auto_resolved"] == 2
        assert pd["routing"]["escalated"] == 1
        # Check tier routing
        assert pd["tier_routing"]["tier_1_xgboost"] == 1  # ML Tier
        assert pd["tier_routing"]["tier_2_llm"] == 1  # SLM Tier
        assert pd["tier_routing"]["tier_0_kev"] == 1  # Deterministic + kev

        # Time series should have one entry
        assert len(data["time_series"]["daily"]) == 1
        assert data["time_series"]["daily"][0]["n"] == 3

    async def test_feedback_submission(self, client):
        """POST /api/feedback/{vuln_id} validates and returns confirmation."""
        response = await client.post(
            "/api/feedback/CVE-2024-0001",
            json={"exploited": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["vulnerability_id"] == "CVE-2024-0001"
        assert "Sprint 20" in data["note"]

    async def test_feedback_with_notes(self, client):
        """POST feedback with optional notes field."""
        response = await client.post(
            "/api/feedback/CVE-2024-0002",
            json={"exploited": False, "notes": "Confirmed by SOC team"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"

    async def test_feedback_auth_required(self, client):
        """Unauthenticated POST returns 401 when auth is enforced.

        Override get_current_user dependency to require auth for this test.
        """
        from auth import get_current_user
        from fastapi import HTTPException
        from main import app

        async def _require_auth():
            raise HTTPException(status_code=401, detail="Not authenticated")

        app.dependency_overrides[get_current_user] = _require_auth
        try:
            response = await client.post(
                "/api/feedback/CVE-2024-0003",
                json={"exploited": True},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    async def test_feedback_validation(self, client):
        """Invalid body (missing required fields) returns 422."""
        response = await client.post(
            "/api/feedback/CVE-2024-0004",
            json={"notes": "Missing exploited field"},
        )
        assert response.status_code == 422

    async def test_accuracy_stub_endpoint(self, client):
        """GET /api/drift/accuracy returns valid structure."""
        response = await client.get("/api/drift/accuracy")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "insufficient_data"
        assert data["samples_with_ground_truth"] == 0
        assert "Sprint 20" in data["message"]
