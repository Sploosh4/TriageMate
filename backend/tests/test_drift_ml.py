"""
Tests for ML drift monitoring — PSI computation and GET /api/drift/ml endpoint.

Covers:
- compute_psi(): identical distributions, known diff, edge cases
- compute_drift(): with reference dists, empty features
- GET /api/drift/ml: valid JSON, expected keys, empty state
"""

import pytest

# Expected camelCase keys from the MlDriftResponse model
ML_DRIFT_RESPONSE_KEYS = {"features", "compositePsi", "status", "totalSamples"}


# ── compute_psi tests ──────────────────────────────────────────────────────


class TestComputePsi:
    """Unit tests for the PSI computation function."""

    def test_identical_distributions(self):
        """PSI should be 0 for identical expected and actual distributions."""
        from analysis.drift import compute_psi

        expected = [0.2, 0.3, 0.3, 0.2]
        actual_counts = [20, 30, 30, 20]  # proportions: 0.2, 0.3, 0.3, 0.2
        psi = compute_psi(expected, actual_counts)
        assert psi == 0.0, f"Expected 0.0, got {psi}"

    def test_known_different_distribution(self):
        """PSI should be > 0 for different distributions."""
        from analysis.drift import compute_psi

        # Expected: 50% in bin 0, 50% in bin 1
        expected = [0.5, 0.5]
        # Actual: 100% in bin 0, 0% in bin 1
        actual_counts = [100, 0]

        psi = compute_psi(expected, actual_counts)
        # PSI = (1.0 - 0.5) * ln(1.0/0.5) + (0.0001 - 0.5) * ln(0.0001/0.5)
        # Bin 0: 0.5 * ln(2) = 0.5 * 0.6931 = 0.3466
        # Bin 1: (0.0001 - 0.5) * ln(0.0001/0.5) = -0.4999 * ln(0.0002) = -0.4999 * (-8.5172) = 4.257
        # Total: ~4.604
        assert psi > 0, f"Expected positive PSI, got {psi}"
        assert psi > 4.0, (
            f"Expected PSI > 4.0 for very different distributions, got {psi}"
        )

    def test_empty_actual(self):
        """PSI should be 0 when there are no actual samples."""
        from analysis.drift import compute_psi

        expected = [0.5, 0.5]
        actual_counts = [0, 0]
        psi = compute_psi(expected, actual_counts)
        assert psi == 0.0, f"Expected 0.0 for empty actual, got {psi}"

    def test_zero_expected_bin(self):
        """PSI should skip bins where expected proportion is zero."""
        from analysis.drift import compute_psi

        expected = [0.0, 1.0]
        actual_counts = [5, 95]
        # Bin 0 has expected=0 so it's skipped; bin 1 has expected=1.0 and actual=0.95
        # PSI = (0.95 - 1.0) * ln(0.95/1.0) = -0.05 * ln(0.95) = -0.05 * -0.0513 = 0.00256
        psi = compute_psi(expected, actual_counts)
        assert psi >= 0, f"Expected non-negative PSI, got {psi}"

    def test_all_in_last_bin(self):
        """PSI handles the case where all actual samples fall in the last bin."""
        from analysis.drift import compute_psi

        expected = [0.25, 0.25, 0.25, 0.25]
        actual_counts = [0, 0, 0, 100]
        psi = compute_psi(expected, actual_counts)
        assert psi > 0, f"Expected positive PSI for shifted distribution, got {psi}"


# ── compute_drift tests ────────────────────────────────────────────────────


class TestComputeDrift:
    """Unit tests for the aggregate drift computation."""

    def test_empty_features_list(self):
        """With no features, all PSI = 0.0 and status = stable."""
        from analysis.drift import compute_drift

        reference_dists = {
            "features": {
                "cvss_av": {
                    "min": 0.0,
                    "max": 3.0,
                    "bins": [0.0, 0.3, 0.6, 0.9, 1.2, 1.5, 1.8, 2.1, 2.4, 2.7, 3.0],
                    "expected": [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
                },
                "epss_score": {
                    "min": 0.0,
                    "max": 1.0,
                    "bins": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                    "expected": [
                        0.5,
                        0.2,
                        0.1,
                        0.05,
                        0.05,
                        0.03,
                        0.02,
                        0.02,
                        0.02,
                        0.01,
                    ],
                },
            },
            "num_samples": 1000,
        }

        result = compute_drift([], reference_dists)
        assert result["composite_psi"] == 0.0
        assert result["status"] == "stable"
        assert result["total_samples"] == 0
        for fname in reference_dists["features"]:
            assert result["features"][fname]["psi"] == 0.0
            assert result["features"][fname]["status"] == "stable"

    def test_with_sample_features(self):
        """compute_drift processes actual feature rows."""
        from analysis.drift import compute_drift

        reference_dists = {
            "features": {
                "cvss_av": {
                    "min": 0.0,
                    "max": 3.0,
                    "bins": [0.0, 0.3, 0.6, 0.9, 1.2, 1.5, 1.8, 2.1, 2.4, 2.7, 3.0],
                    "expected": [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
                },
            },
            "num_samples": 1000,
        }

        features_list = [
            {"cvss_av": 0.0},
            {"cvss_av": 0.0},
            {"cvss_av": 3.0},
            {"cvss_av": 1.5},
            {"cvss_av": 2.5},
        ]

        result = compute_drift(features_list, reference_dists)
        assert result["total_samples"] == 5
        assert "cvss_av" in result["features"]
        assert result["features"]["cvss_av"]["psi"] >= 0
        assert result["status"] in ("stable", "warning", "critical")


# ── Endpoint tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestMlDriftEndpoint:
    """GET /api/drift/ml integration tests."""

    async def test_ml_drift_returns_200(self, client):
        """GET /api/drift/ml should return HTTP 200."""
        response = await client.get("/api/drift/ml")
        assert response.status_code == 200

    async def test_ml_drift_returns_expected_keys(self, client):
        """Response must contain all ML drift keys (camelCase)."""
        response = await client.get("/api/drift/ml")
        data = response.json()

        missing = ML_DRIFT_RESPONSE_KEYS - set(data.keys())
        assert not missing, f"Missing keys in ML drift response: {missing}"

    async def test_ml_drift_composite_psi_is_number(self, client):
        """compositePsi must be a number."""
        response = await client.get("/api/drift/ml")
        data = response.json()
        assert isinstance(data["compositePsi"], (int, float)), (
            f"compositePsi must be numeric, got {type(data['compositePsi'])}"
        )

    async def test_ml_drift_features_is_dict(self, client):
        """features must be a dict."""
        response = await client.get("/api/drift/ml")
        data = response.json()
        assert isinstance(data["features"], dict)

    async def test_ml_drift_status_is_string(self, client):
        """status must be a string (stable/warning/critical)."""
        response = await client.get("/api/drift/ml")
        data = response.json()
        assert isinstance(data["status"], str)
        assert data["status"] in ("stable", "warning", "critical")

    async def test_ml_drift_total_samples_is_int(self, client):
        """totalSamples must be a non-negative integer."""
        response = await client.get("/api/drift/ml")
        data = response.json()
        assert isinstance(data["totalSamples"], int)
        assert data["totalSamples"] >= 0

    async def test_ml_drift_feature_values_have_expected_structure(self, client):
        """Each feature entry must have psi (number) and status (string)."""
        response = await client.get("/api/drift/ml")
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
