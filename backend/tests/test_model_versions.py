"""
Tests for model version management (read-write: list + activate).

Covers:
- GET  /api/model/versions  — listing with correct active version
- POST /api/model/activate — switching versions, error cases
- Activation + predict integration (model loads from new path)
"""

import json
import pytest
from pathlib import Path

pytestmark = pytest.mark.asyncio

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "ml" / "model_registry.json"


def _read_registry() -> dict:
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _write_registry(registry: dict):
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


# ── Session-scoped save/restore to isolate tests ──────────────────────


@pytest.fixture(scope="session", autouse=True)
def _save_and_restore_registry():
    """Save the original registry before the test session and restore after.

    Also re-initialises the predictor paths so other tests are not affected.
    """
    original = None
    if REGISTRY_PATH.exists():
        original = _read_registry()

    yield

    # Restore original state
    if original is not None:
        _write_registry(original)

    # Ensure predictor cache points back to the original active version
    from ml.xgboost_predictor import (
        _init_active_paths_from_registry,
    )

    # Reset in-memory cache first
    import ml.xgboost_predictor as xp

    xp._model = None
    xp._calibrator = None
    _init_active_paths_from_registry()


class TestModelVersions:
    """Model version listing and activation."""

    async def test_list_versions(self, client):
        """GET /api/model/versions returns 3 versions, active is v3."""
        response = await client.get("/api/model/versions")
        assert response.status_code == 200
        data = response.json()

        assert data["active_version"] == "v3", (
            f"Expected active_version v3, got {data['active_version']}"
        )
        assert len(data["versions"]) == 3, (
            f"Expected 3 versions, got {len(data['versions'])}"
        )

        version_ids = [v["version"] for v in data["versions"]]
        assert version_ids == ["v1", "v2", "v3"], (
            f"Unexpected version order: {version_ids}"
        )

        for v in data["versions"]:
            if v["version"] == "v3":
                assert v["is_active"] is True, "v3 should be marked active"
            else:
                assert v["is_active"] is False, f"{v['version']} should not be active"

    async def test_activate_valid_version(self, client):
        """Activate v2, confirm via GET, reset to v3."""
        # Ensure starting from v3
        await client.post("/api/model/activate", json={"version": "v3"})

        # Activate v2
        response = await client.post("/api/model/activate", json={"version": "v2"})
        assert response.status_code == 200
        data = response.json()
        assert data["active_version"] == "v2", (
            f"Expected active v2, got {data['active_version']}"
        )

        # Confirm via GET
        response = await client.get("/api/model/versions")
        assert response.json()["active_version"] == "v2"

        # Reset to v3 for subsequent tests
        response = await client.post("/api/model/activate", json={"version": "v3"})
        assert response.status_code == 200
        assert response.json()["active_version"] == "v3"

    async def test_activate_invalid_version(self, client):
        """Activating a nonexistent version returns 404."""
        response = await client.post("/api/model/activate", json={"version": "v99"})
        assert response.status_code == 404

    async def test_activate_already_active(self, client):
        """Activating the already-active version returns 400."""
        # Ensure v3 is active
        await client.post("/api/model/activate", json={"version": "v3"})

        response = await client.post("/api/model/activate", json={"version": "v3"})
        assert response.status_code == 400

    async def test_activate_then_predict(self, client):
        """Activate v1, call predict(), verify it works with the old model."""
        features = {
            "epss_score": 0.05,
            "cwe_class": "CWE-79",
            "cisa_kev": False,
            "description": "Cross-site scripting vulnerability test",
            "mission_prevalence": "Support",
            "public_wellbeing_impact": "Minimal",
            "internet_facing": True,
            "patch_available": True,
            "domain_joined": True,
        }

        # Activate v1 (Sprint 3 model)
        response = await client.post("/api/model/activate", json={"version": "v1"})
        assert response.status_code == 200
        assert response.json()["active_version"] == "v1"

        # Predict with the old model
        from ml.xgboost_predictor import predict

        result = predict(features)

        assert "exploitation_probability" in result, (
            "Missing exploitation_probability in predict response"
        )
        assert "confidence" in result, "Missing confidence in predict response"
        assert "routing" in result, "Missing routing in predict response"
        assert isinstance(result["exploitation_probability"], float), (
            f"Expected float probability, got {type(result['exploitation_probability'])}"
        )

        # Reset to v3 for other tests
        reset_resp = await client.post("/api/model/activate", json={"version": "v3"})
        assert reset_resp.status_code == 200
        assert reset_resp.json()["active_version"] == "v3"


class TestModelStatus:
    """Model status endpoint: GET /api/model/status."""

    async def test_model_status_shape(self, client):
        """GET /api/model/status returns expected top-level keys."""
        response = await client.get("/api/model/status")
        assert response.status_code == 200
        data = response.json()

        assert "active_version" in data, "Missing active_version key"
        assert "available_versions" in data, "Missing available_versions key"
        assert "score_comparison" in data, "Missing score_comparison key"

        # Active version should be a dict with version/label/metrics
        av = data["active_version"]
        assert isinstance(av, dict), "active_version should be a dict"
        assert "version" in av, "active_version missing version"
        assert "label" in av, "active_version missing label"
        assert "metrics" in av, "active_version missing metrics"
        assert "is_active" in av, "active_version missing is_active"
        assert av["is_active"] is True, "active_version should have is_active=True"

        # available_versions should be a list of dicts
        assert isinstance(data["available_versions"], list), (
            "available_versions should be a list"
        )
        assert len(data["available_versions"]) == 3, (
            f"Expected 3 versions, got {len(data['available_versions'])}"
        )

        # score_comparison should have baseline_scores and versions
        sc = data["score_comparison"]
        assert "baseline_scores" in sc, "score_comparison missing baseline_scores"
        assert "versions" in sc, "score_comparison missing versions"
        assert sc["baseline_scores"] == [94, 87, 71, 63, 55, 41, 22], (
            f"Unexpected baseline_scores: {sc['baseline_scores']}"
        )

    async def test_model_status_active_matches_registry(self, client):
        """Active version info matches the active version in the registry."""
        registry = _read_registry()
        expected_active = registry["active_version"]

        response = await client.get("/api/model/status")
        data = response.json()

        assert data["active_version"]["version"] == expected_active, (
            f"active_version '{data['active_version']['version']}' "
            f"does not match registry '{expected_active}'"
        )

        # Verify the active version's metrics match registry
        for v in registry["versions"]:
            if v["version"] == expected_active:
                assert data["active_version"]["metrics"] == v.get("metrics", {}), (
                    "active_version metrics mismatch with registry"
                )
                break

    async def test_model_status_score_comparison_has_all_versions(self, client):
        """Score comparison contains entries for v1, v2, and v3."""
        response = await client.get("/api/model/status")
        data = response.json()
        versions = data["score_comparison"]["versions"]

        for expected_version in ["v1", "v2", "v3"]:
            assert expected_version in versions, (
                f"Missing {expected_version} in score_comparison.versions"
            )
            entry = versions[expected_version]
            assert "scores" in entry, f"{expected_version} missing scores array"
            assert len(entry["scores"]) == 7, (
                f"{expected_version} scores should have 7 entries, "
                f"got {len(entry['scores'])}"
            )
            assert "note" in entry, f"{expected_version} missing note field"
