"""
Tests for model version management (read-write: list + activate).

Covers:
- GET  /api/model/versions  — listing with correct active version
- POST /api/model/activate — error cases (only v3 remains after hygiene cleanup)
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
        """GET /api/model/versions returns 1 version (v3), active is v3.

        v1 and v2 model files were removed during hygiene cleanup,
        so only v3 remains in the registry.
        """
        response = await client.get("/api/model/versions")
        assert response.status_code == 200
        data = response.json()

        assert data["active_version"] == "v3", (
            f"Expected active_version v3, got {data['active_version']}"
        )
        assert len(data["versions"]) == 1, (
            f"Expected 1 version, got {len(data['versions'])}"
        )

        version_ids = [v["version"] for v in data["versions"]]
        assert version_ids == ["v3"], f"Unexpected version order: {version_ids}"

        for v in data["versions"]:
            assert v["is_active"] is True, "v3 should be marked active"

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
        assert len(data["available_versions"]) == 1, (
            f"Expected 1 version, got {len(data['available_versions'])}"
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
        """Score comparison contains v3 entry only (v1/v2 removed in hygiene)."""
        response = await client.get("/api/model/status")
        data = response.json()
        versions = data["score_comparison"]["versions"]

        for expected_version in ["v3"]:
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
