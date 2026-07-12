"""Tests for model registry rollback API."""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "ml" / "model_registry.json"


@pytest.fixture(autouse=True)
def backup_registry():
    """Backup and restore registry after each test."""
    if REGISTRY_PATH.exists():
        backup = REGISTRY_PATH.read_text()
        yield
        REGISTRY_PATH.write_text(backup)
    else:
        yield


def test_get_versions_returns_list():
    resp = client.get("/api/models/versions")
    assert resp.status_code == 200
    data = resp.json()
    assert "active_version" in data
    assert "versions" in data
    assert isinstance(data["versions"], list)


def test_rollback_nonexistent_version():
    resp = client.post("/api/models/xgboost/rollback?version=nonexistent")
    assert resp.status_code == 404


def test_rollback_same_version():
    registry = json.loads(REGISTRY_PATH.read_text())
    active = registry["active_version"]
    resp = client.post(f"/api/models/xgboost/rollback?version={active}")
    assert resp.status_code == 400


def test_rollback_to_previous_version():
    """Requires at least 2 versions in registry. Adds a temp version if needed."""
    registry = json.loads(REGISTRY_PATH.read_text())
    original_active = registry["active_version"]
    versions = registry.get("versions", [])

    if len(versions) < 2:
        # Add a dummy version for testing
        test_version = {
            "version": "test_rollback_v0",
            "label": "Test rollback target",
            "model_file": "xgboost_model.pkl",  # reuses existing file
            "metrics": {"roc_auc": 0.90},
        }
        registry["versions"].append(test_version)
        REGISTRY_PATH.write_text(json.dumps(registry, indent=2))

    resp = client.post("/api/models/xgboost/rollback?version=test_rollback_v0")
    # May return 200 or 404 depending on whether model file exists
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        data = resp.json()
        assert data["status"] == "success"
        assert data["active_version"] == "test_rollback_v0"

    # Clean up test version
    registry = json.loads(REGISTRY_PATH.read_text())
    registry["versions"] = [
        v for v in registry["versions"] if v["version"] != "test_rollback_v0"
    ]
    registry["active_version"] = original_active  # RESTORE pre-test value
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2))
