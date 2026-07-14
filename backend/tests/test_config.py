"""Tests for the read-only config API endpoint."""

from pathlib import Path
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestConfigEndpoint:
    def test_config_endpoint_exists(self):
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_config_has_thresholds(self):
        resp = client.get("/api/config")
        data = resp.json()
        assert "thresholds" in data
        assert "nvd_ref_threshold" in data["thresholds"]
        assert "cwe_epss_thresholds" in data["thresholds"]

    def test_config_has_scoring(self):
        resp = client.get("/api/config")
        data = resp.json()
        assert "scoring" in data
        assert "weights" in data["scoring"]
        assert "total_weight" in data["scoring"]
        assert "context_multiplier" in data["scoring"]

    def test_config_does_not_expose_feature_names(self):
        """The public config contract must not expose the ML feature order."""
        resp = client.get("/api/config")
        assert resp.status_code == 200
        assert "feature_names" not in resp.json()

    def test_config_scoring_weights_match_module(self):
        from pipeline.config.scoring import SCORING_WEIGHTS

        resp = client.get("/api/config")
        data = resp.json()
        assert data["scoring"]["weights"] == SCORING_WEIGHTS

    def test_config_total_weight_matches_sum(self):
        resp = client.get("/api/config")
        data = resp.json()
        weights = data["scoring"]["weights"]
        total = sum(weights.values())
        assert total == data["scoring"]["total_weight"]

    def test_config_has_threshold_info(self):
        resp = client.get("/api/config")
        data = resp.json()
        assert "threshold_info" in data
        ti = data["threshold_info"]
        # Should have expected keys from threshold_info.json
        expected_keys = {
            "classification_threshold",
            "val_f1",
            "cwe_stratified_thresholds",
            "generated_at",
        }
        assert expected_keys.issubset(ti.keys()), (
            f"threshold_info missing keys. Got {set(ti.keys())}, expected at least {expected_keys}"
        )
        assert isinstance(ti["classification_threshold"], (int, float))
        assert isinstance(ti["val_f1"], (int, float))
        assert isinstance(ti["cwe_stratified_thresholds"], dict)
        assert "generated_at" in ti


class TestThresholdInfoDistinction:
    """ROUTER-LOW-8: missing vs corrupt threshold files must return distinct statuses.

    These tests manipulate the threshold_info.json on disk, then restore it.
    They run serially within the class (pytest default order).
    """

    # Path to the real threshold_info.json
    _THRESHOLD_PATH = (
        Path(__file__).resolve().parent.parent / "ml" / "threshold_info.json"
    )

    def test_threshold_info_not_found_when_missing(self):
        """When threshold_info.json is missing → {'status': 'not_found'}."""
        from routers.config import _load_threshold_info

        backup = None
        if self._THRESHOLD_PATH.exists():
            backup = self._THRESHOLD_PATH.with_suffix(".json.bak")
            self._THRESHOLD_PATH.rename(backup)

        try:
            result = _load_threshold_info()
            assert result == {"status": "not_found"}, (
                f"Expected not_found, got {result}"
            )
        finally:
            if backup:
                backup.rename(self._THRESHOLD_PATH)

    def test_threshold_info_corrupt_when_bad_json(self):
        """When threshold_info.json has invalid JSON → {'status': 'corrupt', ...}."""
        from routers.config import _load_threshold_info

        original_content = None
        if self._THRESHOLD_PATH.exists():
            original_content = self._THRESHOLD_PATH.read_text()

        try:
            self._THRESHOLD_PATH.write_text("{invalid json}")
            result = _load_threshold_info()
            assert result["status"] == "corrupt", (
                f"Expected status 'corrupt', got {result.get('status')}"
            )
            assert "error" in result, "Corrupt response should include an error message"
            assert "JSON decode failed" in result["error"], (
                f"Error message should say 'JSON decode failed', got: {result['error']}"
            )
        finally:
            if original_content is not None:
                self._THRESHOLD_PATH.write_text(original_content)
            elif self._THRESHOLD_PATH.exists():
                self._THRESHOLD_PATH.unlink()
