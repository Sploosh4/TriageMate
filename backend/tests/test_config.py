"""Tests for the read-only config API endpoint."""

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

    def test_config_has_feature_names(self):
        resp = client.get("/api/config")
        data = resp.json()
        assert "feature_names" in data
        assert "tabular_count" in data["feature_names"]
        assert "tabular_names" in data["feature_names"]

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
