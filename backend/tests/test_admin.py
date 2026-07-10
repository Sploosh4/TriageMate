"""
Tests for the Admin Configuration API (routers/admin.py).

Covers:
  - GET  /api/admin/config/scoring
  - PUT  /api/admin/config/scoring (valid, invalid, out-of-range, low total)
  - POST /api/admin/config/scoring/reset
  - Config file persistence
"""

import json
from pathlib import Path

import pytest


# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture(autouse=True)
def _cleanup_config_file():
    """Remove any scoring_weights.json before and after each test."""
    config_file = (
        Path(__file__).resolve().parent.parent
        / "pipeline"
        / "config"
        / "scoring_weights.json"
    )
    # Remove before
    if config_file.exists():
        config_file.unlink()
    yield
    # Remove after
    if config_file.exists():
        config_file.unlink()


# ======================================================================
# GET /api/admin/config/scoring
# ======================================================================


class TestGetScoringConfig:
    """Verify the GET endpoint returns current scoring configuration."""

    async def test_get_scoring_config_returns_200(self, client):
        """GET must return 200 with expected keys."""
        resp = await client.get("/api/admin/config/scoring")
        assert resp.status_code == 200
        data = resp.json()
        assert "weights" in data
        assert "total_weight" in data
        assert "defaults" in data
        assert "default_total" in data
        assert "min_weight" in data
        assert "max_weight" in data
        assert "min_total" in data

    async def test_get_scoring_config_has_seven_weights(self, client):
        """The weights dict must have all 7 keys."""
        resp = await client.get("/api/admin/config/scoring")
        data = resp.json()
        weights = data["weights"]
        assert set(weights.keys()) == {
            "cvss",
            "epss",
            "criticality",
            "exposure",
            "patch",
            "ml_exploitation",
            "security_context",
        }

    async def test_get_scoring_config_total_matches_sum(self, client):
        """total_weight must equal sum of weights values."""
        resp = await client.get("/api/admin/config/scoring")
        data = resp.json()
        assert data["total_weight"] == sum(data["weights"].values())

    async def test_get_scoring_config_defaults_match(self, client):
        """defaults must contain the hardcoded default values."""
        resp = await client.get("/api/admin/config/scoring")
        data = resp.json()
        assert data["defaults"] == {
            "cvss": 40,
            "epss": 20,
            "criticality": 20,
            "exposure": 12,
            "patch": 5,
            "ml_exploitation": 10,
            "security_context": 5,
        }


# ======================================================================
# PUT /api/admin/config/scoring
# ======================================================================


class TestPutScoringConfig:
    """Verify PUT validates and persists weight changes."""

    VALID_WEIGHTS = {
        "cvss": 30,
        "epss": 25,
        "criticality": 15,
        "exposure": 10,
        "patch": 8,
        "ml_exploitation": 12,
        "security_context": 5,
    }

    async def test_put_valid_weights_returns_200(self, client):
        """PUT with valid weights must return 200 and update weights."""
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": self.VALID_WEIGHTS},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["weights"] == self.VALID_WEIGHTS
        assert data["total_weight"] == sum(self.VALID_WEIGHTS.values())

    async def test_put_weights_persists_to_config_file(self, client):
        """After PUT, the config file must exist and contain the weights."""
        config_file = (
            Path(__file__).resolve().parent.parent
            / "pipeline"
            / "config"
            / "scoring_weights.json"
        )
        await client.put(
            "/api/admin/config/scoring",
            json={"weights": self.VALID_WEIGHTS},
        )
        assert config_file.exists()
        with open(config_file) as f:
            saved = json.load(f)
        assert saved["weights"] == self.VALID_WEIGHTS

    async def test_put_weights_updates_in_memory(self, client):
        """After PUT, GET must return the updated weights."""
        await client.put(
            "/api/admin/config/scoring",
            json={"weights": self.VALID_WEIGHTS},
        )
        get_resp = await client.get("/api/admin/config/scoring")
        data = get_resp.json()
        assert data["weights"] == self.VALID_WEIGHTS

    async def test_put_missing_key_returns_422(self, client):
        """PUT without required key must return 422."""
        bad_weights = {
            "cvss": 40,
            "epss": 20,
            "criticality": 20,
            "exposure": 12,
            "patch": 5,
            "ml_exploitation": 10,
            # missing security_context
        }
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": bad_weights},
        )
        assert resp.status_code == 422

    async def test_put_extra_key_returns_422(self, client):
        """PUT with extra unrecognised key must return 422."""
        bad_weights = {
            "cvss": 40,
            "epss": 20,
            "criticality": 20,
            "exposure": 12,
            "patch": 5,
            "ml_exploitation": 10,
            "security_context": 5,
            "extra_key": 10,
        }
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": bad_weights},
        )
        assert resp.status_code == 422

    async def test_put_weight_out_of_range_high_returns_422(self, client):
        """PUT with weight > 100 must return 422."""
        bad_weights = dict(self.VALID_WEIGHTS)
        bad_weights["cvss"] = 200
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": bad_weights},
        )
        assert resp.status_code == 422

    async def test_put_weight_out_of_range_low_returns_422(self, client):
        """PUT with weight < 1 must return 422."""
        bad_weights = dict(self.VALID_WEIGHTS)
        bad_weights["epss"] = 0
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": bad_weights},
        )
        assert resp.status_code == 422

    async def test_put_weight_non_int_returns_422(self, client):
        """PUT with non-integer weight must return 422."""
        # String value for integer field — FastAPI/Pydantic will reject
        resp = await client.put(
            "/api/admin/config/scoring",
            json={
                "weights": {
                    "cvss": 40,
                    "epss": 20,
                    "criticality": 20,
                    "exposure": 12,
                    "patch": "not_an_int",
                    "ml_exploitation": 10,
                    "security_context": 5,
                }
            },
        )
        assert resp.status_code == 422

    async def test_put_low_total_returns_422(self, client):
        """PUT with total < 100 must return 422."""
        low_weights = {
            "cvss": 10,
            "epss": 10,
            "criticality": 10,
            "exposure": 10,
            "patch": 10,
            "ml_exploitation": 10,
            "security_context": 10,  # total = 70
        }
        resp = await client.put(
            "/api/admin/config/scoring",
            json={"weights": low_weights},
        )
        assert resp.status_code == 422


# ======================================================================
# POST /api/admin/config/scoring/reset
# ======================================================================


class TestResetScoringConfig:
    """Verify POST reset restores default weights."""

    async def test_reset_restores_defaults(self, client):
        """After reset, weights must equal the hardcoded defaults."""
        # First change weights
        custom = {
            "cvss": 30,
            "epss": 25,
            "criticality": 15,
            "exposure": 10,
            "patch": 8,
            "ml_exploitation": 12,
            "security_context": 5,
        }
        await client.put("/api/admin/config/scoring", json={"weights": custom})

        # Then reset
        reset_resp = await client.post("/api/admin/config/scoring/reset")
        assert reset_resp.status_code == 200
        data = reset_resp.json()
        assert data["weights"] == data["defaults"]

    async def test_reset_deletes_config_file(self, client):
        """After reset, the config file must not exist."""
        config_file = (
            Path(__file__).resolve().parent.parent
            / "pipeline"
            / "config"
            / "scoring_weights.json"
        )
        # First create a config file
        await client.put(
            "/api/admin/config/scoring",
            json={
                "weights": {
                    "cvss": 30,
                    "epss": 25,
                    "criticality": 15,
                    "exposure": 10,
                    "patch": 8,
                    "ml_exploitation": 12,
                    "security_context": 5,
                }
            },
        )
        assert config_file.exists()

        # Reset
        await client.post("/api/admin/config/scoring/reset")
        assert not config_file.exists()

    async def test_reset_then_get_returns_defaults(self, client):
        """After reset, GET must return default weights."""
        await client.post("/api/admin/config/scoring/reset")
        get_resp = await client.get("/api/admin/config/scoring")
        data = get_resp.json()
        assert data["weights"] == data["defaults"]
        assert data["total_weight"] == data["default_total"]


# ======================================================================
# Config File Override (reload_weights)
# ======================================================================


class TestConfigFileOverride:
    """Verify scoring weights are loaded from config file on import."""

    async def test_config_file_override_at_import(self, client):
        """Write a config file, then verify reload_weights picks it up."""
        import pipeline.config.scoring as scoring_cfg

        custom = {
            "cvss": 35,
            "epss": 20,
            "criticality": 18,
            "exposure": 10,
            "patch": 6,
            "ml_exploitation": 8,
            "security_context": 5,
        }
        with open(scoring_cfg._CONFIG_FILE, "w") as f:
            json.dump({"weights": custom}, f)

        scoring_cfg.reload_weights()
        assert scoring_cfg.SCORING_WEIGHTS == custom

    async def test_invalid_config_file_falls_back(self, client):
        """Write an invalid config file, verify reload_weights falls back."""
        import pipeline.config.scoring as scoring_cfg

        # Write invalid JSON
        with open(scoring_cfg._CONFIG_FILE, "w") as f:
            f.write("not valid json")

        scoring_cfg.reload_weights()
        # Should have fallen back to defaults
        assert scoring_cfg.SCORING_WEIGHTS == {
            "cvss": 40,
            "epss": 20,
            "criticality": 20,
            "exposure": 12,
            "patch": 5,
            "ml_exploitation": 10,
            "security_context": 5,
        }
