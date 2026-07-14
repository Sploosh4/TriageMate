"""
Tests for pipeline/pre_tier.py — Pre-Tier multi-label classifier pipeline.

Tests cover:
  - predict_mission_tags() returns correct dict shape for known demo hosts
  - KNOWN_TAGS returns correct tags for the 31 demo hostnames
  - ML fallback path (mocked model data)
  - Default fallback when both KNOWN_TAGS and ML fail
  - Confidence values are always in [0, 1]

Uses ``unittest.mock.patch.object`` instead of direct module-level state
assignment (``pt._model_data = None``) to avoid shared-state races when
tests are run in parallel.
"""

from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from pipeline.pre_tier import (
    KNOWN_TAGS,
    DEFAULT_RESPONSE,
    predict_mission_tags,
)

import pipeline.pre_tier as pt  # noqa: E402 — used by mock targets


# ── Helpers ──────────────────────────────────────────────────────────────────


def _assert_valid_response(result: dict):
    """Assert the API contract shape and value ranges."""
    required_keys = {
        "mission_prevalence",
        "mission_prevalence_confidence",
        "public_wellbeing_impact",
        "public_wellbeing_confidence",
    }
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys in response. Expected {required_keys}, got {set(result.keys())}"
    )

    assert result["mission_prevalence"] in ("Core", "Support", "Peripheral"), (
        f"Invalid mission_prevalence: {result['mission_prevalence']!r}"
    )
    assert result["public_wellbeing_impact"] in ("Severe", "Moderate", "Minimal"), (
        f"Invalid public_wellbeing_impact: {result['public_wellbeing_impact']!r}"
    )

    assert 0.0 <= result["mission_prevalence_confidence"] <= 1.0, (
        f"mission_prevalence_confidence {result['mission_prevalence_confidence']} "
        f"outside [0, 1]"
    )
    assert 0.0 <= result["public_wellbeing_confidence"] <= 1.0, (
        f"public_wellbeing_confidence {result['public_wellbeing_confidence']} "
        f"outside [0, 1]"
    )


# ── Tests ────────────────────────────────────────────────────────────────────


class TestPredictMissionTagsResponseShape:
    """Verify the API contract for predict_mission_tags()."""

    def test_returns_dict_with_expected_keys(self):
        result = predict_mission_tags("per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        _assert_valid_response(result)

    def test_all_known_hosts_return_valid_response(self):
        """Every hostname in KNOWN_TAGS should return a valid response."""
        for hostname in KNOWN_TAGS:
            result = predict_mission_tags(hostname)
            _assert_valid_response(result)

    def test_known_host_returns_exact_values(self):
        """Spot-check a known host returns the exact hardcoded values."""
        result = predict_mission_tags("per-PRD-CITRIX-ADC01.transport.wa.gov.au")
        assert result["mission_prevalence"] == "Core"
        assert result["mission_prevalence_confidence"] == 0.91
        assert result["public_wellbeing_impact"] == "Moderate"
        assert result["public_wellbeing_confidence"] == 0.88

    def test_another_known_host(self):
        result = predict_mission_tags("per-PRD-PRINT-SVR05.education.wa.edu.au")
        assert result["mission_prevalence"] == "Support"
        assert result["mission_prevalence_confidence"] == 0.85
        assert result["public_wellbeing_impact"] == "Minimal"
        assert result["public_wellbeing_confidence"] == 0.82

    def test_known_host_from_new_23(self):
        """One of the newer 23 entries."""
        result = predict_mission_tags("per-PRD-CAD-DISPATCH01.police.wa.gov.au")
        assert result["mission_prevalence"] == "Core"
        assert result["mission_prevalence_confidence"] == 0.95
        assert result["public_wellbeing_impact"] == "Severe"
        assert result["public_wellbeing_confidence"] == 0.96


class TestDefaultFallback:
    """Phase 3 fallback when both KNOWN_TAGS and ML fail.

    Uses ``mock.patch.object`` to simulate an unavailable model without
    mutating module-level state (avoids shared-state races).
    """

    @pytest.fixture(autouse=True)
    def _force_model_unavailable(self):
        """Force the model to appear unavailable for every test in this class."""
        with (
            patch.object(pt, "_model_data", None),
            patch.object(pt, "_model_attempted", True),
        ):
            yield

    def test_unknown_host_returns_default_when_model_unavailable(self):
        """Unknown host with no model loaded returns Support/Minimal @ 0.60."""
        result = predict_mission_tags("nonexistent-host.example.com")
        assert result == DEFAULT_RESPONSE

    def test_default_confidence_is_exactly_0_60(self):
        result = predict_mission_tags("foo.bar.baz")
        assert result["mission_prevalence_confidence"] == 0.60
        assert result["public_wellbeing_confidence"] == 0.60

    def test_default_labels(self):
        result = predict_mission_tags("foo.bar.baz")
        assert result["mission_prevalence"] == "Support"
        assert result["public_wellbeing_impact"] == "Minimal"


class TestMLFallback:
    """Phase 2 ML model path (mocked).

    Uses ``mock.patch.object`` to inject a mock model without mutating
    module-level state (avoids shared-state races).
    """

    def test_ml_model_returns_correct_structure(self):
        """Mock a successful model prediction and verify the return structure."""
        mock_model = MagicMock()
        # predict returns (n_samples, n_outputs) — 2 outputs → [1, 2] (Support, Severe)
        mock_model.predict.return_value = np.array([[1, 2]])
        # predict_proba returns list of arrays per output
        mock_model.predict_proba.return_value = [
            np.array(
                [[0.1, 0.8, 0.1]]
            ),  # mission: Peripheral=0.1, Support=0.8, Core=0.1
            np.array(
                [[0.05, 0.15, 0.8]]
            ),  # wellbeing: Minimal=0.05, Moderate=0.15, Severe=0.8
        ]

        mock_data = {
            "model": mock_model,
            "classes": {
                "mission": ["Peripheral", "Support", "Core"],
                "wellbeing": ["Minimal", "Moderate", "Severe"],
            },
            "n_features": 60,
        }

        with (
            patch.object(pt, "_model_data", mock_data),
            patch.object(pt, "_model_attempted", True),
        ):
            result = predict_mission_tags("per-PRD-UNKNOWN-HOST01.health.wa.gov.au")
            _assert_valid_response(result)

            # Ensure the model was used (not KNOWN_TAGS nor default)
            assert result["mission_prevalence"] == "Support"
            assert result["mission_prevalence_confidence"] == pytest.approx(
                0.8, abs=1e-4
            )
            assert result["public_wellbeing_impact"] == "Severe"
            assert result["public_wellbeing_confidence"] == pytest.approx(0.8, abs=1e-4)

    def test_ml_model_fallback_on_prediction_failure(self):
        """When ML model raises during predict(), fall back to default."""
        mock_model = MagicMock()
        mock_model.predict.side_effect = ValueError("Model corrupted")

        mock_data = {
            "model": mock_model,
            "classes": {
                "mission": ["Peripheral", "Support", "Core"],
                "wellbeing": ["Minimal", "Moderate", "Severe"],
            },
        }

        with (
            patch.object(pt, "_model_data", mock_data),
            patch.object(pt, "_model_attempted", True),
        ):
            result = predict_mission_tags("per-PRD-UNKNOWN-HOST01.health.wa.gov.au")
            assert result == DEFAULT_RESPONSE


class TestKnownTagsContents:
    """Verify the KNOWN_TAGS dict entries are well-formed."""

    def test_known_tags_has_31_entries(self):
        """There should be exactly 31 known demo hosts."""
        assert len(KNOWN_TAGS) == 31

    def test_all_known_tags_have_valid_values(self):
        """Every KNOWN_TAGS entry has valid mission/wellbeing labels and confidences."""
        for hostname, (mp, mp_c, pwi, pwi_c) in KNOWN_TAGS.items():
            assert mp in ("Core", "Support", "Peripheral"), (
                f"{hostname}: invalid mission_prevalence {mp!r}"
            )
            assert pwi in ("Severe", "Moderate", "Minimal"), (
                f"{hostname}: invalid public_wellbeing_impact {pwi!r}"
            )
            assert 0.0 <= mp_c <= 1.0, (
                f"{hostname}: mp_confidence {mp_c} outside [0, 1]"
            )
            assert 0.0 <= pwi_c <= 1.0, (
                f"{hostname}: pwi_confidence {pwi_c} outside [0, 1]"
            )

    def test_all_known_hostnames_are_fully_qualified(self):
        """Every KNOWN_TAGS hostname should end with a recognised domain."""
        EXCEPTIONS = {"per-PRD-WTR-SCADA01.watercorporation.com.au"}
        for hostname in KNOWN_TAGS:
            if hostname in EXCEPTIONS:
                continue
            assert hostname.endswith((".wa.gov.au", ".wa.edu.au")), (
                f"Hostname not a WA Gov FQDN: {hostname}"
            )


class TestConfidenceRange:
    """Confidence values are always in [0, 1]."""

    def test_known_hosts_have_valid_confidences(self):
        for hostname in KNOWN_TAGS:
            result = predict_mission_tags(hostname)
            _assert_valid_response(result)

    def test_unknown_hosts_have_valid_confidences(self):
        for hostname in [
            "foo.bar.baz",
            "server.example.com",
            "unknown.local",
        ]:
            result = predict_mission_tags(hostname)
            _assert_valid_response(result)

    def test_case_sensitivity_known_hosts_exact_match(self):
        """KNOWN_TAGS uses exact string matching — different case is NOT a known host."""
        # Exact match returns known values
        exact = predict_mission_tags("per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        assert exact["mission_prevalence"] == "Core"

        # Same but lowercased — NOT in KNOWN_TAGS, will use ML or default
        lower = predict_mission_tags("per-prd-moveit-web01.health.wa.gov.au")
        # It should NOT match the known host values
        assert not (
            lower["mission_prevalence"] == "Core"
            and lower["mission_prevalence_confidence"] == 0.94
        ), "Lowercase hostname should not match KNOWN_TAGS"
        _assert_valid_response(lower)
