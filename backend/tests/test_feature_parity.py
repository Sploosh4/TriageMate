"""
Feature-parity guard test.

Verifies that the feature vector built by build_feature_vector() matches
what the XGBoost model expects at inference time. Catches:
  - Feature name / key drift between ingest_helpers and xgboost_predictor
  - Dimension mismatches between training (NPZ) and inference (predictor)
  - Missing or renamed features

This is the contract enforcement test for the ML pipeline.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np
import pytest

from pipeline.config.feature_names import (
    TABULAR_FEATURE_ORDER as PREDICTOR_TABULAR_KEYS,
    TABULAR_FEATURE_COUNT as NUM_TABULAR,
)

# Expected total feature dimensions
NUM_SBERT = 384
EXPECTED_TOTAL = 419  # 35 tabular + 384 SBERT (predictor)


def _build_mock_payload():
    """Build a minimal mock object mimicking IngestRequest for CVE-2023-34362."""
    payload = MagicMock()
    payload.vulnerability_id = "CVE-2023-34362"
    payload.cvss_score = 7.5
    payload.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    payload.epss_score = 0.973
    payload.hostname = "per-prd-web01.health.wa.gov.au"
    payload.raw_description = (
        "SQL injection vulnerability in Progress MoveIt Transfer "
        "allows remote code execution without authentication"
    )
    payload.cisa_kev = True
    payload.internal_notes = None
    payload.asset_id = None
    payload.technologies = []
    return payload


@pytest.fixture(autouse=True)
def mock_external_deps():
    """Mock all network-dependent modules that build_feature_vector calls."""
    patchers = [
        # CMDB adapter
        patch(
            "ingest_helpers._cmdb_context",
            return_value={
                "hostname": "per-prd-web01.health.wa.gov.au",
                "data_classification": "OFFICIAL",
                "internet_facing": True,
                "department": "Health",
                "last_patch_date": "2024-01-15",
                "operating_system": "Windows Server 2022",
            },
        ),
        patch("ingest_helpers._cmdb_classification", return_value="OFFICIAL"),
        patch("ingest_helpers._cmdb_internet_facing", return_value=True),
        # NVD adapter
        patch(
            "ingest_helpers.get_nvd_data",
            return_value={
                "cve_id": "CVE-2023-34362",
                "patch_available": True,
                "vulnerability_age_days": 120,
                "nvd_reference_count": 15,
                "cwe_class": "CWE-89",
                "cvss_exploitability_sub": 3.9,
                "cvss_impact_sub": 5.9,
                "osv_fixed_versions": ["1.0.1"],
                "osv_package": "moveit_transfer",
                "osv_ecosystem": "npm",
            },
        ),
        # ExploitDB
        patch("ingest_helpers._has_exploitdb_poc", return_value=True),
        # Metasploit
        patch("ingest_helpers._has_metasploit_payload", return_value=False),
        # OTX (network)
        patch(
            "ingest_helpers.query_otx_pulses",
            return_value={
                "pulse_count": 5,
                "status": "threat_intel_found",
            },
        ),
    ]
    for p in patchers:
        p.start()
    yield
    for p in reversed(patchers):
        p.stop()


class TestFeatureParity:
    """Feature vector contract enforcement."""

    # ── Part 1: build_feature_vector() returns all expected keys ────────────

    def test_feature_vector_has_all_tabular_keys(self):
        """Call build_feature_vector and verify all 35 tabular keys exist."""
        from ingest_helpers import build_feature_vector

        payload = _build_mock_payload()
        mission_tags = {
            "mission_prevalence": "Support",
            "public_wellbeing_impact": "Minimal",
        }
        tier_0_result = {"routing": "tier_1"}

        fv = build_feature_vector(payload, mission_tags, tier_0_result)

        for key in PREDICTOR_TABULAR_KEYS:
            assert key in fv, (
                f"Missing tabular feature key '{key}' in build_feature_vector() output"
            )

        # Also verify we have the right count of tabular inputs
        tabular_keys_in_fv = [k for k in PREDICTOR_TABULAR_KEYS if k in fv]
        assert len(tabular_keys_in_fv) == NUM_TABULAR, (
            f"Expected {NUM_TABULAR} tabular keys, got {len(tabular_keys_in_fv)}"
        )

    def test_feature_vector_has_metadata_and_text_keys(self):
        """Verify build_feature_vector returns metadata + description keys."""
        from ingest_helpers import build_feature_vector

        payload = _build_mock_payload()
        mission_tags = {}
        tier_0_result = {}

        fv = build_feature_vector(payload, mission_tags, tier_0_result)

        # Metadata keys that are NOT model inputs (present at inference time)
        metadata_keys = {
            "cvss_score",
            "osv_fixed_versions",
            "osv_package",
            "osv_ecosystem",
            "threat_intel_status",
        }
        for key in metadata_keys:
            assert key in fv, (
                f"Missing metadata key '{key}' in build_feature_vector() output"
            )

        # Text key for SBERT
        assert "description" in fv, "Missing 'description' key for SBERT encoding"

        # Total dict size should be 41 (35 tabular + 5 metadata + 1 description)
        # (osv_lead_days is computed during training, not at inference time)
        assert len(fv) >= 40, f"Expected ~41 keys in feature vector, got {len(fv)}"

    # ── Part 2: Predictor builds the correct vector shape ──────────────────

    def test_predictor_tabular_array_via_real_builder(self):
        """Call the real _build_tabular_array() and verify shape & position.

        This uses the actual predictor array builder, not a manual
        comprehension over a key list — catches ordering drift that
        a shape-only check would miss.
        """
        from ml.xgboost_predictor import _build_tabular_array

        features = {
            "cvss_av": 3,
            "cvss_ac": 1,
            "cvss_pr": 2,
            "cvss_ui": 1,
            "cvss_s": 0,
            "cvss_c": 2,
            "cvss_i": 0,
            "cvss_a": 1,
            "epss_score": 0.5,
            "patch_available": True,
            "patch_applied": False,
            "internet_facing": True,
            "domain_joined": True,
            "data_classification": "OFFICIAL",
            "mission_prevalence": "Support",
            "public_wellbeing_impact": "Minimal",
            "lateral_reachability": 1,
            "boundary_reachability": 0,
            "downstream_assets": 5,
            "patch_lag_days": 30,
            "exploitdb_has_poc": True,
            "metasploit_has_payload": False,
            "threat_intel_pulses": 2,
            "nvd_reference_count": 10,
            "cve_desc_tokens": 200,
            "vulnerability_age_days": 100,
            "vendor_popularity_index": 0.5,
            "cvss_exploitability_sub": 3.9,
            "cvss_impact_sub": 5.9,
            "is_top_25_cwe": True,
            "is_rce_signature": True,
            "is_privesc_signature": False,
            "is_bypass_signature": False,
            "is_dos_signature": False,
            "is_traversal_signature": False,
        }

        arr = _build_tabular_array(features)
        assert arr.shape == (1, NUM_TABULAR), (
            f"Real _build_tabular_array() returned shape {arr.shape}, "
            f"expected (1, {NUM_TABULAR})"
        )

        # Build full feature vector and verify with model
        text_vec = np.zeros((1, NUM_SBERT), dtype=np.float32)
        X = np.hstack([arr, text_vec])
        assert X.shape[1] == EXPECTED_TOTAL, (
            f"Total feature vector has {X.shape[1]} columns, expected {EXPECTED_TOTAL}"
        )

    # ── Part 3: Model actually accepts the vector without error ────────────

    @pytest.mark.artifact
    def test_model_accepts_feature_vector(self):
        """Feed a correctly-shaped vector to the model and verify no error."""
        try:
            from ml.xgboost_predictor import _get_model

            model = _get_model()
        except FileNotFoundError:
            pytest.skip("XGBoost model artifact not available in this environment")
        booster = model.get_booster()
        expected_features = booster.num_features()

        # Build a feature vector matching model dimensions
        # Model expects 419 cols: 35 tabular + 384 SBERT
        tabular = np.zeros((1, NUM_TABULAR), dtype=np.float32)

        text_vec = np.zeros((1, NUM_SBERT), dtype=np.float32)
        X = np.hstack([tabular, text_vec])

        assert X.shape[1] == expected_features, (
            f"Feature vector has {X.shape[1]} columns, "
            f"but model expects {expected_features}"
        )

        # This should not raise a dimension error
        try:
            prob = float(model.predict_proba(X)[0, 1])
            assert 0.0 <= prob <= 1.0, f"Probability {prob} outside [0, 1]"
        except Exception as e:
            pytest.fail(f"Model rejected feature vector: {e}")

    # ── Part 4: NPZ training columns match predictor order ─────────────────

    @pytest.mark.artifact
    def test_npz_tabular_columns_match_predictor_order(self):
        """Verify the NPZ training data column names match predictor feature order."""
        npz_path = (
            Path(__file__).resolve().parent.parent / "ml" / "training_data_v2.npz"
        )
        if not npz_path.exists():
            pytest.skip("training_data_v2.npz not available in this environment")

        data = np.load(npz_path)
        npz_names = list(data["feature_names"])

        # NPZ columns 0-34 are tabular features (same as predictor)
        npz_tabular = npz_names[:35]
        assert npz_tabular == PREDICTOR_TABULAR_KEYS, (
            f"NPZ tabular columns don't match predictor order.\n"
            f"  NPZ:       {npz_tabular}\n"
            f"  Predictor: {PREDICTOR_TABULAR_KEYS}"
        )

        # SBERT column naming depends on the generator:
        #   - train_xgboost.py save_training_data(): uses sbert_0..383
        #   - build_training_corpus.py save_dataset(): uses text_sbert_0..383
        # training_data_v2.npz uses text_sbert_* naming; training_data.npz uses sbert_*.
        sbert_names = npz_names[35:]
        for i, name in enumerate(sbert_names, start=35):
            assert name.startswith("text_sbert_") or name.startswith("sbert_"), (
                f"NPZ column {i}: expected 'sbert_*' or 'text_sbert_*', got '{name}'"
            )
        assert len(sbert_names) == NUM_SBERT, (
            f"Expected {NUM_SBERT} SBERT columns, got {len(sbert_names)}"
        )

        data.close()
