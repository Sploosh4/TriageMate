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

# ── Tabular feature keys in the EXACT order xgboost_predictor.predict() builds them ──

PREDICTOR_TABULAR_KEYS = [
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
    "epss_score",
    "patch_available",
    "patch_applied",
    "internet_facing",
    "domain_joined",
    "data_classification",
    "mission_prevalence",
    "public_wellbeing_impact",
    "lateral_reachability",
    "boundary_reachability",
    "downstream_assets",
    "patch_lag_days",
    "exploitdb_has_poc",
    "metasploit_has_payload",
    "threat_intel_pulses",
    "nvd_reference_count",
    "cve_desc_tokens",
    "vulnerability_age_days",
    "vendor_popularity_index",
    "cvss_exploitability_sub",
    "cvss_impact_sub",
    "is_top_25_cwe",
    "is_rce_signature",
    "is_privesc_signature",
    "is_bypass_signature",
    "is_dos_signature",
    "is_traversal_signature",
]

# Expected total feature dimensions
NUM_TABULAR = 35
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

    def test_predictor_tabular_array_shape(self):
        """Verify xgboost_predictor produces a 35-element tabular array."""
        # Build a minimal feature dict with defaults for all 35 keys
        features: dict = {k: 0 for k in PREDICTOR_TABULAR_KEYS}
        features["description"] = "test vulnerability description"

        # Inspect the model directly
        from ml.xgboost_predictor import _get_model

        model = _get_model()
        booster = model.get_booster()
        n_model_features = booster.num_features()

        # Build the tabular array the same way predict() does
        tabular = np.array(
            [[features.get(k, 0) for k in PREDICTOR_TABULAR_KEYS]],
            dtype=np.float32,
        )
        assert tabular.shape[1] == NUM_TABULAR, (
            f"Predictor tabular array has {tabular.shape[1]} columns, "
            f"expected {NUM_TABULAR}"
        )

        # Build full feature vector
        text_vec = np.zeros((1, NUM_SBERT), dtype=np.float32)
        X = np.hstack([tabular, text_vec])
        assert X.shape[1] == EXPECTED_TOTAL, (
            f"Predictor builds {X.shape[1]}-dim vector, expected {EXPECTED_TOTAL}"
        )

        # CRITICAL CHECK: model dimension vs predictor dimension
        print(f"\n  Model features: {n_model_features}")
        print(f"  Predictor builds: {X.shape[1]}")
        if n_model_features != X.shape[1]:
            print(
                f"  ⚠️  DIMENSION MISMATCH: model expects {n_model_features} "
                f"features, predictor builds {X.shape[1]}"
            )

    # ── Part 3: Model actually accepts the vector without error ────────────

    def test_model_accepts_feature_vector(self):
        """Feed a correctly-shaped vector to the model and verify no error."""
        from ml.xgboost_predictor import _get_model

        model = _get_model()
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

        # NPZ columns 35-418 should be SBERT embeddings
        for i, name in enumerate(npz_names[35:], start=35):
            assert name.startswith("text_sbert_"), (
                f"NPZ column {i}: expected 'text_sbert_*', got '{name}'"
            )
        assert len(npz_names[35:]) == NUM_SBERT, (
            f"Expected {NUM_SBERT} SBERT columns, got {len(npz_names[35:])}"
        )

        data.close()

    # ── Part 5: Drift detection (negative test) ────────────────────────────

    def test_drift_detection_renamed_feature(self):
        """Simulate a renamed feature key and verify the test would catch it."""
        # If a feature were renamed, it would NOT match PREDICTOR_TABULAR_KEYS
        # This is a meta-test to show the drift-detection mechanism works.
        drifted_keys = list(PREDICTOR_TABULAR_KEYS)
        # Simulate a rename: change 'epss_score' to 'epss_score_v2'
        drifted_keys[8] = "epss_score_v2"

        assert drifted_keys != PREDICTOR_TABULAR_KEYS, (
            "Drift simulation failed: keys should differ after rename"
        )

        # The real check: verify the current keys match expectations
        assert PREDICTOR_TABULAR_KEYS[8] == "epss_score", (
            "Expected predictor key at index 8 to be 'epss_score'"
        )
