"""
Deterministic behavioural tests for the Tier 1 tabular feature contract.

All tests are:
  - Deterministic (no SBERT download, no NPZ dependency, no live adapters)
  - Designed to fail with clear messages showing the feature name,
    expected contract, and primary correction path
  - Exercising the REAL inference builder (xgboost_predictor._build_tabular_array)
    and REAL runtime feature builder (ingest_helpers.build_feature_vector)
"""

from unittest.mock import patch, MagicMock

import numpy as np
import pytest

from pipeline.config.feature_names import (
    TABULAR_FEATURE_ORDER,
    TABULAR_FEATURE_COUNT,
    TABULAR_METADATA_KEYS,
)


class TestTabularRegistry:
    """Canonical feature-name registry integrity."""

    def test_tabular_registry_is_unique_and_expected_size(self):
        """Assert 35 unique names in TABULAR_FEATURE_ORDER.

        Schema changes require updating ALL producers (ingest_helpers,
        train_xgboost, build_training_corpus) and consumers (xgboost_predictor,
        feature_parity_check) to match. If you change this count, you MUST also
        update the model retraining pipeline and verify feature count/order.
        """
        assert len(TABULAR_FEATURE_ORDER) == 35, (
            f"TABULAR_FEATURE_ORDER has {len(TABULAR_FEATURE_ORDER)} entries, "
            f"expected 35. "
            f"This is the Tier 1 tabular contract — changing it requires a "
            f"full retrain and schema audit across all producers/consumers."
        )
        assert len(set(TABULAR_FEATURE_ORDER)) == 35, (
            "TABULAR_FEATURE_ORDER contains duplicate names. Each name must be unique."
        )
        assert TABULAR_FEATURE_COUNT == 35, (
            f"TABULAR_FEATURE_COUNT ({TABULAR_FEATURE_COUNT}) != 35. "
            f"This constant must always equal len(TABULAR_FEATURE_ORDER)."
        )


class TestRuntimeFeatureVector:
    """Runtime feature vector produced by build_feature_vector()."""

    @pytest.fixture(autouse=True)
    def mock_all_adapters(self):
        """Mock all network/CMDB-dependent adapters for deterministic tests."""
        patchers = [
            patch(
                "ingest_helpers._cmdb_context",
                return_value={
                    "hostname": "mock-host.health.wa.gov.au",
                    "data_classification": "OFFICIAL",
                    "internet_facing": False,
                    "department": "Health",
                    "last_patch_date": "",
                    "operating_system": "Linux",
                },
            ),
            patch("ingest_helpers._cmdb_classification", return_value="OFFICIAL"),
            patch("ingest_helpers._cmdb_internet_facing", return_value=False),
            patch(
                "ingest_helpers.get_nvd_data",
                return_value={
                    "cve_id": "CVE-2024-0001",
                    "patch_available": False,
                    "vulnerability_age_days": 100,
                    "nvd_reference_count": 5,
                    "cwe_class": "CWE-79",
                    "cvss_exploitability_sub": 2.0,
                    "cvss_impact_sub": 4.0,
                },
            ),
            patch("ingest_helpers._has_exploitdb_poc", return_value=False),
            patch("ingest_helpers._has_metasploit_payload", return_value=False),
            patch(
                "ingest_helpers.query_otx_pulses",
                return_value={
                    "pulse_count": 0,
                    "status": "no_threat_intel_available",
                },
            ),
        ]
        for p in patchers:
            p.start()
        yield
        for p in reversed(patchers):
            p.stop()

    def test_runtime_feature_vector_has_exact_tabular_and_metadata_contract(self):
        """Build feature vector and assert exact key subsets.

        Tabular keys must match TABULAR_FEATURE_ORDER exactly.
        Non-tabular keys must equal TABULAR_METADATA_KEYS ∪ {"description"}.
        """
        from ingest_helpers import build_feature_vector

        payload = MagicMock()
        payload.vulnerability_id = "CVE-2024-0001"
        payload.cvss_score = 5.0
        payload.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        payload.epss_score = 0.05
        payload.hostname = "mock-host.health.wa.gov.au"
        payload.raw_description = "Test vulnerability description"
        payload.cisa_kev = False
        payload.internal_notes = None
        payload.asset_id = None
        payload.technologies = []

        mission_tags = {
            "mission_prevalence": "Support",
            "public_wellbeing_impact": "Minimal",
        }
        tier_0_result = {"routing": "tier_1"}

        fv = build_feature_vector(payload, mission_tags, tier_0_result)

        # --- Tabular subset ---
        fv_tabular_keys = [k for k in TABULAR_FEATURE_ORDER if k in fv]
        missing = set(TABULAR_FEATURE_ORDER) - set(fv.keys())

        assert len(fv_tabular_keys) == TABULAR_FEATURE_COUNT, (
            f"build_feature_vector() returned {len(fv_tabular_keys)} tabular keys, "
            f"expected {TABULAR_FEATURE_COUNT}. "
            f"Missing: {missing if missing else 'none'}. "
            f"All 35 tabular keys must be present in the runtime feature dict."
        )
        assert fv_tabular_keys == TABULAR_FEATURE_ORDER, (
            f"Tabular keys in feature vector do not match TABULAR_FEATURE_ORDER order.\n"
            f"  Expected order: {TABULAR_FEATURE_ORDER}\n"
            f"  Got order:      {fv_tabular_keys}"
        )

        # --- Non-tabular subset ---
        non_tabular_keys = set(fv.keys()) - set(TABULAR_FEATURE_ORDER)
        expected_non_tabular = set(TABULAR_METADATA_KEYS) | {"description"}

        assert non_tabular_keys == expected_non_tabular, (
            f"Non-tabular keys don't match expected contract.\n"
            f"  Unexpected: {non_tabular_keys - expected_non_tabular}\n"
            f"  Missing:    {expected_non_tabular - non_tabular_keys}\n"
            f"Expected metadata keys (from TABULAR_METADATA_KEYS): {sorted(TABULAR_METADATA_KEYS)}\n"
            f"Plus 'description' text key."
        )


class TestPredictorBuilder:
    """Real predictor array builder exercised with distinctive values."""

    def test_predictor_builds_values_in_canonical_order(self):
        """Call _build_tabular_array() with distinctive values and assert positions.

        Each position in the output array must correspond to the feature at
        the same index in TABULAR_FEATURE_ORDER.
        """
        from ml.xgboost_predictor import _build_tabular_array

        # Build a dict with a sentinel value for EVERY tabular key
        features = {}
        for i, key in enumerate(TABULAR_FEATURE_ORDER):
            # Use distinctive values that will survive encoding
            if key == "cvss_av":
                features[key] = 3  # Network (pre-encoded)
            elif key == "cvss_ac":
                features[key] = 1  # Low (pre-encoded)
            elif key == "cvss_pr":
                features[key] = 2  # None (pre-encoded)
            elif key == "cvss_ui":
                features[key] = 1  # None (pre-encoded)
            elif key == "cvss_s":
                features[key] = 0  # Unchanged (pre-encoded)
            elif key in ("cvss_c", "cvss_i", "cvss_a"):
                features[key] = 2  # High (pre-encoded)
            elif key == "epss_score":
                features[key] = 0.75
            elif key in (
                "patch_available",
                "patch_applied",
                "internet_facing",
                "domain_joined",
                "exploitdb_has_poc",
                "metasploit_has_payload",
                "is_top_25_cwe",
                "is_rce_signature",
                "is_privesc_signature",
                "is_bypass_signature",
                "is_dos_signature",
                "is_traversal_signature",
            ):
                features[key] = True
            elif key in (
                "lateral_reachability",
                "boundary_reachability",
                "downstream_assets",
                "patch_lag_days",
                "threat_intel_pulses",
                "nvd_reference_count",
                "cve_desc_tokens",
                "vulnerability_age_days",
            ):
                features[key] = 42
            elif key in (
                "vendor_popularity_index",
                "cvss_exploitability_sub",
                "cvss_impact_sub",
            ):
                features[key] = 3.14
            elif key == "data_classification":
                features[key] = "OFFICIAL"
            elif key == "mission_prevalence":
                features[key] = "Core"
            elif key == "public_wellbeing_impact":
                features[key] = "Severe"
            else:
                features[key] = i  # fallback sentinel

        arr = _build_tabular_array(features)
        assert arr.shape == (1, 35), (
            f"_build_tabular_array() returned shape {arr.shape}, expected (1, 35)"
        )

        # Verify each position through the canonical list
        row = arr[0]
        for idx, name in enumerate(TABULAR_FEATURE_ORDER):
            val = float(row[idx])
            assert not np.isnan(val), (
                f"Position {idx} ({name}) is NaN. All 35 positions must be finite."
            )

        # Spot-check: epss_score at index 8 should be 0.75
        assert abs(float(row[8]) - 0.75) < 1e-5, (
            f"Expected epss_score (index 8) ≈ 0.75, got {float(row[8])}. "
            f"Feature order may have shifted."
        )


class TestMissingValuePolicy:
    """Explicit defaults for absent features."""

    def test_cvss_cia_defaults_to_zero(self):
        """All three CIA components default to 0 when absent or malformed."""
        from ml.xgboost_predictor import _build_tabular_array

        # No CIA keys in feature dict — use pre-encoded numerics for CVSS
        features = {
            "cvss_av": 3,
            "cvss_ac": 1,
            "cvss_pr": 2,
            "cvss_ui": 1,
            "cvss_s": 0,
            "epss_score": 0.0,
        }
        arr = _build_tabular_array(features)
        row = arr[0]

        # Index 5: cvss_c, Index 6: cvss_i, Index 7: cvss_a
        for idx, name in [(5, "cvss_c"), (6, "cvss_i"), (7, "cvss_a")]:
            assert float(row[idx]) == 0.0, (
                f"{name} at index {idx} = {float(row[idx])}, expected 0.0. "
                f"Absent/malformed CIA values must default to 0, not 2."
            )

    def test_patch_available_defaults_to_false(self):
        """patch_available defaults to False when absent."""
        from ml.xgboost_predictor import _build_tabular_array

        features = {
            "cvss_av": 3,
            "cvss_ac": 1,
            "cvss_pr": 2,
            "cvss_ui": 1,
            "cvss_s": 0,
            "cvss_c": 0,
            "cvss_i": 0,
            "cvss_a": 0,
            "epss_score": 0.0,
        }
        arr = _build_tabular_array(features)
        row = arr[0]

        # Index 9: patch_available
        assert float(row[9]) == 0.0, (
            f"patch_available at index 9 = {float(row[9])}, expected 0.0. "
            f"Absent patch_available must default to False."
        )

    def test_domain_joined_defaults_to_false(self):
        """domain_joined defaults to False when absent."""
        from ml.xgboost_predictor import _build_tabular_array

        features = {
            "cvss_av": 3,
            "cvss_ac": 1,
            "cvss_pr": 2,
            "cvss_ui": 1,
            "cvss_s": 0,
            "cvss_c": 0,
            "cvss_i": 0,
            "cvss_a": 0,
            "epss_score": 0.0,
        }
        arr = _build_tabular_array(features)
        row = arr[0]

        # Index 12: domain_joined
        assert float(row[12]) == 0.0, (
            f"domain_joined at index 12 = {float(row[12])}, expected 0.0. "
            f"Absent domain_joined must default to False."
        )

    def test_cvss_cia_runtime_build_feature_vector(self):
        """Verify _cvss_cia() handles None, empty, and invalid values."""
        from ingest_helpers import _cvss_cia

        assert _cvss_cia(None) == 0, "_cvss_cia(None) should be 0"
        assert _cvss_cia("") == 0, '_cvss_cia("") should be 0'
        assert _cvss_cia("INVALID") == 0, '_cvss_cia("INVALID") should be 0'
        assert _cvss_cia("H") == 2, '_cvss_cia("H") should be 2'
        assert _cvss_cia("L") == 1, '_cvss_cia("L") should be 1'
        assert _cvss_cia("N") == 0, '_cvss_cia("N") should be 0'
        assert _cvss_cia(123) == 0, "_cvss_cia(123) should be 0 (non-string)"


class TestTrainingBuilders:
    """Training builders emit canonical width and names."""

    def test_training_builders_emit_canonical_width_and_saved_names(self, tmp_path):
        """Supply minimal synthetic corpus; assert 35 tabular columns."""
        from scripts.build_training_corpus import build_feature_vectors, save_dataset

        # Minimal NVD corpus with 10 entries
        nvd_corpus = {}
        for i in range(10):
            cve_id = f"CVE-2024-{i:04d}"
            nvd_corpus[cve_id] = {
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_v3_score": 9.0 + (i % 2) * 1.0,
                "description": f"Test vulnerability {i} with remote code execution",
                "cwe_class": "CWE-89",
                "patch_available": i % 2 == 0,
                "nvd_reference_count": i,
                "cvss_exploitability_sub": 3.9,
                "cvss_impact_sub": 5.9,
                "vulnerability_age_days": 200 + i,
                "vendor": "apache",
            }

        X_tab, cve_ids, dates, descriptions, osv_lead_days = build_feature_vectors(
            nvd_corpus, {}, {}, {}, limit=0
        )
        assert X_tab.shape[1] == 35, (
            f"build_feature_vectors produced {X_tab.shape[1]} columns, "
            f"expected 35. The tabular contract requires exactly 35 features."
        )

        # Verify saved feature_names metadata starts with canonical list
        from pipeline.config.feature_names import TABULAR_FEATURE_ORDER

        all_feature_names = list(TABULAR_FEATURE_ORDER) + [
            f"text_sbert_{i}" for i in range(384)
        ]
        output_path = str(tmp_path / "test_corpus.npz")
        save_dataset(
            np.hstack([X_tab, np.zeros((10, 384), dtype=np.float32)]),
            np.zeros(10, dtype=np.int8),
            all_feature_names,
            output_path,
            dates=dates,
            cve_ids=np.array(cve_ids),
            columns=np.array(TABULAR_FEATURE_ORDER, dtype=str),
        )

        # Verify saved file
        saved = np.load(output_path, allow_pickle=True)
        saved_tabular = list(saved["feature_names"])[:35]
        assert saved_tabular == TABULAR_FEATURE_ORDER, (
            f"Saved NPZ tabular names don't match canonical order.\n"
            f"  Saved:    {saved_tabular}\n"
            f"  Canonical: {TABULAR_FEATURE_ORDER}"
        )
        saved.close()


class TestLegacyReferenceCount:
    """Backward-compatible support for reference_count key."""

    def test_legacy_reference_count_is_supported(self):
        """Both nvd_reference_count and reference_count yield same value at index 23."""
        from ml.train_xgboost import build_tabular_features

        # Create two identical CVEs differing only in the ref-count key name
        base_cve = {
            "cve_id": "CVE-2024-TEST1",
            "description": "Test CVE",
            "cvss_score": 5.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "published_date": "2024-01-01",
            "cwe_id": "CWE-79",
            "cvss_exploitability_sub": 1.0,
            "cvss_impact_sub": 2.0,
            "epss_score": 0.05,
            "references": [],
        }

        # CVE with new key
        cve_new = dict(base_cve, nvd_reference_count=7)
        # CVE with legacy key only
        cve_legacy = dict(base_cve, reference_count=7)
        # CVE with both (new should win)
        cve_both = dict(base_cve, nvd_reference_count=7, reference_count=999)

        X = build_tabular_features([cve_new, cve_legacy, cve_both])

        # Index 23 = nvd_reference_count in TABULAR_FEATURE_ORDER
        assert X[0, 23] == 7.0, (
            f"New key nvd_reference_count should give 7.0 at index 23, got {X[0, 23]}"
        )
        assert X[1, 23] == 7.0, (
            f"Legacy key reference_count should give 7.0 at index 23, "
            f"got {X[1, 23]}. Backward compatibility for old cache is required."
        )
        assert X[2, 23] == 7.0, (
            f"When both keys present, nvd_reference_count should win at index 23, "
            f"got {X[2, 23]}"
        )
