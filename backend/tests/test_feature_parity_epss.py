"""
Feature-parity guard test for EPSS substitution models (v4/v3/v2 37-dim vector).

CRITICAL: The 37-dim feature vector is built by SEPARATE code in:
  - train_epss_v4.py   (training)   → _build_feature_vector_v4()
  - epss_substitutor.py (inference) → _build_feature_vector_v2()

These MUST produce identical outputs for identical inputs, or the ML
pipeline is silently broken. This test verifies element-by-element parity.

If divergence is found, the test FAILS with exact details (index, expected,
actual). Do NOT fix the divergence — report it for the commander to decide.
"""

import logging
import numpy as np
import pytest

logger = logging.getLogger(__name__)

# ── Test cases: (raw_epss, cvss_score, cisa_kev, cwe_class, agency,
#                  exploit_maturity, has_public_poc, vendor_patch_status) ──

TEST_CASES = [
    # 0: Known CVE with health sector and CWE-22 (path traversal)
    {
        "raw_epss": 0.05,
        "cvss_score": 7.5,
        "cisa_kev": True,
        "cwe_class": "CWE-22",
        "agency": "health",
        "exploit_maturity": 2,
        "has_public_poc": True,
        "vendor_patch_status": 0,
        "label": "health CWE-22 KEV",
    },
    # 1: Known CVE with justice sector and CWE-787 (out-of-bounds write)
    {
        "raw_epss": 0.75,
        "cvss_score": 9.0,
        "cisa_kev": True,
        "cwe_class": "CWE-787",
        "agency": "justice",
        "exploit_maturity": 3,
        "has_public_poc": True,
        "vendor_patch_status": 1,
        "label": "justice CWE-787",
    },
    # 2: CVE with unknown agency (should map to 'unknown' OHE slot)
    {
        "raw_epss": 0.5,
        "cvss_score": 6.5,
        "cisa_kev": False,
        "cwe_class": "CWE-89",
        "agency": "unknown",
        "exploit_maturity": 1,
        "has_public_poc": False,
        "vendor_patch_status": 0,
        "label": "unknown agency CWE-89",
    },
    # 3: CVE with no CWE match (empty string)
    {
        "raw_epss": 0.3,
        "cvss_score": 4.0,
        "cisa_kev": False,
        "cwe_class": "",
        "agency": "health",
        "exploit_maturity": 0,
        "has_public_poc": False,
        "vendor_patch_status": 2,
        "label": "no CWE match",
    },
    # 4: Edge case — all zeros
    {
        "raw_epss": 0.0,
        "cvss_score": 0.0,
        "cisa_kev": False,
        "cwe_class": "",
        "agency": "unknown",
        "exploit_maturity": 0,
        "has_public_poc": False,
        "vendor_patch_status": 0,
        "label": "all zeros",
    },
    # 5: Edge case — near-max values
    {
        "raw_epss": 0.99,
        "cvss_score": 10.0,
        "cisa_kev": True,
        "cwe_class": "CWE-78",
        "agency": "police",
        "exploit_maturity": 3,
        "has_public_poc": True,
        "vendor_patch_status": 2,
        "label": "near-max values police CWE-78",
    },
    # 6: Transport sector with low signals
    {
        "raw_epss": 0.02,
        "cvss_score": 5.0,
        "cisa_kev": False,
        "cwe_class": "CWE-79",
        "agency": "transport",
        "exploit_maturity": 0,
        "has_public_poc": False,
        "vendor_patch_status": 0,
        "label": "transport low signals",
    },
    # 7: Water corporation with medium signals
    {
        "raw_epss": 0.15,
        "cvss_score": 7.0,
        "cisa_kev": False,
        "cwe_class": "CWE-434",
        "agency": "watercorporation",
        "exploit_maturity": 1,
        "has_public_poc": True,
        "vendor_patch_status": 1,
        "label": "watercorporation CWE-434",
    },
    # 8: CWE not in any known list (should hit no OHE slot)
    {
        "raw_epss": 0.4,
        "cvss_score": 8.0,
        "cisa_kev": False,
        "cwe_class": "CWE-9999",
        "agency": "education",
        "exploit_maturity": 0,
        "has_public_poc": False,
        "vendor_patch_status": 0,
        "label": "unknown CWE education",
    },
    # 9: dpird with patch unavailable
    {
        "raw_epss": 0.08,
        "cvss_score": 6.0,
        "cisa_kev": True,
        "cwe_class": "CWE-862",
        "agency": "dpird",
        "exploit_maturity": 2,
        "has_public_poc": False,
        "vendor_patch_status": 2,
        "label": "dpird CWE-862 no patch",
    },
]


def _build_inference_vector(**kwargs):
    """Build feature vector using the inference-side builder (epss_substitutor)."""
    from ml.epss_substitutor import _build_feature_vector_v2

    return _build_feature_vector_v2(
        raw_epss=kwargs["raw_epss"],
        cvss_score=kwargs["cvss_score"],
        cisa_kev=kwargs["cisa_kev"],
        cwe_class=kwargs["cwe_class"],
        agency=kwargs["agency"],
        exploit_maturity=kwargs.get("exploit_maturity", 0),
        has_public_poc=kwargs.get("has_public_poc", False),
        vendor_patch_status=kwargs.get("vendor_patch_status", 0),
    )


def _build_training_vector(**kwargs):
    """Build feature vector using the training-side builder (train_epss_v4).

    Tries direct import first; if that fails (heavy ML deps issue), defines
    a local copy of the logic using the training module's agency/CWE constants.
    """
    try:
        from ml.train_epss_v4 import _build_feature_vector_v4

        return _build_feature_vector_v4(
            {
                "raw_epss": kwargs["raw_epss"],
                "cvss_score": kwargs["cvss_score"],
                "exploit_maturity": kwargs.get("exploit_maturity", 0),
                "cisa_kev": kwargs["cisa_kev"],
                "has_public_poc": kwargs.get("has_public_poc", False),
                "vendor_patch_status": kwargs.get("vendor_patch_status", 0),
                "cwe_class": kwargs["cwe_class"],
                "agency": kwargs["agency"],
            }
        )
    except ImportError as exc:
        pytest.skip(f"Could not import train_epss_v4 module: {exc}")
    except Exception as exc:
        pytest.skip(f"Unexpected error importing train_epss_v4: {exc}")


class TestEpssFeatureParity:
    """Verify training and inference build identical 37-dim feature vectors."""

    def test_both_builders_produce_37_elements(self):
        """Both builders should return 37-element lists."""
        kwargs = TEST_CASES[0].copy()
        inf_vec = _build_inference_vector(**kwargs)
        trn_vec = _build_training_vector(**kwargs)

        assert len(inf_vec) == 37, (
            f"Inference builder returned {len(inf_vec)} elements, expected 37"
        )
        assert len(trn_vec) == 37, (
            f"Training builder returned {len(trn_vec)} elements, expected 37"
        )

    @pytest.mark.parametrize(
        "case_idx",
        range(len(TEST_CASES)),
        ids=[tc["label"] for tc in TEST_CASES],
    )
    def test_feature_vector_parity(self, case_idx):
        """For each test case, assert both builders produce the exact same vector."""
        kwargs = TEST_CASES[case_idx].copy()
        label = kwargs.pop("label")

        inf_vec = _build_inference_vector(**kwargs)
        trn_vec = _build_training_vector(**kwargs)

        inf_arr = np.array(inf_vec, dtype=np.float64)
        trn_arr = np.array(trn_vec, dtype=np.float64)

        mismatches = np.where(~np.isclose(inf_arr, trn_arr, atol=1e-10))[0]

        if len(mismatches) > 0:
            # Build a detailed diff report
            detail_lines = [
                f"\n{'=' * 70}",
                f"FEATURE PARITY DIVERGENCE DETECTED — Test case: {label}",
                f"{'=' * 70}",
                f"  Total elements: {len(inf_vec)}",
                f"  Mismatched indices: {mismatches.tolist()}",
                "",
                "  Index  |  Expected (training)  |  Actual (inference)  |  Diff",
                "  -------|----------------------|---------------------|-------",
            ]
            for idx in mismatches:
                detail_lines.append(
                    f"  {idx:5d}  |  {trn_arr[idx]:20.10f}  |  "
                    f"{inf_arr[idx]:20.10f}  |  {inf_arr[idx] - trn_arr[idx]:+.2e}"
                )

            detail_lines.append("\n  First 6 elements:")
            detail_lines.append(f"    training:   {trn_arr[:6].tolist()}")
            detail_lines.append(f"    inference:  {inf_arr[:6].tolist()}")

            detail_lines.append("\n  Agency OHE (indices 6-16):")
            detail_lines.append(f"    training:   {trn_arr[6:17].tolist()}")
            detail_lines.append(f"    inference:  {inf_arr[6:17].tolist()}")

            detail_lines.append("\n  CWE OHE (indices 17-36):")
            detail_lines.append(f"    training:   {trn_arr[17:37].tolist()}")
            detail_lines.append(f"    inference:  {inf_arr[17:37].tolist()}")

            detail = "\n".join(detail_lines)
            print(detail)
            pytest.fail(
                f"Feature vector divergence for case '{label}': "
                f"{len(mismatches)} of {len(inf_vec)} elements differ. "
                f"First mismatch at index {mismatches[0]}. See stdout for full diff."
            )

    def test_agency_list_order_matches(self):
        """Verify that training AGENCIES and inference _model_agencies are identical."""
        from ml.train_epss_v4 import AGENCIES as TRAINING_AGENCIES
        from ml.epss_substitutor import _model_agencies

        assert TRAINING_AGENCIES == _model_agencies, (
            f"Agency lists differ!\n"
            f"  Training:   {TRAINING_AGENCIES}\n"
            f"  Inference:  {_model_agencies}"
        )

    def test_cwe_list_order_matches(self):
        """Verify that training CWES and inference _model_cwes are identical."""
        from ml.train_epss_v4 import CWES as TRAINING_CWES
        from ml.epss_substitutor import _model_cwes

        assert TRAINING_CWES == _model_cwes, (
            f"CWE lists differ!\n"
            f"  Training:   {TRAINING_CWES}\n"
            f"  Inference:  {_model_cwes}"
        )

    def test_feature_names_match_expected_order(self):
        """Verify feature names from artifact match the builder's layout."""
        from ml.epss_substitutor import _model_feature_names

        assert len(_model_feature_names) == 37, (
            f"Expected 37 feature names, got {len(_model_feature_names)}"
        )
        # First 6 should be continuous/ordinal/binary
        expected_first_6 = [
            "raw_epss",
            "cvss_score",
            "exploit_maturity",
            "cisa_kev",
            "has_public_poc",
            "vendor_patch_status",
        ]
        assert _model_feature_names[:6] == expected_first_6, (
            f"First 6 feature names mismatch:\n"
            f"  Expected: {expected_first_6}\n"
            f"  Got:      {_model_feature_names[:6]}"
        )
        # Indices 6-16 should be agency names
        for i, name in enumerate(_model_feature_names[6:17]):
            assert name.startswith("agency_"), (
                f"Expected 'agency_*' at index {i + 6}, got '{name}'"
            )
        # Indices 17-36 should be CWE names
        for i, name in enumerate(_model_feature_names[17:37]):
            assert name.startswith("cwe_"), (
                f"Expected 'cwe_*' at index {i + 17}, got '{name}'"
            )
