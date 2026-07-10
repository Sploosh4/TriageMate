"""
Tests for NPZ column metadata in training_data.npz.

Verifies that the NPZ file saved by save_training_data() / phase_gather()
contains proper feature_names metadata that matches the X matrix dimensions.
"""

from pathlib import Path

import numpy as np
import pytest

from pipeline.config.feature_names import TABULAR_FEATURE_ORDER

NPZ_PATH = Path(__file__).resolve().parent.parent / "ml" / "training_data.npz"


def _load_npz():
    """Load training_data.npz, skip if not present."""
    if not NPZ_PATH.exists():
        pytest.skip(f"{NPZ_PATH} not found — run training gather first")
    return np.load(NPZ_PATH, allow_pickle=True)


def test_npz_training_has_feature_names():
    """feature_names key exists in training_data.npz."""
    data = _load_npz()
    assert "feature_names" in data, "feature_names key missing from training_data.npz"
    data.close()


def test_npz_feature_names_match_dims():
    """len(feature_names) == X.shape[1] (419)."""
    data = _load_npz()
    fnames = data["feature_names"]
    n_cols = data["X"].shape[1]
    assert len(fnames) == n_cols, (
        f"feature_names length ({len(fnames)}) != X columns ({n_cols})"
    )
    data.close()


def test_npz_tabular_names_are_correct():
    """First 35 feature names match TABULAR_FEATURE_ORDER."""
    data = _load_npz()
    fnames = data["feature_names"]
    tabular = fnames[:35]
    for i, (expected, actual) in enumerate(zip(TABULAR_FEATURE_ORDER, tabular)):
        assert expected == actual, (
            f"Mismatch at position {i}: expected '{expected}', got '{actual}'"
        )
    data.close()


def test_npz_sbert_names_are_correct():
    """Remaining 384 feature names follow sbert_0 through sbert_383 pattern."""
    data = _load_npz()
    fnames = data["feature_names"]
    sbert_part = fnames[35:]
    assert len(sbert_part) == 384, f"Expected 384 SBERT names, got {len(sbert_part)}"
    for i in range(384):
        expected = f"sbert_{i}"
        assert sbert_part[i] == expected, (
            f"Mismatch at SBERT position {i}: expected '{expected}', got '{sbert_part[i]}'"
        )
    data.close()


def test_npz_backward_compatible():
    """Old code still loads X, y, dates, and cve_ids without error."""
    data = _load_npz()
    X = data["X"]
    y = data["y"]
    dates = data["dates"]
    cve_ids = data["cve_ids"]
    assert X.shape[0] == y.shape[0], "X and y row count mismatch"
    assert X.shape[0] == dates.shape[0], "X and dates row count mismatch"
    assert X.shape[0] == cve_ids.shape[0], "X and cve_ids row count mismatch"
    data.close()
