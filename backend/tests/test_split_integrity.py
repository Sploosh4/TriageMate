"""Hermetic unit tests for the point-in-time split policy.

These tests use **synthetic data** to directly test split/filter logic.
They do NOT depend on the saved NPZ file or real CVE data — they are
fully hermetic and repeatable.

Tests call ``apply_point_in_time_split()`` from
``backend/ml/split_policy.py`` with controlled numpy arrays and
assert the returned masks have the expected properties.

All tests are currently marked ``@pytest.mark.skip`` because the
function raises ``NotImplementedError``.  When the implementation
lands, remove the skip markers to verify correctness.

See ``docs/architecture/point-in-time-label-policy.md`` (§Appendix B)
for the test plan.
"""

import numpy as np
import pytest

from ml.split_policy import apply_point_in_time_split

# ── Constants matching pipeline defaults ────────────────────────────────
DATE_END = "2024-12-31"
TRAIN_CUTOFF = "2023-06-30"
VAL_CUTOFF = "2023-12-31"


# ── Fully observed negatives ────────────────────────────────────────────


class TestFullyObservedNegative:
    """CVEs published well before DATE_END with no KEV entry.
    These should be fully observed negatives (label 0) and eligible
    for their chronological split."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_goes_to_train_split(self):
        """CVE published 1000 days before DATE_END, label 0, no KEV.
        -> fully observed negative -> eligible for training set."""
        dates = np.array(["2022-03-06"])  # ~1000d before 2024-12-31
        labels = np.array([0])
        kev_dates = np.array([""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=706,
            date_end=DATE_END,
            train_cutoff=TRAIN_CUTOFF,
            val_cutoff=VAL_CUTOFF,
        )
        assert result["is_fully_observed"][0]
        assert not result["censored_mask"][0]
        # Published before TRAIN_CUTOFF -> train set
        assert result["train_mask"][0]
        assert not result["val_mask"][0]
        assert not result["test_mask"][0]

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_goes_to_val_split(self):
        """CVE published 2023-07-15, not in KEV, with obs_window=365.
        -> fully observed negative (535d > 365d) -> eligible for val."""
        dates = np.array(["2023-07-15"])
        labels = np.array([0])
        kev_dates = np.array([""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=365,
            date_end=DATE_END,
            train_cutoff=TRAIN_CUTOFF,
            val_cutoff=VAL_CUTOFF,
        )
        # 2023-07-15 is 535 days before 2024-12-31, which exceeds 365
        assert result["is_fully_observed"][0]
        assert not result["censored_mask"][0]
        assert not result["train_mask"][0]
        assert result["val_mask"][0]
        assert not result["test_mask"][0]


# ── Censored CVEs ───────────────────────────────────────────────────────


class TestCensoredCVE:
    """CVEs published too recently to determine exploitation status.
    Must be excluded from ALL splits."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_excluded_from_all_splits(self):
        """CVE published 30 days before DATE_END, label 0, no KEV.
        -> censored -> NOT in train/val/test."""
        dates = np.array(["2024-12-01"])
        labels = np.array([0])
        kev_dates = np.array([""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=706,
            date_end=DATE_END,
            train_cutoff=TRAIN_CUTOFF,
            val_cutoff=VAL_CUTOFF,
        )
        assert result["censored_mask"][0]
        assert not result["is_fully_observed"][0]
        assert not result["train_mask"][0]
        assert not result["val_mask"][0]
        assert not result["test_mask"][0]

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_consistency_multiple_censored(self):
        """Multiple censored negatives: all excluded from all splits."""
        dates = np.array(["2024-12-01", "2024-11-01"])
        labels = np.array([0, 0])
        kev_dates = np.array(["", ""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=100,
            date_end=DATE_END,
            train_cutoff=TRAIN_CUTOFF,
            val_cutoff=VAL_CUTOFF,
        )
        assert np.sum(result["train_mask"]) == 0
        assert np.sum(result["val_mask"]) == 0
        assert np.sum(result["test_mask"]) == 0
        assert np.sum(result["censored_mask"]) == 2


# ── Recent KEV positives ────────────────────────────────────────────────


class TestRecentKEVPositive:
    """CVEs added to KEV quickly after publication.
    KEV membership is authoritative — they are never censored."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_is_not_censored_despite_recent_publication(self):
        """CVE published 30 days before DATE_END, added to KEV on day 20.
        -> fully observed positive (label 1) -> NOT censored."""
        dates = np.array(["2024-12-01"])
        labels = np.array([1])  # <= 30d from pub to KEV
        kev_dates = np.array(["2024-12-20"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=706,
            date_end=DATE_END,
            train_cutoff=TRAIN_CUTOFF,
            val_cutoff=VAL_CUTOFF,
        )
        assert result["is_fully_observed"][0]
        assert not result["censored_mask"][0]
        # After VAL_CUTOFF -> test set
        assert result["test_mask"][0]


# ── Split distribution ──────────────────────────────────────────────────


class TestSplitDistribution:
    """Mixed synthetic datasets produce representative splits
    containing both positive and negative examples."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_train_has_both_classes(self):
        """Training set contains both label-0 and label-1+ examples."""
        dates = np.array(
            [
                "2022-01-01",
                "2022-06-15",
                "2022-03-01",
                "2022-09-01",
            ]
        )
        labels = np.array([0, 2, 0, 3])
        kev_dates = np.array(["", "2022-09-01", "", "2023-01-01"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=365,
            date_end=DATE_END,
        )
        train_labels = labels[result["train_mask"]]
        assert np.any(train_labels == 0), "Train must have label-0 examples"
        assert np.any(train_labels > 0), "Train must have label-1+ examples"

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_val_has_both_classes(self):
        """Validation set contains both label-0 and label-1+ examples."""
        dates = np.array(
            [
                "2023-07-01",
                "2023-09-15",
                "2023-08-01",
                "2023-11-01",
            ]
        )
        labels = np.array([0, 2, 0, 3])
        kev_dates = np.array(["", "2023-10-01", "", "2024-01-01"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=365,
            date_end=DATE_END,
        )
        val_labels = labels[result["val_mask"]]
        assert np.any(val_labels == 0), "Val must have label-0 examples"
        assert np.any(val_labels > 0), "Val must have label-1+ examples"

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_test_has_both_classes(self):
        """Test set contains both label-0 and label-1+ examples."""
        dates = np.array(
            [
                "2024-01-01",
                "2024-03-15",
                "2024-02-01",
                "2024-06-01",
            ]
        )
        labels = np.array([0, 1, 0, 2])
        kev_dates = np.array(["", "2024-03-20", "", "2024-07-01"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=200,  # allows fully observed 2024 negatives
            date_end=DATE_END,
        )
        test_labels = labels[result["test_mask"]]
        assert np.any(test_labels == 0), "Test must have label-0 examples"
        assert np.any(test_labels > 0), "Test must have label-1+ examples"


# ── Censored cohort separation ──────────────────────────────────────────


class TestCensoredCohort:
    """Censored CVEs are tracked separately from primary splits."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_separate_from_primary_splits(self):
        """Censored CVEs are NOT in train/val/test masks but ARE in
        censored mask.  Fully observed CVEs are in their split."""
        dates = np.array(
            [
                "2022-01-01",  # old non-KEV -> fully observed negative
                "2024-12-01",  # recent non-KEV -> censored
                "2024-11-15",  # recent KEV positive -> fully observed
            ]
        )
        labels = np.array([0, 0, 1])
        kev_dates = np.array(["", "", "2024-11-25"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=365,
            date_end=DATE_END,
        )
        # Censored mask has only the recent non-KEV (index 1)
        assert result["censored_mask"][0] is False
        assert result["censored_mask"][1] is True
        assert result["censored_mask"][2] is False
        # Censored CVE is NOT in any primary split mask
        assert not result["train_mask"][1]
        assert not result["val_mask"][1]
        assert not result["test_mask"][1]

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_censored_count_matches_expected(self):
        """With controlled input, count censored examples correctly."""
        dates = np.array(
            [
                "2022-01-01",  # fully observed (> 365d before DATE_END)
                "2024-11-15",  # censored (< 365d before DATE_END, no KEV)
                "2024-12-01",  # censored
                "2024-10-01",  # KEV positive -> fully observed
            ]
        )
        labels = np.array([0, 0, 0, 1])
        kev_dates = np.array(["", "", "", "2024-10-15"])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=365,
            date_end=DATE_END,
        )
        assert np.sum(result["censored_mask"]) == 2  # indices 1 and 2
        assert np.sum(result["is_fully_observed"]) == 2  # indices 0 and 3


# ── Uniform eligibility across splits ───────────────────────────────────


class TestConsistencyAcrossSplits:
    """The same eligibility rules apply to all splits.
    This is the key architectural requirement (R1)."""

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_censored_excluded_everywhere(self):
        """A censored negative is excluded from ALL splits, not just
        training (as the rejected v1 design proposed)."""
        dates = np.array(["2024-12-01", "2024-11-01"])
        labels = np.array([0, 0])
        kev_dates = np.array(["", ""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=100,
            date_end=DATE_END,
        )
        # Zero entries in train/val/test
        assert np.sum(result["train_mask"]) == 0
        assert np.sum(result["val_mask"]) == 0
        assert np.sum(result["test_mask"]) == 0
        # Both are correctly identified as censored
        assert np.sum(result["censored_mask"]) == 2

    @pytest.mark.skip(reason="Split policy not yet implemented")
    def test_fully_observed_goes_to_correct_split(self):
        """An old negative is eligible for its chronological split.
        It is NOT treated differently based on which split it falls in."""
        dates = np.array(["2023-07-15"])  # val period
        labels = np.array([0])
        kev_dates = np.array([""])
        result = apply_point_in_time_split(
            dates,
            labels,
            kev_dates,
            obs_window_days=500,
            date_end=DATE_END,
        )
        assert not result["censored_mask"][0]
        assert result["is_fully_observed"][0]
        assert result["val_mask"][0]
