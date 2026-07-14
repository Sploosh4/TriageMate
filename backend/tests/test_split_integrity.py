"""Hermetic contract tests for mature point-in-time primary cohorts."""

import numpy as np

from ml.split_policy import apply_point_in_time_split


DATE_END = "2024-12-31"
TRAIN_CUTOFF = "2020-12-31"
VAL_CUTOFF = "2021-12-31"
OBS_WINDOW = 706  # Observation cutoff: 2023-01-25


def _split(dates, labels):
    return apply_point_in_time_split(
        np.array(dates),
        np.array(labels),
        np.array([""] * len(dates)),
        obs_window_days=OBS_WINDOW,
        date_end=DATE_END,
        train_cutoff=TRAIN_CUTOFF,
        val_cutoff=VAL_CUTOFF,
    )


def test_primary_cohorts_have_mature_positive_and_negative_examples():
    """The 706-day policy keeps all primary cohorts class-representative."""
    dates = [
        "2020-01-01",
        "2020-06-01",  # train negative, positive
        "2021-01-01",
        "2021-06-01",  # val negative, positive
        "2022-01-01",
        "2022-06-01",  # test negative, positive
        "2024-01-01",
        "2024-02-01",  # prospective negative, positive
    ]
    labels = [0, 4, 0, 4, 0, 4, 0, 4]

    result = _split(dates, labels)

    for name in ("train_mask", "val_mask", "test_mask"):
        split_labels = np.array(labels)[result[name]]
        assert np.any(split_labels == 0), f"{name} needs a negative"
        assert np.any(split_labels > 0), f"{name} needs a positive"


def test_recent_positive_is_prospective_not_primary_test_data():
    """Confirmed recent positives cannot create a positive-only test cohort."""
    result = _split(["2024-02-01"], [1])

    assert result["is_fully_observed"][0]
    assert not result["censored_mask"][0]
    assert result["prospective_mask"][0]
    assert not result["test_mask"][0]


def test_recent_negative_is_censored_and_prospective():
    """A recent non-KEV CVE is excluded from every primary cohort."""
    result = _split(["2024-02-01"], [0])

    assert result["censored_mask"][0]
    assert result["prospective_mask"][0]
    assert not result["is_fully_observed"][0]
    assert not any(result[name][0] for name in ("train_mask", "val_mask", "test_mask"))


def test_mature_negative_goes_to_its_chronological_primary_split():
    result = _split(["2021-06-01"], [0])

    assert result["is_fully_observed"][0]
    assert result["primary_mask"][0]
    assert result["val_mask"][0]


def test_masks_are_disjoint_and_exhaustive_between_primary_and_prospective():
    result = _split(
        ["2020-01-01", "2021-01-01", "2022-01-01", "2024-01-01"],
        [0, 4, 0, 1],
    )

    combined = sum(
        result[name].astype(int)
        for name in ("train_mask", "val_mask", "test_mask", "prospective_mask")
    )
    assert np.all(combined == 1)


def test_current_previously_degenerate_boundaries_are_rejected_by_contract():
    """Document why 2023-H2/2024 cannot be the primary holdout at 706 days."""
    result = apply_point_in_time_split(
        np.array(["2023-07-01", "2023-11-01", "2024-03-01"]),
        np.array([0, 4, 0]),
        np.array(["", "", ""]),
        obs_window_days=OBS_WINDOW,
        date_end=DATE_END,
        train_cutoff="2023-06-30",
        val_cutoff="2023-12-31",
    )

    assert not np.any(result["val_mask"])
    assert not np.any(result["test_mask"])
    assert np.all(result["prospective_mask"])
