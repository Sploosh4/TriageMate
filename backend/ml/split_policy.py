"""
Point-in-time split policy for training/validation/test splits.

This module defines the split policy that ensures:
- Consistent eligibility rules across all splits (train, val, test).
- No future-information leakage in label construction.
- Three-way label distinction: fully observed positive, fully observed negative,
  censored (unknown).
- Representative val/test with only fully observed examples.
- Separate censored cohort reporting.

The policy implements the revised design from
docs/architecture/point-in-time-label-policy.md (v2).
"""

import numpy as np
from datetime import datetime, timedelta


def apply_point_in_time_split(
    dates: np.ndarray,
    labels: np.ndarray,
    kev_dates: np.ndarray,
    obs_window_days: int = 706,
    date_end: str = "2024-12-31",
    train_cutoff: str = "2023-06-30",
    val_cutoff: str = "2023-12-31",
) -> dict[str, np.ndarray]:
    """Apply point-in-time label policy and chronological split.

    The primary cohorts end at the observation cutoff.  This prevents recent
    positives from forming a test-only cohort after recent negatives have
    been censored.  Records newer than that cutoff are a separate prospective
    cohort, not primary training or evaluation data.

    Every CVE is classified into exactly one of three categories:

    - **Fully observed positive** (label 1-4):
      In KEV with dateAdded <= date_end.  KEV membership is authoritative,
      so the exploitation event is confirmed.  It is usable in primary
      cohorts only when published on or before the observation cutoff.

    - **Fully observed negative** (label 0):
      NOT in KEV, AND published at least ``obs_window_days`` before
      ``date_end``.  Enough time has passed that non-exploitation can be
      inferred with confidence.  Eligible for train/val/test based on
      publication date.

    - **Censored (unknown)**:
      NOT in KEV, AND published fewer than ``obs_window_days`` before
      ``date_end``.  Too recent to know whether exploitation will be
      catalogued.  **Excluded** from all train/val/test splits.
      Reported separately as a prospective cohort.

    The same observation cutoff applies to every label and every primary
    split.  This prevents a class-imbalanced recent holdout.

    Parameters
    ----------
    dates : np.ndarray
        Publication dates as strings (``YYYY-MM-DD``).
    labels : np.ndarray
        Multi-window KEV labels (0-4).  Labels > 0 indicate KEV membership.
        0 indicates not in KEV as of date_end.  Labels are recency-based
        (days from KEV addition to date_end) per the current ``construct_labels()``
        implementation.
    kev_dates : np.ndarray
        KEV addition dates as strings (``YYYY-MM-DD``), empty string if
        not in KEV.  (Used only for interface compatibility; ``labels``
        is the authoritative source for KEV membership.)
    obs_window_days : int
        Observation window in days.  A non-KEV CVE must be published at
        least this many days before ``date_end`` to be considered a fully
        observed negative.
    date_end : str
        Reference date for point-in-time labeling (``YYYY-MM-DD``).
    train_cutoff : str
        Split boundary: CVEs with ``dates <= train_cutoff`` go to the
        training set.
    val_cutoff : str
        Split boundary: CVEs with ``train_cutoff < dates <= val_cutoff``
        go to the validation set.  CVEs with ``dates > val_cutoff`` go
        to the test set.

    Returns
    -------
    dict with keys:
        train_mask : np.ndarray[bool]
            True for CVEs assigned to the training set.
        val_mask : np.ndarray[bool]
            True for CVEs assigned to the validation set.
        test_mask : np.ndarray[bool]
            True for CVEs assigned to the test set.
        censored_mask : np.ndarray[bool]
            True for recent label-0 CVEs whose negative label is unknown.
        is_fully_observed : np.ndarray[bool]
            True for CVEs with reliable, known labels (all positives +
            fully observed negatives).  Equivalent to ``~censored_mask``.
        primary_mask : np.ndarray[bool]
            True for fully observed records eligible for primary
            train/validation/test metrics.
        prospective_mask : np.ndarray[bool]
            True for records newer than the observation cutoff.  Includes
            both censored negatives and confirmed positives, and is excluded
            from primary metrics.

    Notes
    -----
    The four primary masks (train, val, test, censored) are mutually
    exclusive and exhaustive.  ``is_fully_observed`` is a convenience
    alias for the union of train/val/test.
    """
    # 1. Parse reference date and compute observation cutoff
    date_end_dt = datetime.strptime(date_end, "%Y-%m-%d")
    obs_cutoff_dt = date_end_dt - timedelta(days=obs_window_days)
    obs_cutoff_str = obs_cutoff_dt.strftime("%Y-%m-%d")

    # 2. A primary cohort must end at the observation cutoff.  Otherwise all
    # recent negatives are censored while recent positives remain, producing
    # the same degenerate test distribution under a different code path.
    is_primary_period = dates <= obs_cutoff_str

    # 3. Censored = label-0 AND published within observation window.
    # KEV positives (labels 1-4) are always fully observed regardless of publication date.
    # Only label-0 CVEs that are too recent are considered censored.
    too_recent = dates > obs_cutoff_str
    is_positive = labels > 0
    is_fully_observed_negative = ~too_recent & ~is_positive
    is_censored = too_recent & ~is_positive

    is_fully_observed = is_positive | is_fully_observed_negative
    primary_mask = is_primary_period & is_fully_observed
    prospective_mask = ~is_primary_period

    # 4. Chronological split of primary-only records.
    train_mask = primary_mask & (dates <= train_cutoff)
    val_mask = primary_mask & (dates > train_cutoff) & (dates <= val_cutoff)
    test_mask = primary_mask & (dates > val_cutoff)

    # 6. Verify masks are mutually exclusive
    combined = (
        train_mask.astype(int)
        + val_mask.astype(int)
        + test_mask.astype(int)
        + prospective_mask.astype(int)
    )
    assert np.all(combined <= 1), "Split masks overlap!"

    return {
        "train_mask": train_mask,
        "val_mask": val_mask,
        "test_mask": test_mask,
        "censored_mask": is_censored,
        "is_fully_observed": is_fully_observed,
        "primary_mask": primary_mask,
        "prospective_mask": prospective_mask,
    }
