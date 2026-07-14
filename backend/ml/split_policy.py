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

    The chronological split (train/val/test) is computed FIRST based on
    publication dates, then the observation-window eligibility filter is
    applied uniformly to ALL splits.  This ensures that censored negatives
    are removed from every split identically, preventing degenerate
    val/test sets that would otherwise be 100% positive.

    Every CVE is classified into exactly one of three categories:

    - **Fully observed positive** (label 1-4):
      In KEV with dateAdded <= date_end.  KEV membership is authoritative,
      so the exploitation event is confirmed regardless of when the CVE
      was published.  Always eligible for train/val/test.

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

    The eligibility filter is applied **identically** to all splits.
    This is the key difference from the rejected v1 design (which
    filtered only the training split).

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
            True for censored CVEs (excluded from all three splits
            above).
        is_fully_observed : np.ndarray[bool]
            True for CVEs with reliable, known labels (all positives +
            fully observed negatives).  Equivalent to ``~censored_mask``.

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

    # 2. Chronological split FIRST (before any eligibility filtering)
    train_mask = dates <= train_cutoff
    val_mask = (dates > train_cutoff) & (dates <= val_cutoff)
    test_mask = dates > val_cutoff

    # 3. Eligibility filter: censored = label-0 AND published within obs window
    # KEV positives (labels 1-4) are always fully observed regardless of publication date.
    # Only label-0 CVEs that are too recent are considered censored.
    too_recent = dates > obs_cutoff_str
    is_positive = labels > 0
    is_fully_observed_negative = ~too_recent & ~is_positive
    is_censored = too_recent & ~is_positive

    # 4. Eligible = all positives + fully observed negatives
    eligible_mask = is_positive | is_fully_observed_negative

    # 5. Censored CVEs are removed from ALL splits uniformly
    train_mask = train_mask & eligible_mask
    val_mask = val_mask & eligible_mask
    test_mask = test_mask & eligible_mask

    # 6. Verify masks are mutually exclusive
    combined = (
        train_mask.astype(int)
        + val_mask.astype(int)
        + test_mask.astype(int)
        + is_censored.astype(int)
    )
    assert np.all(combined <= 1), "Split masks overlap!"

    return {
        "train_mask": train_mask,
        "val_mask": val_mask,
        "test_mask": test_mask,
        "censored_mask": is_censored,
        "is_fully_observed": eligible_mask,
    }
