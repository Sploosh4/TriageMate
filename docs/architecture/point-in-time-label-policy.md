# Point-in-Time Label and Primary-Cohort Policy

**Status:** Proposed correction — requires review before a fresh gather

## Problem

`DATE_END` is fixed at 2024-12-31. A non-KEV CVE needs an observation
window before it can be treated as a reliable negative. The observed median
KEV lag is about 706 days, so records published after 2023-01-25 have not had
enough time to mature.

The previous Sprint 29 implementation applied this rule uniformly, but kept
the old 2023-H2 validation and 2024 test boundaries. That leaves recent KEV
positives eligible while censoring every recent negative, producing the same
positive-only holdout in a different form.

## Current Labels

`construct_labels()` remains unchanged. Labels 1–4 describe how recently a
CVE was added to KEV relative to `DATE_END`; they do **not** describe the time
from publication to exploitation. A publication-to-KEV label redesign is a
separate future task and must not be mixed with this split correction.

## Corrected Policy

The observation cutoff is:

```
observation_cutoff = DATE_END - observed_KEV_lag
```

For the current data this is approximately 2023-01-25.

- **Primary cohort:** every record published on or before the observation
  cutoff. It is the only data used for training, validation, test metrics,
  calibration, and thresholds.
- **Prospective cohort:** every record published after the cutoff, including
  confirmed positives and censored negatives. It is reported separately and
  excluded from primary metrics.
- **Censored negative:** a prospective label-0 record. Its outcome is not
  sufficiently observed.

Restricting *both* recent positives and recent negatives to the prospective
cohort is necessary for comparable primary class distributions.

## Primary Split Boundaries

With `DATE_START=2019-01-01`, `DATE_END=2024-12-31`, and a 706-day window,
the primary chronological cohorts are:

| Cohort | Dates | Purpose |
|---|---|---|
| Train | 2019-01-01 through 2020-12-31 | Fit model and preprocessing only. |
| Validation | 2021-01-01 through 2021-12-31 | Tune operating thresholds. |
| Test | 2022-01-01 through the observation cutoff | Final primary evaluation. |
| Prospective | After the observation cutoff | Operational follow-up only; no primary metrics. |

This deliberately prefers an older, fully observed holdout to a newer but
invalid one. It is the only way to preserve a strict 706-day observation
window without advancing the fixed KEV snapshot.

## Acceptance Criteria for a Fresh Gather

The gather must print non-zero positive and negative counts for each primary
train, validation, and test cohort. It must also print prospective and
censored counts separately. A gather must fail before saving training data if
any primary cohort has zero records, zero positives, or zero negatives.

Do not run `--train` until the gathered primary cohorts and baseline metrics
have been reviewed.

## Future Options

To evaluate newer periods, use one of these deliberate changes rather than
silently shortening the window:

1. Advance `DATE_END` using a versioned, verified KEV snapshot and choose
   mature primary boundaries; or
2. Create a separately labelled provisional/early-warning evaluation report.

Neither option is part of this correction.
