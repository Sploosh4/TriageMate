# Point-in-Time Label and Primary-Cohort Policy

**Date:** 2026-07-14
**Status:** IMPLEMENTED in PR #68 and validated by the post-policy gather and ML Gate A

## Problem

With `DATE_END` fixed at 2024-12-31, a non-KEV CVE needs sufficient follow-up
before it can be treated as a reliable negative. The observed median KEV lag is
706 days, producing an observation cutoff of 2023-01-25.

The earlier gather filtered recent negatives before using fixed 2023-H2 and
2024 holdouts. It therefore produced validation and test sets containing only
positives. Those sets could not support trustworthy evaluation metrics.

## Label semantics

`construct_labels()` remains unchanged. Labels 1–4 describe how recently a
CVE was added to KEV relative to `DATE_END`; they do not represent the time
from publication to exploitation. A publication-to-KEV label redesign is a
separate future decision.

## Implemented cohort policy

The gather first establishes an observation cutoff:

```text
observation_cutoff = DATE_END - observed_KEV_lag
```

- **Primary cohort:** records published on or before the observation cutoff.
  Only this mature cohort is used for training, validation, test metrics,
  calibration, and thresholds.
- **Prospective cohort:** records published after the cutoff. These are
  reported separately and excluded from primary metrics.
- **Censored negative:** a prospective label-0 record whose outcome is not yet
  sufficiently observed.

Both recent positives and recent negatives remain outside the primary cohort,
which preserves comparable eligibility across classes.

The mature primary cohort is then split chronologically:

| Cohort | Dates | Purpose |
|---|---|---|
| Train | 2019-01-01 through 2020-12-31 | Fit model and preprocessing only |
| Validation | 2021-01-01 through 2021-12-31 | Tune operating thresholds |
| Test | 2022-01-01 through the observation cutoff | Final primary evaluation |
| Prospective | After the observation cutoff | Follow-up only; no primary metrics |

## Post-policy evidence

The fresh gather completed on 14 July 2026 and Gate A passed:

| Cohort | Records | KEV positive | KEV rate |
|---|---:|---:|---:|
| Train | 69,223 | 641 | 0.93% |
| Validation | 20,144 | 200 | 0.99% |
| Test | 26,766 | 132 | 0.49% |

The primary cohort contains 116,133 records and 973 positives. The prospective
cohort contains 144,503 records, including 144,237 censored negatives. The
versioned evidence and artifact/schema fingerprints are recorded in
`backend/reports/investigations/ml-gate-a-2026-07-14.json`.

## Training boundary

Gate A establishes that the gathered artifact and split evidence are coherent;
it does not authorize model training. A baseline `--train` run remains a
separate, explicit user decision under Gate B. No baseline training was run as
part of this policy correction or repository cleanup.

## References

- `backend/ml/split_policy.py`
- `backend/ml/train_xgboost.py`
- `backend/tests/test_split_integrity.py`
- `docs/reference/ml-retraining-gate.md`
- GitHub PR #68
