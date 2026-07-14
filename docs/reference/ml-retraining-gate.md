# ML Retraining Gates — Process Description

This document describes the three gates that govern ML retraining in
TriageMate. Each gate must pass before the next phase begins.

## Gate A: Gather Evidence and Integrity

After a `--gather` has finished, run:

```bash
just ml-gate-a <npz-path> <gather-log-path> <output-json-path>
```

This command reads the saved NPZ and the matching gather log, reports the
primary, prospective, censored, and split statistics, and writes a
reproducible JSON evidence record.

It also validates all required NPZ arrays, row alignment, feature-name width,
artifact SHA-256, and agreement between NPZ row/label counts and the gather
log. Gate A does not invent cohort-size or prevalence thresholds.

**Gate A failure conditions:**

- Missing or corrupt inputs (NPZ or gather log)
- Required evidence lines absent from the gather log:
  - Observation window value
  - Primary / prospective / censored cohort counts
  - Train / validation / test record counts and KEV-positive distributions
  - Final positive rate
- Any split is single-class (all records in a split are KEV-positive or
  all are KEV-negative)

The reviewer evaluates prevalence and cohort-size thresholds after examining
this first post-policy evidence. No thresholds are predefined.

**Script:** `backend/scripts/ml_gate_a_check.py`

The first post-policy gather passed Gate A on 14 July 2026. Its versioned
evidence is `backend/reports/investigations/ml-gate-a-2026-07-14.json`.

## Gate B: Baseline Metrics

After Gate A passes and the reviewer approves its evidence:

1. Review the per-split class distributions from the gather metadata.
2. Ensure each split contains both positive and negative examples.
3. Verify the temporal coverage is sufficient for evaluation.
4. Authorize a baseline run separately.

`--train` is never implicit in a Gate A command. Baseline metrics are
collected before any retraining occurs.

## Gate C: Post-Training Validation (post-`--train`)

After retraining completes:

1. Run `just verify-seeds` — 7 demo scores should be within ±3 of baseline.
2. Run `just test` — all tests must pass.
3. Run feature contract and parity tests — feature dimension and
   inference/training parity must match.
4. Review new model metrics against the previous model registry entry.

## References

| Resource | Purpose |
|---|---|
| `backend/scripts/ml_gate_a_check.py` | Gather evidence extraction and validation |
| `backend/ml/train_xgboost.py` | `--gather` and `--train` entry point |
| `backend/tests/test_feature_contract.py` | Feature dimension contract |
| `backend/tests/test_feature_parity.py` | Training/inference feature parity |
| `backend/scripts/verify_seed_scores.py` | Demo score verification (`just verify-seeds`) |
| `backend/tests/test_ml_gate_a.py` | Gate A script unit tests |
| `backend/reports/investigations/ml-gate-a-2026-07-14.json` | First post-policy Gate A evidence |

## Relationship to Existing Tests

- `test_npz_metadata.py`, `test_feature_contract.py`, and
  `test_feature_parity.py` remain artifact/contract safeguards.
- Gate A complements them by preserving and reviewing gather-time split
  evidence.
- The demo score check is covered by `just verify-seeds` (not part of Gate A).
- Feature dimension is not hardcoded in Gate A — saved `feature_names` and
  contract tests are the source of truth.
