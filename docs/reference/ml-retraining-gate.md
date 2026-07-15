# ML Retraining Gates — Process Description

This document describes the required human review process for ML retraining in
TriageMate. Each gate must pass before the next phase is authorized.

> **Runtime enforcement:** Automatic scheduler-driven retraining is disabled by
> default (`AUTOMATIC_RETRAINING_ENABLED=false`). When disabled, the scheduler
> does not register the retraining job and `check_drift_and_retrain()` returns
> immediately. This env var controls only the periodic scheduler — it does not
> restrict or authorise manual `--train` runs, which remain under direct user
> control. A manual baseline `--train` run should normally be performed with
> automatic retraining disabled to avoid concurrent scheduler interference.

## Gate A: Gather Evidence and Integrity

After a `--gather` has finished, run:

```bash
just ml-gate-a ml/training_data.npz /tmp/sprint29-post-policy-gather.log /tmp/ml-gate-a.json
```

This command reads the saved NPZ and the matching gather log, reports the
primary, prospective, censored, and split statistics, and writes a versioned
evidence summary.

The `just` recipe changes into `backend/`, so relative NPZ paths are
backend-relative; absolute paths also work. The first gather log remained in
`/tmp` and the current evidence JSON does not contain a log hash. The versioned
JSON therefore preserves the parsed evidence and NPZ fingerprint, not a fully
reproducible copy of the source log.

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

## Gate B: Authorized Baseline Training and Metrics

After Gate A passes and the reviewer approves its evidence:

1. Review the per-split class distributions from the gather metadata.
2. Ensure each split contains both positive and negative examples.
3. Verify the temporal coverage is sufficient for evaluation.
4. Obtain explicit user authorization for a baseline `--train` run.
5. Run it in a dedicated branch/workspace and preserve the pre-run artifact
   fingerprints so the candidate can be compared or discarded safely.

> **Note on `AUTOMATIC_RETRAINING_ENABLED`:** This env var controls only
> periodic scheduler-driven retraining. It is unrelated to manual `--train`
> runs. A manual baseline `--train` should normally be performed with automatic
> retraining **disabled** (`AUTOMATIC_RETRAINING_ENABLED=false`, the default)
> to avoid concurrent scheduler interference. Setting it to `true` does not
> itself authorise any training.

`--train` is never implicit in a Gate A command. Passing Gate A alone does not
permit model retraining or model-artifact replacement.

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
