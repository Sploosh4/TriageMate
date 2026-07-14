# Sprint 30 Final Freshness Pass

**Date:** 2026-07-14

**Scope:** Repository reconciliation, security-decision records, point-in-time
split status, ML Gate A evidence, GitHub tracking, and current operational
instructions.

## Sources checked

- `origin/main` through merged PR #77
- GitHub PRs #68–#77 and Issues #58, #64, #67, #78, and #79
- `backend/pipeline/tier_2/tools.py` and config API code/tests
- `backend/ml/split_policy.py`, `train_xgboost.py`, Gate A script/tests, and
  versioned Gate A JSON
- INDEX, ROADMAP, Sprint 29/30 plans, architecture decisions, and historical
  investigation reports

## Corrections required by the pass

| Finding | Resolution |
|---|---|
| Gate B wording implied authorization already existed | Changed to “requires separate future user authorization” |
| Config document claimed an unimplemented absence assertion | Added `test_config_does_not_expose_feature_names` |
| Gate document implied full runtime enforcement | Documented the scheduler enforcement gap and created Issue #79 |
| Historical ML report retained runnable/stale instructions | Replaced its tail with a resolution map and the current gate reference |
| Sprint 29 retained unresolved decision language and a stale 68-feature count | Marked the section historical/resolved and corrected the tabular count to 35 |
| Gate A path/reproducibility wording was ambiguous | Added a backend-relative root command and documented the unversioned/unhashed source log limitation |
| `just retrain-all` was described as including XGBoost | Corrected INDEX and toolbox: it covers Pre-Tier + EPSS v4 only |
| Historical ROC-AUC and config-exposure descriptions were misleading | Added current caveats and Sprint 29 supersession notes |
| `train_xgboost.py` comment misstated cohort/split order | Updated it to match the implemented mature-primary-first policy |

## Verified state

- PRs #76 and #77 are merged; their checks passed.
- Final local verification: lint clean; 498 tests passed and 1 fuzz test was
  skipped by its normal opt-in gate.
- Superseded PRs #69, #72, #73, and #74 are closed.
- Gate A evidence matches the gathered artifact: 116,133 primary records,
  973 positives, and mixed-class train/validation/test cohorts.
- Issue #64 remains open for the Gate B decision; no training was run.
- Issue #67 is assigned to Backlog.
- Issue #79 explicitly tracks default-off/opt-in runtime enforcement before a
  future Gate B run.

## Verdict

The changed documentation is factually safe to commit after the listed
corrections. The ML gates must be described as mandatory operating policy, not
a fully enforced runtime control, until Issue #79 is resolved.
