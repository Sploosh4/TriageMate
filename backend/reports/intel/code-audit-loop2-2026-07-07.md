# Code Comment Audit — Loop 2

**Date:** 2026-07-07
**Requested by:** Commander (sprint quality gate)
**Sources consulted:** Full codebase grep of `backend/` and `frontend/` — `.py`, `.js`, `.html`, `.yml`, `.yaml` files

---

## Overall Verdict

# CLEAN

No outdated, incorrect, or stale comments found that require action. All dimension/feature counts are accurate. All TODO/FIXME markers are absent. All PRIS Act references are intentional transition markers for WAICP migration context.

---

## Findings

### 1. PRIS Act references — 12 matches across codebase

All are explicit transition comments in the form `# WAICP: OFFICIAL (was PRIS Act Category 1)`. These are **intentional** — they document the migration from PRIS Act classification to WAICP during Western Australia's government security framework transition. The "Category 1" string remains in fallback/default code paths so it's correct to note the historical context.

| File | Comment |
|---|---|
| `backend/integrations/cmdb.py:177` | `)  # WAICP: OFFICIAL (was PRIS Act Category 1)` |
| `backend/integrations/cmdb.py:221` | `"data_classification": "Category 1",  # WAICP: OFFICIAL (was PRIS Act Category 1)` |
| `backend/ingest_helpers.py:78` | `}  # WAICP: OFFICIAL (was PRIS Act Category 1)` |
| `backend/analysis/feature_parity_check.py:153` | Same pattern |
| `backend/analysis/feature_parity_check.py:170` | Same pattern |
| `backend/analysis/feature_parity_check.py:219` | Same pattern |
| `backend/ml/xgboost_predictor.py:222` | Same pattern |
| `backend/scripts/build_training_corpus.py:190` | Same pattern |
| `backend/scripts/build_training_corpus.py:262` | Same pattern |
| `backend/routers/cases.py:31` | Same pattern |
| `backend/routers/queue.py:46` | Same pattern |
| `backend/integrations/cmdb.py:172` | Docstring: `Defaults to "Category 1" (PRIS Act legacy) for unknown hosts.` |

Also noted: `docs/archive/sprints-1-6/COURSE_CORRECTION.md` contains an archived reference to PRIS Act. This is an archived document — expected content.

**Verdict:** ✓ Accurate transition documentation — no action needed.

### 2. Dimension counts — CLEAN

- **`backend/scoring.py:28`**: `"Calculate the 0-100 priority score from six weighted dimensions"` — verified: 6 dimensions (cvss, epss, ml_exploitation, criticality, exposure, patch). ✓
- **Frontend JS**: No hardcoded dimension counts — dynamically consumes `scoringWeights` from API response. ✓

### 3. Feature vector counts — CLEAN

| File | Claim | Actual | Match? |
|---|---|---|---|
| `backend/ingest_helpers.py:381` | "42-key feature dict (41 tabular + description)" | 42 keys returned | ✓ |
| `backend/ml/xgboost_predictor.py:105` | "All other 35 features default to neutral" | 35 tabular features in `np.array` (lines 129-165) | ✓ |
| `backend/analysis/feature_parity_check.py:4` | "identical 35-element feature vectors" | `FEATURE_NAMES` has 35 entries, both builders return 35 | ✓ |
| `backend/analysis/validate_conversion.py:83` | `assert X.shape[1] == 35` | `build_tabular_features` returns 35 columns | ✓ |
| `backend/ml/train_xgboost.py:526` | "build_tabular_features() now produces 35 features" | Historical fix note, consistent with current code | ✓ |

### 4. Python 2 anachronisms — CLEAN

No `xrange`, `raw_input`, `from __future__`, `unicode`, `basestring`, or `print ` statements (as opposed to `print()`) found.

### 5. Deprecated model/code references — CLEAN

Searched for `SecureBERT`, `cwe_classifier_deprecated`, `pca_reducer` — zero matches outside commented/deprecated markers.

### 6. Old version strings — CLEAN

No `TriageMate/0.` version strings found in Python code.

### 7. Docker Compose V1 — CLEAN

No `docker-compose ` (space-separated) invocations in `Dockerfile`, `docker-compose.yml`, or `justfile`.

### 8. TODO/FIXME/HACK/WORKAROUND — CLEAN

Zero matches across all `*.py`, `*.js`, `*.html`, `*.yml`, `*.yaml` files. The codebase is free of unfinished work markers.

### 9. Dead file references — CLEAN

No references to `DEMO_SCRIPT` or `TRIAGEMATE_BOOK` in any code files.

### 10. cmdb.py default comment spot-check — CLEAN

- Docstring references `KNOWN_HOSTS` stub, `TRIAGEMATE_CMDB_PROVIDER` env var with `"stub"`, `"servicenow"`, `"itop"` options — all confirmed present in code.
- The "Category 1" defaults in the stub lookup function are consistent with the transition comments throughout the codebase.

---

## Assessment

The codebase is at a high level of comment hygiene. The only references that could *look* outdated at first glance (PRIS Act) are deliberate historical markers that serve an important purpose: they document why `"Category 1"` still exists in classification mappings alongside `"OFFICIAL"` and `"OFFICIAL Sensitive"`. Removing them would lose context for future maintainers.

No dimension/feature count drift was detected between comments and actual code. All counts were verified by manual tally against source.

---

## Recommendations

None. This audit found zero actionable items. The codebase is clean.
