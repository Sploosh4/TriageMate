# Sprint 11 Quality Gate — Model Registry + Endpoints Audit

**Date:** 2026-07-08
**Scope:** Model version management system (registry, endpoints, predictor integration) and audit sampling fix in ingest pipeline
**Performed by:** auditor
**Pre-flight:** All source files readable; no Python imports required beyond JSON parsing for registry validation

## Results Summary

| Section | Verdict | Pass | Fail | Skip |
|---|---|---|---|---|
| 1. Registry File Integrity | **PASS** | 8 | 0 | 0 |
| 2. Model Versions Endpoints | **PASS** | 3 | 0 | 0 |
| 3. Audit Fix Verification | **PASS** | 4 | 0 | 0 |
| 4. Test Coverage | **PASS** | 2 | 0 | 0 |
| 5. Predictor Changes | **PASS** | 4 | 0 | 0 |
| **Overall** | **PASS** | **21** | **0** | **0** |

---

## 1. Registry File Integrity

**Source:** `backend/ml/model_registry.json`

### Checks Performed (8 total)

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 1.1 | Valid JSON | parseable | parseable | **PASS** |
| 1.2 | `versions` count | 3 | 3 | **PASS** |
| 1.3 | Version IDs present | v1, v2, v3 | v1, v2, v3 | **PASS** |
| 1.4 | Each version has all required keys | `version`, `label`, `model_file`, `metrics`, `created_at`, `score_baseline` | All present on all 3 versions | **PASS** |
| 1.5 | `active_version` is "v3" | "v3" | "v3" | **PASS** |
| 1.6 | `active_version` exists in `versions` list | "v3" ∈ [v1, v2, v3] | "v3" ∈ [v1, v2, v3] | **PASS** |
| 1.7 | All `model_file` paths exist on disk | | | **PASS** |
| | v1 → `xgboost_model_old.pkl` | exists | 1,297,434 bytes (Jul 3) | **PASS** |
| | v2 → `xgboost_model_pre_retrain.pkl` | exists | 1,297,434 bytes (Jul 8) | **PASS** |
| | v3 → `xgboost_model.pkl` | exists | 1,315,115 bytes (Jul 8) | **PASS** |
| 1.8 | Referenced calibrator/threshold files exist | | | **PASS** |
| | v1 calibrator → `xgboost_calibrator.pkl` | exists | 827 bytes (Jul 8) | **PASS** |
| | v3 calibrator → `xgboost_calibrator.pkl` | exists | 827 bytes (Jul 8) | **PASS** |
| | v1/v3 threshold → `threshold_info.json` | exists | 78 bytes (Jul 8) | **PASS** |
| | v2 calibrator/threshold → null | N/A (gracefully None) | | **PASS** |

### Details

- **v1** (Sprint 3, 93K records): ROC-AUC 0.9677, score baseline `[95, 88, 70, 62, 54, 40, 21]`
- **v2** (Pre-retrain snapshot): metrics mostly null (recorded as snapshot), score baseline `[94, 87, 70, 62, 54, 41, 22]`
- **v3** (Current, 253K records, 2026-07-08 retrain): ROC-AUC 0.9459, score baseline `[94, 87, 71, 63, 55, 41, 22]`

**Note:** v2 has `roc_auc: null` and `training_samples: null` — this is expected for a pre-retrain snapshot that was not evaluated. No issue.

**Registry verdict: PASS**

---

## 2. Model Versions Endpoints

**Source:** `backend/routers/models.py`

Server was not run (sandbox constraint). Endpoint logic verified by reading router code.

### 2.1 `GET /api/model/versions` — Verified

Reads registry via `_read_registry()`, transforms via `_registry_to_response()`:

- Returns `{"active_version": ..., "versions": [...]}`
- Each version entry includes `is_active: true/false` flag
- All 3 versions (v1, v2, v3) included

### 2.2 `POST /api/model/activate` — Verified

| # | Step | Implementation | Result |
|---|---|---|---|
| 2.2.1 | Validate version exists | Iterates `versions[]`, returns 404 if not found | **PASS** |
| 2.2.2 | Reject already-active | Returns 400 if `active_version == req.version` | **PASS** |
| 2.2.3 | Atomic write | `_write_registry()`: writes `.json.tmp` → `f.flush()` → `os.fsync()` → `replace()` (atomic rename) | **PASS** |
| 2.2.4 | IO error handling | Catches `OSError`, returns 500 with error detail | **PASS** |
| 2.2.5 | Predictor cache invalidation | Calls `set_active_version(req.version)` from `ml.xgboost_predictor` | **PASS** |

### 2.3 `GET /api/model/status` — Verified

Returns three top-level keys:
- `active_version`: full metadata dict for the active version (with `is_active: true`)
- `available_versions`: all 3 versions with `is_active` flags
- `score_comparison`: Contains `baseline_scores` (hardcoded `[94, 87, 71, 63, 55, 41, 22]`) and per-version `versions` with score arrays + notes

**Note:** The hardcoded `baseline_scores` in `score_comparison` (line 87 of `models.py`) matches v3's score_baseline. This is a display constant for the status endpoint, not a logic issue.

**Endpoints verdict: PASS**

---

## 3. Audit Fix Verification

**Source:** `backend/routers/ingest.py`, lines 299–307

### The Bug (Sprint 11 context)
When Tier 0 escalated and Tier 1 auto-resolved, the pipeline only checked `t0_result["routing"]` which was `"escalated"`, so the case was invisible to audit sampling.

### The Fix: `effective_routing` logic

```python
# Line 304-306 of ingest.py:
effective_routing = t0_result["routing"]
if t0_result["routing"] == "escalated" and t1_result:
    effective_routing = t1_result["routing"]
```

### Coverage Matrix

| Scenario | t0_result["routing"] | t1_result | effective_routing | Audit triggers? | Result |
|---|---|---|---|---|---|
| Tier 0 auto-resolved, no Tier 1 | "auto_resolved" | None | "auto_resolved" | ✅ Yes (auto-resolved) | **PASS** |
| Tier 0 escalated, Tier 1 auto-resolved | "escalated" | `{"routing": "auto_resolved"}` | "auto_resolved" | ✅ Yes (this was the bug) | **PASS** |
| Tier 0 escalated, Tier 1 escalated | "escalated" | `{"routing": "escalated"}` | "escalated" | ❌ No (both escalated) | **PASS** |
| Tier 0 escalated, t1_result is None | "escalated" | None | "escalated" | ❌ No (no auto-resolve at any tier) | **PASS** |

The `t1_result` truthiness check on line 305 (`and t1_result`) provides defensive coding against `t1_result` being None — confirmed present.

**Audit fix verdict: PASS**

---

## 4. Test Coverage

**Note:** Tests were examined for structure and count only. Not executed (scope boundary per task).

### 4.1 `backend/tests/test_audit.py`

- **12 tests** across 3 test classes:
  - `TestShouldAudit` (4 tests) — direct `should_audit()` function tests
  - `TestEffectiveRouting` (4 tests) — `effective_routing` logic replication tests
  - `TestAuditPipelineScenarios` (4 tests) — end-to-end routing+audit chain
- Covers all 4 effective_routing scenarios, random-mocking for audit triggers
- Meets the 10+ threshold: **PASS**

### 4.2 `backend/tests/test_model_versions.py`

- **8 tests** across 2 test classes:
  - `TestModelVersions` (5 tests) — list, activate valid, activate invalid, activate already-active, activate then predict
  - `TestModelStatus` (3 tests) — status shape, registry-matching, score comparison completeness
- Includes session-scoped `_save_and_restore_registry` fixture for test isolation
- Meets the 8+ threshold: **PASS**

**Test coverage verdict: PASS**

---

## 5. Predictor Changes

**Source:** `backend/ml/xgboost_predictor.py`

### 5.1 Thread safety: `set_active_version()` uses `_lock`

```
set_active_version() at line 162-195:
  line 185: with _lock:  # acquires lock before modifying shared state
```

The module-level `_lock = threading.Lock()` (line 96) is shared with `_get_model()` and `_get_calibrator()`, both of which also acquire `_lock` when loading model/calibrator. This ensures:
- No concurrent writes to `_active_model_path`, `_active_calibrator_path`, `_model`, `_calibrator`
- No read-write races between activation and prediction

### 5.2 Dynamic paths in `_get_model()`

```
_get_model() at line 99-111:
  line 104: model_path = _active_model_path   ← NOT hardcoded MODEL_FILE
```

Confirmed: uses dynamic `_active_model_path` variable, initialized from registry at import time via `_init_active_paths_from_registry()`.

### 5.3 Dynamic paths in `_get_calibrator()`

```
_get_calibrator() at line 114-121:
  line 116: cal_path = _active_calibrator_path   ← NOT hardcoded CALIBRATOR_FILE
```

Confirmed: uses dynamic `_active_calibrator_path`. Gracefully handles None (null in registry for v2).

### 5.4 Cache invalidation on version switch

```
set_active_version() at line 193-195:
  # Invalidate in-memory cache — forces lazy reload on next predict()
  _model = None
  _calibrator = None
```

Both model and calibrator caches are invalidated. The lazy reload pattern in `_get_model()` / `_get_calibrator()` (double-checked locking) will load the new version's model on the next `predict()` call.

**Predictor changes verdict: PASS**

---

## Verdict

**PASS** — 21 passed, 0 failed, 0 skipped

All checks in scope pass cleanly:

| Section | Result |
|---|---|
| Registry file integrity (8 checks) | PASS |
| Endpoint logic verification (3 endpoints) | PASS |
| Audit fix verification (4 scenarios) | PASS |
| Test coverage (2 files, 20 total tests) | PASS |
| Predictor changes (4 checks) | PASS |

### Key observations

1. **Registry is well-formed** — all model files exist on disk, calibrator/threshold files accounted for across versions, v2 gracefully uses null calibrator
2. **Atomic write pattern** — `_write_registry()` uses temp+flush+fsync+rename, proper OS-level atomicity
3. **Audit fix covers all edge cases** — the `effective_routing` logic cleanly delegates to Tier 1 when it ran, and the `t1_result None` guard prevents AttributeError on missing Tier 1
4. **Thread safety is correct** — `set_active_version()` shares the same `_lock` as the lazy-load functions, preventing read-write races during version switches
5. **Cache invalidation is complete** — both `_model` and `_calibrator` are set to None, forcing fresh load on next prediction
6. **Test coverage is adequate** — 12 audit tests + 8 model version tests, covering normal paths, error paths, and edge cases

### Out of scope (noted but not flagged)
- The hardcoded `baseline_scores` in `models.py:87` duplicates v3's score_baseline — not a bug, it's a display baseline for the status UI
- v2 has null metrics (roc_auc, training_samples) — expected for an unevaluated snapshot
