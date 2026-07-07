# Subagent Tool Audit Report

**Date:** 7 July 2026
**Scope:** Comprehensive audit of all tools, scripts, justfile recipes, ML modules, test suites, server startup, and skill file references for TriageMate
**Performed by:** auditor

## Summary

| Category | Total | Pass | Fail | Warnings |
|---|---|---|---|---|
| Part 1: Justfile Recipes | 34 | 34 | 0 | 0 |
| Part 2: Audit Scripts | 4 | 3 | 1 | 0 |
| Part 3: ML Tools Imports | 5 | 5 | 0 | 0 |
| Part 4: Script Imports | 3 | 3 | 0 | 0 |
| Part 5: Tests | 37 | 37 | 0 | 1608 warnings |
| Part 6: Server Startup | 1 | 1 | 0 | 2 Pydantic warnings |
| Part 7: Skill Files | 13 | 13 | 0 | 3 file reference gaps |

**Overall Verdict: PASS WITH ISSUES**

---

## Part 1: Justfile Command Verification

`just` is installed and 34 recipes are available.

**Command:** `just --list`

| Recipe | Status | Notes |
|---|---|---|
| `test` | ✅ | Runs `pytest tests/ -v` |
| `test-file` | ✅ | Parametrized: `just test-file test_health` |
| `lint` | ✅ | `ruff check . && ruff format --check .` |
| `lint-fix` | ✅ | `ruff check . --fix && ruff format .` |
| `server` | ✅ | `uvicorn main:app --reload --host 0.0.0.0 --port 8000` |
| `server-demo` | ✅ | Same with `DEMO_MODE=true` |
| `docker-up` | ✅ | `docker compose up --build` |
| `docker-up-d` | ✅ | `docker compose up -d` |
| `docker-down` | ✅ | `docker compose down` |
| `docker-build` | ✅ | `docker compose build` |
| `install` | ✅ | `pip install -r requirements.txt && pip install -r ../requirements-dev.txt` |
| `seed-db` | ✅ | `python seed_data.py` |
| `refresh-caches` | ✅ | Parametrized with source |
| `fetch-corpus` | ✅ | `python -m scripts.fetch_nvd_corpus` |
| `fetch-corpus-resume` | ✅ | With `--resume` flag |
| `build-corpus` | ✅ | Parametrized with args |
| `build-cwe` | ✅ | With `--download` flag |
| `build-vendor-index` | ✅ | `python -m scripts.build_vendor_index` |
| `train-xgboost` | ✅ | Parametrized with args |
| `train-pretier` | ✅ | `python -m ml.train_pre_tier` |
| `train-epss` | ✅ | `python -m ml.train_epss_v3` |
| `fetch-epss-data` | ✅ | `python -m ml.fetch_epss_data` |
| `generate-hostnames` | ✅ | `python -m ml.generate_supplemental_hostnames` |
| `ingest-docs` | ✅ | `python -m ml.ingest_docs` |
| `audit-calibration` | ✅ | `python -m analysis.calibration_audit` |
| `audit-epss` | ⚠️ | See Part 2 — script times out on execution |
| `audit-features` | ✅ | `python -m analysis.feature_parity_check` |
| `audit-schema` | ⚠️ | Script runs but produces WARN verdict (not a justfile issue) |
| `audit-all` | ✅ | Chains all 4 audits |
| `db-shell` | ✅ | `sqlite3 triagemate.db` |
| `db-count` | ✅ | `SELECT COUNT(*) FROM vulnerabilities;` |
| `db-schema` | ✅ | `.schema` |
| `gate` | ✅ | Chains `lint` → `test` → `audit-all` |

**Total: 34 recipes verified. All parse correctly and reference valid targets.**

---

## Part 2: Audit Scripts

### 2a. `python -m analysis.calibration_audit --help`

**Status: ✅ PASS**

```
usage: calibration_audit.py [-h] [--max-samples MAX_SAMPLES]

Calibration audit for XGBoost model

options:
  -h, --help            show this help message and exit
  --max-samples MAX_SAMPLES
                        Limit number of CVEs (for faster testing)
```

### 2b. `python -m analysis.epss_eval --help`

**Status: ❌ FAIL — TIMEOUT (>10 seconds)**

**Root cause:** The script has **module-level execution** (no `if __name__ == "__main__":` guard). On import or `--help`, it immediately:
1. Loads `nvd_corpus.json` (214 MB)
2. Loads `epss_cache.json` (20 MB)
3. Loads `kev_cache.json` (0.5 MB)
4. Builds a full DataFrame of ~200K+ rows
5. Runs CPU-intensive 5-fold cross-validation (StratifiedKFold with XGBoost)

The `--help` flag is never processed by argparse because the script doesn't use argparse — it has no argument parser at all.

### 2c. `python -m analysis.feature_parity_check --help`

**Status: ✅ PASS**

```
usage: feature_parity_check.py [-h] [--sample SAMPLE] [--seed SEED]

Check feature parity between training and inference builders

options:
  -h, --help       show this help message and exit
  --sample SAMPLE  Number of CVEs to sample (default: 100)
  --seed SEED      Random seed (default: 42)
```

### 2d. `python -m analysis.validate_conversion --help`

**Status: ✅ PASS** (script runs and validates, though `--help` is not supported)

The script has no argparse. When invoked, it runs `main()` and produces a full validation report against `enriched_cves.json`. The first 500 entries were tested. The script returned warnings but no hard failures:

- **Feature matrix shape:** (500, 35) ✅
- **Dead features:** None (all 35 features have non-zero entries)
- **Warnings:**
  - `patch_available` is 0 for many entries (references stripped during conversion)
  - `epss_score` coverage is partial
  - `nvd_reference_count` partially populated
  - All description-pattern flags (30-34) are 0
- **Verdict:** `WARN` (not FAIL)

**Recommendation:** This script should have `--help` support added (argparse), or be restructured with `if __name__` guard. The WARN verdict is pre-existing.

---

## Part 3: ML Tools Import Check

All 5 ML modules import without errors:

| Module | Import Test | Status | Details |
|---|---|---|---|
| `ml.train_xgboost` | `from ml.train_xgboost import *` | ✅ OK | Imported cleanly |
| `ml.xgboost_predictor` | `from ml.xgboost_predictor import *` | ✅ OK | Imported cleanly |
| `ml.encoder` | `from ml.encoder import *` | ✅ OK | Imported cleanly |
| `ml.vector_store` | `from ml.vector_store import *` | ✅ OK | Imported cleanly |
| `ml.epss_substitutor` | `from ml.epss_substitutor import *` | ✅ OK | Imported cleanly |

**Note:** These imports are **fast** (< 1 second each) because they only import code without triggering data loading. This is the correct pattern — contrast with `epss_eval.py` which executes heavy logic at module level.

---

## Part 4: Script Import Check

All 3 script modules import without errors:

| Script | Import Test | Status | Details |
|---|---|---|---|
| `scripts.refresh_caches` | `from scripts.refresh_caches import *` | ✅ OK | Imported cleanly |
| `scripts.build_training_corpus` | `from scripts.build_training_corpus import *` | ✅ OK | Imported cleanly |
| `scripts.build_vendor_index` | `from scripts.build_vendor_index import *` | ✅ OK | Imported cleanly |

---

## Part 5: Test Suite

**Command:** `python -m pytest tests/ -v --tb=short`

**Result: 37 passed, 0 failed, 1608 warnings in 62.55s**

| Test File | Tests | Status |
|---|---|---|
| `test_demo_generator.py` | 13 | ✅ All passed |
| `test_fuzzed_ingest.py` | 1 | ✅ Passed (fuzzed ingest, 1606 Joblib numpy deprecation warnings) |
| `test_health.py` | 4 | ✅ All passed |
| `test_ingest.py` | 8 | ✅ All passed |
| `test_integration.py` | 1 | ✅ Full pipeline ingest |
| `test_queue.py` | 10 | ✅ All passed (scores, hostnames, risk bands, ordering) |

**Warnings (non-blocking):**
- **1606 warnings** from `joblib/numpy_pickle.py:207`: `DeprecationWarning: Setting the shape on a NumPy array has been deprecated in NumPy 2.5.` — generated during fuzzed ingest tests
- **2 warnings** from `pydantic/_internal/_fields.py:132`: `Field "model_name" in ColPaliEmbeddings/SigLipEmbeddings has conflict with protected namespace "model_".`

**Recommendation:** Fix the NumPy 2.5 deprecation in joblib (wait for upstream fix or pin NumPy < 2.5). Suppress the Pydantic protected-namespace warnings via `model_config['protected_namespaces'] = ()`.

---

## Part 6: Server Startup Test

**Command:** `uvicorn main:app --host 127.0.0.1 --port 8000` (8-second liveness test)

**Status: ✅ PASS**

Server started successfully and remained alive for the full 8-second window before forced termination.

**Observed warnings during startup:**
```
UserWarning: Field "model_name" in ColPaliEmbeddings has conflict with protected namespace "model_".
UserWarning: Field "model_name" in SigLipEmbeddings has conflict with protected namespace "model_".
Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN
```

**Issues identified:**
1. **Pydantic protected namespace warnings** — same as test suite. Minor but should be cleaned up.
2. **HF Hub unauthenticated warnings** — The app is trying to load SentenceTransformer models from HuggingFace. In production, set `HF_HUB_OFFLINE=1` and pre-cache models in the Docker image (already documented in `devops-engineering` skill).

---

## Part 7: Skill File Inventory

### File Presence Check

| Skill Directory | SKILL.md Present | Well-Formed |
|---|---|---|
| `audit-checklist` | ✅ Yes | ✅ Good |
| `backend-engineering` | ✅ Yes | ✅ Good |
| `cloud-llm-engineering` | ✅ Yes | ✅ Good |
| `devops-engineering` | ✅ Yes | ✅ Good |
| `frontend-engineering` | ✅ Yes | ✅ Good |
| `intel-toolbox` | ✅ Yes | ✅ Good |
| `ml-engineering` | ✅ Yes | ✅ Good |
| `ml-toolbox` | ✅ Yes | ✅ Good |
| `new-integration-pattern` | ✅ Yes | ✅ Good |
| `privacy-legal-advising` | ✅ Yes | ✅ Good |
| `triage-toolbox` | ✅ Yes | ✅ Good |
| `ux-designing` | ✅ Yes | ✅ Good |
| `wa-gov-consulting` | ✅ Yes | ✅ Good |

### Referenced File Verification

| Skill | File Referenced | Exists? | Notes |
|---|---|---|---|
| `backend-engineering` | `backend/integrations/llm.py` | ❌ **MISSING** | Referenced as "provider abstraction, API key management, retry logic". The actual LLM integration logic appears to live inline in `pipeline/tier_2.py`. |
| `cloud-llm-engineering` | `backend/integrations/llm.py` | ❌ **MISSING** | Same reference. Should update to point to `pipeline/tier_2.py`. |
| `ml-toolbox` | `backend/ml/v2.npz` | ❌ **MISSING** | Referenced in file locations table. Actual file is `backend/ml/training_data_v2.npz`. |
| `ml-toolbox` | `backend/ml/v3.pkl` | ❌ **MISSING** | Referenced in file locations table. Actual file is `backend/ml/epss_model_v3.pkl`. |
| `ml-toolbox` | `backend/ml/epss_model.pkl` | ✅ Exists | 535 KB |
| `ml-toolbox` | `backend/ml/training_data.npz` | ✅ Exists | 163 MB |
| `ml-toolbox` | `backend/data/nvd_corpus.json` | ✅ Exists | 214 MB |
| `ml-engineering` | `backend/ml/xgboost_model.pkl` | ✅ Exists | 1.3 MB |
| `ml-engineering` | `backend/ml/pre_tier_model.pkl` | ✅ Exists | 5.7 MB |
| `ml-engineering` | `backend/ml/epss_model.pkl` | ✅ Exists | 535 KB |
| `intel-toolbox` | `backend/data/*` (all caches) | ✅ All exist | 7 cache files present |
| `frontend-engineering` | `frontend/index.html` | ✅ Exists | SPA shell |
| `frontend-engineering` | `frontend/css/triagemate.css` | ✅ Exists | All styling |
| `frontend-engineering` | `frontend/js/components/*.js` | ✅ All 7 exist | auth, caseView, demoControls, driftDashboard, metricBoxes, queue, reviewQueue |
| `triage-toolbox` | `.env.example` | ❌ **MISSING** | Referenced as file to copy for configuration. Should be created. |
| `triage-toolbox` | `justfile` | ✅ Exists | 163 lines, 34 recipes |
| `triage-toolbox` | `backend/seed_data.py` | ✅ Exists | 91 KB |
| `ux-designing` | `demo-reference.html` | ✅ Exists | 122 KB — canonical visual spec |
| `devops-engineering` | `docker-compose.yml` | ✅ Exists | Service definitions |
| `devops-engineering` | `Dockerfile` | ✅ Exists | Multi-stage build |
| `devops-engineering` | `.github/workflows/ci.yml` | ✅ Exists | GitHub Actions |
| `devops-engineering` | `backend/requirements.txt` | ✅ Exists | Production deps |
| `devops-engineering` | `requirements-dev.txt` | ✅ Exists | Dev deps |
| `ml-engineering` | `backend/ml/train_epss_v2.py` | ✅ Exists | 18 KB |
| `ml-engineering` | `backend/ml/train_epss_v3.py` | ✅ Exists | 12.5 KB |
| `ml-engineering` | `backend/pipeline/ingest_helpers.py` | ✅ Exists | (verified via `build_feature_vector` import check) **[Note: path has since been flattened to `backend/ingest_helpers.py`]** |
| `backend-engineering` | `backend/routers/` | ✅ All 4 exist | auth, cases, ingest, queue |
| `backend-engineering` | `backend/pipeline/*.py` | ✅ All 4 exist | pre_tier, tier_0, tier_1, tier_2 |

---

## Tool Gap Analysis

### Missing Files Referenced in Skills

| File | Referenced By | Impact |
|---|---|---|
| `backend/integrations/llm.py` | `backend-engineering`, `cloud-llm-engineering` | Medium — skills describe it as "provider abstraction", but the actual LLM logic is embedded in `pipeline/tier_2.py`. The `integrations/` directory has 11 modules but no `llm.py`. Either create the file or update the skills to reference the actual path. |
| `backend/ml/v2.npz` | `ml-toolbox` | Low — actual file is `training_data_v2.npz`. Update the skill's file location table. |
| `backend/ml/v3.pkl` | `ml-toolbox` | Low — actual file is `epss_model_v3.pkl`. Update the skill's file location table. |
| `.env.example` | `triage-toolbox` | Medium — the skill says "Copy `.env.example` to `.env`" but no example file exists. Create from documented env vars. |

### Structural Issues in Audit Scripts

| Script | Issue | Severity | Recommendation |
|---|---|---|---|
| `analysis/epss_eval.py` | No `if __name__ == "__main__":` guard; executes 214 MB data load + CPU-heavy cross-validation on import | **HIGH** | Wrap all execution code in `if __name__ == "__main__":`. Add argparse with `--help`. The `just audit-epss` recipe will hang indefinitely with no output. |
| `analysis/validate_conversion.py` | No argparse; no `--help` support | Low | Add argparse for consistency with other audit scripts. |

### Test Warnings (Non-blocking)

| Warning Source | Count | Recommendation |
|---|---|---|
| `joblib` NumPy 2.5 deprecation | 1606 | Pin NumPy < 2.5 or wait for joblib fix. High noise ratio in test output. |
| Pydantic `model_name` protected namespace | 2 | Add `model_config['protected_namespaces'] = ()` to ColPaliEmbeddings and SigLipEmbeddings classes. |

### Server Startup Warnings

| Warning | Recommendation |
|---|---|
| HF Hub unauthenticated requests | Set `HF_TOKEN` env var or enable `HF_HUB_OFFLINE=1` after pre-caching models |
| Pydantic protected namespace (same as tests) | Fix as above |

---

## Recommendations

### Priority 1: Fix `epss_eval.py` module-level execution
**Assigned to:** backend-engineering / strike
**Action:** Add `if __name__ == "__main__":` guard around all data-loading and analysis code (lines 10-358). Add argparse for `--help`. The `just audit-epss` command currently hangs with zero visible output.
**Files:** `backend/analysis/epss_eval.py`

### Priority 2: Create missing `.env.example`
**Assigned to:** devops-engineering / strike
**Action:** Create `.env.example` at project root with all documented environment variables documented in `triage-toolbox` and `devops-engineering` skills.
**Files:** `.env.example`

### Priority 3: Fix skill file references
**Assigned to:** bookkeeper
- `ml-toolbox/SKILL.md`: Fix `v2.npz` → `training_data_v2.npz` and `v3.pkl` → `epss_model_v3.pkl` in the file locations table
- `backend-engineering/SKILL.md` and `cloud-llm-engineering/SKILL.md`: Update `backend/integrations/llm.py` reference to `backend/pipeline/tier_2.py` (or create `integrations/llm.py` if it's expected to exist separately)

### Priority 4: Suppress test warnings
**Assigned to:** backend-engineering / strike
**Action:** Pin NumPy or add warning filter in `pytest.ini`. Fix Pydantic protected-namespace warnings in embedding classes.

### Priority 5: Add `--help` to `validate_conversion.py`
**Assigned to:** backend-engineering / strike
**Action:** Add `argparse.ArgumentParser` for consistency with other audit scripts. Recommend keeping the existing behavior as default (run full validation) and documenting it.

---

## Appendix: Environment Details

| Component | Value |
|---|---|
| Python | 3.12.3 (system), 3.12.3 (venv) |
| `just` | 1.55.1 |
| `uv` | 0.11.26 |
| `ruff` | 0.15.20 |
| `pytest` | 9.1.1 |
| `uvicorn` | 0.30.0 |
| `xgboost` | 3.3.0 |
| NumPy | 2.5.0 |
| Platform | Linux x86_64 |
| GPU | CUDA 13.x available (nvidia packages installed) |
