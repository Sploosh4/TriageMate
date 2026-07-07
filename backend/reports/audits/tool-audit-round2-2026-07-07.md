# Tool Audit — Round 2 (Deeper Cross-Check)

**Date:** 2026-07-07
**Scope:** Project-wide file existence verification, skill cross-references, AGENTS.md compliance, justfile recipes, test suite execution, dependency environment
**Performed by:** auditor

---

## Results Summary

| Section | Verdict |
|---|---|
| 1. Re-verify Round 1 Issues | ⚠️ PARTIAL FIX — 1 fixed, 1 still missing, 1 still wrong |
| 2. Skill File Cross-References | ❌ 5 FAILURES — missing files & stale references |
| 3. AGENTS.md Compliance | ✅ PASS — all 5 agent files exist, permissions correct |
| 4. Justfile Recipe Spot-Checks | ✅ PASS — all 7 target scripts exist |
| 5. Test Suite Execution | ❌ FAIL — 4 errors, missing dependencies |
| 6. Server Health Check | ⚠️ SKIPPED — cannot start without dependency install |
| 7. Docker Check | ✅ PASS — Dockerfile & docker-compose.yml both exist |
| 8. Git State Check | ❌ SKIPPED — `git` not accessible from sandbox |

**Overall Verdict:** FAIL WITH ISSUES — 5 critical file-mismatch issues, 3 missing files, and no runnable test environment need attention.

---

## 1. Re-verify Round 1 Issues

### 1.1 `.env.example` missing from project root
**Round 1:** ❌ Missing
**Round 2:** ⚠️ **Still an issue.** The file exists at `backend/.env.example` but NOT at the project root (`./.env.example`). The `triage-toolbox/SKILL.md` instructs users to "Copy `.env.example` to `.env`" assuming it's at project root. The `.env.example` exists but in the wrong directory.

**Actual path:** `backend/.env.example` (exists)
**Expected path:** `./.env.example` (does not exist) or skill should reference `backend/.env.example`

### 1.2 `backend/integrations/llm.py` missing
**Round 1:** ❌ Missing
**Round 2:** ❌ **Still missing.** File not found. Referenced by `cloud-llm-engineering/SKILL.md` and `AGENTS.md`-implied pipeline. The `cloud-llm-engineering` skill says "Key Files: `backend/integrations/llm.py` — provider abstraction, API key management, retry logic". No such file exists on disk. The directory listing of `backend/integrations/` shows:
```
advisories.py, cmdb.py, demo_generator.py, exploitdb.py,
greynoise.py, __init__.py, metasploit.py, mitre_mapping.py,
nvd.py, osv.py, otx.py, tenable.py
```
No `llm.py`.

### 1.3 `ml-toolbox` skill wrong filenames for `v2.npz` and `v3.pkl`
**Round 1:** ❌ Wrong filenames
**Round 2:** ❌ **Confirming issue but it's subtler than reported.**

The `ml-toolbox/SKILL.md` File Locations table says:
```
| EPSS models | `backend/ml/epss_model.pkl`, `v2.pkl`, `v3.pkl` |
| Training data | `backend/ml/training_data.npz`, `v2.npz` |
```

Actual file checks:
| Referenced Name | Exists? | Actual File |
|---|---|---|
| `backend/ml/epss_model.pkl` | ✅ YES | `backend/ml/epss_model.pkl` |
| `v2.pkl` (EPSS, relative) | ❌ NO | Code expects `epss_model_v2.pkl` |
| `v3.pkl` (EPSS, relative) | ❌ NO | Code expects `epss_model_v3.pkl` |
| `backend/ml/training_data.npz` | ✅ YES | `backend/ml/training_data.npz` |
| `v2.npz` (training, relative) | ❌ NO | Actual: `training_data_v2.npz` |

The EPSS substitutor code (confirmed via runtime log) attempts to load:
- `epss_model_v3.pkl` — NOT FOUND
- `epss_model_v2.pkl` — NOT FOUND
- `epss_model.pkl` — EXISTS (v1 only)

So the **skill filenames are wrong** AND the **code expects different filenames** (`epss_model_v2.pkl`, `epss_model_v3.pkl`) that also don't exist. V2 and V3 EPSS models have never been trained/persisted to disk.

---

## 2. Skill File Cross-References

Read all 13 SKILL.md files under `.opencode/skills/*/`. Verified every file path reference.

### Results Table

| File Referenced | Referenced By | Exists? | Notes |
|---|---|---|---|
| `backend/ml/xgboost_predictor.py` | ml-engineering | ✅ YES | |
| `frontend/js/components/driftDashboard.js` | frontend-engineering, ROADMAP.md | ✅ YES | |
| `backend/pipeline/tier_2.py` | cloud-llm-engineering, backend-engineering | ✅ YES | |
| `backend/ml/train_xgboost.py` | ml-engineering | ✅ YES | |
| `backend/ml/training_data_v2.npz` | (various) | ✅ YES | |
| `backend/ml/pre_tier_model.pkl` | ml-engineering | ✅ YES | |
| `backend/ml/xgboost_model.pkl` | ml-engineering, ml-toolbox | ✅ YES | |
| `backend/ml/xgboost_calibrator.pkl` | XGBOOST_INVESTIGATION_REPORT.md | ❌ NOT FOUND | Referenced in investigation report but never created |
| `backend/ml/threshold_info.json` | XGBOOST_INVESTIGATION_REPORT.md | ❌ NOT FOUND | Referenced in investigation report but never created |
| `backend/data/mock_cmdb.json` | intel-toolbox | ✅ YES | |
| `backend/data/lancedb/` | ml-engineering (vector_store.py) | ❌ NOT FOUND | Directory does not exist (no LanceDB ingestion has been run) |
| `backend/alembic/versions/005_add_ml_exploitation.py` | sprint plans | ✅ YES | |
| `backend/integrations/llm.py` | cloud-llm-engineering | ❌ NOT FOUND | Already flagged in Round 1 |
| `backend/scripts/fetch_nvd_corpus.py` | ml-engineering | ✅ YES | |
| `backend/scripts/build_training_corpus.py` | ml-engineering | ✅ YES | |
| `backend/.env.example` | triage-toolbox (implicitly) | ✅ YES | But mislocated — in `backend/` not project root |

### Findings

**❌ FAILURE: `backend/ml/xgboost_calibrator.pkl`** — Referenced in `XGBOOST_INVESTIGATION_REPORT.md` but does not exist on disk. The investigation report mentions it as a deliverable from the calibration work, but either the calibrator was never saved or the report was written speculatively.

**❌ FAILURE: `backend/ml/threshold_info.json`** — Same as above. Referenced in the investigation report but never created.

**❌ FAILURE: `backend/data/lancedb/`** — Referenced in `ml/vector_store.py` as the LanceDB storage path. Directory does not exist because `just ingest-docs` has never been run (or failed silently). This causes the health endpoint to fail with an import error in tests because `sentence_transformers` isn't installed (see Section 5).

**❌ FAILURE: `backend/integrations/llm.py`** — Still missing (Round 1 issue).

---

## 3. AGENTS.md Compliance

### File existence
Required squad agent files under `.opencode/agents/`:

| Agent File | Exists? | Has role description? | Permissions correct? |
|---|---|---|---|
| `commander.md` | ✅ YES | ✅ Yes — coordinator, plans sprints, delegates | ✅ edit:deny, bash:deny, write:deny |
| `strike.md` | ✅ YES | ✅ Yes — code writer, full tool access | ✅ No restrictions (full access) |
| `intel.md` | ✅ YES | ✅ Yes — threat intel researcher, .md reports | ✅ read/glob/grep/webfetch only, .md write |
| `auditor.md` | ✅ YES | ✅ Yes — technical auditor, analysis scripts | ✅ Restricted bash (python/pytest/just/ls/cd/pwd/which/mkdir/ruff/uv) |
| `bookkeeper.md` | ✅ YES | ✅ Yes — doc freshness, orphan detection | ✅ read/glob/grep only, .md write |

**Verdict: ✅ PASS** — All 5 agent files exist, correctly describe their roles, and have consistent permission structures. Archived agents from the previous system exist under `.opencode/ARCHIVED/agents/` and are properly segregated.

### Additional observations
- `AGENTS.md` at project root does NOT explicitly say "squad agents are described at `.opencode/agents/`". It describes workflow rules only. The agent definitions are in `opencode.jsonc` and the individual `.md` files.
- The `decision-framework` skill is referenced by all agent files — ✅ consistent.

---

## 4. Justfile Recipe Spot-Checks

Verified the target Python scripts for 5 key recipes:

| Recipe | Command | Target Script | Exists? |
|---|---|---|---|
| `just audit-calibration` | `python -m analysis.calibration_audit` | `backend/analysis/calibration_audit.py` | ✅ YES |
| `just train-xgboost` | `python -m ml.train_xgboost` | `backend/ml/train_xgboost.py` | ✅ YES |
| `just fetch-corpus` | `python -m scripts.fetch_nvd_corpus` | `backend/scripts/fetch_nvd_corpus.py` | ✅ YES |
| `just seed-db` | `python seed_data.py` | `backend/seed_data.py` | ✅ YES |
| `just audit-epss` | `python -m analysis.epss_eval` | `backend/analysis/epss_eval.py` | ✅ YES |
| `just audit-features` | `python -m analysis.feature_parity_check` | `backend/analysis/feature_parity_check.py` | ✅ YES |
| `just audit-schema` | `python -m analysis.validate_conversion` | `backend/analysis/validate_conversion.py` | ✅ YES |
| `just gate` | → lint + test + audit-all | All of the above | ✅ All exist |

**Verdict: ✅ PASS** — All 7 spot-checked recipe target scripts exist on disk. The `audit-all` recipe chains 4 audit sub-recipes correctly.

---

## 5. Test Suite Execution

### Attempt
Installed a fresh `uv venv` in `backend/` and installed dependencies incrementally to isolate the root cause.

### Result: ❌ FAIL — Tests cannot execute without heavy ML dependencies

**What worked:**
- `pytest` framework initializes correctly (pytest 9.1.1 + pytest-asyncio 1.4.0)
- `pytest.ini` config (`asyncio_mode = auto`) is valid
- **Seed data inserted correctly** — all 7 demo rows confirmed:
  ```
  CVE-2023-34362 → score 94, band Very Critical
  CVE-2023-4966  → score 87, band Very Critical
  CVE-2023-27350 → score 71, band Critical
  CVE-2023-36884 → score 63, band Critical
  CVE-2024-1709  → score 55, band Critical
  CVE-2023-22515 → score 41, band Medium
  CVE-2022-47966 → score 22, band Low
  ```

**What failed:**
All 4 health tests failed with `ModuleNotFoundError: No module named 'sentence_transformers'` because the import chain `health endpoint → ml.vector_store → sentence_transformers` forces loading of the full ML stack during app import.

**Root cause chain:**
```
main.py: health() endpoint
  → from ml.vector_store import DB_PATH as rag_db_path
    → from sentence_transformers import SentenceTransformer  💥
```

**Additional dependency gaps identified:**
- `xgboost` — not installed (EPSS substitutor gracefully falls back to rule engine)
- `sentence_transformers` — not installed (blocks health endpoint)
- `torch`, `transformers` — required by sentence_transformers

### Verdict
The test suite is well-structured and the seed data works correctly. However, tests cannot run to completion because the app module graph forces loading of heavy ML dependencies even for simple endpoint tests (health endpoint). A test-only mock/stub for `ml.vector_store` would fix this, OR all requirements need to be installed.

**Count:** 0 passed, 4 failed (at module-import time, not test logic failures)

---

## 6. Server Health Check

**❌ SKIPPED** — Cannot start the server without installing all dependencies (`sentence_transformers`, `xgboost`, `torch`, `transformers`). These require significant download/compile time and exceed the audit timeout budget.

**Recommendation:** Create a lightweight test configuration or mock for `ml/vector_store.py` so the server can start without the full ML stack. Alternatively, install all production dependencies (see `backend/requirements.txt`) and ensure a `.env` file exists.

---

## 7. Docker Check

| Asset | Exists? |
|---|---|
| `Dockerfile` | ✅ YES (`/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP/Dockerfile`) |
| `docker-compose.yml` | ✅ YES (`/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP/docker-compose.yml`) |

**Verdict: ✅ PASS** — Both Docker files present at project root as expected.

---

## 8. Git State Check

**❌ SKIPPED** — The `git` command is not accessible from this sandbox environment. Security restrictions prevent running `git status` or `git log`.

---

## Consolidated Findings

### Critical (blocking functionality)

1. **`backend/integrations/llm.py` still missing** — Blocks Tier 2 LLM integration. Referenced by `cloud-llm-engineering` skill as the provider abstraction layer. Needs creation.

2. **`sentence_transformers` + ML stack not installable in clean venv** — The health endpoint imports `ml.vector_store` which pulls in `sentence_transformers` → `torch` → `transformers`. This means the server cannot start without the full 2GB+ ML dependency tree. Consider lazy imports in the health endpoint.

### Moderate (doc/skill drift)

3. **`ml-toolbox/SKILL.md` file locations table wrong** — References `v2.pkl`, `v3.pkl`, and `v2.npz` which don't exist. Actual files are `epss_model.pkl`, `training_data.npz`, `training_data_v2.npz`. The code also references `epss_model_v2.pkl` and `epss_model_v3.pkl` which don't exist. **Fix:** Update the skill table AND either create the v2/v3 models or remove those references.

4. **`.env.example` in wrong location** — File is at `backend/.env.example` but skills reference it at project root. Either symlink at project root or update skill documentation.

5. **`XGBOOST_INVESTIGATION_REPORT.md` references non-existent files** — `xgboost_calibrator.pkl` and `threshold_info.json` are mentioned as deliverables but don't exist on disk.

### Low (infrastructure)

6. **`backend/data/lancedb/` directory does not exist** — Created when `just ingest-docs` runs. Not a bug, but the directory's absence combined with the eager import in `vector_store.py` causes failures.

7. **No runnable test environment** — The project lacks a pre-configured `.venv` or `requirements.txt` installation instructions that work out of the box. `uv venv` + `uv pip install -r requirements.txt` should work but the heavy packages (torch, transformers, sentence-transformers, xgboost) take significant time to install.

---

## Recommendations

| # | What | Who |
|---|---|---|
| R1 | Create `backend/integrations/llm.py` with provider abstraction, API key management, and retry logic | strike (cloud-llm-engineering) |
| R2 | Update `ml-toolbox/SKILL.md` File Locations table to match actual filenames. Add `epss_model_v2.pkl` and `epss_model_v3.pkl` entries (or remove if never trained) | bookkeeper |
| R3 | Move or symlink `.env.example` to project root, OR update `triage-toolbox/SKILL.md` to document `backend/.env.example` | strike (devops-engineering) |
| R4 | Either create `xgboost_calibrator.pkl` and `threshold_info.json`, or update `XGBOOST_INVESTIGATION_REPORT.md` to remove speculative references | strike (ml-engineering) |
| R5 | Lazy-import `ml.vector_store` in the health endpoint to avoid forcing full ML stack load on server start | strike (backend-engineering) |
| R6 | Run `just ingest-docs` to create the LanceDB vector store directory, or create a stub directory | strike (ml-engineering) |
| R7 | Set up a working venv (`.venv/` with all deps) as part of CI or onboarding | strike (devops-engineering) |
