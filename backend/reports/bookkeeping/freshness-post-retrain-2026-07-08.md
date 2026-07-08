# Bookkeeping Report — Post-Retrain Freshness Pass

**Date:** 2026-07-08
**Trigger:** Post-retrain audit (XGBoost retrain, graphify regeneration, feature-parity guard)

---

## Overall Verdict: **NEEDS ATTENTION** — P0 dimension mismatch will crash Tier 1

---

## P0 — CRITICAL: Production Pipeline Will Crash

### 1. DIMENSION MISMATCH: Model expects 420 features, Predictor sends 419 🚨

**Severity: P0 — Pipeline Tier 1 will fail on every inference**

The retrained XGBoost model (`xgboost_model.pkl`) was trained on **420 features** (36 tabular + 384 SBERT, including `osv_lead_days` as a model input). However, the predictor (`xgboost_predictor.py`) builds only **419 features** (35 tabular + 384 SBERT, excluding `osv_lead_days`).

**Test result:**
```
Model expects: 420 features
419-dim input: FAILED - ValueError: Feature shape mismatch, expected: 420, got 419
```

Every call to `predict()` will crash. The live `GET /api/queue` and `POST /api/ingest` endpoints will return 500 errors whenever Tier 1 runs.

**Root cause:** `build_tabular_features()` in `train_xgboost.py` returns 35 columns, but the NPZ stores 420 columns (36 tabular + 384 SBERT). The training pipeline loads ALL 420 columns from the NPZ and trains the model on them — including `osv_lead_days` at column index 35. The intent was for `osv_lead_days` to be metadata, not a model input.

**Suggested fix (choose one):**
- **Option A (quick fix):** Pad the predictor's tabular vector to 36 columns by inserting 0.0 for `osv_lead_days` at index 35 in `xgboost_predictor.py`. This makes inference work but the model is trained on a metadata feature.
- **Option B (correct fix):** Retrain the model on 419 features by ensuring `osv_lead_days` is excluded from training. In `phase_train()` / `load_training_data()`, drop column index 35 (`osv_lead_days`) before training. This is the intended design (ROADMAP.md line 69: "osv_lead_days is a metadata column... not a model input").
- **Option C (architectural):** Strip `osv_lead_days` from the NPZ entirely and rebuild with `--gather --train`.

---

## P1 — Cross-File Contradictions (Must Fix)

### 2. ROADMAP.md — Claims retrain has NOT been run (it has)

| Line | Says | Reality |
|------|------|---------|
| 167 | "Item 1 (XGBoost retrain) is 🔧 In progress — corpus built; training not yet run" | ✅ Retrain complete 2026-07-08 |
| 171 | "Training not yet run" | ✅ Retrain complete |
| 128 | "Calibrator will be generated after retrain" | ✅ `xgboost_calibrator.pkl` exists (827 B) |
| 133 | "Calibrator... 🔧 Will generate after retrain" | ✅ Calibrator exists |
| 119 | "ROC-AUC 0.9677 post-fix" | Should be **0.9409** (retrained value) |
| 128 | "ROC-AUC 0.9677 (Sprint 3)" | Ambiguous — needs context that Sprint 3 model was replaced |
| 81 | "input for the next full retrain cycle" | Retrain is done, not "next" |

**Fix needed:** Update Sprint NEXT section, Item 1 status to ✅ Done, remove retrain-pending language, update ROC-AUC to 0.9409, update calibrator status.

### 3. xgboost-investigation-report.md — Stale status header

| Line | Says | Reality |
|------|------|---------|
| 3 | "Status: CURRENT — 5 fixes pending retrain" | All 5 fixes applied in retrain |
| 5-6 | "calibrator and threshold_info.json do not yet exist on disk" | Both exist |
| 212-216 | "xgboost_calibrator.pkl and threshold_info.json are runtime artifacts... not shipped" | Now shipped |

**Fix needed:** Update status to "CURRENT — All 8 fixes applied and model retrained (2026-07-08)". Remove the status note about pending retrain and missing files.

### 4. MVP_SCOPE.md — Multiple stale ROC-AUC references (OUTDATED status, but still misleading)

| Line | Says | Should say |
|------|------|------------|
| 67 | "ROC-AUC 0.9677... retrain pending" | "ROC-AUC 0.9409 (retrained 2026-07-08)" |
| 119 | "ROC-AUC 0.9677... retrain pending" | Add retrain completed note |
| 192 | "ROC-AUC 0.9677" | Same + note about retrain |

**Note:** MVP_SCOPE.md is already OUTDATED so these are lower priority than ROADMAP, but they still contradict reality.

### 5. INDEX.md — Stale reference in xgboost-investigation-report description

**Line 42:** "5 require retrain (pending)" → All retrain fixes are now applied.

### 6. AI_PROBLEMS.md — Stale ROC-AUC reference

**Line 141:** "ROC-AUC: 0.9677" — this references the Sprint 3 model which is now replaced. Low impact (historical context) but should note the current retrained model value.

---

## P2 — Skill File Drift

### 7. ml-engineering/SKILL.md — Stale ROC-AUC

**Line 9:** `ROC-AUC 0.9677` → should be `ROC-AUC 0.9409`

Also **line 66:** "Feature count must stay at 419" — this is contradicted by the 420-dim training. If fix Option B is chosen, 419 is still correct. If Option A, document 420.

### 8. backend-engineering/SKILL.md — Stale ROC-AUC

**Line 18:** `ROC-AUC 0.9677` → should be `ROC-AUC 0.9409`

---

## P3 — Minor / Documentation Gaps

### 9. ROADMAP.md Item #12 (Retrain Verification) — Not yet verified

**Line 203-204:** "compare queue scores to baseline [94,87,71,63,55,41,22] ±3". This verification has not been documented as done. The retrain may have shifted scores.

### 10. test_feature_parity.py — Not documented in skill files

File exists at `backend/tests/test_feature_parity.py` but is not mentioned in:
- `ml-toolbox/SKILL.md` (does mention `analysis.feature_parity_check` but not the pytest guard)
- `ROADMAP.md` (Item #10 on line 202 mentions "Feature-parity guard test" as planned — needs status update)

### 11. test_feature_parity.py location mismatch

User context says `tests/test_feature_parity.py` but actual location is `backend/tests/test_feature_parity.py`. The `backend/tests/test_feature_parity.py` imports suggest it runs from `backend/` directory (uses relative imports like `from ingest_helpers`). This is consistent with how other tests work.

---

## ✅ What's Correct

### Symlinks
All 6 root-level symlinks (`AI_PROBLEMS.md`, `MVP_SCOPE.md`, `RESEARCH_FINDINGS.md`, `ROADMAP.md`, `WINDOWS_SETUP.md`, `XGBOOST_INVESTIGATION_REPORT.md`) are intact and point to valid targets. No broken symlinks found.

### Graphify Outputs
- `graphify_output/file_tree.md` — comprehensive (264 entries), includes all new files
- `graphify_output/ml_inventory.md` — correct ROC-AUC (0.9409), lists all new artifacts (calibrator, threshold_info, pre_retrain model)
- `graphify_output/api_deps.md` — complete dependency map

### INDEX.md Graphify Section
Present and correct at lines 85-94 with all 4 graphify outputs listed.

### AGENTS.md Graphify References
Present and correct at lines 24, 27-28 referencing `graphify_output/ml_inventory.md`, `file_tree.md`, `api_deps.md`.

### Backend ml/README.md
Cleanly trimmed to short pointer to `graphify_output/ml_inventory.md` — correct.

### Archived File References
- `ml-implementation-plan.md` is no longer at `docs/reference/` (correctly moved to `docs/archive/`)
- INDEX.md correctly references the archive path

### `Additional Instructions/` References
Only found in archived files (`SPRINT_1_HANDOFF.md` in `docs/archive/sprints-1-6/`) — NOT an issue since these are archived.

### `just gate` Recipe
Includes `just graphify` at line 169 — correct.

---

## Summary of Required Fixes

| # | Severity | File | Issue | Suggested Fix |
|---|----------|------|-------|---------------|
| 1 | **P0** 🚨 | `xgboost_predictor.py` vs `xgboost_model.pkl` | Dim mismatch (419 vs 420) → crashes | Pad to 420 or retrain without osv_lead_days |
| 2 | P1 | `docs/planning/ROADMAP.md` | Retrain status, ROC-AUC, calibrator all stale | Update Sprint NEXT Item 1, ROC-AUC to 0.9409 |
| 3 | P1 | `docs/reference/xgboost-investigation-report.md` | Status header, calibrator notes stale | Update status & remove "pending" language |
| 4 | P1 | `docs/architecture/MVP_SCOPE.md` | 3 stale ROC-AUC + retrain-pending refs | Update numbers or add context notes |
| 5 | P1 | `.opencode/skills/ml-engineering/SKILL.md` | ROC-AUC 0.9677 → 0.9409 | Update line 9 |
| 6 | P1 | `.opencode/skills/backend-engineering/SKILL.md` | ROC-AUC 0.9677 → 0.9409 | Update line 18 |
| 7 | P1 | `docs/INDEX.md` | "5 require retrain (pending)" | Update description |
| 8 | P2 | `docs/reference/AI_PROBLEMS.md` | Stale ROC-AUC reference (historical, low impact) | Optional: add retrain note |
| 9 | P2 | `docs/planning/ROADMAP.md` | Item #10 feature-parity guard: status not updated | Mark ✅ Done |
| 10 | P2 | `.opencode/skills/ml-toolbox/SKILL.md` | test_feature_parity.py not mentioned | Add pytest command for feature-parity test |

---

## Recommendations

1. **Fix the P0 dimension mismatch FIRST** — before any documentation fix, the pipeline must not crash. Option A (pad predictor to 420) is the quickest; Option B (strip osv_lead_days from training) is more correct.

2. Run `just gate` after the fix to regenerate graphify outputs.

3. Update ROADMAP.md Sprint NEXT section to reflect completed retrain.

4. The xgboost-investigation-report.md should get a status bump — from "CURRENT — 5 fixes pending retrain" to "CURRENT — All 8 fixes applied and retrained" or move to ARCHIVED since it's a historical investigation report.
