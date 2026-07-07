# Documentation Audit — Round 2

**Date:** 7 July 2026
**Purpose:** Deep re-audit of ALL `.md` files for remaining outdated, incorrect, or contradictory content after Round 1 fixes.
**Method:** Full read of 20+ documentation files, cross-referenced for contradictions, stale references, and command errors.

---

## Previously Fixed (Round 1 — 7 July 2026)

The Round 1 audit identified ~30 issues across 19 files. The following fixes were applied by Strike after Round 1:

| Action | Status |
|--------|--------|
| `SPRINT_7_HANDOFF.md` moved from root → `docs/archive/sprints-1-6/` | ✅ Done |
| `SPRINT_8_HANDOFF.md` moved from root → `docs/archive/sprints-1-6/` | ✅ Done |
| `SPRINT_9_HANDOFF.md` moved from root → `docs/archive/handoffs/` | ✅ Done |
| Root `.md` files moved into `docs/` with symlinks at root (except `AGENTS.md` and `MVP_SCOPE.md`) | ✅ Done |
| `Additional Instructions/` directory removed (duplicates in `docs/reference/`) | ✅ Done |
| `ARCHIVED/` at root removed | ✅ Done |
| Historical banner added to `SPRINT_9_HANDOFF.md` | ✅ Done |
| Caution banner added to `MVP_SCOPE.md` | ✅ Done |
| Status header added to `SPRINT_NEXT_PLAN.md` | ✅ Done |

**Items flagged in Round 1 but NOT yet fixed:** `docker-compose` → `docker compose` in DEMO_SCRIPT.md and WINDOWS_SETUP.md; PRIS Act → WAICP in DEMO_SCRIPT.md; duplicate label J in AI_PROBLEMS.md; training data size contradictions; ROC-AUC clarification in MVP_SCOPE.md; and others detailed below.

---

## New Issues Found

### 1. Score Ordering Contradiction

**Critical finding:** Two different score orderings appear across files for the 7 demo rows. One has score 55 before 63; the other has 63 before 55.

| File | Line | Score Order |
|------|------|-------------|
| `backend/tests/test_queue.py` | 16 | `[94,87,71,63,55,41,22]` ← **Authoritative (test code)** |
| `docs/ROADMAP.md` | 216, 254 | `[94,87,71,63,55,41,22]` ✅ Correct |
| `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` | 43 | `[94,87,71,63,55,41,22]` ✅ Correct |
| `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | 191 | `[94,87,71,63,55,41,22]` ✅ Correct |
| `docs/archive/sprints-1-6/SPRINT_8_HANDOFF.md` | 201 | `[94,87,71,63,55,41,22]` ✅ Correct |
| `docs/archive/sprints-1-6/SPRINT_9_BRIEFING_PLAN.md` | 851 | `[94,87,71,63,55,41,22]` ✅ Correct |
| **`docs/archive/sprints-1-6/SPRINT_7_HANDOFF.md`** | **240** | **`[94,87,71,55,63,41,22]`** ❌ **Wrong order** |
| **`MVP_SCOPE.md`** | **221** | **`(94, 87, 71, 55, 63, 41, 22)`** ❌ **Wrong order** |

**Verdict:** The test file `test_queue.py:16` is authoritative — it is the automated verification. Score 63 (Office RCE, Row 5) comes before score 55 (ScreenConnect, Row 4). Both `SPRINT_7_HANDOFF.md` and `MVP_SCOPE.md` have the incorrect ordering and should be corrected.

---

### 2. Contradictions Between Files

| File A | File B | Contradiction |
|--------|--------|---------------|
| `docs/ROADMAP.md` line 36: "186K feature vectors, 68 columns" | `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` line 7: "144708 samples, 67 features" | Training data size: 186K vs 144K. Self-contradiction within SPRINT_NEXT_PLAN (line 28 says "186K x 68", line 304 says "144708 samples, 67 features"). |
| `docs/ROADMAP.md` line 133: "ROC-AUC 0.9946" | `MVP_SCOPE.md` lines 115,188: "ROC-AUC 0.9677" | Different files claim different ROC-AUC for the same XGBoost model. 0.9946 was pre-fix (had label leakage); 0.9677 was post-fix. Neither is the upcoming retrain. |
| `docs/ROADMAP.md` line 133: "35 tabular + 384 SBERT = 419 total features" | `docs/reference/TriageMate ML Implementation Plan — Final.md` line 138: "37 tabular + 32 PCA text = 69 features" | Feature count mismatch: 419 vs 69. The codebase removed PCA (now 384-dim raw SBERT + 35 tabular = 419), but the ML Plan still describes the old PCA-based pipeline. |
| `docs/ROADMAP.md` line 106: "5 dimensions" | `backend/scoring.py`: 6 dimensions | ROADMAP says the scoring engine has 5 dimensions. The code has had 6 dimensions since Sprint 3 (including ML Exploitation). |
| `docs/DEMO_SCRIPT.md` line 66: "PRIS Act classification" | `backend/scoring.py`, `backend/seed_data.py`: "OFFICIAL Sensitive" / "WAICP" | DEMO_SCRIPT.md uses outdated "PRIS Act" terminology. The codebase uses WAICP terminology. |
| `docs/DEMO_SCRIPT.md` line 13: "docker-compose up" | `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md` line 163: "docker-compose" | Multiple files use the deprecated `docker-compose` (v1) command. Modern Docker uses `docker compose` (v2, space not hyphen). |
| `docs/reference/TriageMate ML Implementation Plan — Final.md` section 2.8: SecureBERT2.0 CWE classifier is active | `docs/AI_PROBLEMS.md` items 1-3: CWE classifier is DEPRECATED | ML Plan says SecureBERT2.0 is live; AI_PROBLEMS says it was bypassed in favour of NVD API + regex. |
| `docs/reference/TriageMate ML Implementation Plan — Final.md` line 758: `backend/ml/cwe_classifier.py` | Actual code: `backend/ml/cwe_classifier_deprecated.py` | ML Plan references a file that no longer exists at that path (renamed to `_deprecated`). |
| `docs/reference/TriageMate ML Implementation Plan — Final.md` section 2.2: PCA is active (384→32 dims) | `docs/ROADMAP.md` line 133: PCA removed (384-dim raw) | ML Plan says PCA is used; ROADMAP and codebase confirm PCA was removed. |

---

### 3. Stale / Dead File References

| File | Line | Bad Reference | What It Should Be |
|------|------|---------------|-------------------|
| `docs/ROADMAP.md` (Project File Map) | 281-284 | `Additional Instructions/` directory listed | Directory no longer exists (removed in Round 1). Remove from map. |
| `docs/ROADMAP.md` (Project File Map) | 285-286 | `ARCHIVED/` directory listed | Directory no longer exists (removed in Round 1). Remove from map. |
| `docs/ROADMAP.md` (Project File Map) | 274-277 | `SPRINT_7_HANDOFF.md`, `SPRINT_8_HANDOFF.md`, `SPRINT_9_HANDOFF.md` listed at root | Files now in `docs/archive/sprints-1-6/` and `docs/archive/handoffs/`. Update paths. |
| `docs/ROADMAP.md` (Project File Map) | 282-283 | `TriageMate ML Implementation Plan — Final.md` and `Hostname and Data Classification Standards.md` listed under `Additional Instructions/` | These now live at `docs/reference/`. |
| `docs/TRIAGEMATE_BOOK_PROMPT.md` | 34 | `Additional Instructions/Hostname and Data Classification Standards.md` and `Additional Instructions/TriageMate ML Implementation Plan - Final.md` | Directory removed. Should reference `docs/reference/` paths instead. |
| `MVP_SCOPE.md` | 5 | `COURSE_CORRECTION.md` and `PRE_DEMO_PLAN.md` referenced as if at root | Both are archived under `docs/archive/sprints-1-6/`. |
| `docs/reference/TriageMate ML Implementation Plan — Final.md` | 762 | `backend/ml/pre_tier_classifier.py` | This file does not exist. The pre-tier model lives at `backend/ml/pre_tier_model.pkl` with logic in `backend/pipeline/pre_tier.py`. |
| `docs/reference/TriageMate ML Implementation Plan — Final.md` | 758 | `backend/ml/cwe_classifier.py` | File renamed to `cwe_classifier_deprecated.py`. |

---

### 4. Command / Example Errors

| File | Lines | Error | Fix |
|------|-------|-------|-----|
| `docs/DEMO_SCRIPT.md` | 13, 133 | `docker-compose up --build` | `docker compose up --build` (or document both) |
| `docs/DEMO_SCRIPT.md` | 134 | `docker-compose up` | `docker compose up` |
| `docs/DEMO_SCRIPT.md` | 147 | "One-command deploy: `docker-compose up`" | `docker compose up` |
| `docs/WINDOWS_SETUP.md` | 115 | `docker-compose up --build` | `docker compose up --build` |
| `docs/WINDOWS_SETUP.md` | 70 | `TRIAGEMATE_API_KEY` — legacy auth env var | Should be `TRIAGEMATE_ADMIN_USER` / `TRIAGEMATE_ADMIN_PASS` for JWT auth |
| `MVP_SCOPE.md` | 29, 135, 196 | `docker-compose` references | `docker compose` |
| `docs/ROADMAP.md` (Project File Map) | 293-295 | `backend/ingest_helpers.py` described as "37-feature vector builder" | It builds 35 tabular features, not 37. |

---

### 5. Remaining Outdated Statements

| File | Lines | Issue |
|------|-------|-------|
| **`docs/ROADMAP.md`** | 36 | "186K feature vectors, 68 columns" — SPRINT_NEXT_PLAN says 144K samples, 67 features. Actual file needs verification. |
| **`docs/ROADMAP.md`** | 106 | "5 dimensions → 0–100 score" — scoring engine has 6 dimensions (ML Exploitation was added). |
| **`docs/ROADMAP.md`** | 133 | "ROC-AUC 0.9946" — this was the pre-fix value with label leakage. The current model (post-cisa_kev removal) achieved 0.9677. Retrain target is unknown. |
| **`docs/ROADMAP.md`** | 179 | "Sprint NEXT — All five priority items are now complete" — but Item 1 retrain has NOT been run (status is 🔧 Retraining). The retrain is the primary action. |
| **`docs/ROADMAP.md`** | 142-151 | Artifact table: `training_data_v2.npz` row says "Was 186K records, now ~144K" but other parts of same file say 186K. Self-contradictory. |
| **`docs/ROADMAP.md`** (File Map) | 268-370 | Entire file map references old directory structure. Needs rewrite to match current `docs/` architecture. |
| **`MVP_SCOPE.md`** | 3 | Caution banner exists, but the document still frames Docker/JWT/Alembic/T3/drift dashboard/Pre-Tier RF as "deferred" (section 3) when they're implemented. Confusing structure. |
| **`MVP_SCOPE.md`** | 64 | "Tier 1: ROC-AUC 0.9946" — contradicts its own lines 115 and 188 (0.9677). Both need context. |
| **`MVP_SCOPE.md`** | 102-103 | 2.4 Pre-Tier: says "55-dimensional hostname feature vector" — verify this matches actual pre_tier.py. |
| **`MVP_SCOPE.md`** | 117 | "PCA text" — PCA has been removed. Should say "384-dim SBERT text." |
| **`MVP_SCOPE.md`** | 221 | Score ordering wrong: `(94, 87, 71, 55, 63, 41, 22)` should be `(94, 87, 71, 63, 55, 41, 22)`. |
| **`docs/AI_PROBLEMS.md`** | 131 | Duplicate label "J" — second J (line 131) should be "K". Flagged in Round 1 but not fixed. |
| **`docs/AI_PROBLEMS.md`** | lines 131-136 | References 69→68 feature count. Feature count is now 35 tabular (+ 384 SBERT). The 69→68 fix was from the cisa_kev removal era. |
| **`docs/DEMO_SCRIPT.md`** | 39, 66, 149 | "PRIS Act" terminology — should be "WAICP" / "OFFICIAL Sensitive." Flagged in Round 1 but not fixed. |
| **`docs/DEMO_SCRIPT.md`** | 40, 149 | "Category 1-4" classification mentioned — WAICP uses OFFICIAL/OFFICIAL Sensitive labels. The codebase does too. |
| **`docs/DEMO_SCRIPT.md`** | 66 | "CVSS contribution, EPSS probability, asset criticality (based on PRIS Act classification), exposure, and patch availability" — lists only 5 dimensions. Should mention 6th (ML Exploitation). |
| **`docs/WINDOWS_SETUP.md`** | 68-70 | Auth setup references `TRIAGEMATE_API_KEY` (legacy X-API-Key middleware). Should reference `TRIAGEMATE_ADMIN_USER` / `TRIAGEMATE_ADMIN_PASS` for JWT auth. |
| **`docs/WINDOWS_SETUP.md`** | 110 | "Docker on Windows: docker-compose up --build" — uses deprecated command. |
| **`docs/archive/handoffs/SPRINT_NEXT_PLAN.md`** | 7, 304, 318 | "Sprint NEXT complete" / corpus build "DONE" — but XGBoost retrain (the primary action) has NOT been run. Misleading status. |
| **`docs/archive/handoffs/SPRINT_NEXT_PLAN.md`** | 28 | "186K x 68" — contradicts line 7 which says "144708 samples, 67 features." Self-contradictory. |
| **`docs/archive/handoffs/SPRINT_9_HANDOFF.md`** | 139-146 | "68 columns: 36 tabular + 32 text PCA" — PCA removed, feature count is now 35 tabular + 384 SBERT. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 80-84 | "Five weighted dimensions (0–100)" — scoring engine has 6 dimensions. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 98-137 | Lists 37 tabular features including `cisa_kev_status` — this was removed as a training feature (label leakage). Current vector is 35 tabular. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 138 | "37 tabular + 32 PCA text = 69 features" — PCA removed, 35 tabular + 384 SBERT now. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 143-144 | "PCA to 32 dimensions... preserves >85% variance" — PCA removed from pipeline. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 218 | "SecureBERT2.0 CWE Encoder" described as active — deprecated. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 501-503 | PCA pipeline code still in the document — deprecated/removed. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 752, 758 | File paths reference `cwe_classifier.py` and `pre_tier_classifier.py` — neither exists in the active codebase. |
| **`docs/reference/TriageMate ML Implementation Plan — Final.md`** | 185 | "Platt scaling via `CalibratedClassifierCV(method='sigmoid')`" — calibration was removed then re-added differently. Current code uses LogisticRegression for Platt scaling, not CalibratedClassifierCV. |
| **`backend/ml/README.md`** | — | `pre_tier_model.pkl` not listed in the active ML components table. |
| **`backend/ml/README.md`** | — | No mention of pending artifacts (`xgboost_calibrator.pkl`, `threshold_info.json`) expected after retrain. |
| **`docs/RESEARCH_FINDINGS.md`** | 57 | States "ExploitDB PoC and Metasploit fields are always False for all 186K entries — zero variance." This was correct at time of writing but may have been addressed in Sprint 9. |
| **`docs/RESEARCH_FINDINGS.md`** | 144-146 | "Sprint NEXT+2" — some recommendations (CWE-stratified thresholds, random seed fix) were already implemented in Sprint NEXT. Document lacks an "implemented items" caveat. |
| **`docs/XGBOOST_INVESTIGATION_REPORT.md`** | 11 | "all of which now have fixes applied to the working tree" — but 5 of 8 fixes require model retraining which has NOT been run. Calibrator and threshold files don't exist. |
| **`docs/XGBOOST_INVESTIGATION_REPORT.md`** | 182-183 | References `xgboost_calibrator.pkl` and `threshold_info.json` that don't exist on disk. Needs status banner. |
| **`docs/TRIAGEMATE_BOOK_PROMPT.md`** | 34 | References `Additional Instructions/` which no longer exists. Should point to `docs/reference/`. |
| **`docs/TRIAGEMATE_BOOK_PROMPT.md`** | 142 | "42 keys" for feature vector — codebase has 35 tabular + 384 SBERT dims. Not "42 keys." |
| **`docs/TRIAGEMATE_BOOK_PROMPT.md`** | 97 | Says PCA "preserves >85% variance" — PCA removed. |
| **`docs/TRIAGEMATE_BOOK_PROMPT.md`** | 98 | "42 keys, never rename/remove" — feature count changed from 42 to 35. Contract already violated. |
| **`docs/archive/sprints-1-6/SPRINT_7_HANDOFF.md`** | 240 | Score ordering `[94,87,71,55,63,41,22]` — should be `[94,87,71,63,55,41,22]`. |

---

### 6. Symlink / Organization Issues (Freshness Carry-Over)

These issues were flagged in the freshness report and remain unfixed:

| Issue | Detail |
|-------|--------|
| `docs/` files are flat, not in categorized subdirectories | `AGENTS.md` says docs should be in `docs/architecture/`, `docs/guides/`, `docs/planning/`, `docs/research/` but all are flat in `docs/root`. Four subdirectories are empty. |
| `MVP_SCOPE.md` is a real file at root (not symlinked) | Should be moved to `docs/architecture/MVP_SCOPE.md` with symlink. |
| `SPRINT_NEXT_PLAN.md` symlink points to archive | Root → `docs/archive/handoffs/SPRINT_NEXT_PLAN.md`. As an active planning document, it should be in `docs/planning/`. |
| `TRIAGEMATE_BOOK_PROMPT.md` references old paths | Line 34 references `Additional Instructions/` — should be `docs/reference/`. |

---

## Consensus Issues (What's the Truth?)

For items where multiple files disagree, here are the verified answers:

| Disputed Fact | Correct Answer | Source of Truth |
|---------------|---------------|-----------------|
| **Score ordering** | `[94, 87, 71, 63, 55, 41, 22]` (63 before 55) | `backend/tests/test_queue.py:16` |
| **Tabular feature count** | 35 features | `backend/ml/xgboost_predictor.py` + `backend/ingest_helpers.py` |
| **Total feature dimensions** | 35 tabular + 384 SBERT = 419 total | `backend/ml/encoder.py` (no PCA), `backend/ml/xgboost_predictor.py` |
| **Scoring dimensions** | 6 dimensions (CVSS, EPSS, Criticality, Exposure, Patch, ML Exploitation) | `backend/scoring.py` |
| **Current XGBoost ROC-AUC** | 0.9677 (pre-retrain model) | `docs/AI_PROBLEMS.md` item J |
| **Training data size** | Disputed: SPRINT_NEXT_PLAN says 144708 records × 67 features on line 7, but 186K × 68 on line 28. **Needs file verification.** | `backend/ml/training_data_v2.npz` (actual file) |
| **PCA status** | REMOVED — raw 384-dim SBERT used directly | `backend/ml/encoder.py` |
| **CWE classifier** | DEPRECATED — NVD API + regex (`ingest_cwe.py`) used instead | `docs/AI_PROBLEMS.md` items 1-3 |
| **Classification terminology** | WAICP: OFFICIAL / OFFICIAL Sensitive (NOT "PRIS Act") | `backend/scoring.py`, WA Government ICP docs |
| **Docker command** | `docker compose` (v2, space, no hyphen) is current; `docker-compose` (v1) works but deprecated | Docker Engine v25+ ships v2 as `docker compose` |
| **Auth env vars** | `TRIAGEMATE_ADMIN_USER` / `TRIAGEMATE_ADMIN_PASS` (NOT `TRIAGEMATE_API_KEY`) | `backend/auth.py` |
| **CWE classifier file** | `backend/ml/cwe_classifier_deprecated.py` (NOT `cwe_classifier.py`) | Actual filesystem |
| **Pre-tier model file** | `backend/ml/pre_tier_model.pkl` (NOT `pre_tier_classifier.py`) | Actual filesystem |

---

### Important: Training Data Size Mystery

The training data dimensions are inconsistently reported across files:

- `docs/ROADMAP.md` line 36: "186K feature vectors, 68 columns"
- `docs/ROADMAP.md` line 142: "Was 186K records, now ~144K"
- `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` line 7: "144708 samples, 67 features"
- `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` line 28: "186K x 68"
- `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` line 304: "144708 samples, 67 features"
- `docs/archive/handoffs/SPRINT_9_HANDOFF.md` line 48: "186K feature vectors × 68 columns"

The 186K figure likely refers to the raw corpus; 144K refers to the filtered training set after temporal/observation window filters. The 68→67 feature discrepancy may reflect whether the label column is counted. **This needs actual file verification:** run `python -c "import numpy as np; d=np.load('backend/ml/training_data_v2.npz'); print(d['X'].shape, d['y'].shape, list(d.keys()))"` to settle it.

---

## Count of Total Issues Found

| Category | Count |
|----------|-------|
| Score ordering contradictions | 2 files |
| Cross-file contradictions (unique pairs) | 10+ pairs |
| Stale/dead file references | 8 occurrences |
| Command errors (`docker-compose`) | 6 occurrences |
| Outdated statements (unfixed from Round 1) | ~25 across 15 files |
| Path organization issues (freshness carry-over) | 4 |
| Unverified training data claims | 5 files contradict |
| **Total unique issues** | **~40+ (many unfixed from Round 1)** |

---

## Final Recommendations (Prioritized)

### P0 — High Impact (fix immediately, <5 min each)

1. **Fix score ordering in `MVP_SCOPE.md` line 221** — `(94,87,71,55,63,41,22)` → `(94,87,71,63,55,41,22)`
2. **Fix duplicate J label in `docs/AI_PROBLEMS.md`** — Rename second "J" at line 131 to "K"
3. **Add status banner to `docs/XGBOOST_INVESTIGATION_REPORT.md`** — Note that code fixes are applied but retrain not yet run
4. **Remove "Sprint NEXT complete" banner from `SPRINT_NEXT_PLAN.md`** — Retrain is still pending

### P1 — Needs Fix Before Next Person Reads These

5. **Fix `docker-compose` → `docker compose` in DEMO_SCRIPT.md and WINDOWS_SETUP.md** — 6 occurrences total
6. **Fix `PRIS Act` → `WAICP`/`OFFICIAL Sensitive` in DEMO_SCRIPT.md** — 3 occurrences
7. **Fix `TRIAGEMATE_API_KEY` → `TRIAGEMATE_ADMIN_USER`/`TRIAGEMATE_ADMIN_PASS` in WINDOWS_SETUP.md** — Line 70
8. **Fix ROADMAP.md Project File Map (lines 268-370)** — Remove references to deleted directories (Additional Instructions/, ARCHIVED/), update sprint handoff paths to archive locations, update ingest_helpers.py description from "37-feature" to "35-feature"
9. **Fix ROADMAP.md scoring dimension count (line 106)** — Change "5 dimensions" to "6 dimensions"

### P2 — Contradictions That Cause Confusion

10. **Fix `docs/ROADMAP.md` training data size** — Resolve 186K vs 144K contradiction across lines 36, 142-146. Verify actual file dimensions.
11. **Fix `docs/ROADMAP.md` ROC-AUC (line 133)** — Clarify 0.9946 was pre-fix, current is 0.9677, retrain target unknown
12. **Fix `SPRINT_NEXT_PLAN.md` data size** — Resolve 186K vs 144K self-contradiction (lines 7, 28, 304)
13. **Fix `docs/TRIAGEMATE_BOOK_PROMPT.md` references (line 34)** — Change `Additional Instructions/` to `docs/reference/`

### P3 — Major Document Revisions (30+ min each)

14. **Major revision of `docs/reference/TriageMate ML Implementation Plan — Final.md`** — This is the document in worst shape. It still describes PCA pipeline, 37 features, SecureBERT2.0 CWE classifier, 5-dimension scoring, and references non-existent files. Needs either comprehensive update to Sprint 9+ reality, or archive with pointer to ROADMAP.md.
15. **Restructure `MVP_SCOPE.md` section 3** — The caution banner helps, but the framing of completed features as "deferred" is confusing. Consider a "Completed Scope Expansions" section (§2.9) that lists Docker, JWT, Alembic, PostgreSQL, T3 queue, drift dashboard, Pre-Tier RF as done.
16. **Organize flat `docs/` files into categorized subdirectories** — Move files into `docs/architecture/`, `docs/guides/`, `docs/planning/`, `docs/research/` per AGENTS.md and update root symlinks. Move `MVP_SCOPE.md` into `docs/architecture/`.

### P4 — Archive Candidates

17. **Archive `docs/archive/handoffs/SPRINT_9_HANDOFF.md`** — Already historical; PCA reference is codebase-incoherent. Movable to `docs/archive/sprints-1-6/` (out of handoffs/ active planning space).
18. **Archive `docs/archive/sprints-1-6/SPRINT_7_HANDOFF.md` and `SPRINT_8_HANDOFF.md`** — Already archived but contain score ordering errors and agent roster that no longer matches. No reader should rely on them.

### P5 — Minor / Cosmetic

19. **Add `pre_tier_model.pkl` to `backend/ml/README.md`** — Currently not listed.
20. **Add pending artifacts to `backend/ml/README.md`** — Mention `xgboost_calibrator.pkl` and `threshold_info.json` as "pending retrain."
21. **Fix `RESEARCH_FINDINGS.md` caveat** — Add note that CWE-stratified thresholds and random seed fix were implemented in Sprint NEXT.
22. **Fix `docs/TRIAGEMATE_BOOK_PROMPT.md` "42 keys" (line 142)** — Change to 35 tabular + 384 SBERT.
23. **Fix `docs/TRIAGEMATE_BOOK_PROMPT.md` PCA reference (line 97)** — Remove or update.

---

## Summary

**Round 1 fixed ~10 structural issues** (file moves, symlinks, directory cleanup) but **most content-level issues remain unfixed**. The Round 1 audit identified ~30 content issues; this Round 2 audit found that ~25 of them are still present, plus ~15 more newly identified.

The most impactful remaining fixes are:
1. **Score ordering** — 2 files wrong (MVP_SCOPE.md, SPRINT_7_HANDOFF.md)
2. **docker-compose → docker compose** — Still in 4 files despite being flagged
3. **PRIS Act → WAICP** — Still in DEMO_SCRIPT.md
4. **Training data size** — 5 files disagree on 186K vs 144K
5. **ML Implementation Plan** — Comprehensive revision or archive needed

The bookkeeper freshness pass should be triggered after these fixes are applied.
