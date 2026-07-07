# Final Freshness Report

**Date:** 7 July 2026
**Trigger:** Post-Round-2 audit (final freshness pass)

---

## Overall Verdict: CLEAN — Minor Issues Remain

All active documentation files are structurally sound. Round 2 fixes resolved all critical issues (PRIS Act → WAICP, docker-compose → docker compose, duplicate label J). A few minor clarity/consistency issues persist in MVP_SCOPE.md and ROADMAP.md that should be flagged for human review.

---

## Checks

### 1. Root `.md` Files — Symlink Integrity

| File | Type | Resolution |
|---|---|---|
| `AGENTS.md` | **REAL** (1,553 bytes) | ✅ Core agent instructions file |
| `MVP_SCOPE.md` | **REAL** (19,328 bytes) | ✅ Scope authority document |
| `AI_PROBLEMS.md` | Symlink → `docs/reference/AI_PROBLEMS.md` | ✅ Resolves correctly (13,015 bytes, same inode) |
| `DEMO_SCRIPT.md` | Symlink → `docs/guides/DEMO_SCRIPT.md` | ✅ Resolves correctly (7,565 bytes, same inode) |
| `RESEARCH_FINDINGS.md` | Symlink → `docs/research/RESEARCH_FINDINGS.md` | ✅ Resolves correctly |
| `ROADMAP.md` | Symlink → `docs/planning/ROADMAP.md` | ✅ Resolves correctly (19,281 bytes, same inode) |
| `SPRINT_NEXT_PLAN.md` | Symlink → `docs/planning/SPRINT_NEXT_PLAN.md` | ✅ Resolves correctly |
| `TRIAGEMATE_BOOK_PROMPT.md` | Symlink → `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | ✅ Resolves correctly |
| `WINDOWS_SETUP.md` | Symlink → `docs/guides/WINDOWS_SETUP.md` | ✅ Resolves correctly (2,905 bytes, same inode) |
| `XGBOOST_INVESTIGATION_REPORT.md` | Symlink → `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | ✅ Resolves correctly |

**Result: 2 real files + 8 symlinks, all resolving correctly.** ✅

> **Note:** The user's check expected 2 real + 9+ symlinks. 8 are present. No symlink is broken. No root .md file exists without a docs/ counterpart, and vice versa.

### 2. `docs/` Subdirectory File Tree

```
docs/
├── architecture/
│   └── MVP_SCOPE.md
├── archive/
│   ├── Additional Information.md
│   ├── EXTERNAL_AUDITOR_PROMPT.md
│   ├── External Auditor Response.md
│   ├── SECOND_WAVE_PROMPT.md
│   ├── TriageMate ML Research Prompt.md
│   ├── TriageMate ML Research.md
│   ├── TriageMate MVP Transformation.md
│   ├── handoffs/
│   │   └── SPRINT_9_HANDOFF.md
│   └── sprints-1-6/
│       ├── COURSE_CORRECTION.md
│       ├── DEMO_DATA_GENERATOR_PLAN.md
│       ├── DEMO_DATA_GENERATOR_SCOPE.md
│       ├── PRE_DEMO_PLAN.md
│       ├── SPRINT_1_HANDOFF.md
│       ├── SPRINT_2_HANDOFF.md
│       ├── SPRINT_3_HANDOFF.md
│       ├── SPRINT_7_HANDOFF.md
│       ├── SPRINT_8_HANDOFF.md
│       ├── SPRINT_9_BRIEFING_PLAN.md
│       └── TEAM_BRIEFING.md
├── guides/
│   ├── DEMO_SCRIPT.md
│   ├── TRIAGEMATE_BOOK_PROMPT.md
│   └── WINDOWS_SETUP.md
├── planning/
│   ├── ROADMAP.md
│   └── SPRINT_NEXT_PLAN.md
├── reference/
│   ├── AI_PROBLEMS.md
│   ├── Hostname and Data Classification Standards.md
│   ├── TriageMate ML Implementation Plan — Final.md
│   └── XGBOOST_INVESTIGATION_REPORT.md
└── research/
    └── RESEARCH_FINDINGS.md
```

**Result: 5 subdirectories, all populated.** ✅

### 3. Empty Subdirectory Check

| Directory | File Count | Status |
|---|---|---|
| `docs/architecture/` | 1 | ✅ Populated |
| `docs/guides/` | 3 | ✅ Populated |
| `docs/planning/` | 2 | ✅ Populated |
| `docs/reference/` | 4 | ✅ Populated |
| `docs/research/` | 1 | ✅ Populated |
| `docs/archive/` | 7 + 1 + 11 | ✅ Populated |

**Result: No empty subdirectories.** ✅

### 4. `Additional Instructions/` Integrity

| File | Type | Resolution |
|---|---|---|
| `Hostname and Data Classification Standards.md` | Symlink → `docs/reference/Hostname and Data Classification Standards.md` | ✅ Resolves (38,627 bytes, same inode) |
| `TriageMate ML Implementation Plan — Final.md` | Symlink → `docs/reference/TriageMate ML Implementation Plan — Final.md` | ✅ Resolves (45,941 bytes, same inode) |

**Result: 2 symlinks, both resolving to `docs/reference/`.** ✅ No duplicate real files.

### 5. Archive Completeness

All historical documents are properly archived under `docs/archive/`:
- 7 root archive files (prompts, research, transformation docs)
- `handoffs/` — Sprint 9 handoff
- `sprints-1-6/` — 11 sprint documents (handoffs, plans, briefing, course correction)

**Result: Archive is complete.** ✅ No active-doc staleness from unarchived references.

### 6. Stale Terminology Scan

#### "PRIS Act" in active docs

| Location | Status |
|---|---|
| `docs/guides/DEMO_SCRIPT.md` | ✅ **CLEAN** — 0 occurrences (fixed in Round 2) |
| `docs/guides/WINDOWS_SETUP.md` | ✅ **CLEAN** — 0 occurrences |
| `docs/architecture/MVP_SCOPE.md` | ✅ **CLEAN** — 0 occurrences |
| `docs/planning/*.md` | ✅ **CLEAN** |
| `docs/reference/*.md` | ✅ **CLEAN** |
| `docs/research/*.md` | ✅ **CLEAN** |
| `AGENTS.md` | ✅ **CLEAN** |
| **Code files** (seed_data.py, scoring.py, tier_0.py, cmdb.py, pretier_features.py) | ⚠️ Still contain PRIS Act references — **code is out of bookkeeper scope** |
| **Frontend files** (demo-reference.html, index.html) | ⚠️ Contain PRIS Act in inline demo data — **out of bookkeeper scope** |

#### `docker-compose ` (with space) in active docs

| Location | Status |
|---|---|
| `docs/guides/DEMO_SCRIPT.md` | ✅ **CLEAN** — uses `docker compose` |
| `docs/guides/WINDOWS_SETUP.md` | ✅ **CLEAN** — uses `docker compose` |
| `docs/architecture/MVP_SCOPE.md` | ✅ **CLEAN** — uses `docker compose` |
| `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | ✅ **CLEAN** — only references `docker-compose.yml` (filename, not command) |
| `docs/planning/*.md` | ✅ **CLEAN** |
| **Archive files** (TEAM_BRIEFING.md, SPRINT_7_HANDOFF.md) | 🟡 Historical references — acceptable |
| **`.opencode/ARCHIVED/agents/devops-engineer.md`** | 🟡 Archived agent description — acceptable |

**Result: All active docs clean of stale terminology.** ✅

---

## Issues Flagged for Human Review

### 1. MVP_SCOPE.md — Potential training size contradiction

- **Line 65:** "XGBoost model trained on **~144K** post-KEV CVEs" (describes what's in scope)
- **Line 117:** "Retrained on **93,018** post-KEV CVEs" (describes Sprint 3 historical state)

These describe different model versions (144K = future/aspirational corpus; 93,018 = old Sprint 3 model), but appearing in the same document without clarification could confuse a reader. Consider adding temporal context, e.g., "Retrained in Sprint 3 on 93,018 post-KEV CVEs (superseded by 144K v2 corpus)."

### 2. ROADMAP.md — Ambiguous retrain status / ROC-AUC

- **Line 133:** "ROC-AUC 0.9677 post-fix" ✅ (old model)
- **Line 142:** "XGBoost model... Retraining — New: 144K records, ROC-AUC **0.9946**, trained, calibrator pending (needs retrain run)"

The 0.9946 value for the new dataset is suspicious — it matches the pre-fix value from the old model that had label leakage. If this is aspirational rather than actual, it should be marked as such. If the model has actually been trained with 0.9946, the `🔧 Retraining` status is stale.

### 3. Code files still reference "PRIS Act"

The following code files use "PRIS Act" terminology in docstrings/comments:
- `backend/scoring.py` (lines 37, 68)
- `backend/pipeline/tier_0.py` (line 35)
- `backend/integrations/cmdb.py` (line 169)
- `backend/ml/pretier_features.py` (line 310)
- `backend/seed_data.py` (lines 65, 151, 332, 510, 692, 875, 1058, 1240)

If the project is standardising on "WAICP" / "OFFICIAL Sensitive" terminology, these should be updated. ⚠️ Bookkeeper is read-only on code — flagging for engineering team.

### 4. Frontend demo data still references "PRIS Act"

- `index.html` and `demo-reference.html` contain inline demo data with "PRIS Act 2024 Schedule 2" classification labels. These are baked-in demo strings, not documentation. If the demo should reflect WAICP terminology, these need a separate frontend fix.

---

## Orphans Found

None. All archived files are properly isolated and no active doc references point into archives (except cross-references in handoff docs, which is expected).

---

## Auto-Fixed This Round

| File | Fix | Details |
|---|---|---|
| `docs/guides/DEMO_SCRIPT.md` | `PRIS Act` → `WAICP` | 3 occurrences replaced with WAICP/OFFICIAL Sensitive terminology |
| `docs/guides/DEMO_SCRIPT.md` | `docker-compose` → `docker compose` | 3 occurrences of deprecated command replaced |
| `docs/guides/WINDOWS_SETUP.md` | `docker-compose` → `docker compose` | 1 occurrence replaced |
| `docs/reference/AI_PROBLEMS.md` | Duplicate label J removed | Cleaned up (Round 2 fix) |

(These fixes were applied in previous bookkeeping rounds and verified as complete in this pass.)

---

## Remaining Issues (Summary)

| Severity | Issue | File(s) | Action |
|---|---|---|---|
| 🟡 Low | Training size contradiction (144K vs 93K) | MVP_SCOPE.md lines 65, 117 | Add temporal clarification |
| 🟡 Low | Ambiguous ROC-AUC/retrain status | ROADMAP.md line 142 | Clarify actual vs aspirational |
| ⚠️ Info | PRIS Act in code docstrings | 5 backend files | Engineering review needed |
| ⚠️ Info | PRIS Act in demo HTML data | index.html, demo-reference.html | Frontend/seed data fix |

---

## Verdict

**FRESH — Minor Issues Remain**

Round 2 fixes are fully verified. All active documentation uses correct terminology. No broken symlinks, no empty directories, no orphaned references. The remaining items are clarity/consistency nits in two scope/planning files and code-level terminology that is outside the bookkeeper's write scope.
