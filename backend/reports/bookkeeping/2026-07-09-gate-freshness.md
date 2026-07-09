# Bookkeeping Report

**Date:** 2026-07-09
**Trigger:** Gate freshness pass — post-recent-fixes verification

---

## Items Verified (Cross-Doc Contradictions)

### 1. Migration count — ✅ CONSISTENT
| Source | Claim | Actual |
|--------|-------|--------|
| ROADMAP.md:152 | `Alembic migrations (001–007)` | 7 version files on disk (001–007) |
| ROADMAP.md:195 | `7 versioned migrations` | Matches |
| INDEX.md:99 | `research_references \| 97` | Table count matches (not migration-related but verified) |

**Verdict:** All sources agree on 7 Alembic migrations.

### 2. AI_PROBLEMS.md open items count — ✅ CONSISTENT
| Source | Claim | Actual |
|--------|-------|--------|
| INDEX.md:20 | `2 open items (pipeline drifts)` | AI_PROBLEMS.md items 15 & 16 OPEN |
| INDEX.md:42 | `Bug tracker — 2 open items (pipeline drifts)` | Same |
| INDEX.md:76 | `What's broken? — 2 open pipeline drifts` | Same |

The 2 OPEN items are `_cvss_cia` default mismatch (#15) and `lateral_reachability` type mismatch (#16), both MEDIUM severity. All other items are ✅ FIXED or ✅ BYPASSED.

**Verdict:** All sources agree on 2 open items.

### 3. Duplicate file deleted — ✅ RESOLVED
| What was checked | Status |
|------------------|--------|
| `docs/planning/file-consolidation-plan-2026-07-07.md` | ❌ **Does not exist** (correctly deleted) |
| `docs/archive/file-consolidation-plan-2026-07-07.md` | ✅ Exists (single canonical copy) |

No references to the old `planning/` path exist in any active `.md` file. All references use `archive/` path.

### 4. main.py static paths — ✅ CORRECT
| Path | Resolution |
|------|-----------|
| `frontend/css/` | `os.path.join(_PROJECT_ROOT, "frontend", "css")` — dynamic, relative to `__file__` |
| `frontend/js/` | Same pattern |
| `frontend/index.html` | Same pattern |

No hardcoded absolute paths. `_PROJECT_ROOT` resolves to the repo root by navigating up one level from `backend/main.py`.

---

## Cross-Document Consistency Check (INDEX.md vs MVP_SCOPE.md vs AI_PROBLEMS.md)

| Check | Result |
|-------|--------|
| INDEX.md:19 says MVP_SCOPE.md is OUTDATED | ✅ MVP_SCOPE.md:3 has `OUTDATED` badge with caution banner |
| INDEX.md:27 says MVP_SCOPE.md is OUTDATED | ✅ Same badge |
| INDEX.md:20 says AI_PROBLEMS.md is CURRENT | ✅ AI_PROBLEMS.md:3 has `CURRENT` badge |
| INDEX.md:42 says AI_PROBLEMS.md is CURRENT | ✅ Same |
| INDEX.md:18 says ROADMAP.md is CURRENT | ✅ ROADMAP.md:3 has `CURRENT` badge |
| INDEX.md:33 says ROADMAP.md is CURRENT | ✅ Same |

**Verdict:** Status badges are consistent between INDEX.md and the documents themselves.

---

## Minor Issues Found (Auto-fixable / Flagged)

### P3 — ROADMAP.md §Feature Field Status note contradicts table contents

**File:** `docs/planning/ROADMAP.md:76`
**Issue:** The note reads:
> "The 2 excluded: `cisa_kev` (label leakage — removed from training features; it IS the target variable) and `description` (feeds SBERT encoder, not tabular)."

But the table of 37 collected fields (entries 1–37) **does not contain `cisa_kev`**. The field `cisa_kev` was removed from the collection set entirely at an earlier stage (documented in AI_PROBLEMS.md Item A). It cannot be "excluded" from a set it is not in.

The two features in the table that are excluded from tabular model input are:
- `description` (feeds SBERT encoder)
- `osv_lead_days` (stored as NPZ metadata, not a model input)

The note should reference `osv_lead_days` instead of `cisa_kev`.

**Suggestion:** Change note to: "The 2 excluded: `description` (feeds SBERT encoder, not tabular) and `osv_lead_days` (metadata, not a model input)."

---

### P3 — INDEX.md lists archive file under Planning section

**File:** `docs/INDEX.md:36`
**Current entry (under `## Planning`):**
```
| `archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED | Bookkeeper's consolidation proposals — superseded by current doc structure. See `docs/INDEX.md`. |
```

The file path starts with `archive/` but the entry is in the **Planning** section table. Either:
- Move this entry to the `## Archive` section below, or
- Keep it in Planning with a clearer prefix note

**Note:** The path itself is correct (`archive/file-consolidation-plan-2026-07-07.md` exists) — this is a section-placement issue only.

---

### P4 — AI_PROBLEMS.md 36→35 tabular feature reduction undocumented

**File:** `docs/reference/AI_PROBLEMS.md:139-141` (Item K)
**Issue:** Item A+K document the reduction from 37→36 tabular features (removing `cisa_kev`). ROADMAP.md describes 35 tabular features (current). The reduction from 36→35 is not documented anywhere in AI_PROBLEMS.md or ROADMAP.md. There is a gap in the paper trail.

**Impact:** Low. The numbers are consistent across CURRENT docs (all say 35 tabular features). The missing step only affects historical traceability.

---

### P4 — AGENTS.md Quick Reference omits useful docs

**File:** `AGENTS.md:19-30`
**Observation:** The Quick Reference table doesn't mention:
- `docs/planning/HANDOFF-2026-07-08.md` (handoff — current project state summary)
- `backend/reports/intel/wa-gov-infrastructure-research.md` (WA gov research — already in INDEX.md but not in AGENTS.md quick ref)

---

### P4 — backlog/ directory not discoverable from INDEX.md

**File:** `backlog/TASK_STORE_COLUMNS_IN_NPZ.md`
**Issue:** The `backlog/` directory and its task document are not referenced in INDEX.md or AGENTS.md. An AI agent searching for task documents would not find it. The file is self-described as "Task: Store Column Names in NPZ Metadata" — which has been implemented. The document may be stale.

**Note:** Previous bookkeeping report (gate-loop-2026-07-08.md) deemed this "outside `docs/` tree — no INDEX entry needed." Flagging for review: should it be archived or moved to `docs/planning/`?

---

## Orphans Found

### Intentional (no action needed)
| Reference | Reason |
|-----------|--------|
| Archived docs referencing old paths (`integrations/llm.py`, `venv/`, etc.) | Archive docs preserved as historical record |
| MVP_SCOPE.md references "migration 005" (line 84) | Correct — migration 005 is a specific file (005_add_ml_exploitation.py) |
| AI_PROBLEMS.md historical feature counts (37→36) | Historical documentation of past fixes |

### Not found — clean
| Pattern | Result |
|---------|--------|
| `docs/planning/file-consolidation-plan-*-*.md` | ✅ No references to deleted planning-path copy |
| `integrations/llm.py` references in active docs | ✅ Clean (all fixed in hygiene pass) |
| `backend/venv/` references | ✅ Clean (all updated to `.venv`) |

---

## Coverage Gaps

| Gap | Details |
|-----|---------|
| `backlog/` directory undocumented | Task document `TASK_STORE_COLUMNS_IN_NPZ.md` exists but is invisible from INDEX.md. May be stale (task described as already completed). |

---

## Root Symlink Verification

| Symlink | Resolves | Status |
|---------|----------|--------|
| `AI_PROBLEMS.md → docs/reference/AI_PROBLEMS.md` | ✅ | Valid |
| `MVP_SCOPE.md → docs/architecture/MVP_SCOPE.md` | ✅ | Valid |
| `RESEARCH_FINDINGS.md → docs/research/RESEARCH_FINDINGS.md` | ✅ | Valid |
| `ROADMAP.md → docs/planning/ROADMAP.md` | ✅ | Valid |
| `WINDOWS_SETUP.md → docs/guides/WINDOWS_SETUP.md` | ✅ | Valid |
| `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` | ✅ | Valid |

All 6 root-level symlinks resolve correctly. 0 broken symlinks.

---

## Verdict

**MINOR ISSUES**

The major cross-document contradictions that triggered this pass (migration count, AI_PROBLEMS.md entries, duplicate file deletion, main.py static paths) are all **resolved and consistent**. No P0 or P1 issues remain.

Two P3 issues remain:
1. ROADMAP.md note refers to `cisa_kev` as excluded from a table where it doesn't appear (should reference `osv_lead_days`)
2. INDEX.md lists an `archive/`-path file under the Planning section instead of Archive

Both are worth fixing in the next hygiene round but do not affect document coherence.
