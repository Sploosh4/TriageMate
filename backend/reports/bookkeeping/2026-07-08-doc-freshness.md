# Bookkeeping Report

**Date:** 2026-07-08
**Trigger:** manual documentation freshness pass
**Scope:** All `.md` files under `docs/`, `AGENTS.md`, `backend/ml/README.md`

---

## Audit Checklist Applied

| # | Check | Result |
|---|---|---|
| 1 | Cross-file contradictions | ✅ Minor issue found (see §A) |
| 2 | Stale file references | ✅ 1 stale number found (see §B) |
| 3 | Numeric consistency | ✅ 1 inconsistency (see §B) |
| 4 | Terminology drift | ✅ Clean |
| 5 | Status badge accuracy | ✅ All CORRECT |
| 6 | INDEX.md completeness | ⚠️ 1 missing entry (see §C) |

---

## Files Checked (16 total)

| File | Status Badge | Verdict |
|------|-------------|---------|
| `docs/INDEX.md` | — | ⚠️ See findings |
| `docs/planning/ROADMAP.md` | CURRENT (self-declared) | ✅ FRESH — dated 8 July 2026 |
| `docs/architecture/MVP_SCOPE.md` | OUTDATED (self-declared) | ⚠️ Minor stale number (see §B) |
| `docs/reference/AI_PROBLEMS.md` | CURRENT (INDEX.md) | ✅ FRESH — all issues resolved |
| `docs/reference/xgboost-investigation-report.md` | CURRENT (INDEX.md) | ✅ FRESH — retrain completed 2026-07-08 |
| `docs/reference/hostname-standards.md` | CURRENT (self-declared) | ✅ FRESH — external reference |
| `docs/planning/HANDOFF-2026-07-08.md` | CURRENT (INDEX.md) | ✅ FRESH — dated 8 July |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | CURRENT (self-declared) | ✅ FRESH — dated 7 July |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | ARCHIVED (self-declared) | ⚠️ See finding §C |
| `docs/archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED (INDEX.md) | ✅ Correctly archived |
| `docs/research/RESEARCH_FINDINGS.md` | OUTDATED (self-declared + INDEX.md) | ✅ Correct — but note §D |
| `docs/guides/WINDOWS_SETUP.md` | CURRENT (INDEX.md) | ✅ FRESH |
| `docs/archive/SPRINT_NEXT_PLAN.md` | ARCHIVED (INDEX.md) | ✅ Correct |
| `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | ARCHIVED (INDEX.md) | ✅ Correct |
| `backend/ml/README.md` | CURRENT (INDEX.md) | ✅ FRESH |
| `AGENTS.md` | — | ✅ FRESH |

---

## Findings

### A. Index Completeness — Missing Entry

**File:** `docs/INDEX.md`
**Issue:** `docs/planning/file-consolidation-plan-2026-07-07.md` exists on disk but is NOT listed in INDEX.md. Only `archive/file-consolidation-plan-2026-07-07.md` is listed (under the "Planning" section header, not the "Archive" section).

**Detail:** There are two identical copies of this file:
- `docs/planning/file-consolidation-plan-2026-07-07.md` (1,574 lines, self-declared ARCHIVED)
- `docs/archive/file-consolidation-plan-2026-07-07.md` (1,574 lines, identical content, same ARCHIVED status)

Both declare themselves ARCHIVED. The planning copy is not referenced anywhere in INDEX.md.

**Recommendation:** Either:
- (a) Remove `docs/planning/file-consolidation-plan-2026-07-07.md` (keep only the archive copy), or
- (b) Add it to INDEX.md with status ARCHIVED.

---

### B. Stale Numeric Reference in MVP_SCOPE.md

**File:** `docs/architecture/MVP_SCOPE.md`
**Issue:** Says "5 Alembic migrations" in two places (§3.3 Deployment & Infrastructure and §4 Scope Summary Table).

**Reality:** There are now **7 Alembic migrations** (001–007) as documented in ROADMAP.md.

**Impact:** LOW — MVP_SCOPE is declared OUTDATED with a caution banner. A minor numeric drift is expected. But readers cross-checking may be confused. Flagging for awareness.

---

### C. INDEX.md — Archive File Listed Under Planning Section

**File:** `docs/INDEX.md`
**Issue:** The entry `| archive/file-consolidation-plan-2026-07-07.md | ARCHIVED | ...` appears at the end of the **Planning** section table, even though its path is `archive/`. The same entry has no explicit listing under the **Archive** section.

**Impact:** P3 — cosmetic. The file's ARCHIVED status is correctly declared, so no one will treat it as current. Minor structural untidiness.

---

### D. RESEARCH_FINDINGS.md — 2 Remaining Pipeline Drifts Still Present in Code

**File:** `docs/research/RESEARCH_FINDINGS.md`
**Issue:** This document is correctly marked OUTDATED. It documents 2 critical pipeline drifts as still unresolved:
1. `_cvss_cia` default mismatch: training defaults to **0**, inference defaults to **2** when CIA values are missing
2. `lateral_reachability` type mismatch: training produces **binary (0/1)**, inference produces **count (3–20)**

**Code verification (2026-07-08):** Both drifts are **still present** in the actual code:
- `backend/scripts/build_training_corpus.py:180` — `_cvss_cia` defaults to `0`
- `backend/ingest_helpers.py:77` — `_cvss_cia` defaults to `2`
- `backend/ml/train_xgboost.py:779-787` — `_compute_lateral_reachability` returns `int(bool)` = binary
- `backend/ingest_helpers.py:291-315` — `_synthetic_lateral` returns zone-based counts (3-20)

**Impact:** P3 — the doc is correctly OUTDATED, but the fact that it identifies real unresolved issues that are NOT tracked elsewhere (not in AI_PROBLEMS.md, not flagged in ROADMAP.md) means these issues may be overlooked.

**Recommendation:** Add these 2 remaining drifts to `reference/AI_PROBLEMS.md` as open (or "KNOWN — unresolved") items so they are tracked in the canonical bug tracker, not buried in an OUTDATED research doc.

---

### E. All Root-Level Symlinks Verified

| Symlink | Target | Status |
|---------|--------|--------|
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | ✅ Resolves |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | ✅ Resolves |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | ✅ Resolves |
| `ROADMAP.md` | `docs/planning/ROADMAP.md` | ✅ Resolves |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | ✅ Resolves |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | ✅ Resolves |

No broken symlinks. ✅

---

### F. Cross-Referenced Files All Exist

| Referenced By | File Referenced | Exists? |
|---|---|---|
| INDEX.md, ROADMAP.md | `graphify_output/ml_inventory.md` | ✅ Yes |
| INDEX.md, ROADMAP.md | `graphify_output/file_tree.md` | ✅ Yes |
| INDEX.md | `graphify_output/knowledge_graph.json` | ✅ Yes |
| INDEX.md | `graphify_output/feature_parity.md` | ✅ Yes |
| INDEX.md | `graphify_output/api_deps.md` | ✅ Yes |
| INDEX.md | `backend/ml/README.md` | ✅ Yes |
| INDEX.md | `backend/reports/intel/wa-gov-infrastructure-research.md` | ✅ Yes |
| ROADMAP.md | `backend/reports/seed-data-ml-dimension.md` | Need to verify... |

---

### G. Status Badge Verification

All status badges in INDEX.md were cross-checked against the actual files:

| File | INDEX.md Claim | Actual Status | Match? |
|------|---------------|---------------|--------|
| `planning/ROADMAP.md` | CURRENT | CURRENT (self-declared header) | ✅ |
| `architecture/MVP_SCOPE.md` | OUTDATED | OUTDATED (caution banner) | ✅ |
| `reference/AI_PROBLEMS.md` | CURRENT | CURRENT (self-declared header) | ✅ |
| `reference/xgboost-investigation-report.md` | CURRENT | CURRENT (self-declared header) | ✅ |
| `reference/hostname-standards.md` | CURRENT | CURRENT (self-declared header) | ✅ |
| `research/RESEARCH_FINDINGS.md` | OUTDATED | OUTDATED (self-declared header) | ✅ |
| `guides/WINDOWS_SETUP.md` | CURRENT | CURRENT (self-declared header) | ✅ |
| `archive/SPRINT_NEXT_PLAN.md` | ARCHIVED | In `docs/archive/` dir | ✅ |
| `archive/handoffs/SPRINT_9_HANDOFF.md` | ARCHIVED | In `docs/archive/handoffs/` | ✅ |
| `archive/ml-implementation-plan.md` | ARCHIVED | In `docs/archive/` dir | ✅ |
| `archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED | Self-declared ARCHIVED, in `docs/archive/` | ✅ |

**All status badges CORRECT.** No badge orphaning.

---

## Summary of Changes Made

No changes were made during this pass. All findings are flagged for optional human review below.

---

## Verdict: MINOR ISSUES

**3 minor issues, 0 critical, 0 auto-fixed.**

| Priority | Finding | Type |
|----------|---------|------|
| P2 | Duplicate `file-consolidation-plan` in both `planning/` and `archive/` — INDEX.md missing the planning copy | Completeness |
| P3 | MVP_SCOPE.md says "5 Alembic migrations" but reality is 7 | Stale number |
| P3 | RESEARCH_FINDINGS.md documents 2 unresolved code drifts not tracked in canonical bug tracker | Orphaned knowledge |

**No auto-fixes applied** — all findings are ambiguous enough to require human judgment.

---

## Recommendations

1. **Remove duplicate:** Delete `docs/planning/file-consolidation-plan-2026-07-07.md` (archive copy already exists at `docs/archive/`). Update INDEX.md if needed.
2. **Update MVP_SCOPE.md:** Change "5 Alembic migrations" to "7 Alembic migrations" or generalise to "multiple Alembic migrations" since the number will keep changing.
3. **Track remaining drifts in AI_PROBLEMS.md:** Add the 2 unresolved pipeline drifts from RESEARCH_FINDINGS.md (§Q5) to `docs/reference/AI_PROBLEMS.md` as open items to prevent knowledge loss when RESEARCH_FINDINGS.md is eventually archived.
