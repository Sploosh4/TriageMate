# Round 5 Structural Audit
**Date:** 7 July 2026
**Trigger:** Structural audit (all checks)

## Overall Verdict: MINOR ISSUES

3 new issues found. The documentation skeleton is structurally sound — all INDEX.md paths resolve, all active docs have status badges, and deleted files are truly gone. However, the stale `Additional Instructions/` directory persists (flagged in 4 prior reports but never removed), and several docs still reference old filenames.

---

## Check Results

| # | Check | Result | Details |
|---|---|---|---|
| 1 | Root `.md` entries | ✅ PASS | 7 files at root: `AGENTS.md`, `AI_PROBLEMS.md`, `MVP_SCOPE.md`, `RESEARCH_FINDINGS.md`, `ROADMAP.md`, `WINDOWS_SETUP.md`, `XGBOOST_INVESTIGATION_REPORT.md`. All present. |
| 2 | Root `.md` — real vs symlink | ⚠️ SOFT FLAG | AGENTS.md claims root `.md` files (except itself) are symlinks into `docs/`. File info tool follows symlinks so cannot verify directly. Content is identical between root and `docs/` counterparts, consistent with symlinks. No broken links detected. |
| 3 | Additional Instructions/ | 🔴 ISSUE | Directory **still exists** with 2 files: `Hostname and Data Classification Standards.md` and `TriageMate ML Implementation Plan — Final.md`. Both are duplicates of `docs/reference/hostname-standards.md` and `docs/reference/ml-implementation-plan.md` respectively. This was flagged for removal in ROUNDS 1–4 of bookkeeping. |
| 4 | INDEX.md — every path check | ✅ PASS | All 13 referenced paths in `docs/INDEX.md` resolve to existing files. |
| 5 | Reverse — `docs/` files NOT in INDEX | ✅ PASS | All 10 active (non-archive) docs are listed in INDEX.md. 7 archive files (`Additional Information.md`, `EXTERNAL_AUDITOR_PROMPT.md`, etc.) are intentionally excluded per `ai-doc-strategy.md`. |
| 6 | Status badges on all active docs | ✅ PASS | All 10 active docs have a `Status:` badge in the first 5 lines. CURRENT: 7, OUTDATED: 2 (`MVP_SCOPE.md`, `ml-implementation-plan.md`), ARCHIVED: in archive section. |
| 7 | Deleted files — still gone? | ✅ PASS | All 6 paths (`DEMO_SCRIPT.md`, `TRIAGEMATE_BOOK_PROMPT.md`, `SPRINT_NEXT_PLAN.md`, `docs/guides/DEMO_SCRIPT.md`, `docs/guides/TRIAGEMATE_BOOK_PROMPT.md`, `docs/planning/SPRINT_NEXT_PLAN.md`) are confirmed gone. |
| 8 | AGENTS.md path references | ✅ PASS | All 9 path references in AGENTS.md (both Quick Reference table and Directory Map) exist on disk. |
| 9 | Old filename references in current docs | 🔴 ISSUE | See "Old Names Still in Use" below. |
| 10 | PRIS Act reference check | ✅ PASS | Only 1 occurrence, in archived `COURSE_CORRECTION.md` — not actionable. |
| 11 | `docker-compose ` reference check | ✅ PASS | Only 3 occurrences in archived files (`TEAM_BRIEFING.md`, `SPRINT_7_HANDOFF.md`) — historical context, not actionable. |
| 12 | Complete `docs/` tree | ✅ PASS | Tree structure matches INDEX.md. No orphan directories. |

---

## Issues Found

### 🔴 Issue 1: `Additional Instructions/` directory still exists (now flagged x5)

**First flagged:** Bookkeeping Round 1 (freshness-2026-07-07.md)
**Re-flagged:** Rounds 2, 3, 4, and now 5

The directory contains 2 files that are exact duplicates of files in `docs/reference/`:
- `Additional Instructions/Hostname and Data Classification Standards.md` ↔ `docs/reference/hostname-standards.md` (both 38,650 bytes, same content)
- `Additional Instructions/TriageMate ML Implementation Plan — Final.md` ↔ `docs/reference/ml-implementation-plan.md` (both 46,020 bytes, same content)

**Action:** `rm -rf "Additional Instructions/"` — the `docs/reference/` versions are the canonical ones.

### 🔴 Issue 2: Old filename `XGBOOST_INVESTIGATION_REPORT` referenced in current docs

The filename was renamed from `XGBOOST_INVESTIGATION_REPORT.md` (uppercase) to `xgboost-investigation-report.md` (kebab-case). The old name still appears in:

| File | Context |
|---|---|
| `docs/planning/ROADMAP.md:282` | Project File Map: `├── XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | Multiple references using old name |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | Multiple references, often in consolidation proposal context |

**Assessment:** The ROADMAP.md line 282 is a stale entry in the File Map showing the old name — should read `xgboost-investigation-report.md`. The ai-doc-strategy and file-consolidation-plan are CURRENT planning docs that reference the old name as part of their analysis; they should be updated to use the current filename.

### 🔴 Issue 3: Old filename `Hostname and Data Classification Standards` still referenced

The file was renamed from `Hostname and Data Classification Standards.md` (spaces, title case) to `hostname-standards.md` (kebab-case). Old name appears in:

| File | Context |
|---|---|
| `docs/planning/ai-doc-strategy-2026-07-07.md` | Multiple table entries using old filename |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | Consolidation plan references the old name |

**Assessment:** These are CURRENT planning docs that need their references updated to the current filename.

### 🔴 Issue 4: Old name `ML Implementation Plan — Final` still referenced

| File | Context |
|---|---|
| `docs/planning/ai-doc-strategy-2026-07-07.md` | Multiple references using old name |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | Consolidation plan references old name |
| `docs/reference/ml-implementation-plan.md` | Self-references in title and body (title still says "TriageMate ML Implementation Plan — Final") |

**Assessment:** Same pattern — planning docs reference old filenames.

### 🟡 Issue 5: Deleted file `DEMO_SCRIPT.md` still referenced in archived content

| File | Context |
|---|---|
| `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md:139` | `**File:** New — \`DEMO_SCRIPT.md\`` |

**Assessment:** This is in an archived file so it's low-priority, but it's the original source reference for why the symlink existed. Document for provenance.

---

## Orphans Found

None. No archived files are referenced by current (non-archive) docs in a live manner. All old-name references in planning docs are self-referential (documents describing their own consolidation).

---

## Coverage Gaps

None detected. INDEX.md covers all active docs; the structure matches the tree.

---

## SPRINT_9_HANDOFF.md Accuracy Check

**Claim checked:** Line 50 states "Training data v2 | 144K samples × 67 features (+ label = 68 columns)."

**Verdict: ✅ ACCURATE.** The claim 144K × 67 features (+ label = 68 columns) is correct per the current state. The task prompt mentioned a claim of "186K × 68 columns" on line 48, but line 48 is actually the ExploitDB row. Line 50 is the training data row and it reads correctly as "144K samples × 67 features (+ label = 68 columns)". No discrepancy.

---

## Complete Action Items List

| Priority | Action | Command / Details | Previously Flagged? |
|---|---|---|---|
| 🔴 HIGH | Remove `Additional Instructions/` directory | `rm -rf "Additional Instructions/"` | Rounds 1, 2, 3, 4 |
| 🔴 HIGH | Fix `ROADMAP.md:282` — old filename reference | Change `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` to `xgboost-investigation-report.md → docs/reference/xgboost-investigation-report.md` | New |
| 🟡 MEDIUM | Update `ai-doc-strategy-2026-07-07.md` — replace all old filenames | Replace all `XGBOOST_INVESTIGATION_REPORT.md` with `xgboost-investigation-report.md`, `Hostname and Data Classification Standards.md` with `hostname-standards.md`, `ML Implementation Plan — Final.md` with `ml-implementation-plan.md` | New |
| 🟡 MEDIUM | Update `file-consolidation-plan-2026-07-07.md` — same filename fixes | Same replacements as above | New |
| 🟢 LOW | `PRE_DEMO_PLAN.md:139` references `DEMO_SCRIPT.md` | Archived file, low priority. Note for provenance. | New |

---

## Files Modified This Audit

None — read-only audit. No auto-fixes applied as all identified issues require human judgment or `rm` commands.
