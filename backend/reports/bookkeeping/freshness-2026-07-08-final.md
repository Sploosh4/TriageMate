# Bookkeeping Report

**Date:** 2026-07-08
**Trigger:** sprint-end (Sprint 14 — Research & Synthetic Data)
**Auditor:** bookkeeper

## Audit Checklist Applied

| # | Check | Result |
|---|-------|--------|
| 1 | Cross-file contradictions | ✅ No contradictions found between ROADMAP.md, INDEX.md, AI_PROBLEMS.md |
| 2 | Stale file references | ⚠️ Minor (see Items Flagged) |
| 3 | Numeric consistency | ✅ All counts match across files (1,827 assets, 777 findings, 97 refs, 1,476 training rows, 351 holdout) |
| 4 | Terminology drift | ✅ No drift — `has_known_system` references are all transitional (documenting replacement by `system_category`) |
| 5 | Status badge accuracy | ✅ All INDEX.md badges match reality |
| 6 | INDEX.md completeness | ✅ All active docs listed; archive files intentionally excluded per INDEX.md note |

---

## Auto-Fixed

| File | Fix | Before → After |
|------|-----|----------------|
| `.opencode/skills/ml-engineering/SKILL.md` | Added `train_epss_v4.py` to Key Files list | `train_epss_v2.py`, `train_epss_v3.py` → `train_epss_v2.py`, `train_epss_v3.py`, `train_epss_v4.py` |
| `.opencode/skills/triage-toolbox/SKILL.md` | Added `train-epss-v4` and `retrain-all` commands to ML Training section | Missing both commands → added after `generate-hostnames`, before `ingest-docs` |

---

## Items Flagged for Human Review

### 1. `triage-toolbox/SKILL.md` — `generate-hostnames` is legacy
- **Issue:** Line 59 still lists `just generate-hostnames` (the old `generate_supplemental_hostnames.py` script). Both old and new generator scripts exist on disk. The old script is no longer part of the `retrain-all` pipeline. Should this be deprecated, removed, or documented as a legacy path?
- **Current mitigation:** Added `(legacy)` annotation via auto-fix. Full removal or deprecation banner needs human decision.
- **Previous report:** Also flagged in `freshness-2026-07-08.md` (line 36, item 4).

### 2. `ml-toolbox/SKILL.md` — `generate_supplemental_hostnames` command
- **Issue:** Line 76 lists `python -m ml.generate_supplemental_hostnames` as a standalone command with no deprecation note. The new generator is `generate_synthetic_data_v2.py`. Both coexist.
- **Suggestion:** Either add a deprecation note or move to an "Archive/Legacy" section.

### 3. `ROADMAP.md` and `INDEX.md` — Fallback chain omits v2, v1, and heuristic
- **Files affected:** `docs/planning/ROADMAP.md` (lines 145, 289) and `docs/INDEX.md` (line 91)
- **Current text (both):** `EPSS cache → EPSS v4 → EPSS v3`
- **Actual chain (in `epss_substitutor.py`):** `EPSS cache (real scores) → v4 → v3 → v2 → v1 → heuristic rule engine`
- **Severity:** Low — the docs correctly identify the primary path but omit secondary/tertiary fallbacks. The `epss_substitutor.py` docstring (lines 7-11) has the full chain. Consider whether to expand the ROADMAP.md and INDEX.md references.

### 4. `ml-engineering/SKILL.md` — `generate_synthetic_findings.py` not listed as key file
- **Issue:** The Key Files section lists `train_epss_v2.py`, `train_epss_v3.py`, `train_epss_v4.py` (now), and `epss_substitutor.py`, but doesn't mention `generate_synthetic_findings.py` (the input data generator for v4). This is less critical since it's a data generator, not a model file.

---

## Orphans Found

### Active files still referencing `generate_supplemental_hostnames.py`
- `.opencode/skills/ml-toolbox/SKILL.md` — line 76 (`python -m ml.generate_supplemental_hostnames`)
- `justfile` — lines 132-133 (`generate-hostnames` recipe)
- `backend/reports/audits/tool-audit-2026-07-07.md` — line 53 (tool audit table)
- `backend/reports/intel/code-audit-teamB-2026-07-07.md` — line 10 (file list)
- `graphify_output/file_tree.md` — line 125 (auto-generated, will fix on next `just graphify`)
- `graphify_output/api_deps.md` — line 299 (auto-generated, will fix on next `just graphify`)
- `graphify_output/ml_inventory.md` — lines 39, 71 (auto-generated, will fix on next `just graphify`)

**Status:** The old file still exists on disk (`backend/ml/generate_supplemental_hostnames.py`, 16 KB). These references are not "dead" — the file exists. The question is whether to keep maintaining it. The `graphify_output/` files are auto-generated and will self-correct on next `just graphify`.

### `synthetic_findings_v4.json` — never referenced in any .md
- **File:** `backend/ml/synthetic_findings_v4.json` (352 KB, exists on disk)
- **Issue:** This JSON output file from `generate_synthetic_findings.py` is not mentioned in any skill file or index. It's listed in the code (`generate_synthetic_findings.py` line 42) as an output path. Low severity — files under `backend/ml/` don't all need doc entries (only `backend/ml/README.md` exists as a nearby artifact index).

### `epss_model.pkl`, `epss_model_v2.pkl` — referenced in reports but NOT in INDEX.md/ROADMAP.md fallback chain docs
- These exist on disk but are omitted from the documented fallback chain (see Item 3 above).

---

## Coverage Gaps

| Gap | Details |
|-----|---------|
| `triage-toolbox/SKILL.md` missing `retrain-all` and `train-epss-v4` | ✅ **FIXED** (auto-fix applied) |
| `ml-engineering/SKILL.md` missing `train_epss_v4.py` | ✅ **FIXED** (auto-fix applied) |
| Intel-toolbox integration coverage | ✅ Complete — all 10 integrations documented |
| Sprint 14 scripts documented? | ✅ INDEX.md §New Scripts covers all 4 new scripts |

---

## Verdict

**MINOR ISSUES** — No P0 contradictions found. Three auto-fixes applied. Four items flagged for human review, mostly around deprecation status of `generate_supplemental_hostnames.py` and fallback chain completeness in docs.

### What to do next
1. **Decide fate of `generate_supplemental_hostnames.py`** — deprecate/remove or keep as legacy path
2. **Consider expanding fallback chain docs** in ROADMAP.md and INDEX.md to mention v2, v1, heuristic
3. **Run `just graphify`** to regenerate auto-generated files (fixes stale references in `graphify_output/`)

---

## File-by-File Freshness Status

| File | Status | Notes |
|------|--------|-------|
| `docs/INDEX.md` | 🟡 FRESH (needs human review) | Fallback chain omits v2, v1, heuristic |
| `docs/planning/ROADMAP.md` | 🟡 FRESH (needs human review) | Fallback chain omits v2, v1, heuristic |
| `docs/reference/AI_PROBLEMS.md` | ✅ FRESH | All issues marked resolved |
| `docs/architecture/MVP_SCOPE.md` | ✅ FRESH (OUTDATED by design) | Banner correctly warns it's Sprint 1 era |
| `AGENTS.md` | ✅ FRESH | References correct docs |
| `.opencode/skills/ml-toolbox/SKILL.md` | 🟡 FRESH | `generate_supplemental_hostnames` needs deprecation note |
| `.opencode/skills/triage-toolbox/SKILL.md` | ✅ FRESH (auto-fixed) | Missing commands added |
| `.opencode/skills/ml-engineering/SKILL.md` | ✅ FRESH (auto-fixed) | Missing v4 training file added |
| `.opencode/skills/backend-engineering/SKILL.md` | ✅ FRESH | Sprint 14 tables, system_category, dual DDL all documented |
| `.opencode/skills/intel-toolbox/SKILL.md` | ✅ FRESH | All integrations listed |
| `.opencode/skills/audit-checklist/SKILL.md` | ✅ FRESH | Audit procedures current |
| `.opencode/skills/devops-engineering/SKILL.md` | ✅ FRESH | `docker-compose` description is correct (file is named `docker-compose.yml`) |
| `.opencode/DESIGN_RATIONALE.md` | ✅ FRESH | Archived skills rationale preserved |
