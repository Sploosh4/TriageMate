# Bookkeeping Report

**Date:** 2026-07-10
**Trigger:** Sprint 20 completion

## Files Modified

### ROADMAP.md (`docs/planning/ROADMAP.md`)

| Change | Location | Before | After |
|--------|----------|--------|-------|
| Test count | §Current State | `343 pass, 0 fail` | `412 pass, 0 fail` |
| Sprints completed | §Current State | `17, 18, 19` | `17, 18, 19, 20` |
| Sprint 19 deferred bonuses note | §Sprint 19 | Referenced deferral to Sprint 20 | Updated to reflect re-organization (Config API → Sprint 21, Webhook → Sprint 21, CI/Alembic/Rollback → Sprint 22) |
| Sprint 20 status | §Sprint 20 | `🟡 Planned` with placeholder descriptions | `✅ Complete` with detailed descriptions and test counts (31 + 18 + 16 = 65 new tests) |
| Quick Start test count | §Quick Start | `343 tests, 343 pass` | `412 tests, 412 pass` |

### INDEX.md (`docs/INDEX.md`)

| Change | Location | Before | After |
|--------|----------|--------|-------|
| Sprint completion list | Core Documents | `Sprints 17, 18 & 19 complete` | `Sprints 17, 18, 19 & 20 complete` |
| Sprint completion list | Planning section | `Sprints 17, 18 & 19 complete` | `Sprints 17, 18, 19 & 20 complete` |
| Sprint 20 summary | Planning section (description) | Missing | Added "Sprint 20 added multi-step agentic LLM, customizable risk multipliers, and safe PCA." |
| Test count | §Sprint 16 ML Test Files | `343+ tests` | `412+ tests` |
| Sprint 20 section | New section | Missing | Full Sprint 20 component table + test file listing |
| Sprint 20 test file names | §Sprint 20 test files | Incorrect (4 separate files: `test_agent_tools.py`, `test_agent_loop.py`, `test_scoring_weights.py`, `test_pca.py`) | Corrected to actual files (`test_tier2_agent.py`, `test_admin.py`, `test_ml_pipeline.py` with 6 PCA methods) |

## Auto-Fixed

- `docs/INDEX.md` §Sprint 20 test files — corrected 4 phantom file names to real implementation. Agent tool tests and agent loop tests are merged into `test_tier2_agent.py` (633 lines). Admin config tests are in `test_admin.py` (356 lines). PCA tests are methods in `test_ml_pipeline.py` (6 methods).

## Items Flagged for Human Review

- **`backend/pipeline/config/scoring_weights.json`** — Listed in INDEX.md as a component file for customizable risk multipliers, but does not exist on disk. It's described as an optional gitignored override file. May be created at runtime by the admin API or test fixtures. Verify whether this is expected (runtime-only artifact) or if a default file should be committed.
- **`backend/ml/pca_model.pkl`** — Listed in INDEX.md as a PCA model artifact, but does not exist on disk. Generated at training time. Verify this is expected (only created during model training, not at inference startup).
- **ROADMAP.md §Sprint 19 note** — The deferred Sprint 19 bonuses B-G were updated to reflect their new locations in Sprint 21/22, but these should be confirmed by the commander as accurate.

## Cross-Reference Verification

| Check | Status | Details |
|-------|--------|---------|
| ROADMAP ↔ INDEX contradictions | ✅ Clean | Test counts, sprint numbers, and descriptions agree |
| INDEX.md completeness | ✅ Clean | All 12 non-archive `.md` files in `docs/` are listed |
| Stale "343" references | ✅ Clean | No remaining `343 pass/test` references in ROADMAP.md or INDEX.md |
| INDEX.md badge accuracy | ✅ Clean | All CURRENT/OUTDATED/ARCHIVED badges match reality |
| ROADMAP plan file references | ✅ Clean | `.opencode/plans/2026-07-10-sprint-20-planning.md`, `sprint-19.md`, and `sprint-21.md` all exist on disk |
| Item 12 status | ✅ Verified | Still shows 🟡 **Planned for Sprint 21** in §Later — Medium-Term Engineering |

## Coverage Gaps

- None identified. Sprint 20's 3 items (Agentic LLM, Customizable Weights, Safe PCA) are documented in both ROADMAP.md and INDEX.md.

## Current Test Count

**412 pass, 0 fail** (Sprint 20 added 65 new tests: 31 agent + 18 admin + 16 PCA)

## Verdict

**FRESH** — All required updates applied. Two minor runtime-artifact notes flagged for human review.
