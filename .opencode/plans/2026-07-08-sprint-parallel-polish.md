# Sprint: Parallel Polish

**Date:** 8 July 2026
**Type:** Hardening Sprint
**Commander:** Current

## Goal

Execute four independent work items that can run in a parallel git tree without conflicting with the other commander's work (audit sampling fix, model version management, model comparison endpoint). All items touch files completely disjoint from the other tree.

## Context

The other commander is working on:
- Audit sampling fix (`backend/audit.py`)
- Model version management (model config/loading/new API)
- Model comparison endpoint (new API + frontend)

This sprint selects four items that avoid all those touchpoints: CI/CD pipelines, scoring engine tests, frontend polish/JS modernization + dark mode, and seed data ML dimension verification.

## Cross-Tree Coordination Note

The other commander's "model comparison endpoint" includes "minimal frontend display" — this means they will likely add a new `<script>` tag and possibly a new screen `<div>` to `frontend/index.html`. Our Item C (JS modernization) also modifies `index.html` (adding `defer` attributes). This creates a **low-severity merge conflict** — both trees touch adjacent lines in the `<script>` block. Resolution is trivially mechanical: apply our `defer` attributes to all existing `<script>` tags, add their new `<script>` tag (also with `defer`). 30-second manual merge.

**If possible, tell the other commander to use `defer` on any new `<script>` tags they add.**

## Cross-Tree Safety Verification

| Item | Files Touched | Conflicts With Other Tree? |
|---|---|---|
| A: CI/CD | `.github/workflows/ci.yml` only | No — other tree doesn't touch CI |
| B: Scoring tests | `backend/tests/test_scoring.py` (new) | No — new file, zero overlap. `scoring.py` confirmed zero project imports (pure function module). |
| C: Frontend dark mode + JS modernization | `frontend/` only | Low — `index.html` may have trivial merge conflict (see coordination note above). Other tree's model comparison component is a new JS file — won't conflict with existing file edits. |
| D: Seed data ML dimension | Read-only validation + possibly small fix in `seed_data.py` | No — `seed_data.py` is not in the other tree's scope |

## Work Items

### Item A: CI/CD Pipeline Expansion

**Assigned to:** strike (devops-engineering)
**Estimate:** 1 hr
**Description:** The current CI (`ci.yml`) only runs pytest + ruff. This item adds a Docker build job (catches Dockerfile breakage before merge), test coverage reporting via pytest-cov, and a frontend validation step.

Changes:
1. Add a `docker-build` job to `.github/workflows/ci.yml`:
   - Builds the Docker image (`docker build .`) to verify Dockerfile validity
   - Does NOT push — build-only verification
   - Runs on `ubuntu-latest`, only on push to master/sprint-* (not PR, to save CI minutes)
2. Add coverage reporting to the `test` job:
   - Install `pytest-cov`
   - Run `python -m pytest tests/ -v --cov=backend --cov-report=term-missing`
   - Add `--cov-fail-under=60` as a soft gate (current ~66 tests, some modules untested)
3. Add a `frontend-lint` job:
   - Validates `index.html` with a basic HTML check (e.g., `html5validator` or a simple curl + grep for well-formedness)
   - Runs `npx eslint frontend/js/` if we add an `.eslintrc.json` — OR skip ESLint and just verify JS files parse without syntax errors via `node --check`
   - Pragmatic: use `node --check frontend/js/*.js` to catch syntax errors (no npm needed)
4. Update `requirements-dev.txt` with `pytest-cov`

**Assumption:** The Dockerfile builds successfully in CI (it currently builds locally). We're not pushing images — just verifying the build doesn't break. Frontend linting uses `node --check` for syntax-only validation rather than a full linter, avoiding the need for npm/package.json.

**Verification:**
```bash
# Cannot run GitHub Actions locally, but verify:
cd backend && python -m pytest tests/ -v --cov=backend --cov-report=term-missing
docker build .
node --check frontend/js/*.js
```

---

### Item B: Scoring Engine Unit Tests

**Assigned to:** strike (backend-engineering)
**Estimate:** 1 hr
**Description:** `backend/scoring.py` (119 lines) is the core calculation that maps 6 weighted dimensions into a 0-100 priority score and band. It has zero dedicated tests. This item creates comprehensive unit tests for the scoring engine.

Test file: `backend/tests/test_scoring.py`

Test cases (at least 10):
1. `test_default_inputs_returns_reasonable_score` — Call `calculate_final_score()` with minimal args, verify score is 0-100 and band is valid
2. `test_critical_cve_returns_high_score` — CVSS 10, EPSS 0.9, Core mission, Severe wellbeing, internet-facing, no patch → expect score > 80, band "Critical"
3. `test_trivial_cve_returns_low_score` — CVSS 1, EPSS 0.01, Peripheral, Minimal, not internet-facing, patched → expect score < 20, band "Low"
4. `test_mission_prevalence_weights_correctly` — Same CVSS/EPSS, Core vs Peripheral → Core must score higher
5. `test_public_wellbeing_weights_correctly` — Same inputs, Severe vs Minimal → Severe must score higher
6. `test_internet_facing_penalty` — Same inputs, internet-facing vs not → internet-facing must score higher
7. `test_patch_available_reduces_score` — Same inputs, patch_available=True vs False → patched scores lower (or at least not higher)
8. `test_patch_applied_affects_score` — patch_applied=True should reduce score vs False
9. `test_tier_2_adjustment_applied` — Pass tier_2_result with score_adjustment, verify it affects final score
10. `test_substituted_epss_used` — Pass substituted_epss, verify it replaces epss_score in calculation
11. `test_band_mapping_all_levels` — Verify all 4 bands (Critical/High/Medium/Low) can be produced by varying inputs
12. `test_score_clamps_to_0_100` — Verify score never goes below 0 or above 100 regardless of inputs

**Assumption:** The scoring function signature in `scoring.py:14-26` is current and won't change before this sprint. The function uses a weighted-sum approach with 6 dimensions, and the weights are hardcoded. Testing will verify the calculation logic, not that the weights are "correct" (that's a product decision).

**Verification:**
```bash
cd backend && python -m pytest tests/test_scoring.py -v
# All 12+ tests pass
```

---

### Item C: Frontend Dark Mode + JS Modernization

**Assigned to:** strike (frontend-engineering + ux-designing)
**Estimate:** 2 hr
**Description:** Two independent but related frontend improvements that don't touch API contracts.

**CSS audit finding:** The 1667-line CSS uses custom properties for ~50% of color references. The other ~50% are hardcoded hex values. Additionally, the demo controls section (lines 1530-1667) is hardcoded in dark colors (always dark, no light variant). Dark mode requires converting ALL hardcoded colors to custom properties first, then defining dark values. This is more work than the initial estimate but is the correct approach — half-finished dark mode looks broken.

**C1 — Dark mode** (~1.25 hr):
1. Extract all hardcoded hex colors into new CSS custom properties on `:root` (~20 new variables for backgrounds, text, borders, status badges, metric boxes, etc.)
2. Replace all hardcoded hex references with `var(--*)` calls (~50 replacements across the file)
3. Define `[data-theme="dark"]` block with dark-appropriate values for all variables
4. Convert demo controls section (currently always-dark) to use variables so it works in both modes
5. Add a toggle button (sun/moon icon using CSS/unicode, no image assets) in `#top-bar`
6. Persist preference in `localStorage` (`triagemate-theme` key)
7. Check `prefers-color-scheme` media query on first visit
8. Add `transition: background-color 0.3s, color 0.3s, border-color 0.3s` to `body`

**C2 — JS modernization** (~45 min):
All 9 JS files use `var` instead of `let`/`const`. Convert systematically:
1. `frontend/js/app.js` (274 lines)
2. `frontend/js/api.js` (108 lines)
3. `frontend/js/components/queue.js` (136 lines)
4. `frontend/js/components/caseView.js` (122 lines)
5. `frontend/js/components/metricBoxes.js` (39 lines)
6. `frontend/js/components/demoControls.js` (175 lines)
7. `frontend/js/components/auth.js` (240 lines)
8. `frontend/js/components/reviewQueue.js` (300 lines)
9. `frontend/js/components/driftDashboard.js` (96 lines)

Also update `frontend/index.html` to use `defer` on all `<script>` tags (since `let`/`const` are block-scoped and should be loaded in order). Note: this is the same `index.html` that the other commander may touch — see Cross-Tree Coordination Note above.

Rule for conversion: `var` used for reassignment → `let`. `var` never reassigned → `const`. Function-scoped `var` at top level → `let` (may be reassigned). Loop counters → `let`.

**Assumption:** Converting `var` to `let`/`const` is purely syntactic — the existing code doesn't rely on `var` hoisting quirks (e.g., no usage-before-declaration patterns that would hit TDZ with `let`/`const`). Dark mode colors are chosen to maintain WCAG AA contrast ratios (≥4.5:1 for text). The toggle uses CSS/unicode for icons (☀/☾) — no image assets needed.

**Verification:**
```bash
# JS syntax check (Node --check only parses, doesn't execute — safe for DOM-dependent code)
node --check frontend/js/*.js

# HTML loads (requires dev server running)
curl -s http://localhost:8000 | grep -q 'screen-queue' && echo "HTML OK"

# Manual visual checklist:
# 1. Load app, verify all 4 screens render (Queue, Case, Review, Drift)
# 2. Toggle dark mode, verify all UI elements visible (no white-on-white or black-on-black)
# 3. Refresh page, verify dark mode preference persists
# 4. Test demo controls panel in both light and dark modes
# 5. Verify auth modal renders correctly in both modes
# 6. Verify keyboard shortcuts still work (Ctrl+S, Escape)
```

---

### Item D: Seed Data ML Dimension Verification

**Assigned to:** strike (backend-engineering)
**Estimate:** 30 min
**Description:** ROADMAP item #11 — verify that `ml_exploitation_contribution` is correctly populated in seed data demo rows. This is a data quality check.

**Step 0 — Determine expected values (critical first step):** Before any verification, determine what values are SUPPOSED to be in this column. The column was added by Alembic migration 005. It may be populated during ingest/pipeline only (seed data bypasses the pipeline, so 0/NULL is expected) OR seed_data.py may be expected to populate it (bug if missing). This step determines whether the item is a 5-minute verification or a bug fix.

Steps:
1. Check Alembic migration 005 to understand the column schema and default value
2. Read `backend/seed_data.py` to see if it populates `ml_exploitation_contribution`
3. Check the ingest pipeline (`backend/routers/ingest.py`) to see how it's normally populated
4. Query the database (after seed) for values across all demo rows
5. If values are plausible and varied → produce a 1-paragraph verification report. Done.
6. If values are all 0/NULL and should NOT be → fix seed_data.py to populate plausible values, re-seed, verify
7. If values are all 0/NULL and that's EXPECTED (seed bypasses pipeline) → document the finding. Done.

**Assumption:** `ml_exploitation_contribution` is a numeric column on the vulnerabilities table, populated during ingest and/or by seed_data.py. Whether it SHOULD have non-zero values in seed data depends on the pipeline architecture — this is determined in Step 0.

**Verification:**
```bash
cd backend && python -c "
from database import DatabaseManager
db = DatabaseManager()
rows = db.conn.execute('SELECT vulnerability_id, ml_exploitation_contribution FROM vulnerabilities LIMIT 20').fetchall()
for r in rows: print(dict(r))
"
```

---

## Execution Order

All four items are fully independent and can run in any order. However, I recommend this sequence to minimize merge conflict surface:

| Order | Item | Assignee | Risk | Why This Order |
|---|---|---|---|---|
| 1 | A: CI/CD Pipeline Expansion | strike | None | Pure backend infra — zero merge risk, verifiable entirely from CLI |
| 2 | B: Scoring Engine Unit Tests | strike | None | New file only — zero merge risk, fully automated verification |
| 3 | D: Seed Data ML Dimension | strike | None | Read-first approach — determines scope before making changes |
| 4 | C: Frontend Dark Mode + JS Modernization | strike | Low | Highest merge risk due to index.html — run last when we know what the other tree changed |

**If running items in parallel across multiple strike sessions:** A and B can run simultaneously (no shared files). D should complete before any seed_data.py fixes. C should run after D completes if D found a bug that changes seed data (unlikely but possible — both touch different frontend concerns).

---

## Definition of Done

- [ ] CI passes: Docker build job succeeds, coverage reports (≥60%), frontend syntax check passes
- [ ] `pytest tests/test_scoring.py -v` — 12+ tests pass, zero failures
- [ ] `pytest tests/ -v` — all existing tests still pass (no regressions)
- [ ] Dark mode toggle works in both light→dark and dark→light directions
- [ ] Dark mode preference persists across page refresh (localStorage)
- [ ] Demo controls panel renders correctly in both light and dark modes
- [ ] `node --check frontend/js/*.js` — zero syntax errors across all 9 JS files
- [ ] `curl -s http://localhost:8000 | grep -q 'screen-queue'` — HTML loads correctly
- [ ] All 4 screens (Queue, Case, Review, Drift) render visually correct in both modes
- [ ] Seed data verification report produced — values confirmed plausible, OR bug documented with fix applied
- [ ] Bookkeeper freshness pass (at sprint end)
- [ ] Sprint plan filed at `.opencode/plans/2026-07-08-sprint-parallel-polish.md` ✅
