# Bookkeeping Report

**Date:** 2026-07-07
**Trigger:** post-implementation verification after subagent system refinements
**Scope:** 6 changed files (commander.md, strike.md, auditor.md, bookkeeper.md, decision-framework SKILL.md, ingest_helpers.py) + cross-file impact on all `.md` files under `.opencode/` and `docs/`

---

## Auto-Fixed

| File | Fix | Before | After |
|------|-----|--------|-------|
| `.opencode/skills/frontend-engineering/SKILL.md` | Dead skill reference | `triagemate-toolbox` (does not exist) | `triage-toolbox` (correct skill name) |
| `.opencode/skills/ml-engineering/SKILL.md` | Stale file path | `backend/pipeline/ingest_helpers.py` (no such path) | `backend/ingest_helpers.py` (correct) |
| `.opencode/skills/backend-engineering/SKILL.md` | Outdated feature count | `XGBoost (68 features, ROC-AUC 0.9677)` | `XGBoost (419 total features: 35 tabular + 384 SBERT, ROC-AUC 0.9677)` |
| `.opencode/skills/backend-engineering/SKILL.md` | Outdated dimension count | `5-dimension weighted formula (CVSS, EPSS, Asset, Exposure, Patch)` | `6-dimension weighted formula (CVSS, EPSS, Asset Criticality, Exposure, Patch, ML Exploitation)` |

---

## Items Flagged for Human Review

### P1 — Contradictions Between CURRENT Docs

1. **`ml-engineering/SKILL.md` Feature Vector Contract still says "68 features = 35 tabular + 33 signature/derived features"**
   - ROADMAP.md (CURRENT) says the XGBoost model has **419 input dims (35 tabular + 384 SBERT)**.
   - The 68-feature description in the skill predates the PCA removal (v2.5) that switched from compressed SBERT to full 384-dim embeddings.
   - **Impact:** An agent loading this skill will think the feature vector has 68 output features when it actually feeds 419 dims into XGBoost.
   - **Fix needed:** Update the Feature Vector Contract section in `ml-engineering/SKILL.md` (lines 13-47) to describe the current 419-dim setup. Requires confirming the exact expanded tabular count with the strike team.

2. **`ingest_helpers.py` comment says "41 tabular" but ROADMAP.md says "35 tabular"**
   - The latest commit changed the docstring from `"35 tabular + description"` to `"41 tabular + description"` (42 keys total).
   - ROADMAP.md still says the model uses **35 tabular** features.
   - These numbers must reconcile. Either:
     - The 41 raw keys undergo one-hot encoding / expansion to yield 35 model input features (in which case the comment is misleading), or
     - The ROADMAP is stale and the model now uses 41 tabular features (in which case the ROADMAP, training data dims, and `build_tabular_features()` all need updating).

### P2 — Structural Deltas Between Agent Files

3. **`.opencode/DESIGN_RATIONALE.md` — missing `bookkeeper` agent entirely**
   - Says `## Agents (4)` but the team now has 5 agents (commander, strike, intel, auditor, **bookkeeper**).
   - The commander description (line 8) says `"Delegates ALL work to subagents (strike, intel, auditor)"` — missing bookkeeper.
   - The "Skills — Legacy (3, kept unchanged)" section (lines 144-166) still references `dual-database-ddl` and `feature-vector-spec` as active skills. Both were archived to `.opencode/ARCHIVED/skills/` during the 2026-07-07 consolidation.
   - **Note:** This is a design-rationale document — treat as a "living design doc" or "time capsule" at your discretion. If living, it needs updates. If time-capsule, add a status banner.

4. **`.opencode/RESTRUCTURE_HANDOFF.md` — references now-archived skills as active**
   - Lines 60-64 list `dual-database-ddl` and `feature-vector-spec` under "Skills — Legacy (3 kept unchanged)". Both were archived on 2026-07-07, the day after this handoff was written.
   - Same decision needed as #3: add a note or leave as-is.

### P3 — Stale References in Reports

5. **`backend/reports/audits/tool-audit-2026-07-07.md` line 254**
   - Lists `ml-engineering` referencing `backend/pipeline/ingest_helpers.py` as "✅ Exists" — but actual path is `backend/ingest_helpers.py`. The import check may have passed, but the documented path is wrong.

---

## Orphans Found

- **No new orphaned references.** Previous round's findings (DESIGN_RATIONALE.md and RESTRUCTURE_HANDOFF.md referencing archived skills) remain as open items flagged above.

- **Archived files in `docs/archive/` not listed in INDEX.md:**
  - `docs/archive/Additional Information.md`
  - `docs/archive/EXTERNAL_AUDITOR_PROMPT.md`
  - `docs/archive/External Auditor Response.md`
  - `docs/archive/SECOND_WAVE_PROMPT.md`
  - `docs/archive/TriageMate ML Research.md`
  - `docs/archive/TriageMate ML Research Prompt.md`
  - `docs/archive/TriageMate MVP Transformation.md`
  - **Assessment:** These are all archived files. INDEX.md lists `SPRINT_NEXT_PLAN.md` and uses glob patterns for `handoffs/` and `sprints-1-6/` but omits the top-level archive files. Recommendation: Either list them or document the coverage gap.

---

## Cross-Reference Check

| Source | Reference | Status |
|--------|-----------|--------|
| `commander.md` | `cli-toolbox` skill, `triage-toolbox` skill | ✅ Both exist |
| `strike.md` | `cli-toolbox` skill (in Loadable Skills table) | ✅ Exists at system level |
| `strike.md` | All 10 engineering skills in loadable table | ✅ All 10 exist as active skills |
| `auditor.md` | `audit-checklist`, `wa-gov-consulting`, `privacy-legal-advising`, `backend-engineering`, `ml-engineering`, `cli-toolbox` | ✅ All exist |
| `bookkeeper.md` | No Loadable Skills table (uses own checklist) | ✅ N/A |
| `intel.md` | `intel-toolbox`, `wa-gov-consulting`, `privacy-legal-advising`, `cli-toolbox` | ✅ All exist |
| `intel.md` | 6 data source files in backend/data/ | ✅ All exist |
| `backend-engineering/SKILL.md` | Related Skills: `ml-engineering`, `new-integration-pattern` | ✅ Both exist |
| `ml-engineering/SKILL.md` | Related Skills: `ml-toolbox` | ✅ Exists |
| `frontend-engineering/SKILL.md` | Related Skills: `ux-designing`, `triage-toolbox` | ✅ **Fixed** (was `triagemate-toolbox`) |
| `docs/INDEX.md` | All 16 CURRENT/OUTDATED/ARCHIVED documents | ✅ All paths resolve |

---

## Coverage Gaps

- **`intel-toolbox/SKILL.md`** does not list the two new intel reports (`code-audit-full-2026-07-07.md`, `code-audit-loop2-2026-07-07.md`) — these are reports, not data sources, so likely out of scope.
- **`decision-framework` SKILL.md** was listed as a changed file but is outside the repo — could not be verified.

---

## Terminology Consistency Check

| Term | Active Docs | Archived Docs | Verdict |
|------|------------|---------------|---------|
| `PRIS Act` | 0 occurrences | 1 (COURSE_CORRECTION.md) | ✅ Clean |
| `docker-compose` vs `docker compose` | All use `docker compose` | — | ✅ Clean |
| `triagemate-toolbox` vs `triage-toolbox` | 1 broken ref **fixed** | — | ✅ Fixed |
| Feature counts (68 vs 419) | 2 skills stale | — | ⚠️ Flagged |
| Dimension counts (5 vs 6) | 1 skill **fixed** | — | ✅ Fixed |

---

## MCP Tool Consistency Check

| MCP Tool | `opencode.jsonc` | Referenced In | Status |
|----------|-----------------|---------------|--------|
| `db` (SQLite) | ✅ Registered | `backend-engineering/SKILL.md` | ✅ |
| `memory` | ✅ Registered | `commander.md` | ✅ |
| `filesystem` | ✅ Registered | `strike.md` | ✅ |
| `think` | ✅ Registered | `strike.md` | ✅ |

All MCP tools consistently registered and referenced.

---

## Verdict

**MINOR ISSUES** — 4 auto-fixed, 5 flagged for human review

### Summary
**Auto-fixes applied:**
- `frontend-engineering/SKILL.md`: dead skill link `triagemate-toolbox` → `triage-toolbox`
- `ml-engineering/SKILL.md`: stale path `backend/pipeline/ingest_helpers.py` → `backend/ingest_helpers.py`
- `backend-engineering/SKILL.md`: feature count 68→419 dims, dimension count 5→6

**Top priorities for human review:**
1. **P1** — `ml-engineering/SKILL.md` Feature Vector Contract still describes old 68-feature system (contradicts CURRENT ROADMAP)
2. **P1** — `ingest_helpers.py` docstring says "41 tabular" vs ROADMAP's "35 tabular" — needs reconciliation
3. **P2** — `DESIGN_RATIONALE.md` missing bookkeeper, references archived skills — needs update or status banner
4. **P2** — `RESTRUCTURE_HANDOFF.md` references archived skills as active
5. **P3** — `backend/reports/audits/tool-audit-2026-07-07.md` has stale ingest_helpers.py path
