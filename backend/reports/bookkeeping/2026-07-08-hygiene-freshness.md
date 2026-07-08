# Bookkeeping Report

**Date:** 2026-07-08
**Trigger:** Sprint 15.5 Hygiene Cleanup — Phase D (Documentation Sync)

---

## 1. Files Checked and Their Status

| File | Status | Notes |
|---|---|---|
| `docs/INDEX.md` | ✅ UPDATED | Sprint count (14→15), graphify counts (255→299 entries, 371→421 deps) |
| `docs/planning/ROADMAP.md` | ✅ UPDATED | Sprint 15 + 15.5 rows added, migration count (005→007), migration version count (5→7), venv→.venv |
| `docs/planning/HANDOFF-2026-07-08.md` | ✅ UPDATED | `llm.py` reference updated to `pipeline/tier_2.py` |
| `docs/architecture/MVP_SCOPE.md` | ⚠️ Stale but OUTDATED | 4 occurrences of "5 migrations" should be "7", 63 columns should be updated. Document is marked OUTDATED — intentional staleness. |
| `docs/reference/AI_PROBLEMS.md` | ✅ FRESH | All issues resolved. No migration 005 bug tracked. No update needed. |
| `docs/reference/xgboost-investigation-report.md` | ✅ FRESH | No stale references to deleted files. |
| `docs/guides/WINDOWS_SETUP.md` | ✅ FRESH | Already uses `.venv` (updated in hygiene cleanup). |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | ✅ FRESH | No stale references. |
| `docs/research/RESEARCH_FINDINGS.md` | ✅ FRESH | No stale references to deleted files. |
| `backend/ml/README.md` | ✅ FRESH | Points to auto-generated `ml_inventory.md`. |
| `backend/reports/intel/wa-gov-infrastructure-research.md` | ✅ FRESH | No stale references. |
| Auto-generated `graphify_output/*` | ✅ REGENERATED | `just graphify` completed successfully — see §4. |

---

## 2. Orphaned References Found (Auto-Fixed)

### 2.1 Stale `integrations/llm.py` references — FIXED

| File | Fix Applied |
|---|---|
| `.opencode/skills/cloud-llm-engineering/SKILL.md:3,25` | Removed `integrations/llm.py` from description and Key Files section. Merged provider abstraction notes into `tier_2.py` entry. |
| `.opencode/DESIGN_RATIONALE.md:75,77` | Updated description quote and rationale note. Added historical note about `llm.py` removal. |
| `docs/planning/HANDOFF-2026-07-08.md:130` | Changed `LLM (llm.py) \| ✅ Active` to `LLM (pipeline/tier_2.py) \| ✅ Active (code merged from deprecated integrations/llm.py)` |

### 2.2 Stale `backend/venv/` references — FIXED

| File | Fix Applied |
|---|---|
| `docs/planning/ROADMAP.md:302` (was 302, now 376) | `source venv/bin/activate` → `source .venv/bin/activate` |

### 2.3 Stale Alembic migration counts — FIXED

| File | Fix Applied |
|---|---|
| `docs/planning/ROADMAP.md:150` | `001–005` → `001–007` |
| `docs/planning/ROADMAP.md:192` | `5 versioned migrations` → `7 versioned migrations` |

### 2.4 Stale graphify counts — FIXED

| File | Fix Applied |
|---|---|
| `docs/INDEX.md` | `file_tree.md`: `255+ entries` → `299 entries`, `api_deps.md`: `371 dependencies` → `421 dependencies` |

### 2.5 Stale sprint counts — FIXED

| File | Fix Applied |
|---|---|
| `docs/INDEX.md` | `14 completed` → `15 completed` (with Sprints 1–15.5 noted) |

---

## 3. Orphans Found — Intentional Preserves (Not Fixed)

These references are in **archive/plan/historical** documents and are correctly left as-is:

| File | Reference | Reason |
|---|---|---|
| `.opencode/ARCHIVED/agents/cloud-llm-engineer.md:19` | `integrations/llm.py` | Archived agent spec — preserved for historical record |
| `.opencode/plans/2026-07-08-sprint-15.md:31` | `integrations/llm.py` | Historical plan document — correctly documents what was done |
| `.opencode/plans/2026-07-08-sprint-15-HALFWAY.md` | `integrations/llm.py` | Historical plan document |
| `.opencode/plans/2026-07-08-hygiene-plan.md` | `integrations/llm.py` | The hygiene plan itself — correctly documents the removal |
| `docs/archive/*` (multiple files) | `venv/` references | Archive docs — do not need updating by policy |
| `docs/archive/*` (multiple files) | `backend/integrations/` | Archive docs referencing integration modules |
| `backend/reports/audits/*` | `integrations/llm.py` | Historical audit reports documenting state at time of audit |

### Not Found (clean)

| Pattern | Result |
|---|---|
| `xgboost_model_old.pkl` | ✅ No references in any `.md` files |
| `xgboost_model_pre_retrain.pkl` | ✅ No references in any `.md` files |
| `training_data_v2_pre_clean.npz` | ✅ No references in any `.md` files (except the ROADMAP Sprint 15.5 section listing it as deleted) |

---

## 4. Graphify Results

`just graphify` completed successfully with no errors:

| Artifact | Count | Change |
|---|---|---|
| `file_tree.md` | 299 entries | +44 (was 255+). Includes new migrations, test files, stress infra. |
| `api_deps.md` | 421 dependencies | +50 (was 371). Net increase despite `integrations/llm.py` removal — new code adds more imports. |
| `knowledge_graph.json` | 44 nodes, 14 edges | Unchanged |
| `ml_inventory.md` | Generated | Updated following model_registry.json cleanup |
| `feature_parity.md` | Generated | Updated |

---

## 5. Cross-Reference Check

### INDEX.md → all referenced files exist ✅
Verified all 15+ files listed in INDEX.md exist on disk. No dead links.

### ROADMAP.md Related Skills
- `Related Skills` sections verified across current docs
- Agent `Loadable Skills` tables verified

### Migration Doc
No separate migration tracking document exists. Migration state is tracked in:
- `ROADMAP.md` — migration count updated to 001–007
- `backend/alembic/versions/` — 7 migration files on disk

---

## 6. Coverage Gaps

### Noted (low priority — document is OUTDATED)
- `docs/architecture/MVP_SCOPE.md` — 4 references to "5 Alembic migrations" and "63 columns" are stale. Document carries a caution banner and is marked OUTDATED. Consider whether to update or leave as historical artifact.

---

## 7. Items Flagged for Human Review

| Item | Severity | Details |
|---|---|---|
| `MVP_SCOPE.md` stale migration counts | P3 — OUTDATED doc | 4 references say "5 migrations" but 7 exist. Document explicitly marked OUTDATED, so this is expected. Defer to next scope update. |
| `backend/reports/audits/` historical references | P4 — Historical docs | Several audit reports reference `integrations/llm.py` as missing/required. These are historical records of past audits. No action needed. |

---

## 8. Verdict

### **FRESH** ✅

All identified issues have been corrected or noted. No structural contradictions between CURRENT docs. Documentation is consistent with the codebase state after the hygiene cleanup.

### Changes Made Summary
1. **ROADMAP.md** — Added Sprint 15 (Production Confidence) and Sprint 15.5 (Hygiene Cleanup) sections; fixed migration counts (005→007, 5→7); fixed venv→.venv
2. **INDEX.md** — Sprint count (14→15), graphify entry counts (255→299, 371→421)
3. **HANDOFF-2026-07-08.md** — Updated stale `llm.py` reference
4. **cloud-llm-engineering/SKILL.md** — Removed stale `integrations/llm.py` references
5. **DESIGN_RATIONALE.md** — Updated to reflect llm.py removal
6. **graphify_output/** — Regenerated with `just graphify` (all 5 artifacts)
