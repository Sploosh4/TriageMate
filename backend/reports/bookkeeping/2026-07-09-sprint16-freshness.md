# Bookkeeping Report — Sprint 16 Quality Gate

**Date:** 2026-07-09
**Trigger:** Sprint 16 — ML Monitoring Foundation (Quality Gate)

---

## 1. Files Checked and Their Status

| # | File | Status | Notes |
|---|------|--------|-------|
| 1 | `docs/planning/ROADMAP.md` | ⚠️ **NEEDS UPDATE** | Sprint table ends at Sprint 15.5; no Sprint 16 row. ML Artifacts table missing `model_registry_pre_tier.json` and `model_registry_epss.json`. No mention of 5 new test files. |
| 2 | `docs/planning/HANDOFF-2026-07-08.md` | ⚠️ **NEEDS UPDATE** | §1 ML Drift Monitoring table (lines 30–40) shows ❌ None for Pre-Tier RF and EPSS v1–v4 tests/registry — now stale. Line 21 says "142/142 tests pass" — now 275. Line 47 action item ("tests, calibration, model registry") partially fulfilled. |
| 3 | `docs/INDEX.md` | ⚠️ **NEEDS UPDATE** | No Sprint 16 entry. New test files and model registries not indexed. Sprint count stuck at 15. |
| 4 | `backend/ml/README.md` | ✅ **CURRENT** | Redirects to auto-generated `graphify_output/ml_inventory.md` — no update needed. |
| 5 | `docs/reference/AI_PROBLEMS.md` | ✅ **CURRENT** | 2 open pipeline drifts (#15, #16) unrelated to Pre-Tier/EPSS. No Pre-Tier or EPSS issues tracked. |
| 6 | `.opencode/plans/2026-07-09-sprint-16.md` | ✅ **CURRENT** | Sprint plan — accurate as-written. |
| 7 | `graphify_output/file_tree.md` | ✅ **REGENERATED** | 312 entries (was 299). Includes all 5 new test files and 2 new model registries. |
| 8 | `graphify_output/ml_inventory.md` | ✅ **REGENERATED** | Now lists `model_registry_pre_tier.json` and `model_registry_epss.json`. |
| 9 | `graphify_output/feature_parity.md` | ✅ **REGENERATED** | Updated with no new feature changes reported. |

---

## 2. Specific Update Recommendations

### A. `docs/planning/ROADMAP.md` — Required Updates

1. **Sprint table (line 30):** Add row for Sprint 16:
   ```
   | **Sprint 16** | **ML Monitoring Foundation** | ✅ Complete (2026-07-09) |
   ```

2. **ML Artifacts table (lines 138–155):** Add two new entries:
   - Pre-Tier model registry (`model_registry_pre_tier.json`) — ✅ Done — Sprint 16
   - EPSS model registry (`model_registry_epss.json`) — ✅ Done — Sprint 16

3. **Sprint NEXT+ Wave 1 (lines 220–225):** Add the 5 new test files as completed items, or consider adding a new Wave/Sprint 16 section with the deliverables.

4. **Pipeline Stages > Pre-Tier (line 131):** Consider noting that test coverage now exists for Pre-Tier and EPSS substitution models.

### B. `docs/planning/HANDOFF-2026-07-08.md` — Required Updates

1. **§1 ML Drift Monitoring table (lines 30–40):** Update Pre-Tier RF and EPSS v1–v4 columns:

   | Capability | XGBoost (Tier 1) | Pre-Tier RF | EPSS v1–v4 |
   |---|---|---|---|
   | Unit/integration tests | ✅ 3 test files | ✅ 2 test files (`test_pretier_features.py`, `test_pre_tier.py`) | ✅ 1 test file (`test_epss_substitutor.py`) |
   | Feature parity check | ✅ `feature_parity_check.py` (manual) | ✅ `test_feature_parity_pretier.py` (automated) | ✅ `test_feature_parity_epss.py` (automated) |
   | Calibration audit | ✅ `calibration_audit.py` (manual) + Platt calibrator | ❌ None | ❌ None |
   | Drift endpoint | ✅ `GET /api/drift/ml` | ❌ None | ❌ None |
   | Drift alerting/thresholds | ❌ None | ❌ None | ❌ None |
   | PSI/KL divergence | ✅ `backend/analysis/drift.py` | ❌ None | ❌ None |
   | Concept drift | ❌ None | ❌ None | ❌ None |
   | Scheduled retraining | ❌ None | ❌ None | ❌ None |
   | Model registry entry | ✅ 3 versions tracked | ✅ `model_registry_pre_tier.json` | ✅ `model_registry_epss.json` |

2. **Line 21:** `142/142 tests pass` → `275/275 tests pass`

3. **Line 47:** `Pre-Tier and EPSS need foundational verification first (tests, calibration, model registry)`
   → `Pre-Tier and EPSS foundational verification: tests + model registry DONE (Sprint 16). Calibration still outstanding.`

4. **Appendix C (ML Models on Disk):** Add `model_registry_pre_tier.json` and `model_registry_epss.json` entries.

### C. `docs/INDEX.md` — Required Updates

1. **Line 18:** `Sprint 16 — ML Monitoring Foundation` should appear in the Core Documents section or planning section.
2. **Sprint count:** Update "15 completed (Sprints 1–15.5)" → "16 completed (Sprints 1–16)"
3. **New Sprint 16 section:** Add a section documenting the new test files and registries (similar to the existing Sprint 14 sections):

   ```markdown
   ## New Test Files (Sprint 16)

   | File | Tests | Purpose |
   |---|---|---|
   | `backend/tests/test_pretier_features.py` | 57 | Tests for pretier_features.py — feature extraction, 60-dim contract |
   | `backend/tests/test_pre_tier.py` | 16 | Tests for pre-tier inference pipeline, KNOWN_TAGS, ML fallback |
   | `backend/tests/test_feature_parity_pretier.py` | 9 | 60-dim feature vector contract between training and inference |
   | `backend/tests/test_epss_substitutor.py` | 37 | Tests for EPSS fallback chain (v4→v3→v2→v1→rule_engine) |
   | `backend/tests/test_feature_parity_epss.py` | 14 | 37-dim feature vector contract between train_epss_v4.py and epss_substitutor.py |

   ## New ML Registries (Sprint 16)

   | File | Purpose |
   |---|---|
   | `backend/ml/model_registry_pre_tier.json` | Pre-Tier RF model version tracking (v1 active) |
   | `backend/ml/model_registry_epss.json` | EPSS fallback model version tracking (v4 active, v3/v2/v1 fallback) |
   ```

4. **Quick Reference:** Add entries covering the new test files and registries.

---

## 3. Graphify Regeneration

`just graphify` completed successfully and regenerated all 5 auto-generated files:

| File | Before | After |
|------|--------|-------|
| `file_tree.md` | 299 entries | 312 entries |
| `api_deps.md` | 421 dependencies | 423 dependencies |
| `knowledge_graph.json` | 70 nodes, 41 edges | 70 nodes, 41 edges (unchanged) |
| `ml_inventory.md` | Updated | Now includes `model_registry_pre_tier.json` and `model_registry_epss.json` |
| `feature_parity.md` | Updated | No new feature changes detected |

All 5 new test files (`test_pretier_features.py`, `test_pre_tier.py`, `test_feature_parity_pretier.py`, `test_epss_substitutor.py`, `test_feature_parity_epss.py`) appear in `file_tree.md`. Both new registries appear in `file_tree.md` and `ml_inventory.md`. ✅

---

## 4. Orphaned References Found

| Reference | Location | Status |
|-----------|----------|--------|
| Pre-Tier/EPSS test references | `docs/archive/External Auditor Response.md` | **ARCHIVED** — no action needed |
| Pre-Tier/EPSS test references | `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md` | **ARCHIVED** — no action needed |
| Pre-Tier/EPSS test references | `docs/archive/sprints-1-6/SPRINT_7_HANDOFF.md` | **ARCHIVED** — no action needed |
| Pre-Tier/EPSS test references | `docs/archive/ml-implementation-plan.md` | **ARCHIVED** — no action needed |
| Pre-Tier/EPSS test references | `docs/archive/EXTERNAL_AUDITOR_PROMPT.md` | **ARCHIVED** — no action needed |

**No actionable orphaned references found.** All references to old Pre-Tier/EPSS test expectations are in archived files only.

Only 1 CURRENT file references `model_registry`: `docs/planning/ROADMAP.md` (the original `model_registry.json` entry). The two new registries are not yet referenced by any CURRENT docs — this is the coverage gap documented above.

---

## 5. Test Count Verification

| Metric | Value |
|--------|-------|
| Previous count (HANDOFF line 21) | 142/142 tests pass |
| Current count | 275 tests collected |
| New tests contributed by Sprint 16 | 133 |
| Breakdown | `test_pretier_features.py`: 57, `test_pre_tier.py`: 16, `test_feature_parity_pretier.py`: 9, `test_epss_substitutor.py`: 37, `test_feature_parity_epss.py`: 14 |

---

## 6. Coverage Gap Summary

| Gap | Severity | Docs Affected |
|-----|----------|---------------|
| Sprint 16 not in sprint table | P2 | `ROADMAP.md` |
| New model registries not in ML Artifacts | P2 | `ROADMAP.md` |
| §1 ML Drift Monitoring table stale | P1 | `HANDOFF-2026-07-08.md` |
| Test count stale (142→275) | P2 | `HANDOFF-2026-07-08.md` |
| Action item status stale | P2 | `HANDOFF-2026-07-08.md` |
| New test files/registries not indexed | P2 | `INDEX.md` |
| Sprint count (15→16) | P2 | `INDEX.md` |

**No cross-file contradictions found.** The ROADMAP, HANDOFF, and INDEX are internally consistent (they all pre-date Sprint 16), and no document contradicts another on the same topic.

---

## Verdict

**NEEDS ATTENTION** — 3 CURRENT docs need updating after Sprint 16:

1. **`docs/planning/HANDOFF-2026-07-08.md`** — §1 ML Drift Monitoring table is P1-stale: Pre-Tier and EPSS now have tests, feature parity guards, and model registry entries. Test count needs updating.
2. **`docs/planning/ROADMAP.md`** — Needs Sprint 16 row and new ML artifact entries for Pre-Tier and EPSS registries.
3. **`docs/INDEX.md`** — Needs Sprint 16 section indexing new test files and registries. Sprint count needs update (15→16).

The `backend/ml/README.md` and `docs/reference/AI_PROBLEMS.md` are CURRENT and need no changes.

`just graphify` was successful — auto-generated docs are up-to-date with Sprint 16 changes.
