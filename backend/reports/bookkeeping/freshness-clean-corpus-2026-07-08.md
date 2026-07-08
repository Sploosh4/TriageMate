# Bookkeeping Report — Clean Corpus Sprint

**Date:** 2026-07-08
**Trigger:** sprint-end (Clean Corpus)

## Auto-Fixed

### docs/planning/ROADMAP.md
- **ROC-AUC 0.9409 → 0.9459** — 4 occurrences (lines 81, 119, 128, 172)
- **420 columns (36 tabular + 384 SBERT) → 419 columns (35 tabular + 384 SBERT)** — 3 occurrences (lines 128, 131, 172 in table cells)
- **Line 69 note rewritten** — Removed 420-vs-419 mismatch explanation; now states NPZ stores 419 cols matching model, `osv_lead_days` stored as separate metadata array

### graphify_output/ml_inventory.md
- **ROC-AUC 0.9409 → 0.9459** — 2 occurrences (lines 134, 170)
- **Features 420 (36 tabular) → 419 (35 tabular)** — 2 occurrences (lines 133, 139)
- **"36 tabular features" → "35 tabular features"** — 1 occurrence (line 141)
- **Dimension mismatch note rewritten** — Changed from "420 NPZ / 420 train / 419 predict = MISMATCH" to "419 NPZ / 419 train = RESOLVED"
- **Status line** — Changed from ⚠️ "Dimension mismatch: model trained with 420 features, predictor sends 419" to ✅ "Dimension mismatch resolved: model and NPZ both at 419 features"

### docs/reference/xgboost-investigation-report.md
- **ROC-AUC 0.9409 → 0.9459** — 1 occurrence (line 5, status note)

### docs/reference/AI_PROBLEMS.md
- **ROC-AUC 0.9409 → 0.9459** — 1 occurrence (line 141, referring to superseding retrain)

## Items Flagged for Human Review

### P1 — Contradictions in CURRENT docs

| File | Issue |
|------|-------|
| `docs/architecture/MVP_SCOPE.md` | Lines 67, 119, 192 still have "420-dimension feature vector (36 tabular)" and "ROC-AUC 0.9409" — but doc is marked **OUTDATED** with caution banner. Acceptable as-is. |

### P2 — Stale References

| File | Issue |
|------|-------|
| `docs/INDEX.md` §Graphify table (lines 89–94) | Lists only 4 graphify outputs (`file_tree.md`, `api_deps.md`, `ml_inventory.md`, `knowledge_graph.json`). Missing `feature_parity.md`. The directory also contains `TASK_STORE_COLUMNS_IN_NPZ.md` (a task doc, not a graphify output). |
| `AGENTS.md` Quick Reference table | Does not mention `feature_parity.md` in the graphify outputs section. |
| `graphify_output/feature_parity.md` | Still reports 37 tabular inference features vs 35 training features (pre-existing mismatch — inference produces `osv_fixed_versions`, `osv_package`, `osv_ecosystem` as metadata but they're counted as tabular). Not directly caused by this sprint. |

### P3 — Artifact Cleanup

| File | Issue |
|------|-------|
| `graphify_output/TASK_STORE_COLUMNS_IN_NPZ.md` | This is a task instruction document ("Task: Store Column Names in NPZ Metadata") sitting in the auto-generated `graphify_output/` directory. The task it describes has been **completed** (columns are now stored in the NPZ). Should either be archived or moved to `docs/planning/`. Currently pollutes the auto-generated graphify namespace. |
| `graphify_output/feature_parity.md` | The report text says "auto-generated from AST parsing" but the inference vs training count mismatch (37 vs 35) is a known pre-existing condition, not a new regression. Feature parity check needs inference code to drop 2 metadata-only entries from tabular count, OR the inference code needs alignment. Out of scope for this sprint. |

## Orphans Found

None. All active files are referenced where expected. No archived files receive stale references from CURRENT docs.

## Coverage Gaps

None. The `columns` key in the NPZ is documented:
- `graphify_output/ml_inventory.md` — implicitly (NPZ structure described as 419 columns)
- `graphify_output/TASK_STORE_COLUMNS_IN_NPZ.md` — explicitly (task document, though misplaced)
- ROADMAP.md line 69 — updated to mention 35 named columns + osv_lead_days as metadata

No AIRMs/AI_PROBLEMS ticket exists for the NPZ column names feature, but that's consistent with it being a sprint-internal implementation detail.

## Cross-Reference Check

- **ROADMAP.md vs reality**: ✅ All ROC-AUC values now 0.9459, all dimension counts now 419/35. Line 69 note rewritten.
- **INDEX.md status badges**: ✅ All correct. `MVP_SCOPE.md` still OUTDATED (correct), `ml-implementation-plan.md` still ARCHIVED (correct).
- **Numeric consistency**: ✅ 419 features everywhere, 35 tabular everywhere, 253,568 samples consistent.
- **Terminology drift**: ✅ No OCEL→TRACE drift, no PRIS ACT→WAICP drift in the checked docs.
- **Symlink integrity**: ✅ Zero broken symlinks. 6 root-level symlinks all resolve correctly.

## Verdict

**FRESH** — All structural contradictions resolved. Numeric values (ROC-AUC, feature dimensions, sample counts) now consistent across all CURRENT docs. Remaining flags are cosmetic (INDEX.md table, misplaced task doc, pre-existing feature_parity mismatch) — none are P0.

**Recommendation:** If graphify is regenerated (`just graphify`), ensure `feature_parity.md` is included in INDEX.md's graphify table. Consider moving `TASK_STORE_COLUMNS_IN_NPZ.md` out of `graphify_output/`.
