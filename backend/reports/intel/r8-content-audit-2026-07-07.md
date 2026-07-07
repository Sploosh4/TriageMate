# Round 8 — Full Content Audit

**Date:** 2026-07-07
**Requested by:** Commander (recurring content audit)
**Files audited:** All 12 active `.md` files
**Verification tools:** Disk inspection, npz inspection, git log, pytest collect, symlink checks

---

## Verdict

**6 issues found.** Three are critical (numeric contradictions between ROADMAP.md and on-disk training data). Three are medium/low.

After 7 previous rounds, the text-level doc surface is clean — no bad symlinks, no broken paths, no stale status badges, no wrong file references in AGENTS.md or INDEX.md. But a data-level drift has occurred: the `training_data_v2.npz` file was regenerated **after** ROADMAP.md was written, and ROADMAP.md's specs for it are now entirely wrong.

---

## Issue 1 — CRITICAL: training_data_v2.npz dimensions entirely wrong in ROADMAP.md

**Files:** `docs/planning/ROADMAP.md` (lines 38, 146, 189)
**Claim vs reality:**

| Property | ROADMAP.md claims | Actual npz |
|---|---|---|
| Rows (samples) | 144,708 (≈144K) | **253,568** |
| Columns (features) | 67 (35 tabular + 32 auxiliary) | **420** (36 non-SBERT + 384 SBERT) |
| File size | 19.6 MB | **357 MB on disk (341 MB actual)** |

**Details:**
- ROADMAP.md line 38: *"186K raw CVEs → 144K filtered training set, 67 columns (+ 1 label = 68 total)"*
- ROADMAP.md line 146: *"144K records, 67 columns in npz (35 tabular + 32 auxiliary)"*
- ROADMAP.md line 189: *"144,708 samples, 19.6 MB. The training data v2 npz stores 67 columns (35 tabular features + 32 auxiliary/metadata columns)."*

The `training_data_v2.npz` was last modified **2026-07-03 22:45**. ROADMAP.md claims "Last updated: 2 July 2026." The npz was regenerated after the roadmap was written, producing a substantially different dataset that ROADMAP.md never caught up to.

**Key actual stats:**
- `X.shape`: (253,568, 420) — not 144,708 × 67
- `feature_names`: 420 entries — first 36 are tabular (incl. undocumented `osv_lead_days`), next 384 are `text_sbert_0` through `text_sbert_383`
- Positive samples: 1,617 (0.64%)
- `dates` key: present (string dates, chronological split enabled)
- `cve_ids` key: present

---

## Issue 2 — CRITICAL: Undocumented `osv_lead_days` column in training data

**Files:** `docs/planning/ROADMAP.md` §Feature Field Status (lines 40–73), `backend/ml/training_data_v2.npz`

ROADMAP.md's feature table lists exactly 37 collected fields. The actual npz has 36 non-SBERT features (indices 0–35). Index 35 is `osv_lead_days`, which:

1. Does **not** appear in ROADMAP.md's 37-field feature table
2. Is **all zeros** across all 253,568 samples (never populated)
3. Is **not consumed** by `xgboost_predictor.py` (which builds only 35 tabular features, lines 127–168)

This means the training data carries a dead column that neither the predictor nor any documentation accounts for. The model expects 419 features (35 tabular + 384 SBERT), but the npz has 420 columns. The training script must drop `osv_lead_days` before fitting — or the model would reject the input.

---

## Issue 3 — MEDIUM: ROADMAP.md "Last updated" date is stale

**File:** `docs/planning/ROADMAP.md` (lines 3–5)
**Claim:** `> **Status: CURRENT** (2 July 2026)` / `> Last updated: 2 July 2026`
**File mtime:** 2026-07-07 21:19

The file header claims it was last updated on 2 July, but the file modification timestamp is 7 July. While it's possible the content genuinely didn't change and the timestamp reflects git operations, the claim should be updated to reflect the true last-review date.

**Note:** The content does not appear to contain information from after 2 July (no references to the 7 July consolidation docs), so the content date is likely accurate even though the file touch time is later.

---

## Issue 4 — MEDIUM: RESEARCH_FINDINGS.md "EPSS cache entries" number is ambiguous

**File:** `docs/research/RESEARCH_FINDINGS.md` (line 185)
**Claim:** `| EPSS cache entries | 140,487 (subset) |`

**ROADMAP.md** (line 35): `| epss_cache.json | 344,852 scores | FIRST.org |`

These numbers measure different things:
- ROADMAP.md: total EPSS cache file entries = **344,852**
- RESEARCH_FINDINGS.md: EPSS entries that overlap with the NVD corpus = **140,487**

The "(subset)" qualifier is present, but a reader who skims will think the cache has 140K entries when it actually has 344K. The 140K figure refers to the intersection between EPSS and the NVD corpus, not the cache itself.

**Recommended fix:** Change to `EPSS entries matching NVD corpus` for clarity, or add an explanatory footnote.

---

## Issue 5 — LOW: ROADMAP.md Project File Map incomplete

**File:** `docs/planning/ROADMAP.md` (lines 307–309)
**Missing files:** `DEMO_DATA_GENERATOR_PLAN.md` and `DEMO_DATA_GENERATOR_SCOPE.md`

The file tree's `docs/archive/sprints-1-6/` block lists SPRINT handoffs and briefing files but omits two files that exist on disk:

```
docs/archive/sprints-1-6/   ← ROADMAP.md lists only:
  ├── SPRINT_1_HANDOFF.md
  ├── SPRINT_2_HANDOFF.md
  ├── SPRINT_3_HANDOFF.md
  ├── SPRINT_7_HANDOFF.md
  ├── SPRINT_8_HANDOFF.md
  ├── PRE_DEMO_PLAN.md
  ├── COURSE_CORRECTION.md
  ├── SPRINT_9_BRIEFING_PLAN.md
  └── TEAM_BRIEFING.md

  ← But disk also has:
  - DEMO_DATA_GENERATOR_PLAN.md
  - DEMO_DATA_GENERATOR_SCOPE.md
```

These two files appear to be from Sprint 5 (Demo Data Generator). They should be added to the file map for completeness.

---

## Issue 6 — LOW: 35-tabular accounting in ROADMAP.md footnote is confusing

**File:** `docs/planning/ROADMAP.md` (line 75)
**Text:** *"37 fields are collected; 35 are used as tabular features by XGBoost. `cisa_kev` was removed (label leakage fix — it IS the target variable), and `description` feeds the SBERT encoder."*

The 37-field table lists 37 features. The note says 35 are tabular. Neither `cisa_kev` nor raw `description` appear in the 37-field table, so the reader can't see which 2 of the 37 aren't tabular, or how the 37→35 reduction works.

**Suggested clarification:** Either:
- Change "37 fields are collected" to "35 tabular fields are collected" and note that the SBERT description field and the removed `cisa_kev` bring the original design to 37.
- Or keep the 37-field table but annotate which entries are tabular vs non-tabular.

---

## Verified Clean (No Issues Found)

The following cross-checks all passed:

| Check | Result |
|---|---|
| All 6 root symlinks resolve to real files | ✅ |
| No broken symlinks at root | ✅ (DEMO_SCRIPT.md and TRIAGEMATE_BOOK_PROMPT.md removed since Round 7) |
| AGENTS.md claims match reality | ✅ |
| INDEX.md status badges match each file's self-declared status | ✅ |
| All 12 active files are listed in INDEX.md | ✅ |
| File map in AGENTS.md matches disk | ✅ |
| AGENTS.md → INDEX.md → ROADMAP.md chain works | ✅ |
| 37 tests exist (confirmed via `pytest --collect-only`) | ✅ |
| xgboost_model.pkl expects 419 features (35+384) | ✅ |
| training_data.npz (old) has 419 features | ✅ |
| Sprint status table in ROADMAP.md is internally consistent | ✅ |
| AI_PROBLEMS.md #14 status matches ROADMAP.md | ✅ |
| xgboost-investigation-report.md 8-fix claim matches code | ✅ |
| PCA removal consistently reported across all docs | ✅ |
| WINDOWS_SETUP.md instructions are correct | ✅ |
| hostname-standards.md is stable (no changes needed) | ✅ |
| ai-doc-strategy and file-consolidation-plan (both Jul 7) are self-consistent | ✅ |
| No stale terminology (e.g. "PCA", "SecureBERT" as active) outside OUTDATED docs | ✅ |

---

## Summary

| # | Severity | File | Issue |
|---|---|---|---|
| 1 | 🔴 CRITICAL | ROADMAP.md | training_data_v2.npz dimensions wrong: 254K×420 (not 144K×67); file size wrong: 341 MB (not 19.6 MB) |
| 2 | 🔴 CRITICAL | ROADMAP.md + training_data_v2.npz | Undocumented `osv_lead_days` column (all zeros, not consumed by predictor) |
| 3 | 🟡 MEDIUM | ROADMAP.md | "Last updated: 2 July" but file touched 7 July |
| 4 | 🟡 MEDIUM | RESEARCH_FINDINGS.md | "EPSS cache entries: 140,487" ambiguous — means NVD-corpus overlap, not total cache (344K) |
| 5 | 🔵 LOW | ROADMAP.md §Project File Map | Missing 2 files in archive listing: DEMO_DATA_GENERATOR_PLAN.md, DEMO_DATA_GENERATOR_SCOPE.md |
| 6 | 🔵 LOW | ROADMAP.md | 35-tabular footnote confusing: can't trace 37→35 reduction from the table |

**Round 8 assessment:** The text layer is clean — naming, paths, symlinks, status badges, cross-references are all correct after 7+ rounds. The remaining issues are **data drift**: ROADMAP.md's specs for `training_data_v2.npz` are wrong because the file was regenerated after the doc was written, and the new file has an undocumented dead column.

**Recommended actions:**
1. Update ROADMAP.md §§Data Corpus, ML Artifacts, and Sprint NEXT with correct training_data_v2.npz stats (254K rows, 420 columns, 341 MB)
2. Either populate or remove `osv_lead_days` from the npz; document it if intentional
3. Update ROADMAP.md "Last updated" date header
4. Clarify RESEARCH_FINDINGS.md EPSS cache entry label
5. Add the 2 missing files to ROADMAP.md Project File Map
6. Clarify the 35-tabular footnote in ROADMAP.md
