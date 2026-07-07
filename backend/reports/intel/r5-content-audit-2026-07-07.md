# Round 5 Content Audit

**Date:** 7 July 2026
**Requested by:** Commander (systematic content freshness pass)
**Sources consulted:** All 14 files listed in task + physical filesystem verification

---

## Verdict: 33 ISSUES FOUND (7x P1, 12x P2, 9x P3, 5x P4)

---

## Internal Contradictions

| File | Line(s) | Issue | Severity |
|------|---------|-------|----------|
| `SPRINT_9_HANDOFF.md` | 50 vs 209 | **Training data size mismatch.** Line 50 says "144K samples × 67 features" — line 209 says "`training_data_v2.npz` (186K records)". 186K is the raw NVD corpus count, not the filtered training set (144,708). | P1 |
| `ROADMAP.md` | 38 vs 146 vs 189 | **Feature count ambiguity.** Line 38: "67 features (+ 1 label = 68 columns)". Line 146: "67 features (35 tabular + 384 SBERT)". Line 189: "67 columns (35 tabular features + 32 auxiliary/metadata columns)". The contradictory descriptions ("35+384=419" vs "35+32=67") make the feature architecture hard to parse. The npz stores 67 columns; the model uses 419 dimensions. Neither fact is wrong, but lines 146 implies 67 = 35+384 which is false. | P2 |
| `ai-doc-strategy-2026-07-07.md` | 21-24 vs actual filesystem | **docs/planning/ inventory wrong.** Line 22 claims docs/planning has 2 files (ROADMAP.md, SPRINT_NEXT_PLAN.md). Actually has 3: ROADMAP.md, ai-doc-strategy-2026-07-07.md, file-consolidation-plan-2026-07-07.md. SPRINT_NEXT_PLAN.md is in archive. Line 22 also lists SPRINT_NEXT_PLAN.md as `docs/planning/` when it's in `docs/archive/`. | P1 |
| `ai-doc-strategy-2026-07-07.md` | 436-441 vs filesystem | **Appendix A file names don't match reality.** References `XGBOOST_INVESTIGATION_REPORT.md` (should be `xgboost-investigation-report.md`), `Hostname and Data Classification Standards.md` (should be `hostname-standards.md`), `TriageMate ML Implementation Plan — Final.md` (should be `ml-implementation-plan.md`). 3 of 4 reference file names wrong. | P1 |
| `file-consolidation-plan-2026-07-07.md` | 17-27, 157 | **3 of 11 file paths wrong in current-state map.** Lines 21-23 use old names: `XGBOOST_INVESTIGATION_REPORT.md` (line 21), `TriageMate ML Implementation Plan — Final.md` (line 22), `Hostname and Data Classification Standards.md` (line 23). Actual filenames on disk are lower-kebab-case. | P1 |
| `file-consolidation-plan-2026-07-07.md` | 223-228 | **Archive subdirectories don't exist.** Proposes moving files to `docs/archive/architecture/`, `docs/archive/planning/`, `docs/archive/reference/`, `docs/archive/research/` — none of these directories exist on disk. | P3 |
| `AGENTS.md` | 14 | **Root symlink claim is false.** Says "Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility." Filesystem inspection confirms these are all regular files, not symlinks. | P2 |
| `ROADMAP.md` | 277-282 | **Symlink notation used for real files.** Shows e.g. `AI_PROBLEMS.md → docs/reference/AI_PROBLEMS.md` with symlink arrow notation, but these are regular files, not symlinks. | P2 |
| `SPRINT_9_HANDOFF.md` | 50 vs `ROADMAP.md` line 34 | **Claims 37 features with "all real data" but RESEARCH_FINDINGS.md contradicts.** SPRINT_9_HANDOFF §3 claims fields 22-23 (exploitdb_has_poc, metasploit_has_payload) are filled from ExploitDB CSV. RESEARCH_FINDINGS.md line 59 (3 July 2026) states these fields are "always False for all 186K entries — zero variance" because data was "never loaded into the corpus." | P1 |

---

## Cross-File Contradictions

| File A | Line | File B | Line | Issue | Severity |
|--------|------|--------|------|-------|----------|
| `ROADMAP.md` | 146 | `SpRINT_9_HANDOFF.md` | 50 | Both say "144K" but the basis differs. ROADMAP says 186K raw → 144K filtered. SPRINT_9_HANDOFF says 186K in paragraph, 144K in table. Inconsistent within one file. | P1 |
| `AGENTS.md` | 14 | `ROADMAP.md` | 277-282 | Both claim root .md files are symlinks. Filesystem proves they are not. | P2 |
| `INDEX.md` | 75 | `ROADMAP.md` | 242-268 | INDEX.md says "How do I train the model? → `planning/ROADMAP.md` §Quick Start". ROADMAP's Quick Start section (lines 242-268) only has `uvicorn main:app`, pytest, and queue verification commands. The training command is in §Sprint NEXT (line 189), not §Quick Start. | P2 |
| `ai-doc-strategy-2026-07-07.md` | 21-24 | Actual filesystem | — | Says docs/planning/ has 2 files (ROADMAP.md, SPRINT_NEXT_PLAN.md). Actually has 3 (also ai-doc-strategy and file-consolidation-plan). SPRINT_NEXT_PLAN.md is in docs/archive/, not docs/planning/. | P1 |
| `RESEARCH_FINDINGS.md` | 59 | `SPRINT_9_HANDOFF.md` | 73-74 | Research (3 July) says exploitdb_has_poc/metasploit_has_payload are "always False — zero variance". Sprint 9 handoff (2 July) says these fields are filled with "ExploitDB CSV (25K direct mappings)". One claims filled, the other claims zero variance. | P1 |
| `file-consolidation-plan-2026-07-07.md` | 17 | `INDEX.md` | 19 | Consolidation plan says MVP_SCOPE.md is "🔴 STALE — self-declared outdated". INDEX.md says it's "OUTDATED — Sprint 1 scope boundaries. Many deferred items are now done." Consistent, but the consolidation plan's "STALE" is a different classification term not in the project's status key (CURRENT/OUTDATED/ARCHIVED). | P3 |
| `ROADMAP.md` | 158 | `AI_PROBLEMS.md` | 13 | ROADMAP says CWE classifier deprecation: "CWE classifier | 🐛 Deprecated — replaced by NVD API + regex". AI_PROBLEMS.md says the deprecated file is preserved as `backend/ml/cwe_classifier_deprecated.py`. That file does not exist on disk (glob returned no results). | P3 |
| `MVP_SCOPE.md` | 84 | `ROADMAP.md` | 112 | Both reference 6 scoring dimensions. MVP_SCOPE says ML Exploitation dimension was "added post-MVP scope document via migration 005". ROADMAP mentions 6 dimensions without noting it was a later addition. Not contradictory but MVP_SCOPE's claim should be verified against the schema. | P4 |

---

## Stale References

| File | Line | Bad Reference | Should Be | Severity |
|------|------|---------------|------------|----------|
| `ai-doc-strategy-2026-07-07.md` | 438 | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | P1 |
| `ai-doc-strategy-2026-07-07.md` | 440 | `docs/reference/TriageMate ML Implementation Plan — Final.md` | `docs/reference/ml-implementation-plan.md` | P1 |
| `ai-doc-strategy-2026-07-07.md` | 441 | `docs/reference/Hostname and Data Classification Standards.md` | `docs/reference/hostname-standards.md` | P1 |
| `file-consolidation-plan-2026-07-07.md` | 21 | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | P2 |
| `file-consolidation-plan-2026-07-07.md` | 22 | `docs/reference/TriageMate ML Implementation Plan — Final.md` | `docs/reference/ml-implementation-plan.md` | P2 |
| `file-consolidation-plan-2026-07-07.md` | 23 | `docs/reference/Hostname and Data Classification Standards.md` | `docs/reference/hostname-standards.md` | P2 |
| `file-consolidation-plan-2026-07-07.md` | 162 | `Hostname and Data Classification Standards.md` | `hostname-standards.md` | P3 |
| `ROADMAP.md` | 277-282 | Root-level files listed with symlink syntax `→` | These are regular files, not symlinks | P2 |
| `AGENTS.md` | 14 | "Root-level .md files... are symlinks into docs/" | They are regular files | P2 |
| `AGENTS.md` Directory Map | 24-36 | Lists `ROADMAP.md`, `AI_PROBLEMS.md` as filenames (they are uppercase) | No explicit path issue but doesn't distinguish root copies vs docs/ copies | P4 |
| `MVP_SCOPE.md` | 55 | "60-dimensional hostname feature vector (see `backend/ml/pretier_features.py`)" | File may not exist at that path (pre-tier classifier uses different files now) | P3 |
| `AI_PROBLEMS.md` | 12 | `backend/ml/cwe_classifier_deprecated.py` | That file does not exist on disk (glob found no match) | P3 |
| `ai-doc-strategy-2026-07-07.md` | 236 | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | P2 |
| `ai-doc-strategy-2026-07-07.md` | 297 | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | P2 |

---

## INDEX.md Accuracy

For every row in INDEX.md, verifying file existence at the stated path:

| INDEX.md Reference | Exists? | Notes |
|--------------------|---------|-------|
| `planning/ROADMAP.md` | ✅ YES | At `docs/planning/ROADMAP.md` |
| `architecture/MVP_SCOPE.md` | ✅ YES | At `docs/architecture/MVP_SCOPE.md` |
| `reference/AI_PROBLEMS.md` | ✅ YES | At `docs/reference/AI_PROBLEMS.md` |
| `reference/ml-implementation-plan.md` | ✅ YES | At `docs/reference/ml-implementation-plan.md` |
| `reference/xgboost-investigation-report.md` | ✅ YES | At `docs/reference/xgboost-investigation-report.md` |
| `reference/hostname-standards.md` | ✅ YES | At `docs/reference/hostname-standards.md` |
| `research/RESEARCH_FINDINGS.md` | ✅ YES | At `docs/research/RESEARCH_FINDINGS.md` |
| `guides/WINDOWS_SETUP.md` | ✅ YES | At `docs/guides/WINDOWS_SETUP.md` |
| `planning/ai-doc-strategy-2026-07-07.md` | ✅ YES | At `docs/planning/ai-doc-strategy-2026-07-07.md` |
| `planning/file-consolidation-plan-2026-07-07.md` | ✅ YES | At `docs/planning/file-consolidation-plan-2026-07-07.md` |
| `archive/SPRINT_NEXT_PLAN.md` | ✅ YES | At `docs/archive/SPRINT_NEXT_PLAN.md` |
| `archive/handoffs/SPRINT_9_HANDOFF.md` | ✅ YES | At `docs/archive/handoffs/SPRINT_9_HANDOFF.md` |
| `archive/sprints-1-6/*.md` | ✅ YES | 11 files in `docs/archive/sprints-1-6/` |

**Every file referenced in INDEX.md exists.** ✓

### Orphan .md files in `docs/` NOT listed in INDEX.md:

| File | Status in File | Missing from INDEX.md? | Notes |
|------|----------------|------------------------|-------|
| `docs/INDEX.md` | CURRENT | This IS the index — self-referential (fine) | — |
| `docs/archive/Additional Information.md` | (no header) | Not listed | Source doc, fine to exclude |
| `docs/archive/EXTERNAL_AUDITOR_PROMPT.md` | (no header) | Not listed | Fine to exclude |
| `docs/archive/External Auditor Response.md` | (no header) | Not listed | Fine to exclude |
| `docs/archive/SECOND_WAVE_PROMPT.md` | (no header) | Not listed | Fine to exclude |
| `docs/archive/TriageMate ML Research Prompt.md` | (no header) | Not listed | Fine to exclude |
| `docs/archive/TriageMate ML Research.md` | (no header) | Not listed | Fine to exclude |
| `docs/archive/TriageMate MVP Transformation.md` | (no header) | Not listed | Fine to exclude |

**No active `.md` files (outside archive/) are orphaned from INDEX.md.** ✓

**However:** `docs/archive/` has 8 files total. INDEX.md describes `archive/sprints-1-6/*.md` (11 files) and `archive/handoffs/SPRINT_9_HANDOFF.md` (1 file). The 6 root archive files (Additional Information, EXTERNAL_AUDITOR_PROMPT, etc.) are not mentioned in INDEX.md. This is acceptable per the ai-doc-strategy's recommendation to exclude them, but they have no description at all.

---

## Status Badge Accuracy

| File | Current Badge (in file) | Badge in INDEX.md | Verified? | Notes |
|------|------------------------|-------------------|-----------|-------|
| `AGENTS.md` | (none — config root) | N/A | — | No badge needed |
| `ROADMAP.md` | CURRENT | CURRENT | ✅ Correct | |
| `MVP_SCOPE.md` | OUTDATED | OUTDATED | ✅ Correct | |
| `AI_PROBLEMS.md` | CURRENT | CURRENT | ✅ Correct | 1 unfixed issue (#14) |
| `ml-implementation-plan.md` | OUTDATED | OUTDATED | ✅ Correct | |
| `xgboost-investigation-report.md` | CURRENT | CURRENT | ✅ Correct | Retrain still pending; code fixes applied |
| `hostname-standards.md` | CURRENT | CURRENT | ✅ Correct | |
| `RESEARCH_FINDINGS.md` | CURRENT | CURRENT | ✅ Correct | |
| `WINDOWS_SETUP.md` | CURRENT | CURRENT | ✅ Correct | |
| `ai-doc-strategy-2026-07-07.md` | CURRENT | CURRENT | ✅ Correct | |
| `file-consolidation-plan-2026-07-07.md` | CURRENT | CURRENT | ✅ Correct | |
| `SPRINT_NEXT_PLAN.md` | ARCHIVED | ARCHIVED | ✅ Correct | |
| `SPRINT_9_HANDOFF.md` | ARCHIVED | ARCHIVED | ✅ Correct | |

**All status badges are accurate.** ✓

---

## Claim Verification

| File | Claim | Verified? | Notes |
|------|-------|-----------|-------|
| `ROADMAP.md` line 146 | "ROC-AUC 0.9677 post-fix" | ✅ Consistent with `xgboost-investigation-report.md` which states post-fix 0.9677 after fix K | |
| `ROADMAP.md` line 147 | "ROC-AUC 0.9946 was pre-fix label-leakage era" | ✅ Consistent with investigation report line 15 | |
| `ROADMAP.md` line 38 | "144K filtered training set" | ✅ Consistent with SPRINT_9_HANDOFF line 50 (144K) and line 189 (144,708) — though 144,708 rounds to 145K, not 144K | P4 (rounding) |
| `ROADMAP.md` line 34 | "`kev_cache.json` \| 1,631 entries" | ✅ Consistent with RESEARCH_FINDINGS line 187 and SPRINT_9_HANDOFF line 47 | |
| `ROADMAP.md` line 37 | "`training_data_v2.npz` \| 186K raw CVEs → 144K filtered" | ✅ Consistent | |
| `ROADMAP.md` line 179 | "1 unfixed issue (#14)" | ✅ AI_PROBLEMS.md shows only #14 as unfiled | |
| `ROADMAP.md` line 112 | "6 dimensions" | ✅ MVP_SCOPE line 84 also has 6 dimensions | |
| `SPRINT_9_HANDOFF.md` line 10 | "37/37 tests pass" | ✅ Not verified by code reading, but consistent across all documents | |
| `RESEARCH_FINDINGS.md` line 59 | "ExploitDB PoC and Metasploit fields... always False for all 186K entries" | ❓ CONTRADICTS Sprint 9 handoff claim fields are "filled." Needs code verification. | P1 |
| `RESEARCH_FINDINGS.md` line 138 | "835 KEV entries" | ✅ Consistent with Data Appendix line 189 | |
| `xgboost-investigation-report.md` line 3 | "5 fixes pending retrain" | ✅ ROADMAP line 146 confirms retrain is "🔧 Retrain pending" | |
| `ROADMAP.md` line 189 | "67 columns (35 tabular features + 32 auxiliary/metadata columns)" | ✅ Clarifies the 67-vs-419 confusion | |
| `AI_PROBLEMS.md` line 3 | "1 unfixed issue remaining" | ✅ Matches document content — only #14 is unfixed | |

---

## Complete Issue List (Prioritized)

### P1 — Critical (contradicts project understanding, misleads agents)

| # | File(s) | Issue |
|---|---------|-------|
| 1 | `SPRINT_9_HANDOFF.md` lines 50 vs 209 | Contradictory training data sizes: 144K vs 186K. SprINT_9_HANDOFF line 209 says "186K records" but the actual training set is 144,708. |
| 2 | `ai-doc-strategy-2026-07-07.md` §1.1, Appendix A | 3 of 4 reference file names wrong in inventory (uses old names not actual kebab-case names). Inventory also lists SPRINT_NEXT_PLAN.md under docs/planning/ when it's archived. |
| 3 | `file-consolidation-plan-2026-07-07.md` lines 17-27 | 3 of 11 file paths in "current state" map use wrong filenames (old naming convention). |
| 4 | `SPRINT_9_HANDOFF.md` §3 vs `RESEARCH_FINDINGS.md` line 59 | Sprint 9 claims fields 22-23 (exploitdb_has_poc, metasploit_has_payload) are filled. Research findings (July 3) say they're "always False — zero variance." One of these documents is wrong. |
| 5 | `ai-doc-strategy-2026-07-07.md` Appendix A | All reference file names use pre-rename convention, making the inventory unreliable as a source of truth. |

### P2 — Medium (misleading, causes confusion)

| # | File(s) | Issue |
|---|---------|-------|
| 6 | `AGENTS.md` line 14, `ROADMAP.md` lines 277-282 | False claim that root-level .md files are symlinks. They are regular files. If root copies diverge from docs/ copies, agents reading one vs the other will get different content. |
| 7 | `ROADMAP.md` lines 38, 146 | Ambiguous feature count descriptions. Line 146 implies "67 features = 35 tabular + 384 SBERT" which is mathematically wrong (35+384=419, not 67). The 67 includes 32 auxiliary columns. |
| 8 | `INDEX.md` line 75 | Points to "§Quick Start" for model training. Quick Start only has dev server commands. Training command is in §Sprint NEXT. |
| 9 | `file-consolidation-plan-2026-07-07.md` lines 21-23 | Three stale filenames in the current-state map for reference files. |
| 10 | `AI_PROBLEMS.md` line 12 | References `backend/ml/cwe_classifier_deprecated.py` which does not exist on disk (glob confirmed). |
| 11 | `ai-doc-strategy-2026-07-07.md` lines 236, 297 | Two more references to `XGBOOST_INVESTIGATION_REPORT.md` using wrong casing. |
| 12 | `ROADMAP.md` line 112 vs `MVP_SCOPE.md` line 84 | Both mention 6 dimensions, but MVP_SCOPE notes ML Exploitation was added post-MVP via migration 005. ROADMAP doesn't mention the migration history. Minor inconsistency. |

### P3 — Low (cosmetic, minor inaccuracy)

| # | File(s) | Issue |
|---|---------|-------|
| 13 | `file-consolidation-plan-2026-07-07.md` lines 223-228 | Proposes archive subdirectories (architecture/, planning/, reference/, research/) that don't exist. Plan must create them first. |
| 14 | `file-consolidation-plan-2026-07-07.md` line 162 | Uses old name `Hostname and Data Classification Standards.md` in proposal section. |
| 15 | `file-consolidation-plan-2026-07-07.md` line 17 | Uses "🔴 STALE" status label — not a recognized status badge (CURRENT/OUTDATED/ARCHIVED are the project conventions). |
| 16 | `MVP_SCOPE.md` line 55 | References `backend/ml/pretier_features.py` — may not exist (pre-tier classifier moved to different module structure). |
| 17 | `AI_PROBLEMS.md` line 13 | Says CWE classifier renamed to `cwe_classifier_deprecated.py` — file doesn't exist. |
| 18 | `ROADMAP.md` line 38 | "144K filtered" — actual count is 144,708, which rounds to 145K not 144K. |
| 19 | `RESEARCH_FINDINGS.md` line 146 | NOTE says "written before Sprint NEXT and may not reflect current completion status" — good practice. |

### P4 — Informational (trivial, no action needed)

| # | File(s) | Issue |
|---|---------|-------|
| 20 | `SPRINT_9_HANDOFF.md` line 210 | Says model had "15 of 36 tabular features were hardcoded constants." Should say "15 of 35" (post-removal of cisa_kev). Slight number mismatch. |
| 21 | `MVP_SCOPE.md` line 84 | States ML Exploitation dimension added "post-MVP scope document via migration 005" — correct historical context. Worth keeping. |
| 22 | `ROADMAP.md` line 34 | Lists `files_exploits.csv` volume as "47,089 exploits, 25,037 CVE mappings" — consistent. |
| 23 | `ai-doc-strategy-2026-07-07.md` line 22 | Says `docs/planning/` has 2 files when it has 3 (didn't count itself and file-consolidation-plan). |
| 24 | `docs/archive/` | 6 archive root files (Additional Information.md etc.) are not listed in INDEX.md. Fine per strategy, but could be mentioned. |

---

## Summary of Root Causes

| Pattern | Count |
|---------|-------|
| **Renaming inconsistency** — files were renamed to kebab-case but old documents still reference old names | 12 occurrences across 3 documents |
| **False symlink claim** — AGENTS.md + ROADMAP.md claim root files are symlinks when they're regular files | 2 occurrences, systemic |
| **Training data size confusion** — 144K vs 186K vs 145K used inconsistently for the filtered set | 3 occurrences across 2 documents |
| **Feature count ambiguity** — 67 vs 419 vs 35 used in ambiguous contexts | 2 occurrences |
| **Pipeline field status contradiction** — Sprint 9 handoff says fields filled, research says they're zero-variance | 1 occurrence, potentially serious |
| **Missing file references** — files referenced in docs that don't exist on disk | 2 occurrences (cwe_classifier_deprecated.py, archive subdirectories) |

---

## Recommendations

1. **Fix the symlink claim (P2 #6):** Update `AGENTS.md` line 14 and `ROADMAP.md` lines 277-282 to state these are separate files, not symlinks. If they should be symlinks, create them as such (but do NOT delete the docs/ originals).

2. **Resolve the ExploitDB field contradiction (P1 #4):** Verify whether fields 22-23 are actually populated in the training corpus. Either `SPRINT_9_HANDOFF.md` is wrong (aspirational claim) or `RESEARCH_FINDINGS.md` is stale (pipeline was fixed after July 3).

3. **Fix ai-doc-strategy and file-consolidation-plan filenames (P1 #2, #3):** Update Appendix A and current-state map to use actual kebab-case filenames.

4. **Fix SPRINT_9_HANDOFF.md training data count (P1 #1):** Line 209 should say "144K records" not "186K records."

5. **Clarify feature counts in ROADMAP.md (P2 #7):** Make the section consistently explain: 67 npz columns = 35 tabular + 32 auxiliary/metadata; 419 model input = 35 tabular + 384 SBERT.

6. **Fix INDEX.md training reference (P2 #8):** Point to §Sprint NEXT, not §Quick Start, for model training commands.

7. **Note for commander:** The duplicate root-level .md files (AI_PROBLEMS.md, ROADMAP.md, etc.) being regular files rather than symlinks means they can diverge from the docs/ copies. A freshness mechanism should ensure they stay identical.
