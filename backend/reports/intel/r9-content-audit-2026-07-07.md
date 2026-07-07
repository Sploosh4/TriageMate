# Round 9 Content Audit — 12 Active .md Files

**Date:** 2026-07-07
**Requested by:** Commander (surgical content audit after 8 rounds of fixes)
**Files examined:** AGENTS.md, docs/INDEX.md, docs/planning/ROADMAP.md, docs/architecture/MVP_SCOPE.md, docs/reference/AI_PROBLEMS.md, docs/reference/hostname-standards.md, docs/reference/xgboost-investigation-report.md, docs/reference/ml-implementation-plan.md, docs/planning/ai-doc-strategy-2026-07-07.md, docs/planning/file-consolidation-plan-2026-07-07.md, docs/research/RESEARCH_FINDINGS.md, docs/guides/WINDOWS_SETUP.md

> **Status: 11 ISSUES FOUND** — see below. No showstoppers; all are accuracy/consistency gaps.

---

## Summary

| Severity | Count | Key Theme |
|----------|-------|-----------|
| 🔴 Contradiction | 3 | Calibration existence, ROC-AUC era misattribution, test-result self-contradiction |
| 🟡 Stale/Misleading | 4 | INDEX.md incomplete, calibration claim ambiguous, symlink listing incomplete, column-count delta |
| 🔵 Bookkeeping gap | 4 | Missing file from INDEX, self-referencing research note, unlisted Sprint NEXT plan, test assertions vs reality |

---

## 🔴 Issue 1 — Calibration Existence: Three Documents, Three Stories

**Involved files:** ROADMAP.md, AI_PROBLEMS.md, xgboost-investigation-report.md

| Document | Claim |
|----------|-------|
| **ROADMAP.md** (line 138) | Tier 1 includes "calibration" as a ✅ Done feature |
| **AI_PROBLEMS.md** (#5, FIXED) | Calibration was **removed** because XGBoost's `binary:logistic` produces calibrated probabilities natively. |
| **xgboost-investigation-report.md** (line 106-108) | Absence of calibration is a **bug** — `scale_pos_weight` distorts probabilities, post-hoc calibration (Platt scaling) is required. The fix adds it back but retrain is pending. |

**Contradiction:** ROADMAP claims calibration is present. AI_PROBLEMS says removal was correct. Investigation report says removal was wrong and must be re-added. All three cannot be simultaneously accurate.

**Recommendation:** Resolve the factual question — does XGBoost's `binary:logistic` produce properly calibrated probabilities when `scale_pos_weight` is ~214? If yes, strike ROADMAP's "calibration" claim (it's inherent, not a separate step). If no, update AI_PROBLEMS #5 from FIXED to needs-fix. Either way, ROADMAP's "✅ Done + calibration" badge is misleading.

---

## 🔴 Issue 2 — Investigation Report Attributes ROC-AUC 0.9946 to Current Model

**Involved files:** xgboost-investigation-report.md, ROADMAP.md

- **xgboost-investigation-report.md** (line 15, status header "CURRENT"): "The trained XGBoost model reports ROC-AUC 0.9946 but misses 21% of exploited CVEs"
- **ROADMAP.md** (line 138, 147): Current deployed model has **ROC-AUC 0.9677** (Sprint 3 retrain). The 0.9946 was "pre-fix label-leakage era — not representative."

**Problem:** The investigation report says "CURRENT" but describes the label-leakage model's metrics. The real current model (Sprint 3, 0.9677) is different. The report was written on July 2 (during the investigation phase) and its "CURRENT" status refers to its own accuracy as a report, but a reader will interpret "current model" = currently deployed model, which is wrong.

**Recommendation:** Add a header note: "⚠️ The 0.9946 ROC-AUC described herein was the pre-fix model from the label-leakage era. The current deployed model (Sprint 3 retrain) achieves ROC-AUC 0.9677." Or update status to "HISTORICAL ANALYSIS — code fixes applied, retrain pending."

---

## 🔴 Issue 3 — Investigation Report Self-Contradicts on Test Results

**Involved file:** xgboost-investigation-report.md (line 170)

> "All 37 tests pass (5 unrelated `sentence_transformers` failures due to missing dependency, not code)"

**Problem:** If 5 tests fail, "all 37 pass" is factually false. Should read: "32 of 37 tests pass; 5 fail due to missing `sentence_transformers` dependency (unrelated to code changes)."

**Recommendation:** Fix the phrasing to match reality. Precision matters for an audit report.

---

## 🟡 Issue 4 — ROADMAP.md's "calibration" Claim Is at Best Ambiguous

**Involved files:** ROADMAP.md (line 138)

ROADMAP lists "calibration" as a Tier 1 feature status. But:
- AI_PROBLEMS #5 says `CalibratedClassifierCV` was removed — intentionally.
- The investigation report says absence of Platt scaling is a bug.

**Either:** ROADMAP means "XGBoost's built-in binary:logistic calibration is sufficient" (in which case the claim is defensible but conflicts with the investigation report), **or** ROADMAP is describing a non-existent feature.

**Recommendation:** Be explicit: "XGBoost `binary:logistic` (inherently calibrated)" vs "separate Platt calibration step." The current bare word "calibration" will be interpreted differently by every reader.

---

## 🟡 Issue 5 — INDEX.md Missing `backend/ml/README.md`

**Involved file:** docs/INDEX.md

**Problem:** `backend/ml/README.md` (26 lines, CURRENT status, ML artifact index) is not listed in INDEX.md. The file-consolidation-plan.md counts it as an active .md file. AGENTS.md doesn't mention it either. It's effectively invisible to new AI agents.

**Recommendation:** Add a row under Reference or a new subsection: "`backend/ml/README.md` — ML artifact index (lives with code)."

---

## 🟡 Issue 6 — MVP_SCOPE.md Column Count (52) vs ROADMAP.md (63)

**Involved files:** docs/architecture/MVP_SCOPE.md (line 108), docs/planning/ROADMAP.md (line 111)

- MVP_SCOPE.md: "52-column schema"
- ROADMAP.md: "63-column `vulnerabilities` table"

**Assessment:** 52 → 63 is a legitimate delta from Sprint 1 (52 columns) to current (63 columns after migrations 001-005). Not a bug per se (MVP_SCOPE.md is OUTDATED by design). But the magnitude of the gap (11 columns) is not explained anywhere — a reader comparing the two docs will see an unexplained numeric contradiction.

**Recommendation:** Either update MVP_SCOPE.md's 52 reference to note "now 63 columns (5 migrations added since Sprint 1)" or ensure the OUTDATED banner is prominent enough. Current banner is adequate but the numeric delta is still confusing.

---

## 🟡 Issue 7 — ROADMAP.md Sprint NEXT+: Claims "Untested" for Endpoints Marked "✅ Done"

**Involved files:** docs/planning/ROADMAP.md

- **Line 154 (ML Artifacts):** "Review queue (4 endpoints) | ✅ Done"
- **Line 220 (Sprint NEXT+ Wave 1):** Item 9 lists `GET /api/review/queue`, `POST /api/review/flag/{id}`, `POST /api/case/{id}/review`, `GET /api/case/{id}/history` as "all untested"

**Contradiction:** "✅ Done" in ML Artifacts implies full implementation. "Untested" in Sprint NEXT+ implies incomplete. Implementation without tests is valid, but "Done" in a sprint-status context usually includes testing. These two assertions create ambiguity about whether these endpoints are truly production-ready.

**Recommendation:** Clarify "✅ Done (implemented)" vs "✅ Done (implemented + tested)". The review queue endpoints should be marked "🟡 Needs tests" until Wave 1 of Sprint NEXT+ completes.

---

## 🔵 Issue 8 — Investigation Report's "All fixes applied" vs ROADMAP's "Retrain pending" Timeline Ambiguity

**Involved files:** xgboost-investigation-report.md, ROADMAP.md

The investigation report (July 2) says "8 fixes applied, 5 require retrain." ROADMAP (July 7) says Sprint 3 "✅ Complete" and Sprint 9 corpus "retrain pending."

**Problem:** A new reader will wonder: "If Sprint 3 already retrained the model, why does the investigation say retrain is pending? Is Sprint 9's corpus the real blockage?" The answer is yes — but neither document makes this timeline explicit.

**Recommendation:** Add a sentence to ROADMAP's Sprint 9 section: "Note: The XGBoost retrain from this new corpus (training_data_v2.npz) is the 'retrain pending' referenced in xgboost-investigation-report.md. The Sprint 3 retrain (93K records, ROC-AUC 0.9677) was a prior cycle."

---

## 🔵 Issue 9 — file-consolidation-plan.md Lists Archived SPRINT_NEXT_PLAN.md as "Current State"

**Involved file:** docs/planning/file-consolidation-plan.md (line 19)

The "Current State Map" table includes `docs/archive/SPRINT_NEXT_PLAN.md` as file #3 with freshness "🟡 SUPERSEDED." But this file is in `docs/archive/` — it's literally archived. Listing it as "current state" is a temporal artefact (the consolidation plan was written before the archiving was finalized).

**Recommendation:** Add a header note: "This state map reflects the pre-consolidation state of the project. Files marked SUPERSEDED have since been archived." Or update to reflect the current arrangement.

---

## 🔵 Issue 10 — ROADMAP.md Lists `tests/` as "37 tests" but SGT Count Is 37

**Involved file:** docs/planning/ROADMAP.md (line 379)

ROADMAP says "37 tests" for `backend/tests/`. Verified: 17+1+4+7+1+7 = 37 test functions across 6 files. ✅ **Count is correct.** This is not an issue — noted for completeness.

(No action needed — marking as CLEAN check.)

---

## 🔵 Issue 11 — RESEARCH_FINDINGS.md's "Q1's 856 positives has 21 unexplained gap" Is Self-Referential

**Involved file:** docs/research/RESEARCH_FINDINGS.md (line 140)

> "Q1's 856 positives has 21 unexplained gap — kev_cache shows 835 KEV entries in NVD corpus with `dateAdded ≤ 2024-12-31`, not 856. The Q1 analysis likely had a string comparison quirk..."

**Problem:** This is a correction from an independent verifier noting an error in the raw research. It's self-acknowledged and transparent — which is good. But the Q1 analysis (which produced the wrong 856 number) is not actually in this document — it was a separate agent output. The document cites a number that was already corrected.

**Recommendation:** Minor. Could remove the self-reference (the document already reports 835 as the correct number). Not urgent.

---

## Clean Checks (No Issues Found)

| Check | Result |
|-------|--------|
| AGENTS.md vs root symlink reality | ✅ All 6 symlinks exist and resolve to real files |
| AGENTS.md's `.opencode/plans/` claim | ✅ Directory exists with 2 plan files |
| INDEX.md status badges vs file headers | ✅ All 10 indexed files match their self-declared status |
| ROADMAP.md quick-start commands | ✅ `uvicorn main:app`, `localhost:8000`, curl verification all self-consistent |
| ROADMAP.md demo score expectations (94, 87, 71, 63, 55, 41, 22) | ✅ Match MVP_SCOPE.md verification criteria |
| WINDOWS_SETUP.md step order | ✅ `cd backend` then `python seed_data.py` is correct |
| hostname-standards.md | Self-contained external reference — no internal claims to contradict |
| ml-implementation-plan.md | Explicitly OUTDATED, banner matches INDEX.md — no new contradictions identified |
| ai-doc-strategy.md vs current file layout | ✅ Claims from July 7 match observed state |

---

## Recommendations for Strike

| # | Action | Effort | Priority |
|---|--------|--------|----------|
| 1 | Add calibration footnote to ROADMAP.md line 138 clarifying whether it's built-in or external | 1 line | High (resolves 3-way contradiction) |
| 2 | Add timeline note to investigation report header differentiating 0.9946 (pre-fix) vs 0.9677 (current) | 2 lines | High |
| 3 | Fix investigation report line 170: "32 of 37 pass; 5 fail due to missing dep" | 1 line | Medium |
| 4 | Add `backend/ml/README.md` to INDEX.md | 1 line | Medium |
| 5 | Add "implemented, not yet tested" disclaimer to ROADMAP review-queue ✅ badge | 2 lines | Low |
| 6 | Add timeline bridging note to ROADMAP §Sprint 9 linking investigation report retrain to corpus | 3 lines | Low |

---

## Verdict

**NOT CLEAN — 11 issues found.** None are infrastructure-breaking, but three are factual contradictions (calibration existence, ROC-AUC era, test-result claim) that could mislead a new agent or human reader. The remaining eight are bookkeeping/staleness gaps. Recommend resolving the top 3 contradictions before the next agent onboards.
