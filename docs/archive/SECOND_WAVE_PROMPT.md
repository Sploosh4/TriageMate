# Wave 2 Audit Prompt — LOGIC & SEMANTIC CORRECTNESS

> **Status: ARCHIVED** — Historical audit prompt. Preserved for provenance.

## Focus: Logical errors, dead code, contradictory conditions, semantic drift between comments and implementation, data inconsistencies, and schema drift.

---

Read the following files and answer each question with either CONFIRMED (and cite the exact lines) or REJECTED (and explain why):

**File 1: `backend/scoring.py` (full file, 113 lines)**

- The docstring on line 23 says the function calculates the score from "five weighted dimensions." Count the actual dimension keys written into the `dimensions` dict. How many are there? Does the code match the docstring? If not, which dimension is undocumented?
- Lines 88-93 handle the `patch_score` computation. What happens when `patch_available` is `False`? Is there an explicit branch, or does it silently default to 0 — the same value as `patch_available=True AND patch_applied=False`? Is this logical?
- Lines 104-111 map the total score to a band. Write out the four bands and their thresholds. Is there a gap between "Medium" (top of range 50) and "Critical" (bottom of range 51-75)? What band name is missing? Is the 51-75 range labelled "Critical" while >75 is "Very Critical" — does any range ever produce the string "High"?

**File 2: `backend/ml/xgboost_predictor.py` lines 140-151 (routing logic)**

- Trace the three `if/elif` branches on `prob`: branches 1 and 2 both return `"escalated"`. Given that branch 1 matches `prob >= 0.50`, what range of `prob` values can branch 2 (`prob >= 0.40`) ever actually reach? Is the branch distinction meaningful, or is branch 2 dead code masked by an identical action?

**File 3: `backend/seed_data.py` rows 4 and 6**

- Row 4 (CVE-2024-1709, line 582): what is the value of `ml_exploitation_contribution`? Now read the corresponding `scoring_weights_json` entry (lines 658-663): what is the `awarded` value for "ML Exploitation Probability Contribution"? Are these consistent? If not, which one is the ground truth?
- Row 6 (CVE-2023-22515, line 951): what is `ml_exploitation_contribution`? Compare to the `scoring_weights_json` `awarded` for ML (line 1029). Same question — do they agree?
- Row 6 (line 949): `exposure_contribution` is -4. Trace the exposure calculation in `scoring.py` lines 79-85. Starting from `exposure=0`, what base contribution does a *non-internet-facing* asset receive? Can the calculation in `scoring.py` ever yield a negative value? Explain the mismatch.

**File 4: `backend/database.py` lines 265-432 (SQLite schema) and `backend/alembic/versions/003_add_resolved_vulnerabilities.py` (migration)**

- The SQLite `resolved_vulnerabilities` table (lines 361-430) includes `ml_exploitation_contribution INTEGER DEFAULT 0` at line 392. Does the Alembic migration `003_add_resolved_vulnerabilities.py` define the same column? List all six contribution columns present in the migration vs. the inline schema. Are there any missing?

**File 5: `backend/pipeline/pre_tier.py` lines 5-21 (module docstring) and lines 161-196 (`predict_mission_tags` function)**

- The docstring (lines 8-11) describes Phase 1 (ML) before Phase 0 (Fallback). What is the actual resolution order in the code at lines 180-196? Is the docstring's numbering correct, or is the priority order inverted relative to the numbering?
- Line 20 says the API contract "NEVER changes" and lists the return keys. Now check the `KNOWN_TAGS` return path (lines 181-188). Do the return key names exactly match the documented contract? (Look carefully at `mission_prevalence_confidence` vs `mission_prevalence_conf`.)

**File 6: `backend/audit.py` lines 14-18 (`should_audit` function)**

- The function samples auto-resolved cases from "Deterministic" and "ML Tier" detection tiers. Review `backend/seed_data.py` rows — is "SLM Tier" ever auto-resolved? If so, would `should_audit` ever return `True` for those cases? Is this a coverage gap?

---

Report all instances of:
- Commented-out code blocks (search for `# ` lines that look like disabled code)
- TODO / FIXME / HACK / XXX / BUG markers
- `assert` statements that Python would strip under `-O` optimization (creating silent data-validation gaps)
- Functions defined but never called (use `grep -rn 'def ' *.py` and cross-reference with a search for call sites)
