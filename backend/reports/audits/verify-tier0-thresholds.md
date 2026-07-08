# Verification Report: "Tier 0 threshold tuning is deferred for the MVP"

**Date:** 2026-07-08
**Scope:** Verification of the claim that Tier 0 deterministic rule threshold tuning is deferred for the MVP.
**Performed by:** auditor
**Pre-flight:** N/A — no analysis scripts were run; this is a document-and-code inspection task.

---

## Claim Being Verified

> **"Tier 0 threshold tuning is deferred for the MVP."**

Interpretation: The Tier 0 deterministic routing rules (`backend/pipeline/tier_0.py`) use threshold constants (CVSS 9.0, EPSS 0.90, CVSS 4.0, EPSS 0.10) that have *not* been tuned against real WA SOC operational data. Tuning is explicitly deferred to post-MVP work.

---

## Evidence Found

### 1. The Threshold Constants — Hardcoded, Not Externally Configurable

**File:** `backend/pipeline/tier_0.py`, lines 13–16

```python
KEV_CVSS_THRESHOLD = 9.0
KEV_EPSS_THRESHOLD = 0.90
LOW_CVSS_THRESHOLD = 4.0
LOW_EPSS_THRESHOLD = 0.10
```

These are plain Python module-level constants. There is **no mechanism** to override them via:
- Environment variables (confirmed: no `os.getenv()` call exists in `tier_0.py`)
- Config files (confirmed: no config file loading in `tier_0.py`)
- `.env` or `.env.example` (confirmed: no tier-0 threshold env vars exist in either file)

The file docstring (line 5) states: *"Thresholds are configurable constants at the top of the file."* This is technically misleading — they are "configurable" only in the sense that a developer can edit the `.py` file directly. They are **not** externally configurable.

**Contrast with Tier 2:** `backend/pipeline/tier_2.py` lines 30–38 uses `os.getenv()` for every configuration value. Tier 0 has no equivalent pattern.

### 2. Tuning Explicitly Called "Future Work" in MVP_SCOPE.md

**File:** `docs/architecture/MVP_SCOPE.md`

| Location | Text | Meaning |
|---|---|---|
| Line 64 | *"The only future work is threshold tuning."* | In the Tier 0 "IN scope" subsection — acknowledges tuning is not yet done |
| Line 191 | `Pipeline Tier 0 \| Deterministic rules (production-ready) \| Threshold tuning (future refinement)` | Scope summary table: threshold tuning is **Out of Scope** (post-MVP) |

### 3. ROADMAP.md — No Mention of Tier 0 Threshold Tuning

**File:** `docs/planning/ROADMAP.md`

- Line 125: Tier 0 is listed as "✅ Done" with note "Deterministic rules: KEV + CVSS + EPSS"
- **No threshold tuning item exists** anywhere in the roadmap — not in Sprint NEXT, Sprint NEXT+, deferred items, or any sprint.
- The only threshold-related items in the roadmap are:
  - Line 141: XGBoost `threshold_info.json` (Tier 1 classification threshold, not Tier 0)
  - Line 180: XGBoost retrain with exported threshold (again, Tier 1)

The absence of any Tier 0 threshold tuning item across 13 sprints and a "Sprint NEXT" section confirms it was never planned.

### 4. Archived Documents Confirm "Future Work" Pattern

| File | Line | Text |
|---|---|---|
| `docs/archive/sprints-1-6/SPRINT_1_HANDOFF.md` | 151 | *"No ML needed. The only future work is tuning the threshold constants."* |
| `docs/archive/TriageMate MVP Transformation.md` | 612 | *"...configured as constants at the top of the file so they can be tuned without changing logic."* |
| `docs/archive/TriageMate MVP Transformation.md` | 1172 | *"The only future work is tuning the threshold constants."* |
| `docs/archive/ml-implementation-plan.md` | 706 | *"Audit results feed into model retraining prioritization and threshold tuning."* |

All documents consistently identify threshold tuning as outstanding future work.

### 5. No Evidence of Data-Driven Tuning

- No research report, analysis script, or audit record shows that these values were derived from WA SOC operational data.
- The values align with conventional cybersecurity thresholds:
  - **CVSS ≥ 9.0** → industry standard for "Critical" severity (NIST CVSS v3.0 range: 9.0–10.0 = Critical)
  - **EPSS ≥ 0.90** → top decile of exploitation probability
  - **CVSS < 4.0** → below "Medium" severity threshold (NIST: 4.0–6.9 = Medium)
  - **EPSS < 0.10** → bottom decile
- `docs/research/RESEARCH_FINDINGS.md` (lines 88–106) discusses EPSS threshold research for a *substitution model*, not Tier 0. It finds that stratified thresholds vary significantly by CWE — implying the monolithic defaults in Tier 0 are unoptimized.

### 6. No Dedicated Tests for Threshold Values

- There is no `test_tier_0.py` file in `backend/tests/`.
- The integration test (`test_integration.py`, lines 103–106) validates that CVE-2023-34362 (MOVEit, KEV + CVSS 9.8 + internet-facing) hits Tier 0 auto-resolve, but this tests the *logic* (KEV + CVSS ≥ 9.0 + IF → auto-resolve), not whether the 9.0 threshold is optimal.

---

## Verdict

### CONFIRMED — with nuance

**The claim is correct:** Tier 0 threshold tuning is explicitly deferred for the MVP. Four planning documents (MVP_SCOPE.md, SPRINT_1_HANDOFF.md, TriageMate MVP Transformation.md, ml-implementation-plan.md) all state that threshold tuning is "future work" / "future refinement" / deferred. The ROADMAP.md contains no Tier 0 threshold tuning item across any sprint.

**The nuance:** The thresholds *exist* as hardcoded constants with plausible default values (CVSS 9.0, EPSS 0.90, CVSS 4.0, EPSS 0.10). They are not zero or placeholder — they will produce correct deterministic routing for the 7 demo rows (test_integration.py confirms this). The claim is about *tuning* (data-driven optimization against real WA SOC data), not *existence*.

**0 passed, 0 failed, 0 skipped** — this is a document-inspection task, not a test run.

---

## Findings Summary

| Finding | Status | Evidence |
|---|---|---|
| Thresholds are hardcoded Python constants | ✅ CONFIRMED | `tier_0.py:13-16` — plain constants, no env var/config mechanism |
| Thresholds are externally configurable | ❌ REFUTED | No `os.getenv`, no config file, no `.env` entry for thresholds |
| Threshold tuning is deferred/OOS for MVP | ✅ CONFIRMED | MVP_SCOPE.md:64,191; ROADMAP.md no tuning item; SPRINT_1_HANDOFF.md:151 |
| Tuning against real WA SOC data has occurred | ❌ REFUTED | No evidence found; values are conventional defaults |
| Values produce correct demo row routing | ✅ CONFIRMED | test_integration.py:103-106 validates MOVEit hits Tier 0 auto-resolve |

---

## Recommendations

1. **If the claim needs to be actionable:** When WA SOC operational data becomes available, the four threshold constants should be tuned using that data. A principled tuning approach would optimize for metrics like F1, precision@K, or operational workload reduction, depending on WA SOC's priorities.

2. **If the claim is used in a status report:** It is accurate as written, but a reader should understand that the thresholds exist with reasonable defaults and work correctly for the demo. The "deferred" part is only about data-driven optimization.

3. **Optional cosmetic fix:** The docstring in `tier_0.py` line 5 says *"Thresholds are configurable constants at the top of the file."* This could be clarified to: *"Thresholds are set as module-level constants. To tune them for production, edit these values or replace them with an env-var-based configuration pattern (see tier_2.py for precedent)."*

---

## Assumptions

**Assumption 1:** I assumed "tuning" refers to data-driven optimization against real WA SOC operational data, not the mere existence of threshold values or their correctness for the demo. If the claim intended "thresholds are completely absent," it would be false — they exist with conventional defaults.

**Assumption 2:** I assumed the "MVP" is defined by the scope boundaries in `docs/architecture/MVP_SCOPE.md`, `docs/planning/ROADMAP.md`, and associated sprint handoff documents. These are the authoritative sources.

**Assumption 3:** I assumed the absence of any Tier 0 threshold tuning item in ROADMAP.md (across 13 sprints + Sprint NEXT) implies it was never planned for any sprint, consistent with it being deferred.
