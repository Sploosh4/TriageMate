# Code Comment Audit — Outdated/Incorrect Comments

**Date:** 2026-07-07
**Requested by:** Commander (automated audit task)
**Sources consulted:** Full grep scan of backend/ and frontend/ directories; manual review of key files

---

## Summary

Scanned all Python (.py), JavaScript (.js), Dockerfiles, YAML/yml, and HTML files for outdated or incorrect comments. Found **15 issues** across three categories:

| Category | Count |
|---|---|
| PRIS Act → WAICP (name change) | 10 |
| Wrong scoring dimension count | 2 |
| Deprecated feature references | 2 |
| Incorrect version in API metadata | 1 |

The codebase is generally well-maintained — no old PCA references, no SecureBERT references in active code, and feature-count comments (35 tabular + 384 SBERT) are accurate.

---

## Finding 1: PRIS Act → WAICP (10 occurrences)

The legislation formerly known as "PRIS Act" was renamed to "WAICP". However, **10 code-level comment/docstring references still say "PRIS Act"**.

| # | File | Line | What it says | Should say |
|---|---|---|---|---|
| 1 | `backend/seed_data.py` | 65 | `"under the PRIS Act"` (in investigation_notes) | `"under WAICP"` |
| 2 | `backend/seed_data.py` | 151 | `"PRIS Act classification"` | `"WAICP classification"` |
| 3 | `backend/seed_data.py` | 332 | `"PRIS Act classification"` | `"WAICP classification"` |
| 4 | `backend/seed_data.py` | 510 | `"PRIS Act classification"` | `"WAICP classification"` |
| 5 | `backend/seed_data.py` | 692 | `"PRIS Act classification"` | `"WAICP classification"` |
| 6 | `backend/seed_data.py` | 875 | `"PRIS Act classification"` | `"WAICP classification"` |
| 7 | `backend/seed_data.py` | 1058 | `"PRIS Act classification"` | `"WAICP classification"` |
| 8 | `backend/seed_data.py` | 1240 | `"PRIS Act classification"` | `"WAICP classification"` |
| 9 | `backend/integrations/cmdb.py` | 169 | docstring: `"Look up the PRIS Act data classification"` | `"Look up the WAICP data classification"` |
| 10 | `backend/scoring.py` | 37, 68 | param docstring: `"PRIS Act classification level"` and comment: `"It is NOT mandated by the PRIS Act itself."` | `"WAICP classification level"` and `"WAICP"` |

**Also affected** (docstring references, lower priority):
- `backend/ml/pretier_features.py` line 310: `"Derive a PRIS Act data classification from hostname keywords"` → `"WAICP data classification"`
- `backend/pipeline/tier_0.py` line 35: `"PRIS Act data classification level"` → `"WAICP data classification level"`

**Good:** Three files already use `WAICP` correctly:
- `backend/ingest_helpers.py:24` — `"Look up the WAICP data classification"`
- `backend/pipeline/pre_tier.py:7` — `"WAICP OFFICIAL/OFFICIAL Sensitive"`
- `backend/routers/ingest.py:35` — `"Map WAICP classification to numeric compliance category"`

---

## Finding 2: Wrong Scoring Dimension Count (2 occurrences)

The scoring engine now has **6 dimensions** (cvss, epss, ml_exploitation, criticality, exposure, patch), but two references say a different number.

| # | File | Line | What it says | Should say |
|---|---|---|---|---|
| 11 | `backend/tests/test_integration.py` | 114 | Comment: `"Scoring weights — exactly 5 dimensions with correct shape"` | `"Scoring weights — 6 dimensions with correct shape"` (the assert on line 118 already correctly checks `== 6`) |
| 12 | `backend/seed_data.py` | 65 | Investigation notes: `"All four scoring dimensions triggered at maximum severity"` | `"All six scoring dimensions triggered at maximum severity"` |

---

## Finding 3: Deprecated Feature References (2 occurrences)

| # | File | Line | What it says | Should say |
|---|---|---|---|---|
| 13 | `backend/ingest_cwe.py` | 2 | Module docstring: `"CWE classifier for the ingest pipeline."` | Should clarify this is now an NVD API + regex lookup, not a SecureBERT/ML classifier. **Assumption:** This may be intentional legacy naming — confirm with commander. |
| 14 | `backend/main.py` | 109 | `"CWE classifier deprecated — replaced by NVD API + ingest_cwe.py; no update path exists"` | This is **technically correct** but could be clarified — `ingest_cwe.py` IS the replacement, but the comment reads as if the replacement is external. Consider: `"Standalone CWE ML classifier deprecated — ingest_cwe.py (NVD API + regex) is the active implementation"` |

---

## Finding 4: Incorrect API Version (1 occurrence)

| # | File | Line | What it says | Should say |
|---|---|---|---|---|
| 15 | `backend/main.py` | 108 | `version="0.2.0"` in `FastAPI(title="TriageMate API", version="0.2.0")` | **Likely outdated** — Given the project has gone through v2.2, v2.3, v2.5 releases (referenced in comments), the API version `0.2.0` is stale. But this may be intentional semver. Flag as assumption. |

---

## Items Checked — No Issues Found

| Check | Result |
|---|---|
| PCA references in project code | **Clean** — only venv/ references (scikit-learn internals) |
| SecureBERT / CWE ML classifier references | **Clean** — `ingest_cwe.py` is the NVD-based replacement; `main.py` correctly marks CWE classifier as deprecated |
| "68 features" / "69 features" | **Not found** in project code |
| "5 dimensions" → now 6 | **One found** (see #11 above) |
| "37 features" (EPSS models) | **Correct** — these are EPSS-specific models with 37 features; not the main scoring/ML pipeline |
| Sprint references | **Clean** — only `backend/integrations/llm.py:11` (Sprint 6 extraction note, valid historical context) |
| `docker-compose` vs `docker compose` | **Not found** in any project file |
| Frontend JS stale comments | **Clean** — no TODO/FIXME/HACK/WORKAROUND found in frontend |
| Feature count: 35 tabular + 384 SBERT | **Correct** — all references match actual code |
| PCA removal note (v2.5) in encoder.py | **Correct and accurate** |
| KEV temporal bias fix comments in train_xgboost.py | **Accurate and well-documented** |
| "Temporary fix" in train_epss_v2.py (line 201) / epss_substitutor.py (line 452) | These refer to `vendor_patch_status == 1` meaning "temporary fix available" — they are **data labels, not stale code comments** |

---

## Assessment

The codebase is in good shape regarding comment hygiene. The most impactful issue is the **PRIS Act → WAICP rename** (10 occurrences in seed data and docstrings), which should be corrected to avoid confusion with actual WA government terminology. The **5→6 dimension comment** in the integration test is a clear contradiction between the comment and the assertion on the next line — the assertion is correct, the comment is wrong.

No blocking issues found. None of these affect runtime correctness.

---

## Recommendations

| Priority | Action | Files |
|---|---|---|
| **High** | Replace `PRIS Act` with `WAICP` in all docstrings and comments | `backend/scoring.py`, `backend/integrations/cmdb.py`, `backend/pipeline/tier_0.py`, `backend/ml/pretier_features.py` |
| **Medium** | Fix seed_data.py PRIS Act references (demo data) | `backend/seed_data.py` (7 occurrences in data_classification values + 1 in investigation_notes) |
| **Medium** | Fix comment in test_integration.py line 114 | `backend/tests/test_integration.py:114` |
| **Low** | Fix "four scoring dimensions" → "six" in seed_data investigation notes | `backend/seed_data.py:65` |
| **Low** | Update API version in `main.py` | `backend/main.py:108` — current `0.2.0` is likely behind actual release version |
| **Low** | Clarify `ingest_cwe.py` module docstring to avoid implying SecureBERT | `backend/ingest_cwe.py:2` |
| **Info** | `integrations/greynoise.py` — DEPRECATED header is accurate, no change needed | — |
