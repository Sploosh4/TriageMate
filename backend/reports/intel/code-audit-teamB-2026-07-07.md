# Code Comment Audit — Team B (ML / Integrations / Scripts / Analysis / Alembic / Frontend / Config)

**Date:** 2026-07-07
**Requested by:** Commander (via tasking)
**Sources consulted:** Direct file reads of all 54 files in audit scope

## Files Audited

### ML (13 files)
`encoder.py`, `xgboost_predictor.py`, `train_xgboost.py`, `vector_store.py`, `epss_substitutor.py`, `pretier_features.py`, `train_pre_tier.py`, `train_epss_v2.py`, `train_epss_v3.py`, `fetch_epss_data.py`, `generate_supplemental_hostnames.py`, `ingest_docs.py`, `README.md`

### Integrations (12 files)
`nvd.py`, `osv.py`, `exploitdb.py`, `metasploit.py`, `greynoise.py`, `otx.py`, `mitre_mapping.py`, `advisories.py`, `tenable.py`, `cmdb.py`, `demo_generator.py`, `llm.py`

### Scripts (5 files)
`refresh_caches.py`, `build_training_corpus.py`, `build_vendor_index.py`, `build_cwe_hierarchy.py`, `fetch_nvd_corpus.py`

### Analysis (4 files)
`calibration_audit.py`, `epss_eval.py`, `feature_parity_check.py`, `validate_conversion.py`

### Alembic (6 files)
`env.py`, `001_initial_schema.py`, `002_add_analytics_columns.py`, `003_add_resolved_vulnerabilities.py`, `004_add_review_queue.py`, `005_add_ml_exploitation.py`

### Frontend (8 files)
`index.html`, `css/triagemate.css`, `js/api.js`, `js/app.js`, `js/components/auth.js`, `js/components/queue.js`, `js/components/caseView.js`, `js/components/metricBoxes.js`, `js/components/demoControls.js`, `js/components/reviewQueue.js`, `js/components/driftDashboard.js`

### Config (5 files)
`Dockerfile`, `docker-compose.yml`, `justfile`, `opencode.jsonc`, `requirements-dev.txt`

## Findings

### Finding 1: "Category 1–4" terminology persists in code (8 occurrences across 4 files)

The WA government moved from PRIS Act "Category 1–4" to **WAICP** ("OFFICIAL" / "OFFICIAL Sensitive"). The previous audit (2026-07-07-code-comment-audit.md) fixed PRIS Act string references, but the old **"Category 1"** classification name still appears as a mapping key and default value.

| # | File | Line(s) | Details |
|---|---|---|---|
| 1 | `backend/integrations/cmdb.py` | 175 | `ctx.get("data_classification", "Category 1")` — default fallback uses old term |
| 2 | `backend/integrations/cmdb.py` | 219 | `"data_classification": "Category 1"` — stub default dict uses old term |
| 3 | `backend/ml/xgboost_predictor.py` | 218 | `mapping = {"OFFICIAL Sensitive": 4, "OFFICIAL": 2, "Category 1": 1}` — key is old term |
| 4 | `backend/scripts/build_training_corpus.py` | 186 | `_encode_classification` mapping contains `"Category 1": 1` — old term |
| 5 | `backend/analysis/feature_parity_check.py` | 151 | `_train_encode_classification` mapping contains `"Category 1": 1` — old term |
| 6 | `backend/analysis/feature_parity_check.py` | 166 | `_infer_encode_classification` mapping contains `"Category 1": 1` — old term |
| 7 | `backend/ml/pretier_features.py` | 127 | Variable `CATEGORY_4_KEYWORDS` — naming uses old term |
| 8 | `backend/ml/pretier_features.py` | 188 | Variable `CATEGORY_2_KEYWORDS` — naming uses old term |
| 9 | `backend/ml/pretier_features.py` | 207 | Variable `CATEGORY_1_KEYWORDS` — naming uses old term |

**Impact:** Low. These are internal mapping keys and variable names, not user-facing strings or demo data. The WAICP docstring in `pretier_features.py` line 309–310 correctly uses WAICP terminology. However, the inconsistency makes the code harder to reason about.

**Previous audit status:** The PRIS Act → WAICP docstring fixes (e.g. `cmdb.py` line 169 now says "WAICP" correctly) **have been applied**. Only the old "Category" naming remains in mapping keys and variable identifiers.

---

### Finding 2: CMDB stub returns mixed classification terminology

`backend/integrations/cmdb.py`:
- **KNOWN_HOSTS** (lines 44–156) uses WAICP terms: `"OFFICIAL Sensitive"`, `"OFFICIAL"`
- **Fallback stub** (line 219) returns `"Category 1"` — old terminology

This means an unknown host gets the old classification name while known ones get WAICP names. Downstream consumers (`build_training_corpus.py`, `xgboost_predictor.py`) then map these to numeric codes, so the behavior is correct — but the string value is inconsistent.

**Impact:** Low. Numeric encoding works either way, but the mixed output suggests incomplete migration.

---

### Finding 3: Frontend still processes "Category" compliance labels

`frontend/js/components/queue.js` line 130:
```javascript
r.compliance.replace('Category ', 'CAT ')
```

This replaces "Category 1" → "CAT 1" for display. If the backend were to return WAICP terms like "OFFICIAL" or "OFFICIAL Sensitive", this replacement would be a no-op — but it's a latent dependency on old terminology.

**Impact:** Low. No-op for WAICP strings, but creates confusion about which format the backend sends.

---

### Finding 4: Inconsistent User-Agent version strings

Several files use different version strings in HTTP User-Agent headers:

| File | Version | Line |
|---|---|---|
| `backend/integrations/nvd.py` | `TriageMate/0.2.0` | 101 |
| `backend/scripts/refresh_caches.py` | `TriageMate/0.2.0` | 333, 560 |
| `backend/scripts/refresh_caches.py` | `TriageMate/0.3.0` | 370, 441 |
| `backend/scripts/fetch_nvd_corpus.py` | `TriageMate/0.3.0` | 286, 376, 498 |
| `backend/ml/fetch_epss_data.py` | `TriageMate/0.2.0` | 46 |

Three different version strings (`0.2.0` and `0.3.0`) in active use across HTTP requests to external APIs.

**Impact:** Negligible on API behaviour (User-Agent is advisory), but signals poor version discipline.

---

### Finding 5: Feature dimension counts are consistent — no contradictions

I verified every feature-count comment against its implementing code:

| File | Claimed Count | Actual Count | Verdict |
|---|---|---|---|
| `encoder.py` | 384-dim SBERT | 384 | ✅ |
| `xgboost_predictor.py` | 35 tabular + text | 35 + 384 = 419 | ✅ |
| `train_xgboost.py` | 35 tabular | 35 | ✅ |
| `build_training_corpus.py` | 36 tabular + 384 text (model uses 419, osv_lead_days is metadata) | 36 + 384 = 420 | ✅ |
| `pretier_features.py` | 60 dimensions | 60 | ✅ |
| `feature_parity_check.py` | 35 features | 35 | ✅ |
| `validate_conversion.py` | 35 features | 35 | ✅ |

All dimension counts match their code. No contradictions found.

---

### Finding 6: Reference to possibly deleted documentation

`backend/integrations/demo_generator.py` line 14:
```python
# Design per DEMO_DATA_GENERATOR_PLAN.md §3.2 and §3.3.
```

This references a document (`DEMO_DATA_GENERATOR_PLAN.md`) that may have been deleted or moved during the documentation restructuring. I did not find this file in the current project tree.

**Impact:** Low. The comment is historical and doesn't affect execution. If the document has been deleted, this is a dead reference.

---

### Finding 7: "50 well-known CVEs" comment slightly misleading

`backend/scripts/refresh_caches.py` lines 49–52:
```python
# Hardcoded "greatest hits" list of 50 well-known CVEs spanning
# the last several years — used as baseline when mock_cmdb.json
# is not yet available (Phase 1.1 prerequisite).
```

The first block (lines 53–102) contains exactly 50 CVEs. Lines 103–115 add 14 more with the comment `# Phase 3 scenarios (Intel-approved)`. So the comment is technically correct for the first block, but a reader scanning quickly might think the total list is 50.

**Impact:** Trivial documentation clarity issue.

---

### Finding 8: No stale `docker-compose` (hyphenated) commands in audited files

All files in scope use `docker compose` (V2, space-separated) or reference the filename `docker-compose.yml`. No stale V1 commands found in any of the 54 audited files.

---

### Finding 9: No stale TODO/FIXME items found

No `TODO`, `FIXME`, `HACK`, or `XXX` markers were found in any of the 54 Python and JS files in the audit scope. All historical TODOs have been resolved.

---

### Finding 10: `greynoise.py` deprecation notice is current

`backend/integrations/greynoise.py` line 1 is correctly marked `DEPRECATED` with a clear explanation of the replacement (`_synthetic_internet_scan()` in `ingest_helpers.py`). No action needed.

---

## Assessment

The codebase is in **good comment hygiene** for the audited scope. The previous audit's PRIS Act → WAICP fixes have been successfully applied to the docstrings in `cmdb.py` and `pretier_features.py`.

**Remaining issues are cosmetic:**
- "Category 1" mapping keys and variable names (Finding 1, 2, 3) are artifacts of the old PRIS Act naming convention. They don't affect functionality but should be cleaned up for consistency with WAICP.
- Mixed User-Agent version strings (Finding 4) are low-urgency polish.
- The `DEMO_DATA_GENERATOR_PLAN.md` reference (Finding 6) is a minor dead-link comment.

**No critical bugs, no TODO/FIXME debt, no feature count contradictions, no stale docker-compose commands, no PRIS Act strings in the audited files.**

## Recommendations

1. **Low priority** — Rename `CATEGORY_4_KEYWORDS` → `SENSITIVE_KEYWORDS`, `CATEGORY_2_KEYWORDS` → `OFFICIAL_KEYWORDS`, `CATEGORY_1_KEYWORDS` → `UNCLASSIFIED_KEYWORDS` in `pretier_features.py` to match WAICP terminology. Update all mapping keys `"Category 1"` → `"OFFICIAL"` or remove the entry as appropriate (file-by-file review needed).

2. **Low priority** — Unify User-Agent strings to `TriageMate/0.3.0` across all HTTP client files.

3. **Informational** — Verify whether `DEMO_DATA_GENERATOR_PLAN.md` still exists. If deleted, update or remove the comment in `demo_generator.py` line 14.

4. **Clean** — No action needed for PRIS Act, dimension counts, docker-compose, or TODOs. All previously flagged issues in this scope have been resolved.
