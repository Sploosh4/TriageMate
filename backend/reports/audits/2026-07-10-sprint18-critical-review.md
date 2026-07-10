# Critical Review: Sprint 18 Plan

**Date:** 2026-07-10
**Reviewer:** auditor
**Files examined:**
- `.opencode/plans/2026-07-10-sprint-18.md` — the plan
- `backend/database.py` — schema DDL
- `backend/pipeline/tier_0.py` — Tier 0 evaluator
- `backend/pipeline/pre_tier.py` — Pre-Tier model caller
- `backend/routers/ingest.py` — pipeline orchestration
- `backend/routers/queue.py` — existing drift endpoints
- `backend/ml/xgboost_predictor.py` — CWE_EPSS_THRESHOLDS, _tier_zero_check
- `backend/ml/pretier_features.py` — extract_features() output format
- `backend/ml/epss_substitutor.py` — feature vector construction
- `backend/analysis/drift.py` — compute_drift() signature
- `backend/ingest_helpers.py` — serialize_tabular_features(), build_feature_vector()
- `backend/ingest_cwe.py` — get_cwe() → get_nvd_data() chain
- `backend/integrations/nvd.py` — get_nvd_data() return shape
- `backend/tests/test_drift_ml.py` — existing drift test pattern
- `backend/ml/reference_distributions.json` — reference distribution format
- `backend/models.py` — MlDriftResponse, MlDriftFeature models
- `backend/tests/` — test inventory
- `docs/planning/ROADMAP.md` — roadmap item 10
- `backend/reports/intel/2026-07-10-sprint18-verification.md` — referenced verification
- Live DB query for current demo scores

---

## Overall Assessment

**The plan is fundamentally sound but has critical gaps that will cause implementation failures if not addressed.**

Items 1 and 2 (Tier 0 rules) are well-scoped, correctly ordered, and the technical claims check out against the codebase. No circular import risk exists. Part A of Item 2 is confirmed complete.

Items 3 and 4 (drift monitoring) have a **show-stopping DB migration hole**: the plan assumes `CREATE TABLE IF NOT EXISTS` will add columns to existing tables — it will not. The INSERT statements will fail with "no such column" on any existing database. This single issue could derail both items.

The plan's acceptance criteria reference incorrect baseline demo scores (claim `94/92/86/76/71/63/57` but the actual DB has `98/91/73/66/58/44/26`). Anyone using these values for regression testing will get false failures.

Effort estimates for Items 3 and 4 are ~40% understated — 3-4 hours each is likely 5-6 given the DB migration, reference distribution script, and multi-model complexity.

---

## Per-Item Analysis

### Item 1: NVD Reference Count ≥21 Tier 0 Rule

| Dimension | Rating | Evidence |
|-----------|--------|----------|
| Phase order | ✅ Correct | First item. Independent of Items 2-4. No build dependencies. |
| Real problem | ✅ Real | `nvd_reference_count` is already collected at `ingest_helpers.py:478` and fed to XGBoost (`xgboost_predictor.py:80`). Using it in Tier 0 is a free signal with strong research backing (9.5× KEV rate claim). |
| Scope/effort | ✅ Realistic | 30 min. Add parameter to `evaluate_tier_0()`, add constant, add comparison. ~5 lines of logic. |
| Dependencies | ✅ Clean | `get_nvd_data()` is called inside `get_cwe()` at ingest.py line 109 (step 3), which populates the 24h TTL cache. A second call before `evaluate_tier_0()` at line 158 (step 5) is indeed a cache hit. No new network calls. |
| Failure modes | ✅ Safe | NVD data unavailable → `nvd_reference_count=0` → rule doesn't fire → falls through to existing logic. No new failure path introduced. |

**Detail check:** The plan's claim that `get_nvd_data()` is called by `get_cwe()` is confirmed — `ingest_cwe.py:45` calls `get_nvd_data(cve_id)` which populates the NVD module's 24h in-memory TTL cache (`nvd.py:_CACHE`). A subsequent call to `get_nvd_data()` before `evaluate_tier_0()` returns the cached result. ✅

**Verdict: PASS** — No issues.

---

### Item 2: CWE-Stratified EPSS Thresholds — Extend to Tier 0

| Dimension | Rating | Evidence |
|-----------|--------|----------|
| Phase order | ✅ Correct | After Item 1 (or parallel). Modifies same file (`tier_0.py`). |
| Real problem | ✅ Real | The monolithic `LOW_EPSS_THRESHOLD = 0.10` at `tier_0.py:16` is indeed applied uniformly regardless of CWE. `CWE_EPSS_THRESHOLDS` at `xgboost_predictor.py:41-51` has optimal thresholds for 8 CWEs that differ from 0.10. |
| Scope/effort | ✅ Realistic | 45 min. Add `cwe_class` parameter, import constant, replace one line of logic. |
| Dependencies | ✅ Clean | **No circular imports.** `pipeline/tier_0` → `ml/xgboost_predictor` is one-way. Verified via grep: no `ml/` module imports from `pipeline/`. `xgboost_predictor.py`'s module-level side effect (`_init_active_paths_from_registry()` at line 215) reads a JSON file — no risk of circular import loop. |
| Failure modes | ⚠️ Note | **Part A: Dead code fix is confirmed done.** `_tier_zero_check()` at `xgboost_predictor.py:218-245` IS called by `predict()` at line 332. Keys `cwe_class` and `cisa_kev` are present in `build_feature_vector()` output (`ingest_helpers.py:498-499`). ✅ |
| | | **Part B design consideration:** The CWE_EPSS_THRESHOLDS dict was derived for the XGBoost pre-check (high-severity fast-path), not Tier 0's low-severity auto-resolve. Using 0.515 for CWE-78 as a LOW threshold means CVEs with EPSS up to 0.515 are auto-resolved as low — 5× the current 0.10 bar. This could auto-resolve more CWE-78 cases than expected. The plan's rationale is documented but implementers should be aware of the behavioral change. ⚠️ |

**Detail check — import path verification:**
```
tier_0.py imports: logging
  ↓ (adding) ml.xgboost_predictor → ml.encoder → sentence_transformers (no pipeline/)
```
No circular dependency exists. ✅

**Verdict: PASS** — Minor design consideration noted but not a blocker.

---

### Item 3: Pre-Tier RF Drift Monitoring

| Dimension | Rating | Evidence |
|-----------|--------|----------|
| Phase order | ✅ Correct | After Items 1-2. Should precede Item 4 (establishes pattern). |
| Real problem | ✅ Real | XGBoost has PSI drift monitoring (`GET /api/drift/ml`). Pre-Tier model has none. If its 60-dim input distribution shifts, prediction quality degrades silently. |
| Scope/effort | ❌ Underestimated | Plan says 3-4 hrs. Realistic estimate: **5-6 hrs.** Breakdown below. |

**Sub-estimates:**
| Sub-task | Plan estimate | Realistic | Reason |
|----------|:------------:|:---------:|--------|
| DB schema: add `pre_tier_features TEXT` column | (included) | 1.0 hr | See "failure modes" below — ALTER TABLE + migration needed |
| Pipeline: expose feature vector from `pre_tier.py` | (included) | 0.5 hr | `extract_features(hostname)` already exists at `pretier_features.py:361`. `_predict_with_model()` calls it internally. Returning it alongside tags is ~5 lines. |
| Ingest: store in INSERT | (included) | 0.5 hr | Add column value to existing INSERT pattern |
| Reference distribution script | (included) | 1.5-2.0 hr | New script needed to load synthetic_assets (~1,827 rows), compute 60-dim features, create per-feature bins + expected proportions matching `reference_distributions.json` format |
| API endpoint + queue.py changes | (included) | 1.0 hr | Follow `get_ml_drift()` pattern — need new loader for Pre-Tier reference dists |
| Tests | (included) | 0.5 hr | Follow `test_drift_ml.py` pattern |
| **Total** | **3-4 hrs** | **5-6 hrs** | |

| Dependencies | ❌ Major gap | See failure modes |
| Failure modes | ❌ Critical | **DB SCHEMA MIGRATION HOLE:** The plan says to add columns to `CREATE TABLE IF NOT EXISTS` statements in `_init_db_sqlite()` and `_init_db_pg()`. This will NOT add columns to existing tables. When the INSERT at `ingest.py:421-457` tries to write to `pre_tier_features`, the DB will return "no such column" and the ingest will fail. |
| | | **Root cause:** `CREATE TABLE IF NOT EXISTS` only creates the table if it doesn't exist. Since `vulnerabilities` and `resolved_vulnerabilities` tables already exist, the DDL is silently ignored. |
| | | **Required fix:** Either (a) add `ALTER TABLE ... ADD COLUMN ...` statements after the CREATE TABLE, (b) use Alembic migrations (which the codebase supports via `database.py:run_migrations()`), or (c) use `CREATE TABLE IF NOT EXISTS` only for fresh installs and handle migration separately. |

**Detail check — `compute_drift()` compatibility:**
- `compute_drift()` signature at `drift.py:62-65`: `(features_json_list: list[dict], reference_dists: dict) → dict`
- Pre-Tier `extract_features()` returns a dict with 60 keys like `{"env_code": 1, "agency_health": 1, ...}`
- The function bins values per feature against reference bins — binary and ordinal features work fine
- **Silent mismatch risk:** If feature keys in the reference distributions don't exactly match keys from `extract_features()`, `compute_drift()` silently skips them (returns 0.0 PSI for missing features). The plan doesn't include a validation step to verify key alignment.
- **Verdict on compatibility:** Functionally compatible. But add a validation step between generating reference distributions and deploying them. ⚠️

**Verdict: FAIL WITH ISSUES** — DB migration hole is a show-stopper. Effort is significantly underestimated.

---

### Item 4: EPSS Drift Monitoring

| Dimension | Rating | Evidence |
|-----------|--------|----------|
| Phase order | ✅ Correct | After Item 3 (follows established pattern). |
| Real problem | ✅ Real | EPSS substitution models (v4/v3/v2/v1) adjust EPSS for sector relevance. Input distribution shift (CWE mix, agency ratios) degrades substitution quality. |
| Scope/effort | ❌ Underestimated | Same as Item 3 — **5-6 hrs** realistic. Plus additional complexity from multi-model dimensionality (below). |
| Dependencies | ⚠️ Gap | Same DB migration issue as Item 3. |
| Failure modes | ⚠️ Unaddressed | **Feature vector dimensionality varies by model version:** |
| | | - v4/v3/v2: 37-dim (6 continuous + 11 agency OHE + 20 CWE OHE) |
| | | - v1: 22-dim (2 continuous + 1 binary + 8 agency OHE + 11 CWE OHE) |
| | | - Rule engine: no feature vector at all (would need to store NULL) |
| | | The plan assumes a single `epss_reference_distributions.json` but doesn't specify how version differences are handled. If v4 is replaced by v1 (e.g., model file deleted), stored features change from 37-dim to 22-dim. `compute_drift()` would try to bin 22-dim vectors against 37-dim reference bins — mismatched features are silently dropped, giving zero PSI for the missing 15 features. |

**Detail check — feature vector extraction from epss_substitutor.py:**
- `_build_feature_vector_v2()` at line 326 returns `list` (37 elements) — NOT a dict. `compute_drift()` expects `list[dict]` (each row is a dict of feature_name: value).
- `_build_feature_vector_v1()` at line 297 returns `list` (22 elements) — same issue.
- **Plan gap:** The feature vector is a positional list, not a named dict. For `compute_drift()` to work, it needs to be converted to a dict with feature names. The plan doesn't specify where the feature names come from. Looking at `_build_feature_vector_v2()`, the positions are:
  1. raw_epss
  2. cvss_score  
  3. exploit_maturity
  4. cisa_kev
  5. has_public_poc
  6. vendor_patch_status
  7-17. agency OHE (11 agencies including "unknown")
  18-37. CWE OHE (20 CWEs)
  
  This positional scheme needs to be mapped to named features before `compute_drift()` can use it. The plan doesn't address this. ⚠️

- `calculate_substitution()` return values (`_ml_predict()` line 614-621 and `_rule_engine()` line 452-458) currently don't include the feature vector. Adding it as an extra key is backward-compatible (callers ignore unknown keys). ✅

**Verdict: FAIL WITH ISSUES** — Same DB migration hole. Unaddressed feature name mapping complexity. Multi-model dimensionality not handled.

---

### Bonus Items

#### Bonus A: Extend CWE_EPSS_THRESHOLDS Coverage

| Rating | Assessment |
|--------|-----------|
| ⚠️ Scoping | Effort 20 min is realistic (data entry). But lowering `DEFAULT_EPSS_THRESHOLD` from 0.84 to ~0.50 is a behavioral change that affects all CWEs not in the dict. This should be data-backed, not arbitrary. |

#### Bonus B: CWE-Stratified KEV Threshold in Tier 0

| Rating | Assessment |
|--------|-----------|
| ✅ Sound | Same pattern as Item 2 Part B. 15 min estimate is realistic. Depends on Item 2 being done (same approach, same code location). |

#### Bonus C: Update threshold_info.json with CWE Data

| Rating | Assessment |
|--------|-----------|
| ✅ Sound | 15 min. Pure data entry. Depends on Items 2/Bonus A (new thresholds are the data to store). |

#### Bonus D: Document Scoring Weight Design

| Rating | Assessment |
|--------|-----------|
| ⚠️ Discrepancies | Plan says 30 min, but ROADMAP.md line 64 says **1 hr**. Plan says "112-sum weight design" but ROADMAP says **107-sum** weight design. Current scoring.py dimensions sum to 112 (40+20+20+12+5+10+5). One of these documents is wrong — the plan should note and reconcile the discrepancy. |
| | The plan lists this correctly as Bonus (Low priority), matching ROADMAP's placement in "Medium-Term Engineering" not "Sprint 18." However, if scoring weight documentation is important enough to be roadmapped, it's odd to leave it to "if time permits." |
| | No code dependencies — could be done at any time. |

---

## Key Risks (ordered by severity)

### 🔴 Risk 1: DB migration hole will break ingest (Items 3 & 4)
**Severity: Critical** | **Likelihood: Certain**
`CREATE TABLE IF NOT EXISTS` does NOT add columns to existing tables. When the INSERT statement references `pre_tier_features` or `epss_features`, every existing database will reject it with "no such column." This will manifest as a complete ingest failure on any developer or production database that already exists.

**Fix:** Add `ALTER TABLE vulnerabilities ADD COLUMN pre_tier_features TEXT;` (and the equivalent for resolved_vulnerabilities, epss_features, and PostgreSQL variant) either in `init_db()` or as an Alembic migration. The codebase already supports Alembic (`database.py:run_migrations()` at line 225).

### 🔴 Risk 2: Acceptance criteria reference wrong baseline scores
**Severity: High** | **Likelihood: Certain**
The plan claims demo CVEs should score within ±3 of `94/92/86/76/71/63/57` (Item 1 AC) and `94, 87, 71, 63, 55, 41, 22` (backend-engineering skill). The actual DB has `98, 91, 73, 66, 58, 44, 26`. Neither asserted set matches reality.

**Impact:** If the strike agent writes regression tests asserting the plan's values, tests will fail against the real DB, wasting debugging time and potentially causing unnecessary rollbacks.

**Fix:** Update acceptance criteria in the plan to match actual scores. Run `python3 -c "from database import get_db; ..."` to get current truth before finalizing the plan.

### 🟡 Risk 3: Effort estimates 40% understated (Items 3 & 4)
**Severity: Medium** | **Likelihood: High**
Plan says 3-4 hrs per item. Realistic breakdown shows 5-6 hrs each (Item 3: 1hr migration + 0.5hr pipeline + 0.5hr ingest + 2hr reference script + 1hr API + 0.5hr tests). For Item 4, add the feature-name-mapping complexity.

**Impact:** Sprint likely to overflow, especially if both Items 3 and 4 are attempted.

### 🟡 Risk 4: EPSS feature vector is positional, not named (Item 4)
**Severity: Medium** | **Likelihood: High**
`_build_feature_vector_v2()` returns a positional `list` (37 elements), but `compute_drift()` expects `list[dict]` with named keys. The plan doesn't specify how to map positions → names. Without this mapping, `compute_drift()` can't bin EPSS features against reference distributions.

**Fix:** Either (a) convert the positional vector to a dict with named feature keys before storing, (b) create a position-to-name mapping in `epss_substitutor.py`, or (c) modify `_build_feature_vector_v2()` to return a dict.

### 🟡 Risk 5: EPSS model version changes change feature dimensionality (Item 4)
**Severity: Medium** | **Likelihood: Low** (only if model files are added/removed)
If the active model changes from v4 (37-dim) to v1 (22-dim), stored features change size. Reference distributions computed for 37-dim will silently produce zeros for the missing 15 features when binned against 22-dim vectors.

### 🟢 Risk 6: Bonus D score sum mismatch (112 vs 107)
**Severity: Low** | **Likelihood: Certain**
The plan says "112-sum" but ROADMAP.md says "107-sum." Current scoring.py dimensions sum to 112. The ROADMAP is stale. Fix the ROADMAP entry, but not a sprint blocker.

---

## Concrete Recommendations

### Must-fix before sprint execution:

1. **Fix DB migration strategy (Items 3 & 4).** Add `ALTER TABLE` statements or an Alembic migration as the first step of Items 3 and 4. Do not rely on `CREATE TABLE IF NOT EXISTS` to add columns. [Assignee: strike, 1 hr additional per item]

2. **Correct the baseline scores in acceptance criteria.** Update Item 1's AC to reference `98/91/73/66/58/44/26` (the actual current scores). Verify with `python3 -c "from database import get_db; ..."` before writing tests. [Assignee: commander, 5 min]

### Should-fix before sprint execution:

3. **Re-estimate Items 3 and 4.** Set realistic effort of 5-6 hrs each. Either split them into separate sprints or accept that only one may complete in Sprint 18. [Assignee: commander, 5 min]

4. **Add feature name mapping for EPSS feature vector (Item 4).** Document that `_build_feature_vector_v2()` returns a positional list and specify how it's converted to a named dict for storage. Consider storing the vector as a dict keyed by feature names instead of a raw list. [Assignee: strike, embedded in Item 4 work]

5. **Add validation step: verify feature key alignment.** When generating reference distributions for Pre-Tier and EPSS, add a step that checks all feature names match exactly between `extract_features()` output and the reference distribution keys. This prevents silent zero-PSI drift. [Assignee: strike, 15 min per reference script]

### Nice-to-have:

6. **Reconcile score sum discrepancy.** Update ROADMAP.md line 64 to say "112-sum" (or correct value), not "107-sum." [Assignee: bookkeeper, 5 min]

7. **Document CWE-78 behavioral change for Item 2 Part B.** When `LOW_EPSS_THRESHOLD` changes from 0.10 to 0.515 for CWE-78, auto-resolved cases increase. Add a comment in `tier_0.py` explaining the rationale so future maintainers understand why CWE-78 CVEs with EPSS 0.30 get auto-resolved as low. [Assignee: strike, 2 min]

---

## Verdict

**FAIL WITH ISSUES** — 2 items pass, 2 items have critical migration gaps, 4 bonus items noted.

| Item | Status |
|------|--------|
| Item 1: NVD Ref Count Rule | ✅ PASS — Well-scoped, no issues |
| Item 2: CWE-Stratified EPSS Thresholds | ✅ PASS — Part A verified done. Part B is sound. |
| Item 3: Pre-Tier RF Drift Monitoring | ❌ FAIL — DB migration hole blocks ingest. Effort 40% understated. |
| Item 4: EPSS Drift Monitoring | ❌ FAIL — Same DB migration hole. Unaddressed feature name mapping for positional vectors. |
| Bonus A: Extend CWE Thresholds | ⚠️ Not blocked but DEFAULT change should be data-backed |
| Bonus B: CWE-Stratified KEV | ⚠️ Depends on Item 2 |
| Bonus C: threshold_info.json | ⚠️ Depends on Items 2/A |
| Bonus D: Scoring Weight Docs | ⚠️ Effort mismatch (30min vs 1hr), sum mismatch (112 vs 107) |

**Bottom line:** If the DB migration hole is fixed (1 additional hour per Item 3 & 4), the plan is sound. Without this fix, Items 3 and 4 will fail on first deploy to any existing database.
