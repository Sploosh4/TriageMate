# Sprint: Operational Readiness

**Date:** 8 July 2026
**Type:** Hardening Sprint
**Commander:** Current

## Goal

Close three operational gaps: (1) rate limiting that's implemented but invisible/unconfigurable, (2) no operator visibility into cache staleness for KEV/EPSS, and (3) five endpoints in the review/drift surface with zero tests.

## Context

Sprint 9 (Data Supremacy) completed the 37-feature fill. The Clean Corpus sprint (earlier today) fixed the 420 vs 419 dimension mismatch. The system is functional but has no guardrails against ingest floods, no data-freshness visibility, and no regression tests for the review workflow. This sprint addresses those three gaps without touching model logic or adding new features.

## Work Items

### Item 1: Rate limit hardening (env var configurability + test)

**Assigned to:** strike (backend-engineering)
**Description:** The rate limit middleware at `backend/middleware/rate_limit.py` already implements a TokenBucket for ingest/clear/demo endpoints at hardcoded rates (30 req/min, 50 burst). This item makes the rates configurable via environment variables and adds a test proving the limit works.

Changes:
- In `backend/middleware/rate_limit.py`: read `INGEST_RATE_PER_MIN` (default 30), `INGEST_BURST_SIZE` (default 50), `CLEAR_RATE_PER_MIN` (default 2), `CLEAR_BURST_SIZE` (default 3) from `os.getenv()` with current values as defaults.
- Create `backend/tests/test_rate_limit.py` with:
  - `test_ingest_rate_limit_blocks_excess()` — send 60 requests in rapid succession, verify at least some return 429.
  - `test_ingest_rate_limit_allows_normal_rate()` — send 5 requests spaced 2s apart, verify all return 200.
  - `test_clear_rate_limit_blocks_rapid()` — verify /api/ingest/clear rate limit.
- Verify all existing tests (`test_health.py`, `test_queue.py`, `test_ingest.py`) still pass.
- Update `.env.example` with the new env vars.

**Assumption:** The existing TokenBucket implementation is correct and just needs configurability + test proof. Not auditing the bucket math.

**Verification:**
```bash
cd backend && python -m pytest tests/test_rate_limit.py -v
# All 3 tests pass
python -m pytest tests/ -v
# All existing tests still pass
```

---

### Item 2: Cache freshness in /api/health

**Assigned to:** strike (backend-engineering)
**Description:** `/api/health` currently returns `nvd_last_success` (from in-memory tracking in `integrations/nvd.py`) but is missing KEV and EPSS refresh timestamps. This item adds a `_last_refresh` metadata field to the KEV and EPSS cache files (written during `refresh_caches.py`) and exposes them in the health endpoint.

Changes:
- In `backend/scripts/refresh_caches.py`:
  - After writing `kev_cache.json`, write a companion metadata key or add a top-level `_metadata` field with `{"last_refresh_utc": "<ISO timestamp>"}` to the JSON file (wrapping the existing data dict inside a `{"data": {...}, "_metadata": {...}}` structure). Alternative: write a separate `.meta` file alongside. Prefer the inline metadata approach to avoid file proliferation.
  - Same for `epss_cache.json`.
  - **Note:** Existing `epss_cache.json` consumers (`demo_generator.py`, `build_training_corpus.py`) read the file as a flat dict. If changing the structure, ensure backward compat or update all consumers.
- Create `backend/integrations/cache_health.py` with:
  - `get_kev_health()` — reads `kev_cache.json`, returns `{"kev_last_refresh": "<ISO timestamp or ''>", "kev_entry_count": int}`
  - `get_epss_health()` — reads `epss_cache.json`, returns `{"epss_last_refresh": "<ISO timestamp or ''>", "epss_entry_count": int}`
  - Handle missing/corrupt files gracefully (return empty strings).
- In `backend/main.py` — import and call both health functions in the `/api/health` handler, add `kev_last_refresh`, `kev_entry_count`, `epss_last_refresh`, `epss_entry_count` to the response dict.
- In `backend/tests/test_health.py` — add `test_health_has_cache_freshness_keys()` asserting the four new keys exist and are the right types (str, int, str, int).

**Assumption:** The simplest backward-compatible approach is to store the metadata inline but key consumers (`demo_generator.py`, `build_training_corpus.py`) need compatible reads. Prefer a nested structure `{"data": {...}, "_metadata": {...}}` and update the two consumers, rather than a separate file.

**Verification:**
```bash
curl -s http://localhost:8000/api/health | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert 'kev_last_refresh' in data, 'Missing kev_last_refresh'
assert 'epss_last_refresh' in data, 'Missing epss_last_refresh'
print(f\"KEV: {data.get('kev_last_refresh', 'MISSING')} ({data.get('kev_entry_count', '?')} entries)\")
print(f\"EPSS: {data.get('epss_last_refresh', 'MISSING')} ({data.get('epss_entry_count', '?')} entries)\")
print('OK')
"
python -m pytest tests/test_health.py -v
# New test passes
```

---

### Item 3: Test coverage for review queue + drift endpoints

**Assigned to:** strike (backend-engineering)
**Description:** Five endpoints in `backend/routers/cases.py` and `backend/routers/queue.py` have zero test coverage:

1. `GET /api/review/queue` — returns items flagged for review
2. `POST /api/review/flag/{case_id}` — flags a case for review
3. `POST /api/case/{case_id}/review` — submits a review decision
4. `GET /api/case/{case_id}/history` — returns review history
5. `GET /api/drift` — returns drift metrics

Create two test files following the patterns in the existing `test_queue.py` (use `client` fixture from `conftest.py`, check camelCase response keys, use seed data).

Changes:
- Create `backend/tests/test_review.py` with:
  - `test_review_queue_returns_200` — smoke test
  - `test_review_queue_returns_expected_structure` — check `total` and `rows` keys, each `ReviewQueueItem` has required fields (camelCase: `id`, `vulnerabilityId`, `hostname`, `priorityScore`, `riskBand`, `detectionTier`, `flaggedForReview`, `tier2TextConflict`)
  - `test_flag_for_review` — POST to flag a known case, verify 200, then GET `/api/case/{id}` and verify... Actually the response just returns `{"status": "ok", "flagged": true}`. Check the response directly.
  - `test_submit_review` — submit a review for a known case, verify 200, then GET `/api/case/{id}/history` and verify the review appears
  - `test_submit_review_with_override` — submit a review with `override` decision and score, verify the override is stored
- Create `backend/tests/test_drift.py` with:
  - `test_drift_returns_200` — smoke test
  - `test_drift_returns_expected_keys` — verify `scoreTrend`, `tierRouting`, `riskBandDistribution`, `detectionTierTrend`, `featureDrift`, `totalAudited` keys (camelCase)
  - `test_drift_total_audited_is_non_negative` — integer sanity check
- Verify all existing tests still pass.

**Assumption:** The seed data in `seed_data.py` creates at least one vulnerability that can be flagged/reviewed. Tests will use known IDs from seed data (e.g., checking `GET /api/queue` first to find a case ID, or using a known vulnerability_id like `CVE-2023-34362`). If no cases are flagged by default in seed data, the flag test will create the condition.

**Assumption:** The `client` fixture in `conftest.py` runs with auth disabled (AUTH_DISABLED=True for tests), so POST endpoints work without JWT tokens.

**Verification:**
```bash
cd backend && python -m pytest tests/test_review.py tests/test_drift.py -v
# 8+ tests pass
python -m pytest tests/ -v
# All existing tests still pass
```

---

## Sprint Summary

| Item | Effort | Deliverable |
|---|---|---|
| 1. Rate limit hardening | ~0.5 hr | `test_rate_limit.py` + env var config |
| 2. Cache freshness | ~1 hr | `cache_health.py` + 4 new health keys + test |
| 3. Review + drift tests | ~2-3 hrs | `test_review.py` (5 tests) + `test_drift.py` (3 tests) |
| **Total** | **~3.5-4.5 hrs** | |

## Quality Gate

After all items complete:
1. Run `cd backend && python -m pytest tests/ -v` — all tests pass
2. Run lint: `cd backend && ruff check . && ruff format --check .` — clean
3. Trigger bookkeeper for a freshness pass
