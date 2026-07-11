# Sprint 15 — Halfway Handoff

**Date:** 2026-07-08
**Status:** Items 1 & 2 complete + audited. Item 3 code complete, awaiting server start to run stress test.

---

## Sprint Goal

Close the three largest post-MVP gaps from `docs/planning/HANDOFF-2026-07-08.md`: untested Tier 2 LLM pipeline, missing ML drift monitoring, and zero stress testing infrastructure.

---

## Completed

### Item 2 — Tier 2 Unit Test Suite ✅

**Subagent:** strike → auditor

21 unit tests in `backend/tests/test_tier2.py` covering the previously 0%-tested Tier 2 LLM pipeline:

| Test Target | Tests | What's Verified |
|---|---|---|
| `build_prompt()` | 4 | Pure function — tuple return, expected sections in output |
| `call_openai()` | 5 | Mocked HTTP — success, refusal, 429 retry, 5xx retry, missing fields |
| `call_anthropic()` | 3 | Mocked SDK — success, refusal, rate limit retry |
| `call_together()` | 3 | Mocked HTTP — markdown fence stripping, non-json-schema model, invalid JSON |
| `evaluate_tier_2()` | 3 | Orchestration — primary succeeds, all fail → KNOWN_CONFLICTS, all fail → neutral default |
| Cost tracking | 3 | Pure accumulation — token counts, cost calculation |

**Metrics:** 21/21 pass · 77% coverage on `pipeline/tier_2.py` · No new dependencies

**Also done:**
- Deprecation comments on dead code in `backend/integrations/llm.py` (module docstring, `KNOWN_CONFLICTS`, `retry_with_backoff`)
- `just verify-tier2` target added to justfile

**Audit result:** PASS — 6/6 checklist items

---

### Item 1 — ML Drift Foundation ✅

**Subagent:** strike → auditor

PSI-based ML drift monitoring for the XGBoost (Tier 1) model. Pre-Tier and EPSS drift deferred.

**Files created (5):**
| File | Purpose |
|---|---|
| `backend/alembic/versions/006_add_tier_1_features_column.py` | Adds `tier_1_features TEXT` column to `vulnerabilities` |
| `backend/analysis/drift.py` | `compute_psi()` and `compute_drift()` functions |
| `backend/scripts/compute_reference_dists.py` | Computes reference distributions from `training_data_v2.npz` |
| `backend/ml/reference_distributions.json` | 35 features × 10 bins each, 253,568 training samples |
| `backend/tests/test_drift_ml.py` | 14 tests for PSI computation and endpoint |

**Files modified (6):**
| File | Change |
|---|---|
| `backend/database.py` | `tier_1_features TEXT` in SQLite + PG DDL |
| `backend/ingest_helpers.py` | `TABULAR_FEATURE_ORDER` list + `serialize_tabular_features()` |
| `backend/models.py` | `MlDriftFeature` and `MlDriftResponse` Pydantic models |
| `backend/routers/ingest.py` | Stores 35 tabular features as JSON after Tier 1 prediction |
| `backend/routers/queue.py` | `GET /api/drift/ml` endpoint |
| `frontend/js/components/driftDashboard.js` | 5th panel: ML Drift PSI gauge + feature table |

**Metrics:** 14/14 drift tests pass · 144/144 full suite · Route `GET /api/drift/ml` registered

**Audit result:** PASS — 8/8 checklist items

---

### Item 3 — Stress Testing + Visibility 🔧 (code complete, awaiting server run)

**Subagent:** strike → auditor (server-free audit done, 1 regression found and fixed)

**Files created (3):**
| File | Lines | Purpose |
|---|---|---|
| `backend/analysis/stress_db.py` | 138 | SQLite test DB with `test_runs` + `results` tables, 6 indexes |
| `backend/tests/load/locustfile.py` | 390 | Locust HttpUser: ingest (60%), queue read (30%), health (10%) |
| `backend/scripts/stress_report.py` | 515 | 7-section terminal + markdown report generator |

**Files modified (8):**
| File | Change |
|---|---|
| `backend/routers/ingest.py` | Pipeline timing (`time.monotonic()` around all 4 tiers), `X-TriageMate-Verbose` header check, `_trace` dict in response (opt-in, via `response_model_exclude_none=True`) |
| `backend/models.py` | `trace_output: Optional[dict]` field with alias `_trace` |
| `backend/pipeline/tier_2.py` | `LLM_BASE_URL` env var support for non-OpenAI providers |
| `Dockerfile` | `WEB_CONCURRENCY` env var → `--workers` flag |
| `docker-compose.yml` | `deploy.resources.limits` (2 CPUs, 1GB RAM) |
| `backend/.env.example` | Documented `TRIAGEMATE_LLM_BASE_URL` |
| `requirements-dev.txt` | Added `locust>=2.31.0` |
| `justfile` | `stress-test` and `stress-test-no-llm` targets |

**What each piece does:**

- **Verbose mode:** Send `X-TriageMate-Verbose: true` header with ingest requests → response includes `_trace` with per-tier outputs + latency in ms. Without header → response unchanged.
- **Test database:** Per-run SQLite db at `backend/reports/stress/{run_id}.db`. Schema: `test_runs` (metadata) + `results` (12 indexed columns + JSON `trace`). Populated by locust client from API responses.
- **Analysis report:** 7 sections printed to terminal + saved as markdown:
  1. Summary (duration, requests, throughput, error rate)
  2. Tier Routing (counts + % per tier: T0 auto/escalated, T1 auto/escalated, T2 called, T3 flagged)
  3. Accuracy (KEV recall, score separation, low-severity precision)
  4. Latency (p50/p95/p99 per tier + total)
  5. LLM Cost (calls, tokens, estimated cost)
  6. Risk Distribution (band histogram)
  7. Failures (error types, worst offenders)

**Metrics:** 144/144 full suite passes · locustfile imports clean · DB round-trips verified · analysis script produces output

**Server-free audit:** Found 1 regression (`test_full_pipeline_ingest` failed due to `response_model_exclude_none=True` dropping `substitutionBlock` when None) → **FIXED** (changed default from `None` to `SubstitutionBlock(substituted=False)`)

---

## What Remains

The code is complete. What needs to happen when the server is running:

### Step 1: Start the server
```bash
source backend/.venv/bin/activate
cd backend
python seed_data.py
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 2: Quick smoke tests (~30 seconds)
```bash
# Test verbose mode (should show _trace in response)
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -H "X-TriageMate-Verbose: true" \
  -d '{"vulnerability_id": "CVE-2023-36884", "cvss_score": 8.1, "epss_score": 0.05, "hostname": "syd-dmz-web01.transport.wa.gov.au", "description": "Office Memory Corruption Vulnerability", "cisa_kev": true, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('_trace:', 'YES' if '_trace' in d else 'MISSING')"

# Test drift endpoint
curl -s http://localhost:8000/api/drift/ml | python3 -m json.tool | head -15
```

### Step 3: Full stress test (~90 seconds, uses real OpenAI API)
```bash
just stress-test
```
This will:
1. Start the Docker stack (or use running server)
2. Wait for health check
3. Run locust for 60s (10 users, 2 spawn/s) against ingest/queue/health endpoints
4. Generate the analysis report
5. Save the test DB at `backend/reports/stress/{timestamp}.db` and report at `backend/reports/stress/{timestamp}.md`

### Step 4: Final audit
After the stress test runs successfully, delegate to auditor for the full Item 3 audit including the server-dependent checks (verbose mode curl test).

---

## Verification Commands (Reusable)

| Command | What It Does |
|---|---|
| `just test` | Full test suite |
| `just verify-tier2` | Tier 2 tests with coverage (≥70%) |
| `just verify-drift` | Drift tests + endpoint check |
| `just stress-test` | Full stack stress test + report |
| `just stress-test-no-llm` | Stress test without LLM API calls |
| `just lint` | Ruff lint check |

---

## Files Changed This Sprint

### New files (10)
- `backend/tests/test_tier2.py`
- `backend/tests/test_drift_ml.py`
- `backend/analysis/drift.py`
- `backend/analysis/stress_db.py`
- `backend/scripts/compute_reference_dists.py`
- `backend/scripts/stress_report.py`
- `backend/tests/load/locustfile.py`
- `backend/ml/reference_distributions.json`
- `backend/alembic/versions/006_add_tier_1_features_column.py`
- `.opencode/plans/2026-07-08-sprint-15.md`

### Modified files (14)
- `backend/routers/ingest.py`
- `backend/routers/queue.py`
- `backend/routers/cases.py`
- `backend/models.py`
- `backend/database.py`
- `backend/ingest_helpers.py`
- `backend/pipeline/tier_2.py`
- `backend/integrations/llm.py`
- `Dockerfile`
- `docker-compose.yml`
- `backend/.env.example`
- `frontend/js/components/driftDashboard.js`
- `requirements-dev.txt`
- `justfile`
- `backend/tests/conftest.py`

---

## Deferred to Future Sprints
- DeepSeek V4 Flash provider (code path exists via `LLM_BASE_URL`)
- Pre-Tier RandomForest drift monitoring
- EPSS model drift monitoring
- CI performance gates
