# Sprint 27 — Bug Fix Sprint

**Date:** 2026-07-13
**Theme:** Resolve verified security, correctness, and data-integrity defects from the bug hunt in small, independently reviewable slices.

---

## Current State

Two parallel audits completed:
1. **Original sweep (8 agents):** 151 bugs across backend core, routers, integrations, ML, scripts, frontend, tests, infra
2. **Pipeline audit (section 9):** 11 additional findings in `backend/pipeline/`

**Verification addendum** triaged all 151 original findings against post-Sprint-26 `main`:

| Status | Count | Action |
|---|---|---|
| **Confirmed** | 58 | Fix now — present in current code |
| **Latent** | 20 | Fix now — real, needs specific conditions |
| **Evidence needed** | 23 | Investigate then fix |
| **Not a defect** | 50 | Skip — style/maintainability only |

Plus 11 pipeline: 9 Confirmed, 1 Latent, 1 Evidence needed.

**Immediate implementation candidates:** 88 (58 confirmed + 20 latent + 10
pipeline confirmed/latent). This is a triage inventory, **not** a single PR
scope: duplicate findings and items whose desired policy is unclear must be
collapsed before implementation.

**Tests passing:** `just test` reports **457 passed, 1 skipped** on Python 3.12.

---

## Guiding Principles

1. **Security & data integrity first** — missing auth, XSS, agent hostname confusion, hash leaks
2. **ML correctness second** — training bugs degrade every prediction
3. **Correctness bugs third** — scoring distortions, schema drift, resource leaks
4. **Robustness & polish last** — rate limits, cache policies, atomic writes
5. **Evidence-needed items** get a separate investigation pass before code changes
6. **Pipeline not previously audited** — its bugs are interleaved by priority, not separated
7. **No historical migration rewrites** — deployed Alembic revisions are immutable;
   repair schema drift with a new, forward-only migration after checking the
   current head and both SQLite/PostgreSQL upgrade paths.
8. **One security model first** — define authenticated analyst versus admin
   permissions before adding dependencies route-by-route. Do not accidentally
   lock out login, health, or intentionally public static/demo discovery routes.

---

## Phase 1 — Security & Authentication (Highest Priority)

These are the genuine security vulnerabilities an attacker could exploit today on a deployed instance with auth enabled.

### Item 1.1: Add auth to all unprotected router endpoints
**Bugs:** ROUTER-CRIT-1, ROUTER-CRIT-2, ROUTER-CRIT-3, ROUTER-CRIT-4
**Files:** `routers/cases.py`, `routers/ingest.py`, `routers/queue.py`, `routers/models.py`, `routers/config.py`
**Work:**
- Add `user=Depends(get_current_user_if_enabled)` to protected business routes,
  excluding login/refresh, health, and any route explicitly retained as public.
- First establish whether the current auth payload has an admin role/claim. If
  it does not, add and test that authorization model before claiming admin-only
  checks for `/api/ingest/clear`, activation/rollback, and review submission.
- Add auth to `/api/config` or document why it's safe (ROUTER-LOW-1)
- Run `just test` and verify all existing auth tests still pass

### Item 1.2: Fix frontend XSS
**Bugs:** FE-CRIT-1 (confirmed), FE-CRIT-2 (evidence needed), FE-CRIT-3 (evidence needed)
**Files:** `frontend/js/components/caseView.js`, `queue.js`, `driftDashboard.js`
**Work:**
- Add `escHtml()` to all string interpolations in `caseView.js` security context rendering
- Trace and fix the compliance XSS path in `queue.js`
- Trace and fix the drift dashboard label/title XSS in `driftDashboard.js`
- Verify: create a test CVE with `<script>` in description field and confirm it's rendered as text

### Item 1.3: Remove password hash leak during startup
**Bug:** CORE-MED-2
**Files:** `backend/main.py` (remove `_check_admin_password()`), also check `auth.py` does its own hashing
**Work:**
- Remove the redundant `_check_admin_password()` function from `main.py`
- Confirm auth still works via `auth.py`'s own hash computation
- Verify no remaining reference with `rg "_check_admin_password"`

### Item 1.4: Pipeline agent hostname confusion
**Bug:** PIPE-HIGH-2
**Files:** `backend/routers/ingest.py`, `backend/pipeline/tier_2/single.py`, `backend/pipeline/tier_2/agent.py`
**Work:**
- Pass the actual ingest `hostname` into `evaluate_tier_2()`
- Stop deriving hostname from first token of `rag_context`
- Update the function contract and all callers
- Verify agent CMDB/network/telemetry queries target the correct host

---

## Phase 2 — Agentic Tier-2 Safety

### Item 2.1: Agent neutral-fallback broken
**Bug:** PIPE-HIGH-1
**Files:** `backend/pipeline/tier_2/agent.py`, `__init__.py`
**Work:**
- Make `AgenticEvaluator` emit `_fallback` for its neutral-result paths (no
  key, consecutive tool failures, and step limit)
- Make orchestrator recognise `_fallback` and route to single-shot path
- Verify fallback behaviour with tests

### Item 2.2: Cap unbounded agent input
**Bug:** PIPE-HIGH-3
**Files:** `backend/pipeline/tier_2/agent.py`
**Work:**
- Add byte/token limits to CVE description, RAG context, and tool output
- Truncate accumulated tool results before adding to conversation
- Document the truncation policy

### Item 2.3: Cap per-turn tool calls
**Bug:** PIPE-HIGH-4
**Files:** `backend/pipeline/tier_2/agent.py`, `tools.py`
**Work:**
- Add per-turn and total tool-call limits
- Reject duplicate tool calls
- Prevent unbounded synchronous execution

### Item 2.4: Agent response validation
**Bug:** PIPE-MED-2
**Files:** `backend/pipeline/tier_2/agent.py`
**Work:**
- Enforce documented confidence range, score-adjustment range, max text lengths
- Use Pydantic model for final result validation

### Item 2.5: Fix agent_enabled flag not being read
**Bug:** PIPE-MED-3
**Files:** `backend/pipeline/tier_2/agent.py`
**Work:**
- Remove the unused `agent_enabled` argument or check it at `evaluate()` entry
- Ensure the feature flag actually controls agent behaviour

### Item 2.6: Normalise KNOWN_CONFLICTS values
**Bug:** PIPE-MED-4
**Files:** `backend/pipeline/tier_2/agent.py`
**Work:**
- Normalise stored conflict values to match the documented contract (UNCERTAIN, CONFIRMED, NOT_NEEDED)
- Or explicitly widen the public contract if the stored values are intentional

---

## Phase 3 — ML Correctness (Training & Inference)

### Item 3.1: Fix CVE IDs discarded in train-only path
**Bug:** ML-CRIT-1
**File:** `backend/ml/train_xgboost.py`
**Work:** Assign the `data.get("cve_ids", ...)` result to `cve_ids_arr`. Verify with a dry-run train.

### Item 3.2: Fix multi-class ensemble std crash
**Bug:** ML-CRIT-2
**File:** `backend/ml/xgboost_predictor.py`
**Work:** Do not sigmoid a sum of multi-class margins. Convert each partial
tree margin vector with softmax, then sum classes 1–4 (or use a separately
defined uncertainty metric). Add a synthetic five-class regression test.

### Item 3.3: Add None guard in encode_batch
**Bug:** ML-CRIT-3
**File:** `backend/ml/encoder.py`
**Work:** Match the pattern from `encode_description()` — return zero matrix if embedder is None.

### Item 3.4: Fix identical noise in EPSS v4 training
**Bug:** ML-CRIT-4
**File:** `backend/ml/train_epss_v4.py`
**Work:** Use a persistent RNG instance instead of `default_rng(42)` on every call.

### Item 3.5: Fix training/serving encoding default mismatch
**Bug:** SCRIPT-CRIT-1
**Files:** `backend/scripts/build_training_corpus.py`, `backend/ml/xgboost_predictor.py`
**Work:** Align the unrecognised-classification default with the inference
contract (currently OFFICIAL/2). Update parity tests; do not choose a value
without checking the product data-classification policy.

### Item 3.6: Fix non-deterministic reference distributions
**Bug:** SCRIPT-CRIT-2
**File:** `backend/scripts/compute_epss_reference.py`
**Work:** Replace `hash()` with `zlib.crc32()` or `hashlib.md5()` for deterministic cross-run behaviour.

### Item 3.7: Fix NVD null-cve crash
**Bug:** SCRIPT-CRIT-3
**File:** `backend/scripts/fetch_nvd_corpus.py`
**Work:** Guard against `"cve": null` with `(vuln.get("cve") or {}).get("id", "")`.

---

## Phase 4 — Scoring & Data Integrity

### Item 4.1: Fix hardcoded patch status in scoring
**Bug:** ROUTER-HIGH-1
**File:** `backend/routers/ingest.py`
**Work:** Pass `nvd_data.get("patch_available", True)` and `nvd_data.get("patch_applied", False)` to `calculate_final_score()` instead of hardcoded True/False.

### Item 4.2: Fix schema drift — analytics columns missing from DDL
**Bug:** INFRA-CRIT-1
**File:** `backend/database.py`
**Work:** Add `analytics_view_count` and `analytics_last_viewed` to both SQLite and PostgreSQL DDL in `database.py`. Check if any other columns are missing.

### Item 4.3: Fix schema drift — security_context_contribution never in migration
**Bug:** INFRA-CRIT-2
**File:** `backend/database.py` + new forward migration after current Alembic head
**Work:** Create a new migration adding `security_context_contribution` to both
tables. Verify clean upgrade from a fresh database and an upgrade from the
previous head; do not edit an applied migration.

### Item 4.4: Fix migration 002 default (client-side vs server_default)
**Bug:** INFRA-HIGH-8
**File:** new forward migration after current Alembic head
**Work:** Set a database-level default and `NOT NULL` constraint safely for
existing rows. Do not alter revision 002 in place.

### Item 4.5: Fix migration 003 TEXT vs DATETIME
**Bug:** INFRA-HIGH-9
**File:** new forward migration, only if a compatibility query proves the type
drift is harmful
**Work:** SQLite type alteration needs a batch/table-rebuild migration and
PostgreSQL needs an explicit conversion. Investigate existing stored values
before scheduling this; do not edit revision 003.

### Item 4.6: Add resolved_at to archive operation
**Bug:** ROUTER-MED-1
**File:** `backend/routers/ingest.py`
**Work:** Add `CURRENT_TIMESTAMP AS resolved_at` to the SELECT clause in `clear_all_findings`.

---

## Phase 5 — Robustness & Resource Protection

### Item 5.1: Fix bare except in ALTER TABLE migrations
**Bug:** CORE-HIGH-3
**File:** `backend/database.py`
**Work:** Catch `sqlite3.OperationalError` specifically instead of bare `Exception: pass`. Log unexpected exceptions.

### Item 5.2: Fix scheduler TOCTOU race
**Bug:** CORE-HIGH-4
**File:** `backend/scheduler.py`
**Work:** Use `LOCK_FILE.open("x")` for atomic lock acquisition. Wrap in try/except `FileExistsError`.

### Item 5.3: Fix OSV JSONDecodeError not caught
**Bug:** INT-HIGH-1
**File:** `backend/integrations/osv.py`
**Work:** Add `json.JSONDecodeError` to the except clause.

### Item 5.4: Fix Tenable empty IPv4 IndexError
**Bug:** INT-HIGH-2
**File:** `backend/integrations/tenable.py`
**Work:** Add `and ipv4` guard to the isinstance check.

### Item 5.5: Fix HTTPError dead code in NVD
**Bug:** INT-MED-1
**File:** `backend/integrations/nvd.py`
**Work:** Swap except order so `HTTPError` is caught before `URLError`.

### Item 5.6: Fix unbounded CWE cache
**Bug:** CORE-MED-7
**File:** `backend/ingest_cwe.py`
**Work:** Add an explicit bounded/TTL cache while preserving the current cache
statistics and error behaviour. Confirm dependency availability before adding
`cachetools`; do not substitute `lru_cache` blindly because this module manages
its own cache state.

### Item 5.7: Fix temp directory leak in CWE build script
**Bug:** SCRIPT-HIGH-6
**File:** `backend/scripts/build_cwe_hierarchy.py`
**Work:** Use `tempfile.TemporaryDirectory()` context manager instead of `mkdtemp()`.

### Item 5.8: Fix connection leak on archive exception
**Bug:** ROUTER-MED-2
**File:** `backend/routers/ingest.py`
**Work:** Wrap in try/finally to ensure `conn.close()` always fires.

---

## Phase 6 — Pipeline Robustness

### Item 6.1: Agent cost budget is best-effort (document or fix)
**Bug:** PIPE-MED-1
**File:** `backend/pipeline/tier_2/agent.py`
**Work:** Either estimate next-call cost before calling LLM, or document that it's a post-hoc alert threshold.

### Item 6.2: Atomic scoring_weights.json writes
**Bug:** PIPE-MED-5
**File:** `backend/pipeline/config/scoring.py` (or admin router)
**Work:** Write to temp file, then rename. Serialise concurrent admin updates.

### Item 6.3: Populate PRE_TIER_FEATURE_NAMES
**Bug:** PIPE-LOW-1
**File:** `backend/pipeline/config/feature_names.py`
**Work:** Either populate it from a tested, non-circular source or stop
exporting it as a canonical list. No production consumer currently depends on it.

---

## Phase 7 — Frontend Polish

### Item 7.1: Fix screen fade-out animation
**Bug:** FE-MED-1
**File:** `frontend/js/app.js`, `frontend/css/triagemate.css`
**Work:** Delay `hidden` class addition or use `visibility:hidden` instead of `display:none`.

### Item 7.2: Fix reviewQueue state management
**Bug:** FE-HIGH-1
**File:** `frontend/js/components/reviewQueue.js`
**Work:** Assign `appState.queueData = rows.rows` instead of the wrapper object.

### Item 7.3: Fix 204 No Content crash in api.js
**Bug:** FE-HIGH-2
**File:** `frontend/js/api.js`
**Work:** Guard `res.json()` with `res.status !== 204` check.

### Item 7.4: Remove dead code in reviewQueue
**Bug:** FE-HIGH-3
**File:** `frontend/js/components/reviewQueue.js`
**Work:** Remove the unreachable `if (!res.ok) throw ...` block.

### Item 7.5: Investigate keydown listener lifecycle
**Bug:** FE-MED-5 (evidence needed)
**File:** `frontend/js/app.js`
**Work:** First prove repeated registration through the view lifecycle. Add
cleanup only if the reproduction demonstrates accumulation.

### Item 7.6: Resolve weight-zero policy before changing the slider
**Bug:** FE-LOW-3
**Files:** `frontend/js/components/adminSettings.js`, `pipeline/config/scoring.py`, `routers/admin.py`
**Work:** The backend currently rejects weights below 1, so changing only the
slider would create a UI/API mismatch. Decide whether zero is a supported
weight; if not, close this as not actionable. If yes, change validation,
defaults, UI, and tests together.

---

## Phase 8 — Investigation Pass (Evidence Needed)

These 23 items need targeted reproduction before they can be turned into code changes. Each gets a short investigation task.

| Bug ID | What to investigate | How to test |
|---|---|---|
| CORE-MED-5 | Are there sensitive non-POST routes that should be rate-limited? | Audit route methods |
| ROUTER-LOW-1 | Is `/api/config` exposing sensitive info? | Product decision |
| ROUTER-LOW-5 | Can we trigger an uncaught JSON error on webhook endpoint? | Send XML payload |
| ROUTER-LOW-8 | Does the caller/UI need to distinguish corrupt vs missing threshold file? | Check frontend |
| INT-MED-2 | Do we have a GreyNoise key and can we reproduce 429? | Integration test |
| INT-MED-3 | Do we have OTX configured and can we reproduce throttling? | Integration test |
| ML-HIGH-3 | Find a legacy/changed-dimension checkpoint to reproduce migration bug | Search for old .npz |
| ML-HIGH-4 | What's the actual class distribution impact of unstratified split? | Stats analysis |
| ML-LOW-6 | Find a document whose chunking violates size/heading contract | Test with `#` headers |
| ML-LOW-9 | Test with a newer LanceDB version | pip install, run tests |
| SCRIPT-HIGH-4 | What Tier-0 precision metric was intended and is it useful? | Code review + owner |
| SCRIPT-LOW-2 | Verify CVE-2024-1709 vs CVE-2024-1708 for ScreenConnect | Check NVD |
| FE-CRIT-2 | Locate exact current compliance rendering XSS path | grep + manual test |
| FE-CRIT-3 | Locate current drift dashboard label XSS path | grep + manual test |
| FE-MED-5 | Confirm whether keydown listeners accumulate across lifecycle calls | Debug test |
| TEST-CRIT-1 | Verify test_alembic subprocess environment and DB URL in CI | Check CI logs |
| TEST-MED-1 | Reproduce inter-test failure in test_drift_webhook | Parallel test run |
| TEST-MED-2 | Reproduce fixture cleanup/race in test_rollback | Order-dependent test |
| TEST-LOW-3 | Check test fixture/database isolation for flag-for-review tests | Review conftest |
| TEST-LOW-4 | Reproduce parallel interleaved test failure in test_pre_tier | Order-dependent test |
| TEST-LOW-6 | Reproduce registry file race across test modules | Concurrent test run |
| INFRA-HIGH-2 | Check seed_data idempotency and decide if it should run every start | Code review |
| PIPE-HIGH-5 | Confirm the intended access boundary for agent tool parameters | Security review |

---

## Success Metrics

After all phases complete:
- `just test` passes: **458+ passed, same skip count** (no regressions)
- Each merged slice has explicit regression tests and a focused review of its
  auth/schema/model-contract effects; do not use the original, unverified
  severity labels as a completion metric.
- Auth dependency present on all router endpoints (verify with `rg "Depends\(get_current_user_if_enabled\)"`)
- ML training path for `--train` preserves CVE IDs
- EPSS v4 training adds varied noise per sample
- Reference distributions are deterministic across runs
- Schema drift between DDL and migrations resolved
- Security-context frontend fields are escaped, and protected routes have
  tested access-control decisions.

## Suggested PR sequence

1. **PR A — access control and XSS:** establish roles/dependencies, protect
   selected routes, then fix confirmed `caseView.js` XSS with browser-facing
   regression tests.
2. **PR B — Tier-2 agent safety:** hostname contract, real fallback marker,
   bounded conversation/tool calls, output validation, and tests. Treat
   cross-asset tool binding as a security-design review, not an assumption.
3. **PR C — ML correctness:** CVE-ID retention, multi-class uncertainty fix,
   encoder fallback, deterministic EPSS noise, and encoding-parity test.
4. **PR D — schema/data integrity:** new forward migration(s), inline-DDL
   parity, archive timestamp, then SQLite and PostgreSQL migration tests.
5. **PR E — bounded reliability fixes:** scheduler lock, cache bound, parser
   guards, temp cleanup, and connection finalisation.

Do not combine these PRs: each changes a different contract and needs an
independent CI result and review.

---

## Out of Scope for This Sprint

- The 50 "Not a defect" items (style/performance suggestions only)
- Refactoring the pipeline config package or adding new features
- Training/retraining ML models (code fixes only)
- Adding new tests for previously untested paths (except for fixed bugs)
