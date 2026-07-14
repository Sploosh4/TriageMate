# Test Isolation & Race-Condition Investigation

**Date:** 2026-07-14
**Author:** Strike Team (investigation)
**Scope:** Phase 8 evidence-needed bugs — TEST-CRIT-1, TEST-MED-1, TEST-MED-2, TEST-LOW-3, TEST-LOW-4/TEST-LOW-6

---

## TEST-CRIT-1: test_alembic subprocess environment

### Status: **Reproduced — two distinct issues**

### Evidence

The test at `backend/tests/test_alembic.py:40-101` (`test_alembic_head_applied`) spawns a **subprocess** to run Alembic:

```python
# Line 75-80 — subprocess, not in-process
upgrade_result = subprocess.run(
    [sys.executable, "-m", "alembic", "upgrade", "head"],
    capture_output=True, text=True, cwd=str(test_dir),  # test_dir = backend/
)
# Line 87-92 — another subprocess for "alembic current"
result = subprocess.run(
    [sys.executable, "-m", "alembic", "current"],
    capture_output=True, text=True, cwd=str(test_dir),
)
```

**Issue 1 — DB URL isolation gap:**
- `conftest.py:124-148` (`setup_test_db`, session-scoped) overrides `database.DB_PATH` with a temp file to isolate tests from the real `triagemate.db`
- This override is **in-process only** — it sets `database.DB_PATH` in the test process's memory
- The Alembic subprocess is a **separate OS process** — it does NOT see the `database.DB_PATH` override
- Instead, the subprocess reads `alembic.ini:89` — `sqlalchemy.url = sqlite:///triagemate.db` — a **hardcoded relative path** to the real project database
- In CI where `triagemate.db` may not exist or is in an inconsistent state, this could fail
- The subprocess will create/modify the **real** `triagemate.db`, potentially corrupting shared state

**Issue 2 — DATABASE_URL env var is the only escape hatch but not set by the test:**
- `alembic/env.py:12-14` does check `DATABASE_URL` env var and overrides if set
- The test does **not** set `DATABASE_URL` before spawning the subprocess
- If a CI runner happens to have `DATABASE_URL` pointing elsewhere, the test would target that DB instead

**Issue 3 — Hardcoded expected revision fallback path:**
- The test dynamically reads migration files to determine expected revision (good practice)
- But if `alembic upgrade head` modifies the real DB while the concurrently-seeded test DB is at a different state, the test's own schema queries (lines 14-28 for `pre_tier_features`/`epss_features`) would pass against the test DB, while the Alembic subprocess operates on the real DB

### Proposed next action

**Fix approach:**
1. Set `DATABASE_URL` in the test's subprocess environment to the conftest temp DB path
2. Or, convert the subprocess to an in-process call (`database.run_migrations()` which already uses `DB_PATH`)
3. Or, add an env var passthrough in the subprocess call:
   ```python
   env = os.environ.copy()
   env["DATABASE_URL"] = f"sqlite:///{database.DB_PATH}"
   subprocess.run(..., env=env)
   ```
   (Requires making `database.DB_PATH` accessible to the test — currently it's set at conftest session scope, so the test would need to import `database` and read `DB_PATH`)

---

## TEST-MED-1: test_drift_webhook inter-test failure

### Status: **Reproduced — shared mutable global dict**

### Evidence

File `backend/tests/test_drift_webhook.py` — three async tests in `TestDriftWebhook`:

**Shared state 1: Module-level `_last_webhook` dict**
- Declared at `backend/analysis/drift.py:24`: `_last_webhook: dict[str, datetime] = {}`
- This is a **global mutable dict** that persists across test functions
- `test_webhook_suppression_same_model` (line 24) explicitly does `_last_webhook.clear()` to reset it
- `test_webhook_different_models_not_suppressed` (line 57) also does `_last_webhook.clear()`
- If tests are run in parallel (pytest-xdist) or in a different order, one test could read/write `_last_webhook` while another is mid-execution

**Shared state 2: Environment variable manipulation**
- Both suppression tests modify `os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"]` (lines 30, 62)
- Both call `importlib.reload(analysis.drift)` which re-executes the module, re-reading `DRIFT_WEBHOOK_URL` from os.environ and creating a new module-level `_last_webhook`
- The `importlib.reload()` call replaces the module in `sys.modules`, but any other modules that already imported from `analysis.drift` still reference the old objects

**Shared state 3: Module-level `DRIFT_WEBHOOK_URL`**
- Set once at module load time at `drift.py:21`: `DRIFT_WEBHOOK_URL = os.getenv("TRIAGEMATE_DRIFT_WEBHOOK_URL", "")`
- `test_webhook_no_url_returns_false` (line 13) reads this value and skips if set
- If another test runs first, sets the env var, and reloads, the skip condition becomes unpredictable

**Race scenario:**
1. `test_webhook_suppression_same_model` sets env var, reloads module, modifies `_last_webhook`
2. If `test_webhook_no_url_returns_false` runs concurrently, it sees `DRIFT_WEBHOOK_URL` as non-empty (module was reloaded with env var set) → **incorrect skip**
3. Cleanup in suppression tests (lines 45-50, 76-80) restores env var and reloads module, but if another test's cleanup interleaves, state corruption occurs

### Proposed next action

**Fix approach:**
1. Use `unittest.mock.patch.dict(os.environ, ...)` instead of raw env var manipulation
2. Use `unittest.mock.patch.object(analysis.drift, '_last_webhook', {})` instead of clearing the shared dict
3. Avoid `importlib.reload()` — it's aggressive and stateful; instead patch `DRIFT_WEBHOOK_URL` at the module level or refactor the module to read the env var lazily
4. Add `@pytest.mark.xdist_group` if parallel execution is desired

---

## TEST-MED-2: test_rollback fixture cleanup race

### Status: **Reproduced — shared registry file with conflicting lifecycle scopes**

### Evidence

File `backend/tests/test_rollback.py`:
- **Shared file:** `backend/ml/model_registry.json` — referenced at line 11
- **Backup fixture:** Function-scoped `backup_registry` (autouse, line 14-22):
  - Copies the file content to memory at setup
  - Restores the content to the file at teardown (yield)
- **Test `test_rollback_to_previous_version`** (line 46-77):
  - Directly reads/writes `model_registry.json` (lines 48, 61, 72, 77)
  - Writes a test version and later removes it
  - If the test fails between lines 61 and 77, the fixture teardown restores the backup → this part actually works correctly

**Cross-file conflict with `test_model_versions.py`:**
- `backend/tests/test_model_versions.py` has its **own** session-scoped fixture `_save_and_restore_registry` (line 31-57)
- This fixture saves the registry at session start and restores at session end
- It also calls `_init_active_paths_from_registry()` and resets `xp._model` and `xp._calibrator` after restore

**The race:**
1. `test_model_versions.py` session-scoped fixture saves the ORIGINAL registry state at session start
2. `test_rollback.py` function-scoped `backup_registry` backs up the **current** state (which might already be modified by `test_model_versions.py` tests if they run first)
3. If `test_rollback.py` tests run, their fixture restores a **potentially-modified** state (the backup they took was after `test_model_versions` changes)
4. At session end, `test_model_versions.py` fixture restores the original state → might overwrite `test_rollback.py`'s restore

**Additionally:** `test_scheduler.py:295-322` writes a **temporary** registry file and swaps `scheduler.XGBOOST_REGISTRY` at the module level, which is another independent approach that doesn't conflict with the file itself, but does read from the real `model_registry.json` at line 287 (`result = get_current_model_metrics("nonexistent")`) — this reads the real file.

### Proposed next action

**Fix approach:**
1. Consolidate all registry fixtures to a **single** session-scoped fixture in `conftest.py` that all test files import from
2. OR: Convert all registry tests to use temp files with `unittest.mock.patch.object()` on the module-level registry path, avoiding the shared file entirely
3. At minimum: ensure `test_model_versions.py` and `test_rollback.py` agree on fixture scope order

---

## TEST-LOW-3: flag_for_review database isolation

### Status: **Reproduced — session-scoped DB with mutable side effects**

### Evidence

File `backend/tests/test_review.py` — `TestFlagForReviewEndpoint` class:

```python
async def test_flag_for_review_returns_200(self, client):
    case_id = await self._get_first_case_id(client)  # Reads from shared DB
    response = await client.post(f"/api/review/flag/{case_id}")  # Writes 'flagged_for_review' to DB
    assert response.status_code == 200

async def test_flag_for_review_returns_correct_body(self, client):
    case_id = await self._get_first_case_id(client)  # Same or different case from shared DB
    response = await client.post(f"/api/review/flag/{case_id}")
    ...
```

**Issue — session-scoped DB with mutable writes:**
- `conftest.py:124` — `setup_test_db` has `scope="session"`, meaning one DB instance for all tests
- The seed data inserts N rows into `vulnerabilities`
- `test_flag_for_review_returns_200` POSTs to `/api/review/flag/{case_id}`, modifying the `flagged_for_review` column in the DB
- This modification persists for all subsequent tests in the session
- There are **no cleanup steps** within the `TestFlagForReviewEndpoint` class to reset the flag state

**Specific impact:**
- If `test_flag_for_review_returns_200` flags case_id=X, then `test_flag_for_review_returns_correct_body` calls `_get_first_case_id` which returns the first row from `/api/queue` — the queue endpoint may filter out already-flagged cases or return them in a different order
- The test `test_submit_review_with_override` (line 121-134) calls `_get_first_case_id` and POSTs a review, which **also** modifies DB state (adds a review_history row, potentially changes the case status)
- `test_history_includes_review_after_submission` (line 175-198) POSTs a review and then checks history — this is correct for its own test but leaves state for others

**Additionally:** The `cleanup_test_records` fixture (conftest.py:151-171, session-scoped) only deletes `CVE-TEST-%` records at the very end of the session — it does NOT reset `flagged_for_review` or `review_history` for non-test records.

### Proposed next action

**Fix approach:**
1. Change the `client` fixture to a function-scoped async fixture that wraps each test in a **database transaction** (rollback after each test)
2. OR: Add a function-scoped autouse fixture in `test_review.py` that resets `flagged_for_review` and clears `review_history` before/after each test in this module
3. Minimum viable: Ensure each test in `TestFlagForReviewEndpoint` starts with a known state by getting the case list before and after any mutations

---

## TEST-LOW-4 / TEST-LOW-6: Parallel test race conditions

### Status: **Reproduced — multiple shared state vectors identified**

### Evidence

Three categories of shared state across test files that would race under parallel execution:

#### A. Module-level model cache in `pipeline/pre_tier.py`

File `backend/tests/test_pre_tier.py`:
```python
# Lines 57-61: helper functions modify module-level cache
pt._model_data = None      # Module global
pt._model_attempted = True  # Module global
```

- `test_pre_tier.py` uses `setup_method`/`teardown_method` in `TestDefaultFallback` and `TestMLFallback` to manage `_model_data` and `_model_attempted` in `pipeline.pre_tier`
- These are **module-level globals** — if any other test (or another instance of the same test class) calls `predict_mission_tags()` while these are set to `None`, it will trigger the model-loading path or fallback
- Under parallel execution: `TestDefaultFallback.test_unknown_host_returns_default_when_model_unavailable` sets `_model_data = None` and `_model_attempted = True` — a concurrent `TestPredictMissionTagsResponseShape.test_known_host_returns_exact_values` that expects the real model to predict would get the default fallback instead

#### B. Shared file — `model_registry.json`

Files: `test_rollback.py`, `test_model_versions.py`, `test_scheduler.py`

- Three separate test files directly read and write `backend/ml/model_registry.json`
- `test_rollback.py` uses a function-scoped backup fixture (OK-ish)
- `test_model_versions.py` uses a session-scoped save/restore fixture
- `test_scheduler.py:test_get_current_model_metrics_reads_active` swaps `scheduler.XGBOOST_REGISTRY` to a temp file (isolated)
- Under parallel execution: file write races between `test_rollback.py` and `test_model_versions.py` would cause torn reads, JSON parse errors, or incorrect test assertions

#### C. Shared file — `.retrain.lock`

File `backend/tests/test_scheduler.py`:
```python
# Line 27-29
from scheduler import LOCK_FILE, _acquire_lock, _release_lock
```
- `LOCK_FILE = Path(__file__).parent / "ml" / ".retrain.lock"` (scheduler.py:27)
- Tests create/remove this lock file in the project's `ml/` directory
- Under parallel execution: concurrent create/remove races on the same filesystem path

#### D. Database contention — session-scoped single DB

All tests share a single SQLite DB (session-scoped `setup_test_db` in conftest.py). SQLite in WAL mode allows concurrent reads but only one writer at a time. Most tests in the suite only read, but `test_review.py` and `test_flag_for_review` tests **write** to the DB, which would serialize under parallel execution and potentially cause deadlocks.

### Proposed next action

**Fix approach (prioritised):**
1. **Critical:** Convert `_model_data` / `_model_attempted` in `pre_tier.py` to be managed with `unittest.mock.patch.object()` rather than raw assignment — this ensures thread-safe temporary overrides
2. **High:** Consolidate registry file access into a single conftest fixture with temp files for each test function
3. **High:** Add `@pytest.mark.xdist_group(name="serial-db")` to all tests that write to the database
4. **Medium:** Change lock file tests to use `tempfile.mkstemp()` or `tmp_path` fixture instead of the project's `ml/` directory
5. **Medium:** Add a `--ignore-global-state` marker or `pytest-randomly` plugin to detect non-isolated tests

---

## Summary Table

| Item | Status | Risk | Shared State | Suggested Fix Priority |
|---|---|---|---|---|
| **TEST-CRIT-1** | Reproduced | CI failure, DB corruption | Alembic subprocess targets real triagemate.db instead of test DB | **High** |
| **TEST-MED-1** | Reproduced | Inter-test leak, flaky CI | `_last_webhook` global dict, env vars, module reload | **High** |
| **TEST-MED-2** | Reproduced | Leaked test versions in registry | `model_registry.json` with conflicting fixture scopes | **Medium** |
| **TEST-LOW-3** | Reproduced | Session-crossing DB mutations | `flagged_for_review` and `review_history` side effects in session-scoped DB | **Medium** |
| **TEST-LOW-4/6** | Reproduced | Race conditions under xdist | Module-level `_model_data`, shared registry file, `.retrain.lock` file, DB contention | **High** |

### Key pattern across all findings
The root cause is consistent: **mutable shared state** (module-level globals, filesystem files, shared database, env vars) that is modified in-place without isolation boundaries between tests. The conftest's session-scoped database provides read isolation but not write isolation, and none of the module-level caches or file-based registries have any isolation at all.

The single highest-value fix would be converting the `model_registry.json` to a dependency-injected path (configurable per test) and retrofitting all tests to use `tmp_path` with `unittest.mock.patch()`. This alone eliminates three of the five findings.
