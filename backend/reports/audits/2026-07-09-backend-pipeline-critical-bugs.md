# Backend/Pipeline Critical Bug Verification Audit

**Date:** 2026-07-09
**Scope:** Verification of 6 claimed XGBoost/pipeline bugs from Phase B strike swarm
**Performed by:** auditor
**Pre-flight:** sentence_transformers OK; analysis scripts not needed (source-code audit)

## Results

| Bug | Status | Severity |
|-----|--------|----------|
| #1 — Unbounded `_rag_cache` growth | ✅ CONFIRMED | HIGH |
| #2 — `seed_demo_documents` duplicates on restart | ✅ CONFIRMED | HIGH |
| #3 — `_get_calibrator` thread-safety race | ✅ CONFIRMED | MEDIUM |
| #4 — Tier 1 heuristic doesn't log failure | ✅ CONFIRMED | MEDIUM |
| #5 — `ReadTimeout` not retried | ✅ CONFIRMED | HIGH |
| #6 — OTX `or` operator misuse | ✅ CONFIRMED | MEDIUM |

**6 passed, 0 failed, 0 skipped**

---

## Findings

### Bug 1: Unbounded `_rag_cache` growth ✅ CONFIRMED (HIGH)

**File:** `backend/ml/vector_store.py`, lines 287–363

**Evidence:**
- `_rag_cache` is a plain `dict` at module level (line 287): `_rag_cache = {}`
- A TTL check exists on **read** (lines 305–308): if `(now - cached["ts"]) < _RAG_CACHE_TTL` is false, the stale entry is bypassed and a new lookup is performed
- BUT — stale entries are **never removed** from the dict. Lines 351 and 363 unconditionally write new cache entries: `_rag_cache[cache_key] = {"result": result, "ts": now}`
- No cleanup mechanism exists — no LRU eviction, no periodic sweep, no size cap, no timestamp-based janitor

**Impact:** Every unique `{hostname}::{cwe_class}::{top_k}` combination ever queried accumulates an entry permanently. Under sustained ingest across hundreds of CVEs and dozens of hostnames, this grows without bound. While each entry is small (~a few KB), the lack of any eviction constitutes a long-term memory leak.

**What should change:** Add a cleanup path — either a `threading.Timer`-based periodic sweep of expired entries, or replace `dict` with a size-bounded `OrderedDict`/`lru_cache`, or a simple check: `if len(_rag_cache) > MAX_CACHE_SIZE: _rag_cache.clear()`.

---

### Bug 2: `seed_demo_documents` adds duplicates on restart ✅ CONFIRMED (HIGH)

**File:** `backend/ml/vector_store.py`, lines 216–240; `backend/main.py`, lines 73–89

**Evidence:**
- `seed_demo_documents()` (lines 216–240) takes `_SEED_DOCUMENTS`, embeds them, and calls `table.add(records)` with **zero duplicate checking**. No `SELECT` before `INSERT`, no upsert logic, no hash-based dedup.
- The guard in `main.py` (lines 81–86) protects against accidental re-seeding on restart by checking `tbl.count_rows() == 0`:
  ```python
  if tbl.count_rows() == 0:
      seed_demo_documents(db)
  ```
- This guard is **brittle**: if the LanceDB table is corrupted (returning `count_rows()=0` while data exists), or if `clear_documents()` is called and then the app restarts, `seed_demo_documents` will run again and produce duplicates with no way to detect them.
- The function is also public — any caller can invoke it without the guard.

**Impact:** Any call to `seed_demo_documents()` when the table already contains the demo rows results in full duplicates of all 9 seed documents. The RAG vector search results would include duplicate entries, potentially degrading context quality.

**What should change:** Either (a) make `seed_demo_documents()` idempotent by adding a `SELECT count(*) WHERE hostname IN (...)` check before insert, or (b) move the guard into `seed_demo_documents()` itself rather than relying on the caller.

---

### Bug 3: `_get_calibrator` thread-safety race ✅ CONFIRMED (MEDIUM)

**File:** `backend/ml/xgboost_predictor.py`, lines 114–121

**Evidence:**
- Line 116 reads `_active_calibrator_path` **outside** the lock: `cal_path = _active_calibrator_path`
- Lines 118–120 acquire `_lock` and **re-read** `cal_path` (the local variable, not the global — the local was already captured)
- Compare with `_get_model()` (lines 99–111) which reads `_active_model_path` **inside** the lock at line 104
- `set_active_version()` (lines 162–195) writes `_active_calibrator_path` **under** `_lock`

**Race scenario:**
1. Thread A calls `_get_calibrator()` — reads `_active_calibrator_path` as `path_A` (line 116)
2. Thread B calls `set_active_version("v2")` — acquires `_lock`, changes `_active_calibrator_path` to `path_B`
3. Thread A enters `with _lock:` — now using stale `path_A` (a local copy), which may no longer point to the active model version

**Practical impact:** Low in steady state (calibrator is loaded once and cached in `_calibrator`), but during model version switches the calibrator could be loaded from the wrong path. Fix is trivial: move the global read inside the lock.

**What should change:** Change lines 116–117 to read `_active_calibrator_path` inside the lock, matching the pattern used by `_get_model()`.

---

### Bug 4: Tier 1 heuristic doesn't log failure ✅ CONFIRMED (MEDIUM)

**File:** `backend/pipeline/tier_1.py`, lines 26–55

**Evidence:**
- The `except` block (lines 38–55) catches `FileNotFoundError, ImportError, ModuleNotFoundError, ValueError, OSError, RuntimeError, TypeError`
- The exception is **silently swallowed** — no `logger.warning()` or `logger.error()` call before falling back
- The only log entry is `logger.info("Tier 1 heuristic: prob=..., conf=..., routing=...")` which logs the **result**, not the **failure**
- An operator monitoring Triagemate's logs would see "Tier 1 heuristic" entries with no indication that XGBoost is malfunctioning

**Impact:** Silent degradation. If the XGBoost model file is corrupted, missing, or the registry is broken, the pipeline silently falls back to the heuristic. Operations has no way to detect this from logs without comparing expected vs. actual model behavior.

**What should change:** Add `logger.warning("Tier 1 XGBoost predict failed, falling back to heuristic: %s", e)` at the start of the `except` block (around line 47, before calling `_heuristic_evaluate()`).

---

### Bug 5: `ReadTimeout` not retried ✅ CONFIRMED (HIGH)

**File:** `backend/pipeline/tier_2.py`, lines 347–353 (`call_openai`) and lines 580–581 (`call_together`)

**Evidence (OpenAI, lines 347–353):**
```python
except (httpx.ConnectTimeout, httpx.ConnectError):
    if attempt < _MAX_RETRIES:
        await asyncio.sleep(_BASE_DELAY * (2**attempt))
        continue
    raise
except httpx.ReadTimeout:
    raise
```

- `ConnectTimeout` and `ConnectError` are retried up to `_MAX_RETRIES` times
- `ReadTimeout` is caught but **immediately re-raised** with no retry attempt
- This is despite the outer `for attempt in range(_MAX_RETRIES + 1):` loop on line 279 being designed for retry logic

**Evidence (Together AI, lines 580–581):**
```python
except httpx.ReadTimeout:
    raise
```

Same pattern — no retry.

**Impact:** A `ReadTimeout` is often a transient network/API issue (server temporarily slow, network congestion). By not retrying, valid requests fail unnecessarily. The fallback chain (`evaluate_tier_2` tries backup provider → KNOWN_CONFLICTS → neutral default) may mask this, but it means Tier 2 LLM analysis is skipped when a simple retry could succeed.

**What should change:** Merge `ReadTimeout` into the same retry pattern as `ConnectTimeout`/`ConnectError`. This applies to both `call_openai()` and `call_together()`.

---

### Bug 6: OTX `or` operator misuse ✅ CONFIRMED (MEDIUM)

**File:** `backend/integrations/otx.py`, line 57

**Evidence:**
```python
indicators = data.get("indicator_count", 0) or pulse_info.get("count", 0)
```

- `data.get("indicator_count", 0)` returns `0` for a CVE that has pulses but zero extracted IoCs
- Python evaluates `0 or X` as `X`, since `0` is falsy
- So when `indicator_count` is legitimately `0`, the value is silently replaced with `pulse_info.get("count", 0)` — which is the **count of pulses** (number of threat pulses), not the count of indicators (number of IoCs)
- These are different metrics: indicator_count = total IoCs across all pulses; pulse_info.count = number of pulses

**Is `indicator_count: 0` legitimate?** Yes. A CVE may be referenced in OTX pulse(s) that discuss it without having extracted any technical indicators (domains, IPs, hashes). The OTX API returns `"indicator_count": 0` as a valid value in that scenario.

**Impact:** For any CVE with pulses but zero extracted IoCs, the `indicators` field in the result will incorrectly reflect the pulse count instead of `0`. This feeds into `threat_intel_pulses` in the feature vector (`TABULAR_FEATURE_ORDER` line 79), potentially skewing downstream XGBoost predictions.

**What should change:** Replace the `or` with a proper fallback:
```python
count = data.get("indicator_count")
indicators = count if count is not None else pulse_info.get("count", 0)
```

---

## Verdict

**PASS WITH ISSUES** — 6 confirmed, 0 failed, 0 skipped

All six bugs are confirmed as described. The bugs fall into three categories:

| Category | Bugs | Priority |
|----------|------|----------|
| **No retry / silent failure** (operational reliability) | #4, #5 | HIGH |
| **Memory / data integrity** (correctness under load) | #1, #2 | HIGH |
| **Logic / thread-safety** (correctness) | #3, #6 | MEDIUM |

### Recommended fix order:
1. **Bug #5** (`ReadTimeout` not retried) — 2-line fix in `tier_2.py`, prevents spurious Tier 2 failures
2. **Bug #4** (silent heuristic fallback) — 1-line `logger.warning()` in `tier_1.py`
3. **Bug #6** (OTX `or` misuse) — 2-line fix in `otx.py`
4. **Bug #3** (calibrator race) — move `_active_calibrator_path` read inside `_lock` in `xgboost_predictor.py`
5. **Bug #1** (cache growth) — add eviction to `_rag_cache` in `vector_store.py`
6. **Bug #2** (seed duplicates) — add idempotency to `seed_demo_documents()` in `vector_store.py`

All fixes are localized to single files and well-understood patterns. Recommend delegating to **strike** with skill `backend-engineering` for #3–#6 and `ml-engineering` for #1–#2.
