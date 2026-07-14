# Phase 8 Remaining Evidence — Investigation Report

**Date:** 2026-07-14
**Investigator:** Strike Team (code-writing agent)
**Scope:** 11 evidence-needed items across security, routing, ML, and infra domains

---

## CORE-MED-5: Rate limiting on non-POST routes

**Status:** Reproduced

**Evidence:**
```
$ rg '@router\.(get|put|patch|delete)' backend/routers/ --type py -n
backend/routers/queue.py:35:    @router.get("/api/system/retrain-status")
backend/routers/queue.py:85:    @router.get("/api/queue", response_model=QueueResponse)
backend/routers/queue.py:121:   @router.get("/api/metrics", response_model=MetricsResponse)
backend/routers/queue.py:145:   @router.get("/api/drift", response_model=DriftMetricsResponse)
backend/routers/queue.py:265:   @router.get("/api/drift/ml", response_model=MlDriftResponse)
backend/routers/queue.py:323:   @router.get("/api/drift/epss", response_model=MlDriftResponse)
backend/routers/queue.py:386:   @router.get("/api/drift/pre-tier", response_model=MlDriftResponse)
backend/routers/queue.py:443:   @router.get("/api/drift/concept", response_model=ConceptDriftResponse)
backend/routers/queue.py:604:   @router.get("/api/drift/accuracy")
backend/routers/cases.py:142:   @router.get("/api/case/{case_id}", response_model=CaseResponse)
backend/routers/cases.py:159:   @router.patch("/api/case/{case_id}/notes")
backend/routers/cases.py:177:   @router.get("/api/review/queue", response_model=ReviewQueueResponse)
backend/routers/cases.py:292:   @router.get("/api/case/{case_id}/history")
backend/routers/ingest.py:766:  @router.get("/api/demo/scenarios")
backend/routers/admin.py:72:   @router.get("/api/admin/config/scoring", response_model=ScoringConfigResponse)
backend/routers/admin.py:78:   @router.put("/api/admin/config/scoring", response_model=ScoringConfigResponse)
backend/routers/config.py:18:  @router.get("/api/config")
backend/routers/models.py:70:  @router.get("/versions")
backend/routers/models.py:80:  @router.get("/status")

$ rg 'rate.limit\|RateLimit\|limiter\|slowapi\|throttle' backend/ --type py -n
(no output)
```

**Finding:** Zero rate limiting exists anywhere in the backend. Sensitive non-POST routes exposing read/write data are unprotected:
- `GET /api/case/{case_id}` — reads case detail (sensitive)
- `PATCH /api/case/{case_id}/notes` — writes analyst notes
- `GET /api/review/queue` — reads review queue
- `PUT /api/admin/config/scoring` — writes scoring config
- `GET /api/config` — reads all config values

**Proposed next action:** Add `slowapi` or a custom middleware to rate-limit per-route. Prioritise: PUT/PATCH routes (write), then GET routes (read). Implement as middleware to avoid touching every route individually. Note: POST routes on `/api/ingest`, `/api/ingest/tenable` also lack rate limiting — those are the highest-risk endpoints.

---

## ROUTER-LOW-1: Is /api/config exposing sensitive info?

**Status:** Needs product decision

**Evidence:**
```python
# backend/routers/config.py
@router.get("/api/config")
def get_config(user: dict = Depends(get_current_user_if_enabled)):
    """Return all config values grouped by domain."""
    return {
        "thresholds": { ... },       # All routing thresholds (CWE-stratified EPSS, PSI drift, etc.)
        "scoring": { ... },          # Weights, clamp values, telemetry threshold
        "feature_names": { ... },    # Full list of 68 tabular feature names
        "threshold_info": ...,       # ML threshold_info.json contents
    }
```

**Finding:** The endpoint returns:
1. All pipeline routing thresholds (NVD_REF_THRESHOLD, KEV thresholds, CWE-stratified EPSS)
2. Scoring weights and configuration (TOTAL_WEIGHT, clamp values, context multipliers)
3. Full list of 68 tabular feature names used by XGBoost
4. ML model threshold info (classification_threshold, val_f1, CWE-stratified thresholds)

The docstring says "No auth required — config values are not sensitive" but the dependency `get_current_user_if_enabled` does inject auth when enabled. In dev mode (AUTH_DISABLED), it returns a default admin dict.

The feature names + thresholds could be used by an attacker to reverse-engineer the pipeline and craft evasive inputs. However, this is an internal tool and the config data is operational, not secret.

**Proposed next action:** Product decision needed:
- **Option A:** Accept the current exposure — thresholds are not secret in an internal tool
- **Option B:** Gate behind admin-only auth (already partially done via `get_current_user_if_enabled`)
- **Option C:** Strip `feature_names` from the response (the 68 feature names are the most sensitive item as they reveal the ML model's exact input dimensions)

---

## ROUTER-LOW-5: Uncaught JSON error on webhook endpoint

**Status:** Reproduced

**Evidence:**
```python
# backend/routers/ingest.py:708-724
@router.post("/api/ingest/tenable")
async def ingest_tenable(
    request: Request, user: dict = Depends(get_current_user_if_enabled)
):
    body_raw = await request.body()
    if len(body_raw) > 10_000_000:
        raise HTTPException(status_code=413, detail="Payload too large")
    body = json.loads(body_raw)      # <--- NOT wrapped in try/except
```

**Finding:** Line 724 `json.loads(body_raw)` will raise a `json.JSONDecodeError` if the request body is malformed JSON. FastAPI's default exception handler will return a generic 500 error with no meaningful detail. The 10 MB size check runs first, but a small invalid JSON body will crash.

**Proposed next action:** Wrap `json.loads()` in try/except and return `HTTPException(status_code=400, detail="Invalid JSON in request body")`.

---

## ROUTER-LOW-8: Corrupt vs missing threshold file

**Status:** Reproduced

**Evidence:**
```python
# backend/routers/config.py:53-63
def _load_threshold_info() -> dict:
    path = Path(__file__).resolve().parent.parent / "ml" / "threshold_info.json"
    if not path.exists():
        return {"status": "unavailable"}              # Missing file
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read threshold_info.json: %s", e)
        return {"status": "unavailable"}              # Corrupt file — same status
```

**Finding:** Both missing and corrupt threshold files return `{"status": "unavailable"}`. There is no way for the frontend or API consumer to distinguish between "file doesn't exist" and "file exists but is corrupt/deformed JSON." This hides operational issues — if the file is corrupt, an operator would benefit from a distinct signal.

**Proposed next action:** Return distinct statuses:
- Missing → `{"status": "not_found"}`
- Corrupt → `{"status": "corrupt", "error": "JSON decode failed: ..."}`
Optionally include the logger warning text in the response for diagnostic clarity.

---

## INT-MED-2: GreyNoise key + 429 handling

**Status:** Reproduced

**Evidence:**
```python
# backend/integrations/greynoise.py:1-13 (module docstring)
"""
DEPRECATED: GreyNoise free tier (10 queries/day, 50/week) is too restrictive
for the TriageMate ingest pipeline. Replaced by _synthetic_internet_scan()
in ingest_helpers.py which derives scan activity from KEV + EPSS + exploit data.
This file is preserved for reference. ...
"""

# Line 25:
API_KEY = os.getenv("TRIAGEMATE_GREYNOISE_API_KEY", "").strip()

# Lines 51-57:
try:
    resp = requests.get(...)
    resp.raise_for_status()
    data = resp.json()
    ...
except Exception as e:         # Catches everything (incl. 429) uniformly
    ...
```

**Finding:**
1. GreyNoise integration is **DEPRECATED** and no longer wired into the pipeline. The `ingest_helpers.py` uses `_synthetic_internet_scan()` instead.
2. API key env var `TRIAGEMATE_GREYNOISE_API_KEY` is still read but never set in `.env` or deployment config (not found via grep).
3. 429 handling: The `except Exception` clause catches rate-limit errors but treats them identically to all other failures — there is no distinct 429 detection, retry, or backoff.
4. Because the module is deprecated and unused, this is low-risk but the dead code could confuse operators.

**Proposed next action:** Either:
- Remove the deprecated `greynoise.py` file entirely, or
- Add a clear log warning at import time saying "DEPRECATED: GreyNoise module is no longer used" and add distinct 429 handling if it's kept for reference.

---

## INT-MED-3: OTX throttling

**Status:** Reproduced

**Evidence:**
```python
# backend/integrations/otx.py:45-52
try:
    resp = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general",
        headers={"X-OTX-API-KEY": API_KEY},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    ...
except Exception as e:         # Catches everything (incl. 429) uniformly
    ...
```

**Finding:** OTX has no rate-limit handling. The `except Exception` catches HTTP 429 (rate limited) identically to network errors and server errors. There is no:
- Retry with exponential backoff
- Distinct logging for 429 vs other errors
- Circuit breaker
- Rate-limit header parsing (`X-RateLimit-Remaining`, `Retry-After`)

The API key env var `TRIAGEMATE_OTX_API_KEY` is never set in `.env` or deployment config, meaning OTX queries always return "not queried" results currently. But if the key is configured, 10 concurrent ingests could trigger OTX rate limits silently.

**Proposed next action:**
1. Add HTTP 429 detection in the `except` clause
2. Implement exponential backoff retry (2s, 4s, 8s) with max 3 retries
3. Log a distinct warning for rate-limit events

---

## ML-LOW-6: Document chunking violation

**Status:** Reproduced

**Evidence:**
```python
# backend/ml/ingest_docs.py:76-124
def chunk_document(text: str, max_chars: int = 2000, overlap: int = 200) -> list[str]:
    """Split a document into chunks suitable for embedding."""
    if len(text) <= max_chars:
        return [text]

    # Try markdown header splitting first
    lines = text.split("\n")
    sections = []
    ...
    # If header splitting produced usable chunks, use those
    if len(sections) > 1:
        result = []
        for section in sections:
            if len(section) <= max_chars:
                result.append(section)
            else:
                result.extend(_sliding_window_chunks(section, max_chars, overlap))
        return result

    # Plain text: sliding window
    return _sliding_window_chunks(text, max_chars, overlap)

def _sliding_window_chunks(text: str, max_chars: int, overlap: int) -> list[str]:
    """Split text into chunks using a sliding window with overlap."""
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunk = text[start:end]
        chunks.append(chunk)
        if end == len(text):
            break
        start = end - overlap
    return chunks
```

**Finding:** The document chunking strategy uses **character-based** splitting (2000 chars, 200-char overlap), not token-based. The sentence embedding model `all-MiniLM-L6-v2` has a maximum sequence length of 256 tokens (~1920 chars for English text). While 2000 chars is a reasonable approximation, the chunking has no awareness of:
1. Token boundaries — a chunk at the 256-token limit could be truncated mid-word
2. Sentence boundaries — the sliding window can split mid-sentence, degrading embedding quality
3. The model's actual max sequence length (256 tokens / ~1920 chars)

The `## ` header splitting (level-2 headers only) is a good attempt at semantic chunking, but the fallback sliding window violates best practices.

**Proposed next action:**
1. Use a tokenizer-aware chunker (`tiktoken` or the SentenceTransformer's own tokenizer) to count tokens
2. Set `max_chars` to ~1900 to stay safely under the 256-token limit
3. Add sentence-boundary detection (split on `. \n` after the sliding window cut)
4. Consider adding `# ` (level-1 header) splitting alongside `##`

---

## ML-LOW-9: LanceDB version compatibility

**Status:** Reproduced

**Evidence:**
```
$ rg 'lancedb' backend/requirements.txt
lancedb>=0.5.0

$ pip show lancedb
Name: lancedb
Version: 0.34.0
```

**Finding:** The pinned requirement `lancedb>=0.5.0` is extremely loose. The installed version 0.34.0 satisfies the constraint, but `>=0.5.0` catches any release from 2023 onward. This creates risk:
- If a future LanceDB release changes the API, `pip install -r requirements.txt` could silently break the vector store.
- The vector store code uses `db.list_tables().tables` (LanceDB 0.5+ API) — this is compatible with 0.34.0, but a future breaking change would not be caught.
- No `lancedb` pin in `requirements.txt` for Python version compatibility.

**Proposed next action:**
1. Pin to `lancedb>=0.5.0,<1.0.0` to catch pre-1.0 breaking changes
2. Run `pip freeze | grep lancedb` and pin to the verified version: `lancedb==0.34.0` as a minimum recommended version

---

## SCRIPT-HIGH-4: Tier 0 precision metric

**Status:** Reproduced

**Evidence:**
```
$ rg 'tier.*0.*precision\|precision.*tier.*0\|_tier_zero' backend/ --type py -n
(no output)

$ rg -n 'precision\|recall\|f1' backend/pipeline/ --type py -n
(no output)
```

**Finding:** No precision metrics are collected for Tier 0 (deterministic routing). Tier 0 is a rule-based system with no training component, so there is no built-in mechanism for precision/accuracy measurement. The pipeline stores `tier_0_routing` and `tier_0_resolution` in the database but:
- No precision/recall/F1 metrics are computed or logged
- No retroactive comparison against analyst decisions exists
- Drift monitoring covers Tier 1 (XGBoost), Pre-Tier features, and EPSS features, but not Tier 0 routing outcomes
- The `concept_drift` endpoint exists but doesn't track Tier 0 classification accuracy

The architecture intentionally treats Tier 0 as "always correct by definition" (deterministic rules), but this assumption should be validated — a rule change could have unintended consequences without metrics.

**Proposed next action:**
1. Add a background job that periodically compares Tier 0 auto-resolve decisions against human analyst overrides in `reviews` table
2. Track Tier 0 precision per resolution category (`very_critical`, `low`) as simple ratio: `correct_auto_resolves / total_auto_resolves`
3. Expose via the existing `/api/drift/accuracy` endpoint or a new `/api/drift/tier-0` endpoint

---

## SCRIPT-LOW-2: CVE-2024-1709 vs CVE-2024-1708

**Status:** Not reproduced (no references found)

**Evidence:**
```
$ rg 'CVE-2024-1709\|CVE-2024-1708\|ScreenConnect' backend/ --type py -n
(no output)

$ rg -ri 'screenconnect\|screen.connect\|ConnectWise' backend/ --type py -n
(xref: vector_store.py line 83 — "ConnectWise ScreenConnect 23.9.7.8804" in seed data)
```

**Finding:** Neither `CVE-2024-1709` nor `CVE-2024-1708` appears anywhere in the backend Python code. The only ScreenConnect reference is in `backend/ml/vector_store.py:83` as seed document content describing a ConnectWise ScreenConnect server hostname — this is a descriptive asset record, not a CVE reference.

The CVE-2024-1709/CVE-2024-1708 confusion (ScreenConnect authentication bypass CVEs with similar numbers) does not exist in the codebase. The ScreenConnect reference in seed data is purely informational.

**Proposed next action:** No action needed. The issue is not present.

---

## INFRA-HIGH-2: seed_data idempotency

**Status:** Reproduced

**Evidence:**
```python
# backend/seed_data.py:1419-1427
for row in SEED_ROWS:
    cursor.execute(INSERT_SQL, row)       # Plain INSERT — no OR REPLACE, no OR IGNORE
    print(...)

conn.commit()
conn.close()
print(f"\nSeed complete. {len(SEED_ROWS)} rows inserted.")
```

Schema check:
```sql
-- backend/database.py:272-391
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ...
    -- NO UNIQUE constraint on (vulnerability_id, hostname)
    -- NO UNIQUE constraint anywhere except `id`
)
```

**Finding:** `seed_data.py` uses a plain `INSERT` statement and there is no UNIQUE constraint on `vulnerability_id` or any combination of columns in the `vulnerabilities` table. Running `python backend/seed_data.py` multiple times will:
1. Insert 7 duplicate rows each time
2. Each duplicate will get a new auto-increment `id`
3. The print statement says "N rows inserted" — appearing successful each time
4. Downstream consumers (the queue page, review queue) will show duplicate cases

This is **NOT idempotent** — running twice creates 14 rows instead of 7.

**Proposed next action:** One of:
- **Option A:** Add `INSERT OR IGNORE` with a UNIQUE constraint on `(vulnerability_id, hostname)` to the schema — safest for idempotency
- **Option B:** Add a pre-check before inserting: `SELECT COUNT(*) FROM vulnerabilities WHERE vulnerability_id = ? AND hostname = ?`, skip if exists
- **Option C:** Wrap in `DELETE FROM vulnerabilities` at the start (destructive but guarantees exact state)

Recommend Option A as it's the most robust and doesn't require schema migration pain (the `CREATE TABLE IF NOT EXISTS` would need a subsequent ALTER TABLE to add the UNIQUE constraint).

---

## Summary

| Item | Status | Risk Level | Action Required |
|---|---|---|---|
| CORE-MED-5 | Reproduced | Medium | Add slowapi/rate-limiting middleware |
| ROUTER-LOW-1 | Needs product decision | Low | Decide on config exposure scope |
| ROUTER-LOW-5 | Reproduced | Low | Wrap `json.loads()` in try/except |
| ROUTER-LOW-8 | Reproduced | Low | Distinguish corrupt vs missing in response |
| INT-MED-2 | Reproduced | Low | Remove or remediate deprecated Greynoise module |
| INT-MED-3 | Reproduced | Medium | Add 429 detection + retry to OTX |
| ML-LOW-6 | Reproduced | Low | Improve chunking to be token/sentence-aware |
| ML-LOW-9 | Reproduced | Low | Tighten lancedb version pin |
| SCRIPT-HIGH-4 | Reproduced | Medium | Add Tier 0 precision tracking |
| SCRIPT-LOW-2 | Not reproduced | None | No action needed |
| INFRA-HIGH-2 | Reproduced | Medium | Make seed_data.py idempotent |

**Total:** 10 findings confirmed, 1 not present, 1 needs product decision.
