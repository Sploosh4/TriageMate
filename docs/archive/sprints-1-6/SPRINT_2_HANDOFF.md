# Sprint 2 Handoff — TriageMate MVP

> **Status: ARCHIVED** — Sprint 2 historical record

> **Sprint 3 complete:** XGBoost model retrained and running. See `SPRINT_3_HANDOFF.md` for details.

**Date:** 30 June 2026
**Status:** Cloud LLM Tier 2 enabled and RAG vector store built and verified. Tier 2 now runs live OpenAI API calls with structured outputs, retry logic, and backup provider fallback. RAG store persists across reboots with TTL cache, write lock, and a document ingestion CLI. All 7 demo rows preserved.

---

## 1. What Sprint 2 Built

Sprint 2 took the Tier 2 stub and the bare LanceDB scaffolding from Sprint 1 and turned them into production-grade subsystems:

- **Cloud LLM Tier 2** — Multi-provider (OpenAI/Anthropic/Together AI), schema-enforced structured outputs, exponential backoff retry with error-type awareness, backup provider automatic failover, prompt caching (OpenAI auto-prefix, Anthropic `cache_control` blocks), cost tracking with per-call JSON logging, structured prompt engineering with force-reflection template, API key validation with startup warnings.

- **RAG Vector Store** — Persistent LanceDB at `backend/data/lancedb` (no longer `/tmp/`), 7 seeded demo documents with full asset configuration context, TTL cache (60s, keyed by hostname) avoiding redundant queries on concurrent hostname ingress, `threading.Lock` for write safety, FTS index fallback with logged errors, `ingest_docs.py` CLI script with markdown-header chunking, path traversal protection, and file size limits.

- **Infrastructure improvements** — `/api/health` endpoint reporting provider, API key status, document count, and store path. Startup warnings for missing API key. SentenceTransformer pre-loaded on startup. `python-dotenv` and `anthropic` SDK added to requirements.

- **Bug fixes** — AI_PROBLEMS #11 (LanceDB ephemeral path → persistent), #12 (FTS bare `except:pass` → logged warning), #13 (unused variable removed). Tier 1 XGBoost ValueError now catches the feature mismatch and falls back to heuristic gracefully.

---

## 2. Sprint 2 Project Structure Changes

### New Files
| File | Purpose |
|---|---|
| `backend/.env.example` | Environment variable template with all 8 configurable vars |
| `backend/ml/ingest_docs.py` | CLI tool for ingesting documents into the RAG vector store |

### Modified Files
| File | Key Changes |
|---|---|
| `backend/pipeline/tier_2.py` | Complete rewrite: structured outputs, retry logic, backup provider, prompt caching, cost tracking |
| `backend/ml/vector_store.py` | Persistent path, TTL cache, write lock, FTS logging |
| `backend/routers/ingest.py` | Passes `rag_context` string to Tier 2 (not raw dict), removed unused variable |
| `backend/ingest_helpers.py` | Returns `rag_context` string in dict; fallback sets defaults |
| `backend/main.py` | Health endpoint, startup warnings, embedder pre-load, version bump to 0.2.0 |
| `backend/models.py` | Added `TriageConflictResult` Pydantic model (6 fields, all required) |
| `backend/pipeline/tier_1.py` | Added `ValueError` to except clause (XGBoost feature mismatch → heuristic fallback) |
| `backend/requirements.txt` | Added `python-dotenv>=1.2.0`, `anthropic>=0.108.0` |
| `.gitignore` | Added `backend/data/` and `.env` |
| Various `.md` docs | Updated to mark Sprint 2 status |

### Auto-Created
| Path | Notes |
|---|---|
| `backend/data/lancedb/` | Persistent LanceDB store (created on startup). Add to `.gitignore`. |

---

## 3. Tier 2 Architecture Deep-Dive

### 3.1 Provider Dispatch

`evaluate_tier_2()` in `tier_2.py:568-610` iterates through a provider list: primary first, then backup (if configured). Each provider has its own retry loop. If all providers fail, it falls through to `KNOWN_CONFLICTS` cache, then to a neutral default.

```
evaluate_tier_2()
  │
  ├─ Primary provider (from TRIAGEMATE_LLM_*)
  │    ├─ call_openai()      → json_schema + strict:true
  │    ├─ call_anthropic()   → client.messages.parse() + Pydantic model
  │    └─ call_together()    → json_schema (best-effort) + prompt guidance
  │    └─ Retry 3x on: ConnectTimeout, ConnectError, 5xx
  │       └─ NOT on: ReadTimeout (partial-cost risk), 4xx (auth won't fix)
  │
  ├─ Backup provider (if BACKUP_API_KEY set, same retry logic)
  │
  └─ KNOWN_CONFLICTS cache → neutral default
```

### 3.2 Structured Outputs per Provider

| Provider | Mechanism | Constraint Level | Refusal Handling |
|---|---|---|---|
| **OpenAI** | `response_format.type: json_schema` + `strict: true` | **Constrained decoding** — model physically cannot emit non-conforming tokens | Check `choice.finish_reason == "content_filter"` and `message.refusal` |
| **Anthropic** | `client.messages.parse()` + `output_config.format.type: json_schema` with `additionalProperties: false` | **Constrained decoding** — server-enforced | Check `response.stop_reason == "refusal"`; retry on `stop_reason == "max_tokens"` with doubled tokens |
| **Together AI** | `response_format.type: json_schema` + always-embedded schema text in prompt | **Best-effort guidance** — not constrained decoding | Catch `json.JSONDecodeError` from return; fall through to backup/cache |

### 3.3 Shared Output Schema (`TriageConflictResult`)

Defined in `models.py:99-108`. All fields are required (no `Optional`/`Union` — Anthropic's JSON Schema subset does not support `anyOf`):

```python
class TriageConflictResult(BaseModel):
    text_conflict: bool
    conflict_note: str
    rag_result: str           # UNCERTAIN | CONFIRMED | NOT_QUERIED
    resolution: str
    confidence: float          # 0.0–1.0
    score_adjustment: int      # -70 to +10
```

Used as: OpenAI/Together `response_format` schema, Anthropic `output_config.format`, and the inline prompt schema for guidance.

### 3.4 Prompt Design (Caching-Optimised)

`build_prompt()` returns `(system_content, user_content)` — two separate strings.

| Message | Content | Cache Behaviour |
|---|---|---|
| **System** (static) | Role definition, force-reflection steps (A→B→C), JSON output schema | **OpenAI:** auto-prefix cached. **Anthropic:** `cache_control: {"type": "ephemeral"}` on this block |
| **User** (dynamic) | CVE ID, CVSS, CISA KEV, EPSS, CVSS vector, description, mission tags, RAG context, upstream Tier 1 scores | Not cached (changes per call) |

The static portion is typically ~1,000–1,500 tokens, above OpenAI's minimum for caching (1024 tokens) but below Anthropic Haiku 4.5's minimum (4096 tokens). Cache may not activate on Anthropic for MVP-scale prompts — this is acceptable.

### 3.5 Resilience Pipeline

```
API call attempt (provider-specific with internal retry)
  │
  ├── Success → log metrics → return result
  │
  └── Exception after retries exhausted:
       │
       ├── Backup provider configured? → try backup
       │
       ├── CVE in KNOWN_CONFLICTS? → return cached result with fallback note
       │
       └── Unknown CVE → return neutral default:
            text_conflict: false
            confidence: 0.30
            score_adjustment: 0
```

### 3.6 Cost Tracking

Module-level accumulators in `tier_2.py`. On each API call:

```json
{"event":"llm_call","provider":"openai","model":"gpt-4o-mini",
 "input_tokens":842,"output_tokens":156,"cached_tokens":0,"estimated_cost_usd":0.000356}
```

Rates used (approximate per-1M-tokens): OpenAI $0.15/$0.60, Anthropic $0.25/$1.25, Together $0.20/$0.20.

---

## 4. RAG Vector Store Architecture

### 4.1 Storage

| Property | Sprint 1 (stub) | Sprint 2 (real) |
|---|---|---|
| **Path** | `/tmp/triagemate_lancedb` | `backend/data/lancedb` |
| **Persistence** | Lost on reboot | Survives reboot |
| **Documents** | 3 hardcoded in seed | 7 documents (1 per demo host) |
| **Write safety** | None | `threading.Lock` guards `add()`/`delete()` |
| **Read safety** | N/A | Lock-free (Lance immutable manifest versioning) |
| **FTS errors** | `except: pass` | `logging.warning` with exception message |

### 4.2 7 Seeded Documents

| Hostname | Document Type | Content Summary |
|---|---|---|
| PRD-MOVEIT-WEB01.health.wa.gov.au | cmdb_record | MOVEit Transfer 2023.0.0, internet-facing, no WAF, patch available |
| PRD-CITRIX-ADC01.transport.wa.gov.au | cmdb_record | Citrix NetScaler ADC 13.1-49.13, internet-facing, 20+ downstream |
| PRD-PRINT-SVR05.education.wa.edu.au | cmdb_record | PaperCut MF 22.0.6, internal-only, 28 downstream endpoints |
| PRD-RMM-GW01.sharedservices.wa.gov.au | cmdb_record | ConnectWise ScreenConnect 23.9.7, isolated VLAN, 14 endpoints |
| PRD-FILE-STORE02.communities.wa.gov.au | gpo_report | Defender ASR rule GPO status: UNCERTAIN (replication failure) |
| PRD-WIKI-CORE01.wapol.internal.wa.gov.au | change_record | Confluence upgrade to 8.5.2, hostname alias confusion with CORE02 |
| PRD-ITSM-TOOL01.finance.wa.gov.au | application_config | SAML SSO disabled (`saml.sso.enabled=false`), LDAP only |

### 4.3 TTL Cache

`query_rag()` caches results per `hostname::cwe_class::top_k` key with a 60-second TTL. This prevents redundant LanceDB queries when multiple CVEs on the same hostname are ingested concurrently. Cache is invalidated after TTL expiry or on server restart. The cache is a simple in-memory dict — no external dependency.

### 4.4 Document Ingestion CLI (`ingest_docs.py`)

```bash
# Ingest a single file for a specific hostname
python -m ml.ingest_docs --file runbook.md --hostname prd-app01.wa.gov.au

# Ingest an entire directory recursively
python -m ml.ingest_docs --dir ./docs --reset

# Override document type
python -m ml.ingest_docs --file app.properties --document-type app_config
```

Safety features:
- **Path traversal protection**: rejects paths resolving outside the project directory
- **File size limits**: rejects files >10MB, warns at >1MB
- **Content validation**: JSON files are validated with `json.loads()` before embedding
- **Chunking**: markdown-header splitting (## sections) + sliding window at 2000 chars with 200 overlap

---

## 5. Infrastructure Improvements

### 5.1 Environment Configuration

All Tier 2 settings are configured via `.env` (loaded by `python-dotenv` at module import):

```
TRIAGEMATE_LLM_PROVIDER=openai          # openai | anthropic | together
TRIAGEMATE_LLM_API_KEY=sk-...           # Provider API key
TRIAGEMATE_LLM_MODEL=gpt-4o-mini        # Model name
TRIAGEMATE_LLM_MAX_TOKENS=1024          # Response token budget
TRIAGEMATE_LLM_TIMEOUT=30               # API timeout (seconds)
TRIAGEMATE_LLM_BACKUP_PROVIDER=         # Optional secondary provider
TRIAGEMATE_LLM_BACKUP_API_KEY=          # Backup API key
TRIAGEMATE_LLM_BACKUP_MODEL=            # Backup model name
```

Template at `backend/.env.example` with key format documentation.

### 5.2 `/api/health` Endpoint

```
GET /api/health
```

Returns configuration status (does NOT probe the LLM API):
```json
{
  "status": "ok",
  "version": "0.2.0",
  "tier_2_provider": "openai",
  "llm_available": true,
  "rag_documents": 7,
  "rag_store_path": "/home/.../backend/data/lancedb"
}
```

### 5.3 API Key Validation

At import time, `tier_2.py` validates API key formats and logs a warning on mismatch:
- OpenAI: should start with `sk-` or `sk-proj-`
- Anthropic: should start with `sk-ant-api03-`

Validation does not block — a mismatched key still works if using a custom proxy.

---

## 6. Sprint 2 Verification Results

All tests pass with the live server running.

| Test | Result |
|---|---|
| **KNOWLEDGE_CONFLICTS fallback** | Returns correct cached data for CVE-2023-36884 (text_conflict=True, confidence=0.72) |
| **Neutral default** | Returns neutral assessment for unknown CVEs without API key |
| **Cloud LLM (OpenAI)** | Returns structured JSON with text_conflict, conflict_note, resolution — confirmed working with gpt-4o-mini |
| **RAG context injection** | LLM analysis references "ASR rule enforcement status" from the GPO report for PRD-FILE-STORE02 |
| **RAG TTL cache** | Same object returned for duplicate hostname queries within 60s |
| **LanceDB persistence** | Store survives server restart (`backend/data/lancedb`, not `/tmp/`) |
| **Document ingestion** | `ingest_file()` chunks markdown and adds to vector store; `query_rag()` retrieves it |
| **Path traversal protection** | Rejects `/etc/passwd` with `ValueError` |
| **7 demo rows preserved** | All scores match SPRINT_1_HANDOFF.md §6 (94, 87, 71, 55, 63, 41, 22) |
| **Health endpoint** | Returns correct provider, document count, version 0.2.0 |
| **Cost tracking** | Server logs show `"event":"llm_call"` with tokens and estimated cost |

---

## 7. Known Gotchas

1. **.env lives at `backend/.env`** — not the project root. `load_dotenv()` in `tier_2.py` searches from the current working directory. If you run `uvicorn` from outside `backend/`, the .env won't be found.

2. **uvicorn --reload does NOT watch .env files** — only .py files. If you change `.env` while the server is running, touch a .py file (e.g., `touch main.py`) to force a reload.

3. **Anthropic cache threshold** — Claude Haiku 4.5 requires >=4096 tokens for cache activation. MVP prompts are ~1500 tokens. Caching works on OpenAI (auto-prefix, 1024 token minimum) but may NOT activate on Anthropic. This is documented and acceptable — don't bloat prompts to reach the threshold.

4. **Together AI structured outputs are best-effort** — Unlike OpenAI (constrained decoding via `strict: true`) and Anthropic (GA structured outputs with `additionalProperties: false`), Together AI's JSON Schema mode is prompt guidance only. The schema is always embedded in the system prompt text as a fallback. Some models may not support `response_format.type: json_schema`.

5. **XGBoost feature mismatch** — The XGBoost model expects 69 features but `build_feature_vector()` produces 68 (known bug, AI_PROBLEMS #4-10 area). Sprint 2 added `ValueError` to the catch clause in `tier_1.py` so the heuristic fallback runs instead of crashing. This is a Sprint 3 item.

6. **RAG cache is in-memory** — The TTL cache is a plain Python dict. It's lost on server restart (acceptable — LanceDB queries are fast). For production, consider Redis or a persistent cache.

7. **LanceDB is single-writer** — The `threading.Lock` prevents concurrent writes from corrupting the manifest. Reads are safe without locks. The ingest CLI runs outside the web process, so concurrent writes between web and CLI could theoretically conflict. In practice, the web process never writes to LanceDB (only reads), so this is safe.

---

## 8. API Contract Changes (from Sprint 1)

### New Endpoint
- `GET /api/health` — returns configuration status (no LLM probe)

### Unchanged
- `GET /api/queue` — same shape
- `GET /api/case/{id}` — same shape
- `GET /api/metrics` — same shape
- `POST /api/ingest` — same shape (but `build_prompt()` signature changed internally)

### Internal Interface Change
`tier_2.evaluate_tier_2()` no longer accepts `config_context: dict`. Instead it accepts:
- `rag_context: str` — formatted RAG text string
- `cisa_kev: bool` — CISA KEV status
- `epss_score: float` — EPSS score
- `cvss_vector: str` — CVSS vector string

---

## 9. What Remains — Sprint 3 Priorities

| Priority | Item | Effort | Notes |
|---|---|---|---|
| **1** | Tier 1 XGBoost tuning | 1 week | Fix feature count mismatch, validate against 7 demo rows |
| **2** | Pre-Tier multi-label classifier | 1–2 weeks | Needs 200–500 labeled assets from analyst |
| **3** | CWE encoder | 1 week | AI_PROBLEMS #1–3 must be fixed first |
| **4** | EPSS substitution model | 2–4 weeks | Needs sector-weighted exploitation data |
| **5** | Liveness/readiness health checks | 1 day | Distinguish `/api/health` from `/api/ready` |

### Lower Priority / Stretch
| Item | Notes |
|---|---|
| pydantic-settings migration | Type-safe validation; replace raw `python-dotenv` |
| `tiktoken` integration | Precise token counting instead of character heuristic |
| Confluence/SharePoint auto-sync | Beyond MVP scope — `ingest_docs.py` is the MVP approach |

---

## 10. Quick Start (Updated for Sprint 2)

```bash
cd "TriageMate MVP/backend"
source venv/bin/activate

# Install new dependencies (Sprint 2 additions)
pip install -r requirements.txt

# Seed the database (one-time, already done)
python seed_data.py

# Copy and configure environment
cp .env.example .env
# Edit .env with your API key

# Start the server
uvicorn main:app --reload

# Verify everything
curl -s http://localhost:8000/api/health | python3 -m json.tool
curl -s http://localhost:8000/api/queue | python3 -c "import sys,json;print(len(json.load(sys.stdin)['rows']),'rows')"
```

**Ingest a test CVE that reaches Tier 2:**
```bash
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CVE-2023-50000",
    "hostname": "PRD-FILE-STORE02.communities.wa.gov.au",
    "cvss_score": 6.8,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cisa_kev": false,
    "epss_score": 0.22,
    "target_ip": "10.0.0.1",
    "raw_description": "Example vulnerability description for testing"
  }' | python3 -c "import sys,json;d=json.load(sys.stdin);print('Tier:',d['queueRow']['tier'],'| Conflict:',d['caseView']['textConflict'])"
```

Expected output: `Tier: SLM Tier | Conflict: True`
