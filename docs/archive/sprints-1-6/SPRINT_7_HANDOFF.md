# Sprint 7 Handoff — Commander Briefing

> **Date:** 2 July 2026
> **From:** Commander (Sprints 1-6)
> **To:** Incoming Commander
> **Repo state:** `master @ 8cbabae` — clean working tree, 37/37 tests pass

---

## 1. What You're Walking Into

TriageMate is a vulnerability triage platform built for the WA government SOC. It ingests raw vulnerabilities (from curl, Tenable exports, or a demo generator), runs them through a 4-stage ML pipeline, assigns a 0-100 priority score, and displays results in a web dashboard.

The codebase is **5,500+ lines** across ~60 files. It works. It ships with 7 seed demo rows, 37 tests, and a demo data generator that can produce hundreds of realistic findings from a 28-host mock CMDB. The pipeline runs real ML at every stage: deterministic rules (Tier 0), XGBoost (Tier 1, ROC-AUC 0.9677 on 93K CVEs), and cloud LLM with RAG (Tier 2).

The app was just hardened for production with PostgreSQL support and JWT authentication. It is demo-ready but not yet deployable outside a developer machine without additional work.

---

## 2. Completed Sprints (What You Don't Need to Revisit)

| Sprint | Commit | What Was Built |
|---|---|---|
| **Sprint 1** | `49ecbb2` | FastAPI backend with SQLite, 4 pipeline stages (Tier 0 real, others stubs), scoring engine, static frontend (HTML/JS/CSS), background scheduler + audit, MVP scope document. 7 demo rows seeded. |
| **Sprint 2** | included in `49ecbb2` | Cloud LLM Tier 2: multi-provider (OpenAI/Anthropic/Together), schema-enforced structured outputs, exponential backoff, backup provider failover, prompt caching, cost tracking. RAG vector store: persistent LanceDB, 7 seeded docs, TTL cache, write lock, ingestion CLI. |
| **Sprint 3** | included in `49ecbb2` | XGBoost model retrained: fixed 69→68 feature mismatch caused by `cisa_kev` label-leakage removal. DMatrix compatibility fix for XGBoost 3.3.0. Full validation — all 7 demo rows match exact expected scores (94, 87, 71, 55, 63, 41, 22). ROC-AUC 0.9677. |
| **Course Correction** | `11dd427`, `5ce731e` | 11/11 production-readiness items: CMDB adapter (replaced 7-host hardcode), NVD API client with caching, threat intel enrichment (ExploitDB, Metasploit via NVD references), MITRE ATT&CK dynamic mapping, summary paragraph generation, advisory reference enrichment, bulk ingest endpoint, EPSS availability flag, test DB isolation. |
| **Sprint 4 (Pre-Demo Hardening)** | `0c4828c`, `be685b8` | 9/9 items: X-API-Key auth middleware (now superseded by JWT in Sprint 6), Tenable.io webhook, training/production encoding audit (3 features verified), NVD degradation visibility (health endpoint + case view badge), Docker + docker-compose, demo script, screenshots tool, clean machine test, Windows setup instructions. |
| **Sprint 5 (Demo Data Generator)** | `b21e69b` | 28-host mock CMDB as JSON, pre-tier model retrained, NVD/KEV/EPSS cache builder scripts + pre-populated cache data (~2,600 NVD entries, 338 KEV entries), cache-to-pipeline wiring (BLOCKER D5 fix: DEMO_MODE reads nvd_cache.json instead of live NVD), 5 curated demo scenarios + random wave generator, demo UI controls (scenario picker, generate, clear), archive table + rate-limited clear endpoint, 17 generator tests. External auditor reviewed, 2 BLOCKERs and 2 HIGH findings resolved. |
| **Sprint 6 (Production Hardening)** | `8cbabae` | PostgreSQL support: DatabaseManager class with dual SQLite/PostgreSQL backend via DATABASE_URL env var. docker-compose updated with postgres:16-alpine service. JWT authentication: auth.py (JWT HS256 tokens + bcrypt hashing), login/refresh endpoints, HTTPBearer on all /api/* routes, login modal UI, 401 auto-refresh in fetch wrapper. Backward-compat: when TRIAGEMATE_ADMIN_USER is unset, auth is a no-op. |

---

## 3. What's Left — The Remaining Work

### 3.1 Known Bugs (from AI_PROBLEMS.md)

| # | Severity | Description | File | Impact |
|---|---|---|---|---|
| **10** | 🟡 MEDIUM | Patch features hardcoded to 1/0 in training data. Training saw `patch_available=True` (100%) and `patch_applied=False` (100%). Production sees ~30% True for `patch_available`. Model may overweight these features. | `backend/ml/train_xgboost.py:376-377` | Minor calibration drift — model trained on unrealistic patch distributions |
| **14** | 🟢 TRIVIAL | Tier 1 heuristic always escalates (confidence range 0.72-0.85 always falls in escalation window). Only triggered when XGBoost model unavailable (fallback path — never reached now). | `backend/pipeline/tier_1.py:63` | No practical impact — XGBoost model is always available |

### 3.2 Technical Debt (Not Tracked in AI_PROBLEMS.md)

| Item | Severity | Location | Notes |
|---|---|---|---|
| **FastAPI `on_event` deprecated** | 🟢 LOW | `backend/main.py:48` | Should migrate to `lifespan` context manager. Deprecation warning on every startup. |
| **LanceDB `table_names()` deprecated** | 🟢 LOW | `backend/ml/vector_store.py:306` | Should use `list_tables()` instead. Warning on every startup when LanceDB initializes. |
| **joblib/numpy shape warning** | 🟢 LOW | N/A (pre-existing) | 1,600+ warnings during tests. NumPy 2.5 deprecated setting shape on arrays. Comes from joblib's pickle deserialization of XGBoost model. No fix available — wait for joblib/xgboost update. |
| **`cwe_classifier_deprecated.py` still in repo** | 🟢 LOW | `backend/ml/cwe_classifier_deprecated.py` | 656MB SecureBERT2.0 model bypassed in favor of NVD API + regex lookup. Deprecated file preserved for reference but never loaded. Could be deleted. |
| **`database.py` is 819 lines** | 🟠 MEDIUM | `backend/database.py` | The DatabaseManager class + PostgreSQL compatibility layer + full schema definition all in one file. Should be split into `database.py` (manager), `schemas.py` (SQL DDL), and `pg_compat.py` (PostgreSQL wrappers) before it grows further. |
| **Auth: plain-text password comparison** | 🟠 MEDIUM | `backend/routers/auth.py:37` | Login route compares `body.password != ADMIN_PASS` directly. The `auth.py` module has `hash_password()` and `verify_password()` functions, but they're unused. Should either hash the admin password at deploy time or switch to env-var bcrypt hash. |
| **Auth: no refresh token rotation** | 🟡 LOW | `backend/routers/auth.py:54-83` | `/api/auth/refresh` returns the same refresh token. No rotation, no revocation list. Acceptable for single-user MVP; should be addressed before multi-user deployment. |
| **Frontend: no auth header in demo controls** | 🟡 MEDIUM | `frontend/js/components/demoControls.js` | Demo controls use raw `fetch()` without the `_authFetch()` wrapper from api.js. If auth is enabled, demo controls will 401. This is documented — demo should run with auth unset. |

### 3.3 Post-MVP Feature Backlog (from ROADMAP.md §8)

These are ordered by my recommendation of what to tackle next:

**High-impact, low-blocker (can start immediately):**
1. **CI/CD pipeline** — GitHub Actions workflow for pytest + lint on push/PR. ~2 hrs, devops-engineer.
2. **Alembic database migrations** — Replace ad-hoc `_migrate_add_column()` with proper Alembic. The database schema has changed across 6 sprints and needs versioned migrations before any further schema changes. ~3 hrs, backend-engineer + devops-engineer.
3. **Rate limiting on ingest endpoints** — Protect `/api/ingest`, `/api/ingest/batch`, `/api/ingest/tenable`, and `/api/demo/generate` from abuse. Simple in-memory token bucket. ~2 hrs, backend-engineer.
4. **Fix AI_PROBLEMS #10** — Either backfill training data with production-realistic patch feature distributions, or retrain with these features removed. ~3 hrs, ml-engineer.
5. **Structured JSON logging** — Current logging is `print()`-style. JSON-structured logs enable log aggregation and alerting. ~2 hrs, backend-engineer.

**Medium-impact, some dependencies:**
6. **Model drift dashboard** — Uses data from `audit.py` (already running — 7.5% random sample of auto-resolved cases). Visual dashboard showing score distributions over time, tier routing percentages, feature drift alerts. ~4 hrs, frontend-dev + ux-designer + ml-engineer.
7. **Tier 3 Human Review queue** — Dedicated UI for analyst to review and provide feedback on auto-resolved cases. The feedback data feeds future model retraining. ~5 hrs, frontend-dev + ux-designer + backend-engineer.
8. **Email/Slack notifications** — Alert when a Very Critical finding is auto-resolved. Configurable via env vars. ~2 hrs, backend-engineer + cloud-llm-engineer.

**Blocked on external data:**
9. **Pre-Tier RandomForest classifier** — Replace 7-host dictionary with real ML model. Needs 200-500 WA government assets labeled with mission_prevalence and public_wellbeing_impact. Blocked until labeled data exists.
10. **Tier 2 CWE encoder (ModernBERT)** — Replace NVD API CWE lookup with local model. Blocked until someone wants to fix the SecureBERT head naming issues or fine-tune ModernBERT on NVD CWE mappings.
11. **EPSS substitution model** — Sector-adjusted EPSS scores. Blocked on sector-weighted exploitation data.
12. **WA-specific XGBoost tuning** — Fine-tune on local incidents. Blocked on validation data from WA SOC.

**Production ops:**
13. **HTTPS/TLS** — Required before any network-exposed deployment.
14. **Role-based access control** — Analyst vs admin permissions. Needs user story definition first.

---

## 4. Agent Roster (Your Teams)

You have 8 subagents available. Their definitions live in `.opencode/agents/`. They are NOT nested — you spawn each directly from your Commander session via the `task` tool.

### Intel Team (Pre-Build Gates — Read-Only)

These two agents validate domain decisions BEFORE Strike writes any code. Never skip the Intel gate on items involving WA government conventions or privacy/legal concerns.

| Agent | File | Expertise |
|---|---|---|
| `wa-gov-consultant` | `.opencode/agents/wa-gov-consultant.md` | WA government department structure, hostname conventions, SOC workflow, data classification (Category 1-4), ACSC Essential Eight, mission tag assignments. Read-only — you rule, you do not write code. |
| `privacy-legal-advisor` | `.opencode/agents/privacy-legal-advisor.md` | Australian Privacy Act 1988, WA Freedom of Information Act, demo data safety (fictional hostnames must not match real assets), data retention policies. Read-only — you flag risks, you do not write code. |

### Strike Team (Builders — Write All Code)

These six agents implement features. Assign each agent a specific set of files and a clear deliverable. They should never touch each other's files in the same wave — if two agents need the same file, sequence them.

| Agent | File | Expertise |
|---|---|---|
| `backend-engineer` | `.opencode/agents/backend-engineer.md` | Python 3.11+, FastAPI routers/middleware/DI, Pydantic v2 models, SQLite schema, pipeline stages (Pre-Tier→Tier 0→Tier 1→Tier 2), scoring engine, ingest pipeline, background scheduler. |
| `cloud-llm-engineer` | `.opencode/agents/cloud-llm-engineer.md` | Multi-provider LLM (OpenAI/Anthropic/Together), exponential backoff, force-reflection prompt, KNOWN_CONFLICTS cache, graceful degradation, cost tracking, NVD API lookups. |
| `devops-engineer` | `.opencode/agents/devops-engineer.md` | Docker + docker-compose, environment config (.env, TRIAGEMATE_* prefix), requirements.txt, git workflow, pytest config, CI/CD pipeline design. |
| `frontend-dev` | `.opencode/agents/frontend-dev.md` | Vanilla JS (no framework), Fetch API, DOM manipulation (textContent over innerHTML), CSS conventions, component architecture (api.js / app.js / components/*.js). |
| `ml-engineer` | `.opencode/agents/ml-engineer.md` | XGBoost training/inference, feature vectors (68 features), scikit-learn preprocessing, NVD/EPSS data pipelines, LanceDB vector store, pre-tier classifier training. |
| `ux-designer` | `.opencode/agents/ux-designer.md` | CSS design system (triagemate.css), visual hierarchy, accessibility (WCAG), color palette, typography, dashboard layout, component patterns. demo-reference.html is the visual spec. |

### Audit Team (Post-Build Verifiers)

Verification happens after Strike finishes. You can assign any builder agent to audit work by giving them a read-only verification prompt. Common audit pattern: launch a `backend-engineer` with instructions to run tests, check API contracts, and verify scores without writing code.

---

## 5. Commander Workflow

This is the pattern from TEAM_BRIEFING.md. It works. Use it.

```
PHASE 0: PLAN
  - Read ROADMAP.md for current status
  - Read AI_PROBLEMS.md for unfixed bugs
  - Read this document for remaining work
  - Decide sprint scope. Pick items from §3 above.
  - Identify which items need Intel gates (WA gov conventions? privacy concerns?)
  - Identify which files each item touches (to avoid agent file conflicts)

PHASE 1: INTEL (if needed)
  - For items with domain ambiguity, paste prompts into sessions with:
    - wa-gov-consultant (hostname plausibility, SOC workflow, data classification)
    - privacy-legal-advisor (demo data safety, compliance, retention)
  - Intel agents are READ-ONLY. They rule — Strike cannot override.
  - Intel returns: approve / amend (with suggestion) / reject.
  - Wait for Intel before launching Strike on gated items.

PHASE 2: STRIKE (parallel where possible)
  - For each item, spawn the right agent via task tool
  - Give each agent: exact file paths to touch, what to build, verification commands
  - Agents that touch different files can run in parallel
  - Agents that touch the same file must be sequenced
  - Each agent must: read existing files first, match conventions, verify their work

PHASE 3: AUDIT
  - After Strike finishes, verify everything:
    1. uvicorn main:app starts without errors (from backend/)
    2. pytest backend/tests/ -v — all 37 pass
    3. 7 demo row scores within ±3 of expected (94, 87, 71, 55, 63, 41, 22)
    4. GET /api/health returns 200
    5. GET /api/queue returns rows sorted by priority
    6. POST /api/ingest with test payload returns 200
    7. Unknown hostname ingest does not crash
    8. Swagger /docs shows all endpoints

PHASE 4: COMMIT
  - git add + git commit (pre-commit hooks run ruff check + ruff format)
  - If ruff fails: fix issues, amend commit
  - Push when ready
  - Update ROADMAP.md with completed items
```

---

## 6. Recommended Sprint 7 Scope

Based on what's left and what will give the most value per hour, I recommend:

### Sprint 7: Operations Foundation

**Goal:** Make the app deployable and monitorable. Close the gap between "runs on a dev laptop" and "runs in production."

| # | Item | Agent | Effort | Why Now |
|---|---|---|---|---|
| 7.1 | **Alembic database migrations** | backend-engineer | 3 hrs | The schema has changed 6+ times with ad-hoc `_migrate_add_column()`. Before ANY further schema changes, we need proper versioned migrations. This unblocks all future DB work. |
| 7.2 | **Rate limiting on ingest** | backend-engineer | 2 hrs | `/api/ingest` and `/api/demo/generate` have no protection. A runaway script or accidental loop fills the DB. Simple in-memory token bucket is all that's needed. |
| 7.3 | **CI/CD pipeline (GitHub Actions)** | devops-engineer | 2 hrs | Currently no automated testing on push. A workflow that runs pytest + ruff on every push catches regressions before they reach master. |
| 7.4 | **Structured JSON logging** | backend-engineer | 2 hrs | Current logs are `print()`-style. JSON-structured logs are required for any log aggregation system (CloudWatch, ELK, Loki). |
| 7.5 | **Clean up technical debt** | backend-engineer | 1.5 hrs | Fix FastAPI on_event→lifespan, LanceDB table_names→list_tables, delete cwe_classifier_deprecated.py, add bcrypt hash for admin password. |

**Total: ~10.5 hrs. No Intel gate needed (all are engineering decisions, not domain questions). All items can run in parallel except 7.5 should come last (touches files modified by 7.1-7.4).**

### What to Defer

- **Post-MVP features** (Tier 3 UI, dashboard, notifications) — wait until the ops foundation is solid
- **ML models** — still blocked on labeled WA data
- **HTTPS/TLS, RBAC** — wait until there's a deployment target
- **AI_PROBLEMS #10** — medium-priority, can be bundled into a future "model refresh" sprint

---

## 7. Key Files to Read Before You Start

| File | Why |
|---|---|
| `ROADMAP.md` | Master status. Read §7-§9 for what's done, §8 for what's left. |
| `AI_PROBLEMS.md` | Bug tracker. #10 is the only actionable unfixed bug. |
| `MVP_SCOPE.md` | Boundaries — what's in scope and what was deliberately deferred. |
| `backend/main.py` | Entry point. How routes are wired, how auth is applied, startup lifecycle. |
| `backend/database.py` | DatabaseManager class. How SQLite vs PostgreSQL is selected, schema DDL. |
| `backend/auth.py` | JWT token creation/verification, get_current_user dependency, AUTH_DISABLED flag. |
| `backend/routers/ingest.py` | Most complex router — ingest, batch ingest, Tenable webhook, demo endpoints, clear endpoint. |
| `backend/pipeline/` | pre_tier.py, tier_0.py, tier_1.py, tier_2.py — the 4-stage pipeline. tier_0 is deterministic, tier_1 is XGBoost, tier_2 is cloud LLM. |
| `backend/integrations/` | cmdb.py, nvd.py, tenable.py, demo_generator.py, exploitdb.py, metasploit.py, mitre_mapping.py, advisories.py |
| `frontend/js/api.js` | `_authFetch()` wrapper — all API calls go through here. Has Bearer token injection + 401 refresh logic. |
| `frontend/js/components/demoControls.js` | Demo mode UI — scenario picker, generate, clear. NOTE: does NOT use _authFetch(). |
| `.opencode/agents/` | 8 agent definition files. Read the ones you'll use before tasking them. |

---

## 8. Git Conventions

- Branch from `master` for each sprint: `git checkout -b sprint-7/master master`
- Optional: create per-track branches if items have file conflicts (`sprint-7/track-alembic`, etc.)
- Commit messages: concise, describe what and why
- Pre-commit hooks run `ruff check .` and `ruff format --check .` on all Python files (including untracked ones in the working tree — if ruff-format fails on an untracked file, fix it with `./backend/venv/bin/python -m ruff format <file>`)
- Do NOT commit: `.env` files, `triagemate.db`, `backend/data/lancedb/`
- After each item or wave: `pytest backend/tests/ -v` must pass

---

## 9. Verification Commands

```bash
# From project root:
cd backend && source venv/bin/activate

# Start server
uvicorn main:app --reload --host 0.0.0.0

# Health check
curl -s http://localhost:8000/api/health | python3 -m json.tool

# Queue (auth must be unset)
curl -s http://localhost:8000/api/queue | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d['rows']),'rows')"

# 7 demo row scores
curl -s http://localhost:8000/api/queue | python3 -c "
import sys,json
rows=json.load(sys.stdin)['rows'][:7]
expected=[94,87,71,55,63,41,22]
for r,e in zip(rows,expected):
    ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
    print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
"

# Full test suite
python -m pytest tests/ -v

# Swagger docs
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/docs
```

---

## 10. Quick Reference: What Each Sprint Added (for debugging)

If something breaks and you need to trace it back:

| If the problem is in... | It was probably introduced in... | Key files |
|---|---|---|
| Pipeline / scoring / ingest | Sprint 1, Course Correction | `pipeline/`, `scoring.py`, `ingest_helpers.py` |
| Tier 2 LLM calls / RAG context | Sprint 2 | `pipeline/tier_2.py`, `ml/vector_store.py` |
| XGBoost model / feature vectors | Sprint 3 | `ml/xgboost_predictor.py`, `ml/xgboost_model.pkl` |
| CMDB / NVD / MITRE / advisories | Course Correction | `integrations/cmdb.py`, `integrations/nvd.py`, `integrations/mitre_mapping.py` |
| Auth / Tenable webhook / Docker | Sprint 4 | `main.py` (old middleware, now removed), `integrations/tenable.py`, `docker-compose.yml` |
| Demo generator / mock CMDB / scenarios | Sprint 5 | `integrations/demo_generator.py`, `data/mock_cmdb.json`, `data/nvd_cache.json` |
| PostgreSQL / JWT auth / login | Sprint 6 | `database.py` (DatabaseManager), `auth.py`, `routers/auth.py`, `js/components/auth.js` |

---

## 11. One Thing to Be Careful About

The `database.py` file is now 819 lines. It contains the DatabaseManager class, both SQLite and PostgreSQL DDL, PostgreSQL connection wrapper classes, and module-level singleton logic. If you're adding Alembic (7.1), you'll need to extract the schema DDL into migration files and the DatabaseManager into a cleaner structure. **Do not let database.py grow beyond 1,000 lines.** The PostgreSQL wrappers (`_PGConnection`, `_PGCursor`, `_PGCompatRow`) could move to `integrations/pg_compat.py`. The schema DDL should become Alembic migration scripts.
