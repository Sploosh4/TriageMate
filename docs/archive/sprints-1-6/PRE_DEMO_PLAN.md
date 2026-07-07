# TriageMate — Pre-Demo Hardening Plan

> Created: 1 July 2026
> Prerequisite: COURSE_CORRECTION.md complete (11/11 items). All phases 1-4 done.
> See: ROADMAP.md for master status, AI_PROBLEMS.md for bugs
> Team instructions: TEAM_BRIEFING.md

---

## Why This Exists

The Course Correction plan hardened the pipeline from MVP to production-capable — CMDB adapter, NVD enrichment, MITRE mapping, summaries, advisories, bulk ingest, correct EPSS semantics, test isolation, and 3 fixable-now enrichments (ExploitDB, Metasploit, patch_available).

But before showing TriageMate to a WA government stakeholder, five critical gaps remain:

1. **No auth** — CORS wild-open on all endpoints. If exposed to hotel WiFi or a conference network, an attacker can inject findings or exfiltrate case data.
2. **No live-ingest credibility** — WASOC uses Tenable.io (confirmed). Without a webhook that accepts their export format, the first live CVE on their real host shows sparse results (Category 1 defaults, no CMDB context), undermining trust.
3. **Silent NVD degradation** — One NVD timeout silently zeroes 7+ features (CWE, reference count, age, sub-scores, patch_available, exploitdb, metasploit). No user-visible indicator.
4. **Training/production encoding drift** — `patch_available`, `exploitdb_has_poc`, `metasploit_has_payload` were hardcoded during training but are now inferred from NVD reference tags. The model may overweight these features relative to their training distributions.
5. **No demo logistics** — No walkthrough script, no Docker one-command deploy, no clean-machine test, no Windows instructions.

This document maps the pre-demo hardening items, ordered by dependency.

---

## Team Legend

| Tag | Team | When they act |
|---|---|---|
| `[STRIKE]` | Strike Team — builds, implements, writes code | Primary owner of every item |
| `[INTEL]` | Intel Team — validates domain decisions BEFORE code is written | Pre-build gate on items marked |
| `[AUDIT]` | Audit Team — verifies correctness AFTER code is written | Post-build gate on every item |

An item marked `[STRIKE][INTEL]` means: **Intel validates first, then Strike builds, then Audit verifies.**
An item marked `[STRIKE]` only means: **Strike builds, Audit verifies. Intel not needed (no domain ambiguity).**

---

## Phase 1 — Security & Credibility (the deal-breakers)

### 1.1 API Auth Middleware `[STRIKE]`

**Strike builds:**
**Files:** `backend/main.py`, `backend/.env.example`

**What:** Add `X-API-Key` header check to all `/api/*` routes via FastAPI middleware or `Depends()`. API key read from `TRIAGEMATE_API_KEY` env var. If env var unset → all requests pass (localhost-only safe default). If set → 401 on mismatch.

**Why:** CORS `allow_origins=["*"]` combined with binding to `0.0.0.0` and no auth means anyone on the same network can call `/api/ingest`, read `/api/queue`, or exfiltrate `/api/case/{id}`. A stakeholder asking "is this secure?" needs an answer better than "don't expose it to a network."

**Audit checks:**
- `TRIAGEMATE_API_KEY` unset → `/api/queue` returns 200 (backward compatible)
- `TRIAGEMATE_API_KEY=test-key` set → `/api/queue` returns 401 without header
- `TRIAGEMATE_API_KEY=test-key` set → `/api/queue` with `X-API-Key: test-key` returns 200
- `/docs` (Swagger) still accessible (auth only on `/api/*` routes)
- Frontend at `/` still loads (auth only on API routes)

**Effort:** ~1.5 hrs

### 1.2 Tenable.io Webhook `[STRIKE][INTEL]`

**Intel pre-build questions:**
- What is Tenable.io's export JSON format? Which fields map to `IngestRequest` fields?
- Does Tenable provide CVE ID, CVSS vector, hostname, OS, description, scanner output?
- Should this be a separate endpoint (`POST /api/ingest/tenable`) or a format-flag on the existing endpoint?
- Does Tenable export include EPSS scores? (Likely no — EPSS is a separate FIRST.org feed.)

**Strike builds:**
**Files:** New — `backend/integrations/tenable.py`, modify `backend/routers/ingest.py`

**What:** Accept Tenable.io export JSON, map fields to `IngestRequest`, auto-ingest. Design as a separate endpoint `POST /api/ingest/tenable` that accepts the raw Tenable export and returns `list[CaseResponse]`. Internally maps each finding to an `IngestRequest` and calls `ingest_vulnerability()`.

**Why:** WASOC uses Tenable.io (confirmed via wa.gov.au). Accepting their export format directly means the first live CVE on their real host produces a credible result — hostname populates, NVD enrichment fires, MITRE techniques resolve, summary is generated. No manual curl with hand-crafted JSON.

**Audit checks:**
- Post a sample Tenable export → all findings map to IngestRequest fields correctly
- CVSS vector parsed from Tenable format (it may differ from our `cvss_vector` format)
- `scanner_output_raw` populated from Tenable plugin output
- `weakness_template_raw` populated from Tenable plugin description
- Hostname extracted from Tenable export → CMDB adapter resolves correctly

**Effort:** ~2.5 hrs

---

## Phase 2 — Accuracy & Observability

### 2.1 Training/Production Encoding Audit `[STRIKE]`

**Strike builds:**
**Files:** Read `backend/ml/train_xgboost.py` (encoding logic for `patch_available`, `exploitdb_has_poc`, `metasploit_has_payload`), compare with `backend/integrations/nvd.py` / `backend/integrations/exploitdb.py` / `backend/integrations/metasploit.py`

**What:** Verify that the production encoding of three features matches the training encoding:
- `patch_available`: In training was hardcoded to `True` for all rows (AI_PROBLEMS #10). In production, it's inferred from NVD reference tags. If training saw 100% True and production sees ~30% True, the model may overweight patch_available.
- `exploitdb_has_poc`: In training was hardcoded to `False` for all rows. In production, it's inferred from NVD references. If training saw 0% True and production sees ~15% True, the model may overweight this.
- `metasploit_has_payload`: Same pattern — training 0% True, production may see non-zero.

If encoding mismatch is confirmed, either: (a) backfill training data with the production encoding and note the calibration shift, or (b) if the shift is minor (<5 percentage points), document it and accept.

**Why:** The ROC-AUC 0.9677 was measured against training encoding. If production encoding differs, the model may be miscalibrated — scores could drift in an unpredictable direction.

**Audit checks:**
- Training encoding values for `patch_available`, `exploitdb_has_poc`, `metasploit_has_payload` documented (what were they?)
- Production encoding values for same features measured on N=100 random CVEs (what are they now?)
- If delta >5%, either backfill training or document calibration shift
- If delta <5%, accept and note

**Effort:** ~1.5 hrs

### 2.2 NVD Degradation Visibility `[STRIKE]`

**Strike builds:**
**Files:** `backend/routers/queue.py` (health endpoint), `frontend/js/components/caseView.js`

**What:** Three additions:
1. Add `nvd_last_success` (ISO timestamp) and `nvd_status` ("ok" / "degraded" / "unreachable") to `GET /api/health`
2. Add a `nvd_freshness` field to `CaseViewData` (in `ingest.py` response builder) — seconds since NVD was last successfully queried for this CVE
3. Add a visual indicator in Case View Pane 4 (scoring/registry panel) — amber badge "Enrichment Stale" if NVD data is >24h old or was never fetched

**Why:** One NVD timeout silently zeroes 7+ features. The WARNING logs exist but nobody watches logs in a demo. A visible "Enrichment Stale" badge in the case view makes the degradation immediately obvious.

**Audit checks:**
- `GET /api/health` includes `nvd_last_success` and `nvd_status` fields
- Healthy state: `nvd_status: "ok"` on fresh NVD response
- Degraded state: `nvd_status: "degraded"` when NVD is unreachable for >60s
- Case View Pane 4 shows amber "Enrichment Stale" badge when NVD data is >24h old
- Badge is absent when enrichment is fresh

**Effort:** ~3 hrs

---

## Phase 3 — Demo Logistics

### 3.1 Demo Script `[STRIKE]`

**Strike builds:**
**File:** New — `DEMO_SCRIPT.md`

**What:** Written walkthrough script. Structure:
1. Launch (one command)
2. Show queue with 7 seed rows — explain the columns
3. Show case view for MOVEit row (panels 1-4, point out MITRE techniques, advisory, scoring gauge)
4. Live ingest via Tenable webhook — show it appear in queue
5. Show case view for new row — compare richness vs seed row
6. Show filter + metrics boxes
7. Close: "you can deploy this on your own infra with one docker-compose command"

**Why:** A live demo without a script risks the stakeholder asking "what am I looking at?" before we've shown the value. The script ensures the walkthrough hits every feature in a deliberate order.

**Audit checks:**
- Walk through the script step by step — does every command work?
- Does the live ingest produce a believable result?
- Is the total walkthrough under 5 minutes?

**Effort:** ~1 hr

### 3.2 Docker + docker-compose `[STRIKE]`

**Strike builds:**
**Files:** `Dockerfile` (exists, may need updates), `docker-compose.yml` (exists, may need updates)

**What:** Verify and harden the existing Docker setup:
- `docker-compose up` starts the app in one command
- `.env` passed through correctly (API keys, CMDB provider, auth key)
- SBERT model pre-cached in the Docker image (no HuggingFace calls on startup)
- `HF_HUB_OFFLINE=1` set in the container
- Volume mount for `backend/data/` (persistent LanceDB + SQLite)

**Why:** "Run this on your own infra" is a stronger close than "I can run it on my laptop." One-command deploy removes friction.

**Audit checks:**
- `docker-compose up` on a clean machine starts the app
- `GET /api/health` returns 200
- No HuggingFace HTTP calls in container logs (model pre-cached)
- `backend/data/` volume persists across container restarts
- 7 demo rows visible in queue

**Effort:** ~2 hrs

### 3.3 Pitch Deck / Screenshots `[STRIKE]`

**Strike builds:**
**Files:** New — `SCREENSHOTS/` directory (or embed in a presentation)

**What:** Capture:
1. Queue view with all 7 rows + filter dropdown open
2. Case view Pane 1 (narrative) for a row with MITRE techniques
3. Case view Pane 2 (accordions) with scanner output and advisory reference visible
4. Case view Pane 3 (notes + gauge)
5. Case view Pane 4 (scoring breakdown + asset registry)
6. Live-ingest result: queue with 8 rows, new row highlighted
7. Swagger `/docs` with all endpoints

**Why:** Screenshots in a pitch deck let the stakeholder see the product before committing to a live demo. If the live demo has technical issues, the screenshots are the fallback.

**Audit checks:**
- All 7 screenshots captured and saved
- Each shows a distinct feature (not 7 variations of the same view)
- Resolution sufficient for a projector (1920x1080 minimum)

**Effort:** ~1 hr

### 3.4 Clean Machine Test `[AUDIT]`

**Audit verifies:**
**What:** Clone the repo on a machine that has never run TriageMate:
1. `git clone` → `pip install -r requirements.txt` → `python seed_data.py` → `uvicorn main:app`
2. Verify: queue loads, all 7 scores within ±3, metrics return (2, 4, 2, 3), `/api/ingest` works
3. Run `pytest backend/tests/ -v` → all 20 pass
4. Verify `HF_HUB_OFFLINE=1` works after first download

**Why:** Assumptions about installed dependencies, Python version, and OS-specific quirks only surface on a fresh machine.

**Effort:** ~1 hr

### 3.5 Windows Setup Instructions `[STRIKE]`

**Strike builds:**
**File:** New — `WINDOWS_SETUP.md`

**What:** Step-by-step Windows setup:
- Install Python 3.10+ from python.org
- Create venv, activate (Windows syntax: `venv\Scripts\activate`)
- Install dependencies (note: `torch` CPU-only for Windows)
- Run seed data, start uvicorn
- Access `http://localhost:8000`

**Why:** WA government staff predominantly use Windows laptops. The current README has Linux-oriented commands.

**Effort:** ~30 min

---

## Dependency Graph

```
Phase 1 (Security & Credibility)
├── 1.1 Auth middleware [STRIKE]          No dependencies
└── 1.2 Tenable webhook [STRIKE][INTEL]   Intel first, then Strike

Phase 2 (Accuracy & Observability)
├── 2.1 Encoding audit [STRIKE]           No dependencies
└── 2.2 NVD degradation [STRIKE]          No dependencies

Phase 3 (Demo Logistics)
├── 3.1 Demo script [STRIKE]              Depends on 1.2 (needs Tenable webhook for live ingest demo)
├── 3.2 Docker [STRIKE]                   No dependencies
├── 3.3 Pitch deck [STRIKE]               No dependencies
├── 3.4 Clean machine test [AUDIT]        Depends on 1.1, 1.2, 2.1, 2.2, 3.2 (needs finished code)
└── 3.5 Windows instructions [STRIKE]      No dependencies
```

**Recommended execution order:**
1. Intel briefs 1.2 (Tenable format validation)
2. While Intel works, Strike starts 1.1 (auth) + 2.1 (encoding audit) + 2.2 (NVD degradation) — all parallel, all [STRIKE] only
3. Intel returns → Strike builds 1.2 (Tenable webhook)
4. Strike builds 3.1, 3.2, 3.3, 3.5 in parallel (all independent)
5. Audit verifies everything, including 3.4 (clean machine test)

---

## Total Estimated Effort

| Phase | Hours |
|---|---|
| Phase 1 (Security & Credibility) | 4 |
| Phase 2 (Accuracy & Observability) | 4.5 |
| Phase 3 (Demo Logistics) | 5.5 |
| **Total** | **14 hrs** |

---

## Team Workload Summary

| Team | Items owned | Pre-build gates | Post-build gates |
|---|---|---|---|
| **Intel** | 1 item (1.2) | 1.2 | — |
| **Strike** | 8 items (1.1, 1.2, 2.1, 2.2, 3.1, 3.2, 3.3, 3.5) | — | — |
| **Audit** | 7 items (1.1, 1.2, 2.1, 2.2, 3.2, 3.4) + all default checks | — | Every item has specific audit checks |

---

## What Can Be Deferred

| Item | Reason |
|---|---|
| Post-MVP ML models (Pre-Tier, EPSS, CWE encoder, WA-specific tuning) | Requires 200-500 labeled WA assets. No dataset exists. |
| Production hardening (PostgreSQL, HTTPS, CI/CD, rate limiting) | Demo is single-user, localhost or Docker. None of these affect the demo experience. |
| Real scanner integration beyond Tenable (Nessus, Qualys) | Tenable is the confirmed WASOC scanner. Others can follow the same pattern post-demo. |
| Dashboard / notifications / T3 review queue | Feature work. Not needed for first stakeholder impression. |
