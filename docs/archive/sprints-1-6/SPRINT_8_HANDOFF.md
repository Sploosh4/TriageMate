# Sprint 8 Handoff — Commander Briefing

> **Date:** 2 July 2026
> **From:** Commander (Sprints 7-8)
> **To:** Incoming Commander
> **Repo state:** `master @ 61ea545` — clean working tree, 37/37 tests pass

---

## 1. What We Did (Sprints 7-8)

| Sprint | Commit | What |
|--------|--------|------|
| **Sprint 7** | `faf0785` | Operations Foundation: Alembic migrations (3 revisions), rate limiting (ingest 30/min, demo 10/min, clear 2/min), structured JSON logging, FastAPI lifespan context manager, LanceDB API fix, bcrypt auth fix, GitHub Actions CI |
| **Sprint 8 W1** | `24e5798` | WAICP classification labels (Category → OFFICIAL/OFFICIAL Sensitive), `per-` location prefix on all mock hostnames, FICTITIOUS DATA watermark on frontend |
| **Sprint 8 W2** | `8e69308` | OTX integration (`threat_intel_pulses`), synthetic network fields (`patch_applied`, `lateral_reachability`, `boundary_reachability`, `downstream_assets`) |
| **Sprint 8 Fix** | `61ea545` | Replaced GreyNoise API with synthetic scan detection (free tier too restrictive) |

---

## 2. The 37-Feature Field Status

This is the core metric. The goal is to fill all 37 features with real or synthetic data.

### FIELDS WITH REAL DATA (20)

| # | Field | Source |
|---|-------|--------|
| 1-8 | `cvss_av/ac/pr/ui/s/c/i/a` | Parsed from CVSS vector in payload |
| 9 | `cvss_score` | From payload |
| 10 | `epss_score` | EPSS cache + substitution engine |
| 11 | `internet_facing` | CMDB lookup per host |
| 12 | `domain_joined` | Derived from hostname pattern |
| 13 | `data_classification` | CMDB → WAICP labels (OFFICIAL / OFFICIAL Sensitive) |
| 14 | `mission_prevalence` | Pre-tier tags (KNOWN_TAGS dict / model) |
| 15 | `public_wellbeing_impact` | Pre-tier tags |
| 16 | `cve_desc_tokens` | Computed from description length |
| 17 | `vulnerability_age_days` | NVD API → published date diff |
| 18 | `nvd_reference_count` | NVD API |
| 19 | `cvss_exploitability_sub` | NVD API |
| 20 | `cvss_impact_sub` | NVD API |

### FIELDS WITH REAL DATA FROM NVD (4)

| # | Field | Source |
|---|-------|--------|
| 21 | `is_top_25_cwe` | NVD CWE class → MITRE Top 25 check |
| 22-26 | `is_rce/privesc/bypass/dos/traversal_signature` | Regex pattern matching on CVE description |

### FIELDS WITH SYNTHETIC DATA FROM CMDB (4)

| # | Field | Source |
|---|-------|--------|
| 27 | `patch_applied` | Derived from CMDB `last_patch_date` + CVSS severity + patch availability |
| 28 | `lateral_reachability` | Derived from CMDB `network_zone` + `role` |
| 29 | `boundary_reachability` | Derived from CMDB `internet_facing` + `network_zone` |
| 30 | `downstream_assets` | CMDB `dependent_assets` count, falls back to role estimation |

### FIELDS WITH API-BACKED DATA (2)

| # | Field | Source | API Key Needed |
|---|-------|--------|----------------|
| 31 | `threat_intel_pulses` | AlienVault OTX API | `TRIAGEMATE_OTX_API_KEY` in `backend/.env` |
| 32 | `internet_scan_detected` | Synthetic from KEV + EPSS + exploit data | None |

### FIELDS WITH NVD-DERIVED DATA (4 — Adequate but improvable)

| # | Field | Current Source | Could Improve With |
|---|-------|---------------|-------------------|
| 33 | `patch_available` | NVD API | OSV.dev (precise fixed-in-version ranges for open-source) |
| 34 | `exploitdb_has_poc` | NVD reference tags (binary check) | Full ExploitDB codebase (~50k exploits, richer metadata) |
| 35 | `metasploit_has_payload` | NVD reference tags | Full ExploitDB via SearchSploit |
| 36 | `vendor_popularity_index` | Static lookup table (top 10 vendors) | Expand lookup, or derive from CMDB registered_applications |
| 37 | `description` | CVE description (for SBERT/PCA) | Always available |

### FIELDS NOT YET FILLABLE (5)

| # | Field | Currently | What It Would Take |
|---|-------|-----------|-------------------|
| — | `patch_lag_days` | Already computed from CMDB + NVD | Works, no action needed |
| — | These 4 are now synthetically filled in Sprint 8 W2: `patch_applied`, `lateral_reachability`, `boundary_reachability`, `downstream_assets` | Synthetic | See above — already done |

**Net: 36/37 fields produce real or synthetic data. The last improvable ones (4) are functional but could be improved with richer data sources.**

---

## 3. Remaining Gaps

### Gap 1: Enrich `patch_available` with OSV.dev

OSV.dev (https://osv.dev) provides precise "fixed in version X" data for open-source packages. Free, no API key. Would replace the vague NVD `patch_available` field with actual version-specific fix information.

- **Effort:** 1-2 days
- **Files to touch:** New `backend/integrations/osv.py`, modify `backend/ingest_helpers.py`
- **Pattern to follow:** Copy `backend/integrations/otx.py` (cached API client)
- **API:** `POST https://api.osv.dev/v1/query` with package name + version

### Gap 2: Full ExploitDB Integration

Currently `exploitdb_has_poc` and `metasploit_has_payload` are derived from NVD reference tags (parsing URLs for keywords). A full ExploitDB clone gives:
- Direct CVE-to-exploit mapping (via `files_exploits.csv`)
- Exploit type (remote, local, web app, DoS)
- Exploit reliability/verified status
- ~50k exploits dating back to 1999

- **Effort:** 2-3 days
- **Files to touch:** Modify `backend/integrations/exploitdb.py`, add EDB CSV parsing
- **Note:** ExploitDB repo is ~5GB. The CSV metadata file is much smaller and sufficient for feature enrichment.

### Gap 3: Comprehensive Vulnerability Database

The Commander's original vision: a dataset covering vulnerabilities beyond KEV (99%+ of all CVEs have no exploitation label) and beyond EPSS (many CVEs lack EPSS scores). This is the next commander's primary focus per the outgoing Commander's directive.

**Key sources already identified (see `TEAM_BRIEFING.md` Intel patterns):**
- OSV.dev — non-CVE open-source vulnerabilities
- GitHub Security Advisories (GHSA) — ~345k advisories, many pre-CVE
- MITRE ATT&CK — CVE-to-technique mappings
- CWE Database — full weakness hierarchy (944 types)
- CISA Advisories — campaign context and detection rules
- CAPEC — 559 attack patterns bridging CWE to real-world attacks

---

## 4. How to Add a New Data Source

Every data integration follows the same pattern. Use `backend/integrations/nvd.py` or `backend/integrations/otx.py` as your template:

1. **Create** `backend/integrations/your_source.py`
   - Module-level in-memory `_CACHE` dict with TTL (3600s = 1hr)
   - API key via `os.getenv("TRIAGEMATE_YOUR_KEY", "").strip()`
   - `if not API_KEY:` → return safe defaults immediately (no crash)
   - `try/except` wrapping all API calls → log warning, return safe defaults
   - Structured logging: `logger.info(msg, extra={"event": "your_event", "cve_id": cve_id})`
   - `requests.get()` with `timeout=10` (requests is already in requirements.txt)

2. **Modify** `backend/ingest_helpers.py`
   - Import your function
   - Call it in `build_feature_vector()` to fill the appropriate field
   - Add a synthetic fallback for when no API key is configured

3. **Add** env var to `backend/.env`
   - `TRIAGEMATE_YOUR_KEY=your-key-here`

4. **Verify**
   - `uvicorn main:app` starts from `backend/` — no import errors
   - `pytest backend/tests/ -v` — all 37 pass
   - `curl http://localhost:8000/api/queue` — 7 demo row scores within ±3 of expected (94, 87, 71, 63, 55, 41, 22)
   - Test with key absent: returns safe defaults, doesn't crash
   - Test with key present: returns real data

---

## 5. OTX Quick Setup

Add this line to `backend/.env`:

```
TRIAGEMATE_OTX_API_KEY=your-otx-key-here
```

Get a key at: https://otx.alienvault.com/ → Sign Up → API page

---

## 6. Commander Workflow (The Team System)

Three teams. Launch in this order:

| Phase | Team | When | Role |
|-------|------|------|------|
| 1 | **Intel** | Before code | Validates domain decisions. Read-only. Delegate WA-gov questions to `wa-gov-consultant`, legal to `privacy-legal-advisor`. |
| 2 | **Strike** | After Intel sign-off | Builds and implements. Writes all code. |
| 3 | **Audit** | After Strike | Verifies correctness. Runs tests, checks scores, finds regressions. |

**Typical prompt format for a team:**
```
You are [Team] on TriageMate. Your role: [one sentence].
Read [files] before starting.
[Itemized tasks with exact file paths]
[Verification criteria]
```

---

## 7. Verification Commands

```bash
# From project root
cd backend && source venv/bin/activate

# Start server
uvicorn main:app --reload

# Tests (must all pass)
python -m pytest tests/ -v

# 7 demo row scores (must be within ±3 of expected)
curl -s http://localhost:8000/api/queue | python3 -c "
import sys,json
rows=json.load(sys.stdin)['rows'][:7]
expected=[94,87,71,63,55,41,22]
for r,e in zip(rows,expected):
    ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
    print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
"

# Feature vector check (how many fields are LIVE vs DEAD)
python3 -c "
import sys; sys.path.insert(0,'.')
from ingest_helpers import build_feature_vector
from models import IngestRequest
from pipeline.pre_tier import predict_mission_tags
from pipeline.tier_0 import evaluate_tier_0
p=IngestRequest(vulnerability_id='CVE-2023-34362',hostname='per-PRD-MOVEIT-WEB01.health.wa.gov.au',cvss_score=9.8,description='MOVEit Transfer SQL Injection',raw_epss=0.97,cisa_kev=True,cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
tags=predict_mission_tags(p.hostname)
t0=evaluate_tier_0(p.cvss_score,p.cisa_kev,p.raw_epss or 0,'OFFICIAL Sensitive',True)
fv=build_feature_vector(p,tags,t0)
dead=[k for k,v in fv.items() if k!='description' and v in (0,0.0,False,'')]
print(f'LIVE: {37-len(dead)}, DEAD: {len(dead)}')
if dead: print('Dead fields:', dead)
"
```

---

## 8. Key Files

| File | Purpose |
|------|---------|
| `backend/ingest_helpers.py` | All 37 features live here in `build_feature_vector()`. The synthetic helpers are above it. |
| `backend/ml/xgboost_predictor.py` | Consumes the 37 features. `predict()` at line 33. |
| `backend/integrations/*.py` | API clients: nvd.py, otx.py, cmdb.py, exploitdb.py, metasploit.py, greynoise.py (deprecated) |
| `backend/data/mock_cmdb.json` | 31 fictional WA government hosts with CMDB context |
| `backend/pipeline/tier_0.py` | Deterministic rules using cisa_kev, cvss, epss, classification, internet_facing |
| `ROADMAP.md` | Master status. Update after each sprint. |
| `TEAM_BRIEFING.md` | How to write team prompts. |
| `backend/.env` | Env vars. Add API keys here with TRIAGEMATE_ prefix. |

---

## 9. Recommended Next Sprint

**Focus: Fill the remaining improvable fields and start the comprehensive vulnerability database.**

| # | Item | Effort |
|---|------|--------|
| 9.1 | **OSV.dev integration** — precise patch data for open-source CVEs. Fills `patch_available` better. | 1-2 days |
| 9.2 | **Full ExploitDB integration** — direct CVE-to-exploit mapping. Fills `exploitdb_has_poc` and `metasploit_has_payload` better. | 2-3 days |
| 9.3 | **CWE Database enrichment** — full weakness hierarchy, not just single CWE label. Improves `is_top_25_cwe` and case view. | 1-2 days |
| 9.4 | **Comprehensive vulnerability database design** — survey GHSA, OSV, MITRE ATT&CK, CISA Advisories, CAPEC for what data each provides and how they'd feed the pipeline. Start with the Intel Team. | 2-3 days |

---

## 10. Git

- Branch from `master` for new work
- Pre-commit hooks run `ruff check` + `ruff format` on all Python files
- If ruff format fails: `cd backend && source venv/bin/activate && ruff format ../backend/<file.py>`
- NEVER commit `backend/.env` (contains API keys — it's in `.gitignore`)
- After each wave: `pytest backend/tests/ -v` must pass
