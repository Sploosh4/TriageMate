# Demo Data Generator — Scope Document

> **Status: ARCHIVED** — Sprint 5 historical record

> **Author:** Intel Team  
> **Status:** Draft for Commander review  
> **Prerequisite reading:** `PRE_DEMO_PLAN.md`, `ROADMAP.md`, `MVP_SCOPE.md`  
> **Discover completed:** 1 July 2026 (13 questions, Commander interviewed)

---

## 1. Executive Summary

TriageMate currently runs on 7 hand-crafted demo rows. To demonstrate credible live-ingest to a WA government stakeholder, we need a **built-in Demo Data Generator** that produces realistic Tenable-format findings from public CVE data sources and feeds them through the full pipeline.

The generator is activated via a **UI toggle** ("Enter Demo Mode"). It produces findings in **Tenable.io export JSON format** so it exercises `POST /api/ingest/tenable` — the same endpoint a real Tenable scanner would hit. This means the pipeline, enrichment, scoring, MITRE mapping, summary generation, and Tier 2 analysis are all stress-tested with realistic data.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    TriageMate (FastAPI)                      │
│                                                              │
│  ┌────────────┐   ┌──────────────────┐   ┌───────────────┐  │
│  │ Frontend   │   │ Router Layer     │   │ Pipeline      │  │
│  │ (HTML/JS)  │──▶│ /api/ingest      │──▶│ Pre-Tier      │  │
│  │            │   │ /api/ingest/     │   │ Tier 0        │  │
│  │ Demo toggle│   │   tenable        │   │ Tier 1 (XGB)  │  │
│  │ Wave btn   │   │ /api/ingest/     │   │ Tier 2 (LLM)  │  │
│  │ Clear btn  │   │   clear          │   │               │  │
│  └────────────┘   └───────┬──────────┘   └───────────────┘  │
│                           │                                  │
│                    ┌──────▼──────────┐                       │
│                    │ Demo Generator  │                       │
│                    │ (integrations/  │                       │
│                    │  demo_generator │                       │
│                    │  .py)           │                       │
│                    │                  │                       │
│                    │  Reads from:    │                       │
│                    │  ├─ nvd_cache   │                       │
│                    │  ├─ epss_cache  │                       │
│                    │  ├─ kev_cache   │                       │
│                    │  └─ mock_cmdb   │                       │
│                    └─────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

Key design decision: the generator produces **Tenable-format JSON** and submits it to `POST /api/ingest/tenable` internally. This tests the Tenable mapping layer, not just the ingest endpoint.

---

## 3. Data Source Caches

Three flat JSON files, pre-bundled in the repo at `backend/data/`. Ship with ~500–1000 curated CVEs covering the target OS/app mix. Refreshable via CLI.

### 3.1 `backend/data/nvd_cache.json`

```json
{
  "CVE-2024-3094": {
    "cvss_v3_score": 9.1,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe_class": "CWE-787",
    "description": "A critical out-of-bounds write vulnerability in XZ Utils...",
    "vulnerability_age_days": 94,
    "patch_available": true,
    "exploitdb_has_poc": true,
    "metasploit_has_payload": false,
    "nvd_reference_count": 15,
    "cvss_exploitability_sub": 3.9,
    "cvss_impact_sub": 5.2,
    "vendor": "tukaani",
    "product": "xz utils"
  }
}
```

**Source:** NVD API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`)  
**Key needed:** `NVD_API_KEY` (free from [NVD](https://nvd.nist.gov/developers/request-an-api-key))  
**Refresh:** `python -m scripts.refresh_caches --source nvd`

### 3.2 `backend/data/epss_cache.json`

Existing format, already shipped with the repo. Contains ~250K CVE records with EPSS score + percentile.

```json
{"CVE-2024-3094": {"epss": 0.95667, "percentile": 0.99862, "date": "2026-06-30"}}
```

**Source:** FIRST.org EPSS CSV (`https://epss.cyentia.com/epss_scores-current.csv.gz`)  
**Key needed:** None (free, rate-limited)  
**Refresh:** `python -m ml.fetch_epss_data` (already exists)

### 3.3 `backend/data/kev_cache.json`

```json
{
  "CVE-2024-3094": {
    "known_exploited": true,
    "date_added": "2024-04-17",
    "due_date": "2024-05-08",
    "action": "Apply per-station mitigations or vendor instructions...",
    "note": "Exploitation detected by CISA in XZ Utils backdoor incident"
  }
}
```

**Source:** CISA KEV catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)  
**Key needed:** None (public feed)  
**Refresh:** `python -m scripts.refresh_caches --source kev`

### 3.4 Refresh CLI

Unified command: `python -m scripts.refresh_caches` refreshes all three caches. Flags for individual sources (`--source nvd`, `--source epss`, `--source kev`). The NVD source reads a list of CVE IDs from the mock CMDB's `registered_applications` + OS mappings to know which CVEs to fetch.

---

## 4. Mock CMDB

### 4.1 Size and Scope

Expanded from 7 to **~25–30 fictional WA government hosts** across departments:

| Department | Hosts | Example hostnames |
|---|---|---|
| Health | 4–5 | `PRD-MOVEIT-WEB01.health.wa.gov.au`, `PRD-EHR-APP01.health.wa.gov.au` |
| Transport | 3–4 | `PRD-CITRIX-ADC01.transport.wa.gov.au`, `PRD-MARINE-DOC01.transport.wa.gov.au` |
| Education | 3–4 | `PRD-PRINT-SVR05.education.wa.edu.au`, `PRD-STUDENT-DB01.education.wa.edu.au` |
| Communities | 3–4 | `PRD-FILE-STORE02.communities.wa.gov.au`, `PRD-CASEMGT-APP01.communities.wa.gov.au` |
| WA Police | 3–4 | `PRD-WIKI-CORE01.wapol.internal.wa.gov.au`, `PRD-CAD-DISPATCH01.wapol.wa.gov.au` |
| Finance | 3 | `PRD-ITSM-TOOL01.finance.wa.gov.au`, `PRD-BUDGET-DB01.finance.wa.gov.au` |
| Justice | 3 | `PRD-COURT-FILE01.justice.wa.gov.au` |
| Water/Environment | 2 | `PRD-WATER-SCADA01.water.wa.gov.au` |

### 4.2 Fields Per Host (unchanged from current schema)

```
hostname, data_classification, internet_facing, network_zone,
operating_system, role, business_owner, technical_owner,
interface_type, patch_cycle, last_patch_date, last_scan_date,
registered_applications, dependent_assets, service_account
```

### 4.3 Storage

Stored as `backend/data/mock_cmdb.json` (array of JSON objects) rather than hardcoded in Python. The CMDB adapter (`backend/integrations/cmdb.py`) reads from this file when `DEMO_MODE=true`.

---

## 5. Demo Generator Engine

**File:** `backend/integrations/demo_generator.py`

### 5.1 Generation Modes

#### Mode A: Curated Scenarios (Stories)

Pre-written scenario sets defined in `backend/data/demo_scenarios.json`. Each scenario defines:

```json
{
  "id": "ransomware-incident",
  "name": "Ransomware Incident — Health Sector",
  "description": "Simulates a ransomware precursor: 3 critical CVEs on MOVEit, 2 on file server",
  "findings": [
    {"hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au", "cve_id": "CVE-2024-3094"},
    {"hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au", "cve_id": "CVE-2023-34362"},
    {"hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au", "cve_id": "CVE-2024-5806"},
    {"hostname": "PRD-FILE-STORE02.communities.wa.gov.au", "cve_id": "CVE-2024-38077"}
  ]
}
```

When a scenario is selected, the generator looks up each CVE in the caches, constructs a complete Tenable-format JSON payload, and submits it via `/api/ingest/tenable`.

Scenarios included:
- **Ransomware Incident** — Health sector, 5 critical findings on MOVEit + file server
- **Perimeter Breach** — Transport, Citrix ADC + marine system CVEs
- **Insider Data Exfiltration** — Communities, file server + casemgt app
- **Supply Chain Attack** — Finance, ITSM tool + budget system
- **Low-Severity Hygiene** — Education, print server + student DB (demonstrates auto-resolve)
- **Mixed Tier Demo** — Mix of all tiers (incorporates the original 7 seed rows as a scenario)

#### Mode B: Host-Appropriate Random

Generator selects CVEs from the cache that match each host's operating system and registered applications. Algorithm:

1. For each host in the mock CMDB, extract OS keyword (e.g., "Windows Server 2019") and app names (e.g., "IIS", "Apache", "Confluence")
2. Look up NVD cache entries whose `vendor`/`product` fields match the host's software
3. Filter to a realistic severity distribution (e.g., 20% Critical, 30% High, 30% Medium, 20% Low)
4. Sampling strategies: "small wave" = 5–10 findings, "medium wave" = 15–30, "large wave" = 40–60

### 5.3 Tenable Payload Construction

Each generated finding is wrapped in a Tenable v2 export record:

```json
{
  "asset": {
    "hostname": "PRD-MOVEIT-WEB01",
    "fqdn": "PRD-MOVEIT-WEB01.health.wa.gov.au",
    "ipv4": "10.0.1.50",
    "operating_system": ["Windows Server 2019 Standard"],
    "uuid": "mock-uuid-0001",
    "tracked": true
  },
  "plugin": {
    "id": 19506,
    "name": "CVE-2024-3094 — XZ Utils Backdoor (Critical)",
    "family": "Misc.",
    "description": "<description from nvd_cache>",
    "synopsis": "<short summary>",
    "cve": ["CVE-2024-3094"],
    "cvss3_base_score": 9.1,
    "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_base_score": 7.5,
    "cvss_vector": "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "risk_factor": "CRITICAL",
    "exploit_available": true,
    "exploit_framework_metasploit": false,
    "has_patch": true
  },
  "port": {
    "port": 443,
    "protocol": "TCP",
    "service": "HTTPS"
  },
  "severity": "CRITICAL",
  "severity_id": 4,
  "state": "OPEN",
  "first_found": "2026-06-15T00:00:00Z",
  "last_found": "2026-07-01T00:00:00Z",
  "output": "<realistic scanner output simulating Nessus plugin output>"
}
```

The payload is posted to the internal `POST /api/ingest/tenable` route, exercising the full Tenable→IngestRequest mapping layer.

---

## 6. Demo Mode UI

### 6.1 Activation

A **"Demo Mode" toggle** in the frontend header bar. When clicked:
- Queue displays "DEMO MODE" badge in the header
- Controls panel appears with: "Generate Wave" dropdown, "Clear All" button, scenario picker
- The 7 original demo seed rows remain visible — they're one option in the scenario picker

### 6.2 Controls

| Control | Behaviour |
|---|---|
| **Scenario picker** | Dropdown listing curated stories. Selecting one generates all findings for that story and adds them to the queue in real-time. |
| **Generate Random Wave** | Slider/dropdown for wave size (Small/Medium/Large). Picks host-appropriate CVEs and generates them. |
| **Clear All** | Moves all findings from `vulnerabilities` to `resolved_vulnerabilities` archive table. Queue empties. Countdown notification: "15 findings archived." |
| **Exit Demo Mode** | Disables controls, hides the panel. Findings remain in queue (they're real pipeline results, just generated by demo). |

### 6.3 Frontend Files

New component: `frontend/js/components/demoControls.js`  
Toggle + panel added to `frontend/index.html`

---

## 7. Archive / Clear Endpoint

### 7.1 New Endpoint

`POST /api/ingest/clear` — moves all rows from `vulnerabilities` to `resolved_vulnerabilities` and returns the count of archived records.

### 7.2 Archive Table Schema

```sql
CREATE TABLE IF NOT EXISTS resolved_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    vulnerability_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    -- All same columns as vulnerabilities table...
    resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolution_reason TEXT DEFAULT 'demo_clear'
);
```

Mirrors the `vulnerabilities` table exactly, with two additional columns: `resolved_at` and `resolution_reason`.

---

## 8. Pre-Tier ML Model Update

The existing `pre_tier_model.pkl` was trained on the 7 original hosts. With 25–30 hosts in the expanded mock CMDB:

1. Extend `backend/data/pretier_training_data.json` with training examples for all new hosts — each hostname tagged with (mission_prevalence, public_wellbeing_impact) based on its role and department
2. Retrain `python -m ml.train_pre_tier` to produce an updated `pre_tier_model.pkl`

This means `predict_mission_tags()` will return plausible tags for all new hosts via the **ML model path** (not the hardcoded dict or default fallback). The 7 original hosts remain in `KNOWN_TAGS` for backward compatibility.

---

## 9. Deliberately Out of Scope (MVP)

| Item | Reason |
|---|---|
| **Continuous / firehose stress test** | Deferred at Commander's request. Wave generation covers the need. |
| **Non-Tenable scanner formats** | Qualys, Nessus, OpenVAS — follow same pattern post-demo |
| **Individual finding resolution** | Commander chose clear-all with archive. Individual resolve adds complexity without MVP value. |
| **Persistent demo data across restarts** | Clear-all + regenerate is sufficient. Archived data survives in `resolved_vulnerabilities`. |
| **Real Tenable webhook listener** | The demo generator exercises the same endpoint. Adding a real listener is a configuration change in Tenable.io UI, not code. |
| **Authentication for demo endpoints** | Demo mode runs behind the existing `X-API-Key` auth middleware (Item 1.1). No separate auth needed. |

---

## 10. Dependency Graph

```
Phase 1: Foundation
└── 1.1 Mock CMDB expansion (backend/data/mock_cmdb.json)
    └── 1.2 Pre-tier model retrain (backend/ml/train_pre_tier.py)

Phase 2: Data Caches
├── 2.1 NVD cache builder + data (backend/data/nvd_cache.json)
├── 2.2 EPSS cache (existing — backend/data/epss_cache.json)
├── 2.3 KEV cache builder + data (backend/data/kev_cache.json)
└── 2.4 Unified refresh script (backend/scripts/refresh_caches.py)

Phase 3: Generator Engine
├── 3.1 Curated scenarios JSON (backend/data/demo_scenarios.json)
└── 3.2 Generator logic (backend/integrations/demo_generator.py)

Phase 4: API + UI
├── 4.1 Clear endpoint (backend/routers/ingest.py)
├── 4.2 Archive table migration (backend/database.py)
├── 4.3 Demo mode UI (frontend/js/components/demoControls.js)
└── 4.4 Integrate toggle + controls into frontend

Phase 5: Test + Verify (Audit)
└── 5.1 Pytest for generator, endpoint, and full pipeline
```

---

## 11. Effort Estimates (Rough)

| Item | Effort | Dependencies |
|---|---|---|
| Mock CMDB expansion | 1 hr | None |
| Pre-tier model retrain | 1 hr | 1.1 |
| NVD cache builder + data | 2 hrs | 1.1 (knows which CVEs) |
| KEV cache builder + data | 0.5 hr | None |
| Unified refresh script | 0.5 hr | 2.1, 2.2, 2.3 |
| Curated scenarios JSON | 1 hr | 1.1, 2.1, 2.2, 2.3 |
| Generator logic | 3 hrs | 3.1, 2.1, 2.2, 2.3 |
| Clear endpoint | 0.5 hr | None |
| Archive table migration | 0.5 hr | None |
| Demo mode UI (controls) | 1.5 hrs | 4.1 |
| Frontend toggle integration | 0.5 hr | 4.3 |
| Testing | 1.5 hrs | All above |
| **Total** | **~13 hrs** | |

---

## 12. What Commander Needs to Provide

| Item | Where to put it | How to get it |
|---|---|---|
| **NVD API key** | `NVD_API_KEY=...` in `backend/.env` | Free signup at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |
| **Review mock hostnames** | Approve/amend the list in Section 4.1 before implementation | Read and reply |
| **LLM API key (already in .env)** | `TRIAGEMATE_LLM_API_KEY=...` in `backend/.env` | Already configured per ROADMAP.md |

---

## 13. Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Cache data goes stale (CVEs published after cache snapshot) | Medium | Refresh script; daily update cron available. Generator only needs plausible CVEs, not every CVE. |
| Mock CMDB hostnames don't feel realistic to WA government stakeholders | Medium | Commander reviews hostnames before implementation. Pattern follows existing 7 hosts. |
| Generated Tenable payloads don't match real Tenable format exactly | Low | Payload structure sourced from Tenable's v2 export documentation (validated in Intel Item 1.2). |
| Demo mode UI obscures real app functionality | Low | Demo controls are visually distinct (badge/banner), toggle in/out. Queue remains functional either way. |
| Archive table fills disk with repeated clear-all cycles | Low | Each clear is N rows. At 7–150 rows per cycle, disk is not a concern. Manual cleanup: `DELETE FROM resolved_vulnerabilities`. |
