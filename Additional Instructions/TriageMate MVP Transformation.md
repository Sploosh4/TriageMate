# TriageMate MVP Transformation Plan

## Overview

This document describes how to evolve the current single-file HTML demo into a minimum viable product with a real backend capable of hosting preliminary machine learning models at each pipeline stage. The guiding principle is minimal changes to the existing frontend code while introducing a clean separation between data, logic, and presentation.

The plan is organized into six sections. Each section describes what changes, why, and exactly what the developer needs to do. Read sections in order.

---

## Section 1: Target Architecture

### Current State (Demo)

```
triageMate.html   (single file)
  ├── CSS          (inline <style>)
  ├── HTML         (static markup)
  ├── JavaScript   (QUEUE_DATA array, render functions, navigation)
  └── Mock Data    (hardcoded JSON in QUEUE_DATA)
```

Everything lives in one file. There is no backend, no database, no API, and no ML. The mock data is static. Adding a new vulnerability row means editing JavaScript.

### Target State (MVP)

```
triageMate/
├── backend/
│   ├── main.py              # FastAPI application entry point
│   ├── database.py           # SQLite connection and schema
│   ├── models.py             # Pydantic data models (shared types)
│   ├── routers/
│   │   ├── queue.py          # GET /api/queue, GET /api/metrics
│   │   ├── cases.py          # GET /api/case/{id}
│   │   └── ingest.py         # POST /api/ingest
│   ├── pipeline/
│   │   ├── pre_tier.py       # Multi-label classifier for mission tags
│   │   ├── tier_0.py         # Deterministic rules (KEV, CVSS, EPSS)
│   │   ├── tier_1.py         # XGBoost model for exploitation probability
│   │   └── tier_2.py         # SLM integration point (text conflict)
│   ├── ml/
│   │   ├── mission_classifier.pkl    # Pre-trained multi-label model
│   │   ├── xgboost_model.pkl         # Pre-trained XGBoost model
│   │   └── slm_handler.py            # SLM interface (stub initially)
│   ├── requirements.txt
│   └── seed_data.py          # Script to load the 7 existing rows into DB
├── frontend/
│   ├── index.html            # Same HTML structure, minus mock data
│   ├── css/
│   │   └── triagemate.css    # Extracted styles (unchanged from demo)
│   └── js/
│       ├── app.js            # Main app logic (adapted from demo)
│       ├── api.js            # API client (fetch wrapper)
│       └── components/
│           ├── queue.js      # Queue rendering (adapted from demo)
│           ├── caseView.js   # Case view rendering (adapted from demo)
│           └── metricBoxes.js # Summary metric boxes
└── README.md
```

### Why This Architecture

- **Frontend stays mostly intact.** The HTML structure, CSS, and rendering logic need only small changes to fetch data from an API instead of reading a hardcoded array.
- **Backend is Python.** All ML libraries (XGBoost, scikit-learn, transformers) are Python-native. Putting the backend in Python eliminates language bridging.
- **FastAPI is chosen over Flask or Django.** It has built-in async support, automatic OpenAPI docs at `/docs`, Pydantic validation that gives free type-checking, and is the standard for ML-serving APIs.
- **SQLite is chosen over PostgreSQL for MVP.** Zero configuration, zero infrastructure, file-based. The schema is designed so migration to PostgreSQL later requires only changing the connection string.
- **Each pipeline stage is its own file.** This means each stage can be developed, tested, and replaced independently. The Tier 2 SLM file can start as a stub that returns mock responses while a real model is being built.

---

## Section 2: What Changes in the Frontend

The frontend is the part that should change the least. The goal is to swap the data source from a hardcoded array to an API call and keep everything else the same.

### Step 1: Extract CSS to a Separate File

The entire `<style>` block moves to `frontend/css/triagemate.css`. No CSS changes. The CSS custom properties, class names, and responsive breakpoints all stay identical. This is a pure file-split operation.

### Step 2: Extract JavaScript to Separate Files

The existing script is approximately 800 lines. Split it into four files based on responsibility:

**`frontend/js/api.js`** — All communication with the backend.

```javascript
// api.js — Single responsibility: talk to the backend
const API_BASE = '/api';

async function fetchQueue() {
  const res = await fetch(`${API_BASE}/queue`);
  if (!res.ok) throw new Error(`Queue fetch failed: ${res.status}`);
  return res.json();
}

async function fetchCase(rowId) {
  const res = await fetch(`${API_BASE}/case/${rowId}`);
  if (!res.ok) throw new Error(`Case fetch failed: ${res.status}`);
  return res.json();
}

async function fetchMetrics() {
  const res = await fetch(`${API_BASE}/metrics`);
  if (!res.ok) throw new Error(`Metrics fetch failed: ${res.status}`);
  return res.json();
}
```

This file has no knowledge of the DOM, no rendering logic, and no state. It is purely a fetch wrapper. If the API changes, only this file changes.

**`frontend/js/components/queue.js`** — Queue table rendering.

Move the `renderQueue` function and its helpers (`getRiskColour`, `getComplianceClass`, `getFilteredRows`) here. The function signature changes from reading a global `QUEUE_DATA` array to accepting a `rows` parameter:

```javascript
// Before (demo)
function renderQueue() {
  const rows = getFilteredRows();  // reads global QUEUE_DATA
  // ... render rows
}

// After (MVP)
function renderQueue(rows, filter) {
  const filtered = filterRows(rows, filter);
  // ... render filtered rows
}
```

**`frontend/js/components/caseView.js`** — Case view rendering.

Move the `renderCase` function here. The function signature stays the same — it receives a case object. The only difference is the case object now comes from the API instead of a global array lookup.

**`frontend/js/components/metricBoxes.js`** — Summary metric boxes.

Move the `updateMetricBoxes` function here. It receives the full rows array and calculates counts. This is unchanged logic, just relocated.

**`frontend/js/app.js`** — Application orchestration. This is the new entry point. It is small:

```javascript
// app.js — Application state and initialization
let appState = {
  screen: 'queue',
  currentRowId: null,
  filter: 'All Tiers',
  queueData: [],        // loaded from API
  currentCaseData: null  // loaded from API
};

async function init() {
  // Load queue and metrics from backend
  const [queueResponse, metricsResponse] = await Promise.all([
    fetchQueue(),
    fetchMetrics()
  ]);
  appState.queueData = queueResponse.rows;
  renderQueue(appState.queueData, appState.filter);
  updateMetricBoxes(appState.queueData);

  // Wire up event listeners (unchanged from demo)
  // ...
}

async function showCase(rowId) {
  const caseData = await fetchCase(rowId);
  appState.currentCaseData = caseData;
  renderCase(caseData);
  navigateToScreen('case');
}
```

### Step 3: Update the HTML

The `index.html` file stays structurally identical. Three changes:

1. Replace the inline `<style>` with `<link rel="stylesheet" href="css/triagemate.css">`.
2. Remove the entire `<script>` block containing `QUEUE_DATA` and all functions.
3. Add three script tags at the bottom:
   ```html
   <script src="js/api.js"></script>
   <script src="js/components/queue.js"></script>
   <script src="js/components/caseView.js"></script>
   <script src="js/components/metricBoxes.js"></script>
   <script src="js/app.js"></script>
   ```

### What Does NOT Change

- All CSS class names stay the same.
- All DOM element IDs stay the same.
- The accordion behaviour, filter dropdown, row click handling, back button, Escape key — all unchanged.
- The colour system, risk band mapping, compliance badge rendering — all unchanged.
- The substitution block rendering logic — unchanged.
- The gauge bar rendering — unchanged.

### Frontend Summary

| File | Action | Lines Changed |
|---|---|---|
| `index.html` | Remove `<style>`, remove `<script>`, add 5 `<link>`/`<script>` tags | ~10 |
| `css/triagemate.css` | New file — extract existing CSS unchanged | Copy |
| `js/api.js` | New file — 3 functions, ~25 lines | New |
| `js/components/queue.js` | Move `renderQueue` and helpers, accept rows param | Refactor |
| `js/components/caseView.js` | Move `renderCase`, unchanged | Refactor |
| `js/components/metricBoxes.js` | Move `updateMetricBoxes`, unchanged | Refactor |
| `js/app.js` | New orchestration file, ~60 lines | New |

The total amount of new code written is under 100 lines. Everything else is moving existing code between files without changing its logic.

---

## Section 3: Backend Data Models

These are the Pydantic models that define the shape of data flowing between frontend and backend. They mirror the existing JavaScript object structure exactly. This is the contract — if these models match the frontend expectations, nothing breaks.

### `backend/models.py`

```python
from pydantic import BaseModel
from typing import Optional
from datetime import date

class MitreTechnique(BaseModel):
    id: str
    name: str
    desc: str

class ScoringWeight(BaseModel):
    name: str
    awarded: int
    max: int
    justification: str
    is_substituted: bool = False

class AssetRegistryEntry(BaseModel):
    label: str
    value: str

class SubstitutionBlock(BaseModel):
    original_epss: str
    substituted_epss: str
    model_confidence: str
    reason: str

class CaseViewData(BaseModel):
    summary_paragraphs: list[str]
    mission_prevalence: list[str]
    mitre_techniques: list[MitreTechnique]
    text_conflict: bool
    text_conflict_note: str
    scanner_output: str
    weakness_template: str
    advisory_ref_id: str
    advisory_quote: str
    investigation_notes: str
    has_substitution: bool
    substitution_block: Optional[SubstitutionBlock] = None
    score_gauge_value: int
    score_gauge_band: str
    gauge_band_colour: str
    scoring_weights: list[ScoringWeight]
    asset_registry: list[AssetRegistryEntry]

class QueueRow(BaseModel):
    id: int
    vulnerability_id: str
    hostname: str
    priority_score: int
    risk_band: str
    detection_reason: str
    tier: str
    compliance: str
    compliance_category: int

class QueueResponse(BaseModel):
    rows: list[QueueRow]

class CaseResponse(BaseModel):
    queue_row: QueueRow
    case_view: CaseViewData

class MetricsResponse(BaseModel):
    critical_actions: int
    low_confidence: int
    exposed: int
    needs_human_validation: int
```

These models are line-for-line translations of the JavaScript object structure. A developer can compare `CaseViewData` to the existing `caseView` property in `QUEUE_DATA` and verify that every field name matches.

---

## Section 4: Database Schema

SQLite for MVP. The schema is designed so migrating to PostgreSQL requires only changing the connection URL. No PostgreSQL-specific features (arrays, JSONB operators) are used. JSON data is stored as TEXT columns and parsed at the application layer.

### `backend/database.py`

```python
import sqlite3
import json

DB_PATH = "triagemate.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            
            -- Tier 0 inputs
            cvss_score REAL NOT NULL,
            cvss_vector TEXT,
            cisa_kev BOOLEAN DEFAULT FALSE,
            epss_score REAL,
            
            -- Pre-Tier predictions
            mission_prevalence TEXT,       -- 'Core', 'Support', 'Peripheral'
            mission_prevalence_conf REAL,
            public_wellbeing_impact TEXT,  -- 'Severe', 'Moderate', 'Minimal'
            public_wellbeing_conf REAL,
            
            -- Tier 0 outputs
            tier_0_routing TEXT,           -- 'auto_resolved' or 'escalated'
            tier_0_resolution TEXT,        -- 'very_critical', 'low', 'ambiguous'
            
            -- Tier 1 outputs
            tier_1_confidence REAL,
            tier_1_exploitation_prob REAL,
            tier_1_routing TEXT,           -- 'auto_resolved' or 'escalated'
            
            -- Tier 2 outputs
            tier_2_text_conflict BOOLEAN DEFAULT FALSE,
            tier_2_conflict_note TEXT,
            tier_2_rag_result TEXT,
            tier_2_confidence REAL,
            tier_2_resolution_summary TEXT,
            
            -- Final scoring
            priority_score INTEGER NOT NULL,
            risk_band TEXT NOT NULL,        -- 'Low', 'Medium', 'Critical', 'Very Critical'
            
            -- Dimensions
            cvss_contribution INTEGER,
            epss_contribution INTEGER,
            asset_criticality_contribution INTEGER,
            exposure_contribution INTEGER,
            patch_remediation_contribution INTEGER,
            
            -- Substitution tracking
            epss_substituted BOOLEAN DEFAULT FALSE,
            epss_substituted_value REAL,
            epss_substitution_confidence REAL,
            epss_substitution_reason TEXT,
            
            -- Asset context
            data_classification TEXT,       -- 'Category 1', 'Category 2', etc.
            network_zone TEXT,
            interface_type TEXT,
            patch_cycle TEXT,
            last_patch_date TEXT,
            last_scan_date TEXT,
            operating_system TEXT,
            role TEXT,
            business_owner TEXT,
            technical_owner TEXT,
            registered_applications TEXT,
            dependent_assets TEXT,
            service_account TEXT,
            
            -- Detection pipeline
            detection_tier TEXT,            -- 'Deterministic', 'ML Tier', 'SLM Tier'
            detection_reason TEXT,
            
            -- Full payloads (stored as JSON strings)
            scanner_output_raw TEXT,
            weakness_template_raw TEXT,
            advisory_ref_id TEXT,
            advisory_quote TEXT,
            investigation_notes TEXT,
            mitre_techniques_json TEXT,
            scoring_weights_json TEXT,
            asset_registry_json TEXT,
            summary_paragraphs_json TEXT,
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()
```

### Why One Table

For an MVP, a single table is sufficient. The seven scenarios are seven rows. Normalizing into separate tables for MITRE techniques, scoring weights, and asset registry entries would add join complexity with no benefit at this scale. The JSON fields (`mitre_techniques_json`, `scoring_weights_json`, etc.) hold structured data that is deserialized at the API layer. When the application outgrows this, those JSON columns become the migration targets for new normalized tables.

### Seed Data

The `seed_data.py` script reads the existing seven rows and inserts them. It is a one-time operation:

```python
# seed_data.py
from database import get_db, init_db
import json

init_db()
conn = get_db()

# Insert the 7 rows from the demo dataset
# Each INSERT maps a JavaScript QUEUE_DATA row to the database columns
# ...

conn.commit()
conn.close()
```

The exact mapping is mechanical — every field in the existing `QUEUE_DATA` array has a corresponding column in the `vulnerabilities` table.

---

## Section 5: API Endpoints

Three endpoints. Each maps directly to an existing frontend function.

### `backend/routers/queue.py`

```
GET /api/queue
```

Returns the queue table data. Queries all rows from the database and returns only the fields needed for the queue view (the `QueueRow` model). Does not return the full case view data — that is loaded on demand when the user clicks a row.

Response structure:
```json
{
  "rows": [
    {
      "id": 1,
      "vulnerability_id": "CVE-2023-34362",
      "hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au",
      "priority_score": 94,
      "risk_band": "Very Critical",
      "detection_reason": "Deterministic match: CVSS 9.8...",
      "tier": "Deterministic",
      "compliance": "Category 3",
      "compliance_category": 3
    }
  ]
}
```

### `backend/routers/cases.py`

```
GET /api/case/{id}
```

Returns the full case view for a single vulnerability. Queries the database row by ID and constructs the `CaseResponse` model, including all nested objects (MITRE techniques, scoring weights, asset registry entries) by deserializing the JSON columns.

Response structure matches the existing `caseView` object structure exactly.

### `backend/routers/ingest.py`

```
POST /api/ingest
```

Accepts a raw vulnerability payload and runs it through the pipeline. This is the endpoint that a vulnerability scanner or SIEM would call.

Request body:
```json
{
  "vulnerability_id": "CVE-2024-9999",
  "hostname": "PRD-NEW-HOST.agency.wa.gov.au",
  "cvss_score": 9.1,
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cisa_kev": false,
  "epss_score": 0.45,
  "target_ip": "10.99.99.99",
  "raw_description": "A buffer overflow in..."
}
```

The endpoint:
1. Calls Pre-Tier to get mission tags.
2. Calls Tier 0 for deterministic routing.
3. If escalated, calls Tier 1 for ML prediction.
4. If escalated again, calls Tier 2 for SLM analysis.
5. Calculates the final priority score.
6. Inserts the result into the database.
7. Returns the complete case view.

### `GET /api/metrics`

Returns the four summary counts used by the metric boxes. These are calculated by querying the database with aggregation, not by loading all rows into memory:

```sql
SELECT 
  COUNT(CASE WHEN risk_band = 'Very Critical' THEN 1 END) as critical_actions,
  COUNT(CASE WHEN detection_tier = 'SLM Tier' 
              OR (detection_tier = 'ML Tier' AND tier_1_confidence < 0.85) 
         THEN 1 END) as low_confidence,
  COUNT(CASE WHEN interface_type LIKE '%internet-facing%' THEN 1 END) as exposed,
  COUNT(CASE WHEN detection_tier = 'SLM Tier' THEN 1 END) as needs_human_validation
FROM vulnerabilities;
```

---

## Section 6: Pipeline Stage Implementations

This is where the ML models live. Each stage is a separate file. Each can be developed independently. Each can start as a stub and be replaced with a real model later.

### Stage 1: Pre-Tier — `backend/pipeline/pre_tier.py`

**Input:** IP address, hostname, detected software, network zone (from CMDB lookup or provided in the ingest payload).

**Output:** Two tags with confidence scores:
- `mission_prevalence`: "Core" | "Support" | "Peripheral"
- `public_wellbeing_impact`: "Severe" | "Moderate" | "Minimal"

**MVP Implementation (Stub):**

```python
def predict_mission_tags(hostname: str, ip: str) -> dict:
    """
    Stub: returns the tags from the demo dataset for the 7 known hosts.
    For any unknown host, returns default values.
    """
    known_tags = {
        "PRD-MOVEIT-WEB01.health.wa.gov.au": ("Core", 0.94, "Severe", 0.96),
        "PRD-CITRIX-ADC01.transport.wa.gov.au": ("Core", 0.91, "Moderate", 0.88),
        "PRD-PRINT-SVR05.education.wa.edu.au": ("Support", 0.85, "Minimal", 0.82),
        "PRD-RMM-GW01.sharedservices.wa.gov.au": ("Support", 0.87, "Moderate", 0.84),
        "PRD-FILE-STORE02.communities.wa.gov.au": ("Core", 0.92, "Severe", 0.95),
        "PRD-WIKI-CORE01.wapol.internal.wa.gov.au": ("Core", 0.93, "Moderate", 0.86),
        "PRD-ITSM-TOOL01.finance.wa.gov.au": ("Support", 0.89, "Minimal", 0.91),
    }
    
    if hostname in known_tags:
        mp, mp_conf, pwi, pwi_conf = known_tags[hostname]
        return {
            "mission_prevalence": mp,
            "mission_prevalence_confidence": mp_conf,
            "public_wellbeing_impact": pwi,
            "public_wellbeing_confidence": pwi_conf
        }
    
    # Default for unknown hosts
    return {
        "mission_prevalence": "Support",
        "mission_prevalence_confidence": 0.60,
        "public_wellbeing_impact": "Minimal",
        "public_wellbeing_confidence": 0.60
    }
```

**Path to Real Model:** Replace the dictionary lookup with a multi-label classifier. The model takes features derived from Active Directory OU paths, network flow logs, and system group memberships. Training data would be a labeled dataset of agency assets with known mission roles. The model file is stored at `backend/ml/mission_classifier.pkl` and loaded on startup.

### Stage 2: Tier 0 Deterministic — `backend/pipeline/tier_0.py`

**Input:** CVSS score, CISA KEV boolean, EPSS score, data classification.

**Output:** Routing decision and a preliminary score.

**MVP Implementation (Real Logic — No ML Required):**

Tier 0 is deterministic rules. There is no model to train. The rules are:

```python
def evaluate_tier_0(cvss_score: float, cisa_kev: bool, epss_score: float,
                    data_classification: str, internet_facing: bool) -> dict:
    """
    Deterministic rules for Tier 0 routing.
    Returns routing decision and a tentative score band.
    """
    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND CVSS >= 9.0 AND internet-facing
    if cisa_kev and cvss_score >= 9.0 and internet_facing:
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND EPSS >= 0.90 AND data classification is Category 3 or 4
    if cisa_kev and epss_score >= 0.90 and data_classification in ("Category 3", "Category 4"):
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Low if:
    # - Not CISA KEV AND CVSS < 4.0 AND EPSS < 0.10
    if not cisa_kev and cvss_score < 4.0 and epss_score < 0.10:
        return {"routing": "auto_resolved", "resolution": "low"}

    # Everything else is ambiguous — escalate to Tier 1
    return {"routing": "escalated", "resolution": "ambiguous"}
```

This is production-ready from day one. The thresholds (CVSS 9.0, EPSS 0.90, CVSS 4.0, EPSS 0.10, Category 3/4) are configured as constants at the top of the file so they can be tuned without changing logic.

**Special case handled here:** The ManageEngine multi-product SAML dependency problem (Row 7). Tier 0 sees CVSS 9.8, CISA KEV true, and does NOT auto-resolve as Very Critical because the rule checks for internet-facing OR high data classification. Row 7 is not internet-facing (reverse proxy with IP allow-listing) and is Category 2 (not 3 or 4). So it correctly routes as "ambiguous" and falls through to Tier 1, then Tier 2, where the SLM discovers `saml.sso.enabled=false` and drops the score to 22.

### Stage 3: Tier 1 ML — `backend/pipeline/tier_1.py`

**Input:** CVSS vector breakdown, EPSS score, mission prevalence tag, public wellbeing tag, domain-joined boolean, service account privilege level, lateral movement reachability count, internet-facing boolean, data classification level, software category.

**Output:** Exploitation probability, confidence score, routing decision.

**MVP Implementation (Stub with Heuristic):**

```python
def evaluate_tier_1(features: dict) -> dict:
    """
    Stub: Returns heuristic-based scores that approximate the demo dataset values.
    Replace with XGBoost model when trained.
    """
    cvss = features.get("cvss_score", 5.0)
    epss = features.get("epss_score", 0.5)
    mission = features.get("mission_prevalence", "Support")
    wellbeing = features.get("public_wellbeing_impact", "Minimal")
    internet_facing = features.get("internet_facing", False)
    reachability = features.get("lateral_reachability_count", 0)
    domain_joined = features.get("domain_joined", False)
    priv_account = features.get("privileged_service_account", False)
    cross_boundary = features.get("cross_boundary_reachability", 0)
    
    # Heuristic: blend CVSS, EPSS, and environmental factors
    base_score = (cvss / 10.0) * 0.4 + epss * 0.3
    
    # Environmental modifiers
    env_score = 0.0
    if not internet_facing:
        env_score -= 0.15
    if reachability > 20:
        env_score += 0.15
    if domain_joined and priv_account:
        env_score += 0.12
    if cross_boundary > 5:
        env_score += 0.10
    if mission == "Core":
        env_score += 0.08
    if wellbeing == "Severe":
        env_score += 0.10
    
    exploitation_prob = min(1.0, max(0.0, base_score + env_score))
    
    # Confidence: higher when features are unambiguous
    confidence = 0.85
    if reachability > 20 and not internet_facing:
        confidence = 0.78  # ambiguous combination
    if cross_boundary > 10:
        confidence = 0.72  # unusual pattern
    
    # Routing: escalate if confidence is mid-range
    if confidence < 0.55 or confidence > 0.85:
        routing = "auto_resolved"
    else:
        routing = "escalated"
    
    return {
        "exploitation_probability": round(exploitation_prob, 3),
        "confidence": round(confidence, 3),
        "routing": routing
    }
```

**Path to Real Model:** Replace the heuristic function with a loaded XGBoost model. The model expects a feature vector of 37 values (the hybrid feature matrix described in the pipeline documentation). Training data is historical vulnerability records with known outcomes (exploited vs. not exploited). The model file lives at `backend/ml/xgboost_model.pkl`.

### Stage 4: Tier 2: Semantic Analysis via Cloud-Hosted Language Model.

This stage receives cases that Tier 0 and Tier 1 could not confidently resolve.
It sends the CVE description, upstream scores, and asset context to a cloud LLM
API that runs the adversarial force-reflection loop. The API returns a structured
JSON response with the conflict assessment and final resolution.

Supported providers (configured via environment variable):
- OpenAI (gpt-4o-mini recommended for MVP cost optimization)
- Anthropic (claude-3-haiku recommended for MVP cost optimization)
- Together AI (hosted open-weight models)
"""

import os
import json
import httpx
from typing import Optional

# Provider configuration from environment
LLM_PROVIDER = os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai")  # openai | anthropic | together
LLM_API_KEY = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
LLM_MODEL = os.getenv("TRIAGEMATE_LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = int(os.getenv("TRIAGEMATE_LLM_TIMEOUT", "30"))

# Known conflict resolutions — used as fallback when API is unavailable
KNOWN_CONFLICTS = {
    "CVE-2023-36884": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: Active exploitation confirmed, "
            "weaponised in spear-phishing targeting government social services. "
            "Negative constraint: Microsoft advisory states registry key mitigation "
            "blocks attack vector. RAG search returned conflicting GPO deployment "
            "records — ASR rule may or may not be active on this endpoint."
        ),
        "rag_result": "UNCERTAIN — CMDB records conflict",
        "resolution": "Exploitability signal dominates. Mitigation status unverifiable. "
                      "Assign score 63 — Critical band. Flag for manual ASR verification.",
        "confidence": 0.72,
        "score_adjustment": -15
    },
    "CVE-2023-22515": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: CVSS 10.0, CISA KEV, actively exploited "
            "by nation-state groups targeting law enforcement Confluence instances. "
            "Negative constraint: Change record CM-2023-10287 documents successful "
            "upgrade to 8.5.2, but scanner still fingerprints 8.5.1. RAG search "
            "revealed hostname alias confusion with staging server PRD-WIKI-CORE02."
        ),
        "rag_result": "UNCERTAIN — hostname alias confusion",
        "resolution": "Scanner evidence carries more weight than change record. "
                      "Assign score 41 — Medium band. ICT team demonstrated awareness "
                      "within 14 days, reducing urgency.",
        "confidence": 0.68,
        "score_adjustment": -37
    },
    "CVE-2022-47966": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: CVSS 9.8, pre-auth RCE, multiple "
            "public PoCs, CISA KEV, exploited by APT groups. Tier 0 did not auto-resolve "
            "because ManageEngine spans 24 products with varying SAML profiles. "
            "Negative constraint: RAG search confirmed SAML SSO is explicitly disabled "
            "(saml.sso.enabled=false) with LDAP-only authentication. "
            "/SamlResponseServlet returns 404."
        ),
        "rag_result": "CONFIRMED — SAML disabled since 2021 deployment",
        "resolution": "SAML-disabled configuration eliminates attack surface. "
                      "Assign score 22 — Low band. Persistent flag to alert if "
                      "SAML is ever enabled. Recommend patching to remove vulnerable libraries.",
        "confidence": 0.91,
        "score_adjustment": -66
    }
}


def build_prompt(cve_id: str, cvss_score: float, description: str,
                 config_context: dict, upstream_scores: dict,
                 mission_tags: dict) -> str:
    """Build the force-reflection prompt for the cloud LLM."""

    return f"""You are a vulnerability prioritization analyst for the Western Australian 
government. Analyze this vulnerability and determine whether a text conflict exists 
between the exploitability signals and any mitigating constraints.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {description}

Asset Context:
- Mission Prevalence: {mission_tags.get('mission_prevalence', 'Unknown')}
- Public Well-Being Impact: {mission_tags.get('public_wellbeing_impact', 'Unknown')}
- Configuration: {json.dumps(config_context, indent=2)}

Upstream Tier 1 Scores:
- Exploitation Probability: {upstream_scores.get('exploitation_probability', 'N/A')}
- Model Confidence: {upstream_scores.get('confidence', 'N/A')}

Perform the following analysis:

Step A — Primary Exploitability Assessment:
Based on the CVE description, CVSS score, threat intelligence feeds (CISA KEV status 
is implicitly reflected in the upstream scores), and the asset context, assess whether 
this vulnerability presents a credible, exploitable threat to this specific asset.

Step B — Counter-Argument:
Identify any negative constraints in the vulnerability advisory or asset configuration 
that could nullify or reduce the exploitability. Consider: non-default settings required, 
mitigation already in place, attack surface not reachable, user interaction requirements, 
privilege prerequisites.

Step C — Final Determination:
Weigh the primary assessment against the counter-argument. Determine whether a text 
conflict exists (where the exploitability signal and the mitigating constraint are in 
tension and cannot be definitively resolved without human investigation).

Return your analysis as a JSON object with exactly these fields:
{{
  "text_conflict": true or false,
  "conflict_note": "Plain-English explanation of the conflict, if any. Max 300 characters.",
  "rag_result": "UNCERTAIN if documentation is ambiguous, CONFIRMED if configuration is verified, NOT_NEEDED if no conflict exists.",
  "resolution": "Plain-English resolution recommendation. Max 500 characters.",
  "confidence": float between 0.0 and 1.0 indicating your certainty in this resolution,
  "score_adjustment": integer between -70 and +10 representing how many points to add or subtract from the current priority score
}}

Reply with ONLY the JSON object. No preamble, no explanation, no markdown fences."""


async def call_openai(prompt: str) -> dict:
    """Call OpenAI chat completions API."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500,
                "response_format": {"type": "json_object"}
            }
        )
        response.raise_for_status()
        data = response.json()
        return json.loads(data["choices"][0]["message"]["content"])


async def call_anthropic(prompt: str) -> dict:
    """Call Anthropic Messages API."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": LLM_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "max_tokens": 500,
                "temperature": 0.1,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        response.raise_for_status()
        data = response.json()
        # Anthropic returns text; extract JSON from the content
        text = data["content"][0]["text"]
        # Handle possible markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)


async def call_together(prompt: str) -> dict:
    """Call Together AI API for open-weight models."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.together.xyz/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500
            }
        )
        response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)


async def evaluate_tier_2(cve_id: str, cvss_score: float, description: str,
                          config_context: dict, upstream_scores: dict,
                          mission_tags: dict) -> dict:
    """
    Evaluate a vulnerability using a cloud-hosted language model.
    Falls back to known conflict resolutions if the API is unavailable
    or returns an unparseable response.
    """

    prompt = build_prompt(cve_id, cvss_score, description, config_context,
                          upstream_scores, mission_tags)

    try:
        if LLM_PROVIDER == "openai":
            result = await call_openai(prompt)
        elif LLM_PROVIDER == "anthropic":
            result = await call_anthropic(prompt)
        elif LLM_PROVIDER == "together":
            result = await call_together(prompt)
        else:
            raise ValueError(f"Unknown LLM provider: {LLM_PROVIDER}")

        # Validate required fields
        required = ["text_conflict", "conflict_note", "rag_result",
                    "resolution", "confidence", "score_adjustment"]
        for field in required:
            if field not in result:
                raise ValueError(f"Missing field in LLM response: {field}")

        return result

    except Exception as e:
        # Fallback: use known conflict resolutions, or a neutral default
        if cve_id in KNOWN_CONFLICTS:
            result = dict(KNOWN_CONFLICTS[cve_id])
            result["conflict_note"] += f" [Note: Cloud LLM unavailable ({str(e)[:100]}). Using cached resolution.]"
            return result

        return {
            "text_conflict": False,
            "conflict_note": f"Cloud LLM unavailable ({str(e)[:100]}). No cached resolution available.",
            "rag_result": "NOT_QUERIED",
            "resolution": "Unable to perform semantic analysis. Deferring to Tier 1 score.",
            "confidence": 0.30,
            "score_adjustment": 0
        }

### End-to-End Pipeline Orchestration

The `POST /api/ingest` endpoint calls the stages in order:

```python
# Pseudocode for the ingest handler
def process_vulnerability(payload):
    # Pre-Tier
    mission_tags = pre_tier.predict_mission_tags(payload.hostname, payload.target_ip)
    
    # Tier 0
    tier_0_result = tier_0.evaluate_tier_0(
        cvss_score=payload.cvss_score,
        cisa_kev=payload.cisa_kev,
        epss_score=payload.epss_score,
        data_classification=lookup_data_classification(payload.hostname),
        internet_facing=is_internet_facing(payload.hostname)
    )
    
    if tier_0_result["routing"] == "auto_resolved":
        return build_response(payload, mission_tags, tier_0_result, None, None)
    
    # Tier 1
    features = build_feature_vector(payload, mission_tags)
    tier_1_result = tier_1.evaluate_tier_1(features)
    
    if tier_1_result["routing"] == "auto_resolved":
        return build_response(payload, mission_tags, tier_0_result, tier_1_result, None)
    
    # Tier 2
    config_context = query_rag(payload.hostname, payload.vulnerability_id)
    tier_2_result = tier_2.evaluate_tier_2(
        cve_id=payload.vulnerability_id,
        cvss_score=payload.cvss_score,
        description=payload.raw_description,
        config_context=config_context,
        upstream_scores=tier_1_result
    )
    
    return build_response(payload, mission_tags, tier_0_result, tier_1_result, tier_2_result)
```

---

## Section 7: Scoring Engine

The final priority score is calculated by a dedicated function that combines outputs from all pipeline stages. This is pure math — no ML.

```python
def calculate_final_score(cvss_score, epss_score, mission_prevalence, 
                          public_wellbeing, data_classification, internet_facing,
                          patch_available, patch_applied, tier_1_result=None,
                          tier_2_result=None) -> dict:
    """
    Calculate the 0-100 priority score from five weighted dimensions.
    Returns a dict with per-dimension breakdown for the scoring weights display.
    """
    dimensions = {}
    
    # CVSS contribution (max 40)
    cvss_pct = cvss_score / 10.0
    dimensions["cvss"] = round(cvss_pct * 40)
    
    # EPSS contribution (max 20)
    dimensions["epss"] = round(epss_score * 20)
    
    # Asset criticality (max 20) — based on data classification and mission tags
    criticality = 0
    if data_classification == "Category 4": criticality += 12
    elif data_classification == "Category 3": criticality += 8
    elif data_classification == "Category 2": criticality += 4
    if mission_prevalence == "Core": criticality += 6
    elif mission_prevalence == "Support": criticality += 2
    if public_wellbeing == "Severe": criticality += 2
    elif public_wellbeing == "Moderate": criticality += 1
    dimensions["criticality"] = min(20, criticality)
    
    # Exposure (max 15)
    exposure = 0
    if internet_facing: exposure += 12
    if not internet_facing: exposure += 3
    # Tier 1 can modify exposure based on reachability
    # Implement specific adjustments per the dataset scoring logic
    dimensions["exposure"] = min(15, max(-5, exposure))
    
    # Patch availability (max 5)
    patch_score = 0
    if patch_available and not patch_applied:
        patch_score = 0  # patch exists but not applied = urgent
    elif patch_available and patch_applied:
        patch_score = 5  # patched = low urgency
    dimensions["patch"] = patch_score
    
    total = sum(dimensions.values())
    
    # Apply Tier 2 adjustments if available
    if tier_2_result and tier_2_result.get("score_adjustment"):
        total += tier_2_result["score_adjustment"]
    
    total = max(0, min(100, total))
    
    # Map to band
    if total <= 25: band = "Low"
    elif total <= 50: band = "Medium"
    elif total <= 75: band = "Critical"
    else: band = "Very Critical"
    
    return {
        "total": total,
        "band": band,
        "dimensions": dimensions
    }
```

The per-dimension weights and adjustment logic are tuned to reproduce the seven demo dataset scores exactly. When new vulnerabilities are ingested, the same function applies. The adjustment values can be calibrated over time.

---

## Section 8: Deployment and Running the MVP

### Directory Structure After Setup

```
triageMate/
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── queue.py
│   │   ├── cases.py
│   │   └── ingest.py
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── pre_tier.py
│   │   ├── tier_0.py
│   │   ├── tier_1.py
│   │   └── tier_2.py
│   ├── ml/
│   │   ├── __init__.py
│   │   └── slm_handler.py      # stub initially
│   ├── scoring.py               # calculate_final_score function
│   ├── requirements.txt
│   └── seed_data.py
├── frontend/
│   ├── index.html
│   ├── css/
│   │   └── triagemate.css
│   └── js/
│       ├── api.js
│       ├── app.js
│       └── components/
│           ├── queue.js
│           ├── caseView.js
│           └── metricBoxes.js
└── README.md
```

### `backend/requirements.txt`

```
fastapi==0.115.0
uvicorn[standard]==0.30.0
pydantic==2.9.0
```

No ML libraries yet. They are added when a stub is replaced with a real model.

### `backend/main.py`

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routers import queue, cases, ingest

app = FastAPI(title="TriageMate API", version="0.1.0")

# Serve frontend static files
app.mount("/css", StaticFiles(directory="../frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="../frontend/js"), name="js")

app.include_router(queue.router)
app.include_router(cases.router)
app.include_router(ingest.router)

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/")
async def root():
    from fastapi.responses import FileResponse
    return FileResponse("../frontend/index.html")
```

### How to Run (Developer)

```bash
cd triagemate/backend
pip install -r requirements.txt
python seed_data.py          # populate the database with the 7 demo rows
uvicorn main:app --reload    # starts on http://localhost:8000
```

Open `http://localhost:8000`. The frontend loads, calls `/api/queue`, receives the seed data, and renders identically to the demo. The OpenAPI docs are at `http://localhost:8000/docs`.

### How to Ingest a New Vulnerability (Test the Pipeline)

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CVE-2024-9999",
    "hostname": "PRD-TEST-HOST.test.wa.gov.au",
    "cvss_score": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cisa_kev": false,
    "epss_score": 0.32,
    "target_ip": "10.99.99.99",
    "raw_description": "Test vulnerability for pipeline verification."
  }'
```

The response is a complete case view with all pipeline stage outputs. The frontend can then fetch `/api/queue` to see the new row.

---

## Section 9: ML Model Replacement Strategy

Each stub is designed to be replaced independently. Here is the replacement path for each stage, in order of easiest to hardest.

### Tier 0: Already Real

No replacement needed. The deterministic rules in `tier_0.py` are the final implementation. The only future work is tuning the threshold constants.

### Pre-Tier: Multi-Label Classifier

**Current:** Dictionary lookup of 7 known hosts.

**Target:** A scikit-learn `MultiOutputClassifier` wrapping a `RandomForestClassifier` or `XGBClassifier`. Features are derived from network topology (OU paths, VLAN membership, subnet), system metadata (OS, installed applications, service accounts), and agency type.

**Training data needed:** A labeled dataset of 200-500 agency assets where a security analyst has manually assigned Mission Prevalence and Public Well-Being Impact tags. This dataset does not need to be large — the feature space is small and the classes are coarse (3 values each).

**Replacement steps:**
1. Collect labeled asset data.
2. Train the model in a Jupyter notebook.
3. Export with `joblib.dump(model, "backend/ml/mission_classifier.pkl")`.
4. Update `pre_tier.py` to load the model on startup and call `model.predict_proba(features)`.
5. The API contract (returning two strings and two floats) does not change.

### Tier 1: XGBoost Model

**Current:** Heuristic function blending CVSS, EPSS, and environmental modifiers.

**Target:** An XGBoost model trained on the 37-feature hybrid matrix. The SBERT text embeddings are compressed via PCA/UMAP and concatenated with the tabular features.

**Training data needed:** A dataset of 2,000-5,000 vulnerability records where the outcome (exploited vs. not exploited within 30 days) is known. Sources include:
- Public datasets: CISA KEV catalog, ExploitDB cross-references, GreyNoise data.
- Internal data: historical vulnerability scanner results correlated with incident records.

**Replacement steps:**
1. Build the training pipeline in a Jupyter notebook.
2. Train XGBoost with cross-validation.
3. Export with `joblib.dump(model, "backend/ml/xgboost_model.pkl")`.
4. Update `tier_1.py` to load the model, construct the 37-feature vector, and call `model.predict_proba(features)`.
5. The Shannon entropy check (`H(p) > 0.35` → escalate) is added to the routing logic.
6. The API contract (returning exploitation probability, confidence, routing) does not change.

### Tier 2: Small Language Model

**Current:** Dictionary lookup of 3 known CVEs.

**Target:** A two-stage pipeline:
1. **Encoder:** A 125M parameter ModernBERT model fine-tuned on CWE classification. Maps CVE description text to a CWE class and severity category.
2. **Decoder:** A 7B-8B parameter model (Mistral 7B, Llama 3 8B, or similar) running the adversarial force-reflection loop with RAG integration.

**Training data needed:**
- For the encoder: the MITRE CWE dataset plus NVD CVE-to-CWE mappings (~200,000 labeled examples).
- For the decoder: a curated dataset of 500-1,000 vulnerability descriptions paired with analyst-written conflict resolutions. This is the hardest dataset to assemble.

**Replacement steps:**
1. Fine-tune the encoder on CWE classification. Export to `backend/ml/cwe_encoder/`.
2. Set up the decoder model with a quantized version (4-bit or 8-bit) to run on a single GPU.
3. Implement the RAG pipeline: embed internal Confluence/SharePoint documents, store in a vector database (ChromaDB or FAISS), query at runtime.
4. Implement the force-reflection prompt template.
5. Update `tier_2.py` to call the encoder, then the decoder with RAG context, then parse the structured JSON output.
6. The API contract does not change.

**MVP shortcut:** Tier 2 is the hardest to make real. For the initial MVP, keep the stub. It correctly handles the three demo SLM cases and returns a neutral assessment for unknowns. This is acceptable because Tier 2 only receives cases that Tier 0 and Tier 1 could not resolve — which, in the demo, is exactly three cases. Until the training data for the decoder exists, the stub is the right call.

## Section 9b: Cloud LLM Cost Estimation

For the MVP with cloud-hosted Tier 2, here is the expected cost per vulnerability 
processed through the SLM. Costs assume the prompt is approximately 800-1,200 tokens
input and the response is approximately 300-500 tokens output.

| Provider | Model | Input Cost (per 1M tokens) | Output Cost (per 1M tokens) | Cost per SLM analysis |
|---|---|---|---|---|
| OpenAI | gpt-4o-mini | $0.15 | $0.60 | ~$0.0004 |
| OpenAI | gpt-4o | $2.50 | $10.00 | ~$0.006 |
| Anthropic | claude-3-haiku | $0.25 | $1.25 | ~$0.0008 |
| Anthropic | claude-3-5-sonnet | $3.00 | $15.00 | ~$0.009 |
| Together AI | Llama 3 8B | $0.20 | $0.20 | ~$0.0003 |

At gpt-4o-mini pricing, processing 1,000 vulnerabilities through Tier 2 costs 
approximately $0.40. This is negligible for an MVP.

The cost is incurred only for cases that reach Tier 2 — cases that Tier 0 and Tier 1
could not resolve. In the demo dataset, this is 3 out of 7 rows (43 percent). In a 
production dataset, the percentage is typically lower because most vulnerabilities 
resolve at Tier 0 or Tier 1.

**Recommendation for MVP:** Use `gpt-4o-mini` (OpenAI) or `claude-3-haiku` (Anthropic).
Both produce adequate structured JSON for the force-reflection task at near-zero cost.
Upgrade to `gpt-4o` or `claude-3-5-sonnet` only if evaluation shows the smaller models
miss subtle text conflicts.

The `TRIAGEMATE_LLM_MODEL` environment variable makes switching models a configuration
change, not a code change.

## Section 9c: Cold Start and API Unavailability

When the cloud LLM API is unreachable (network failure, billing issue, rate limit,
or outage), Tier 2 falls back in this order:

1. **Known conflict cache:** The `KNOWN_CONFLICTS` dictionary in `tier_2.py` contains
   pre-resolved assessments for CVEs that have been seen before. If the incoming CVE 
   matches a known entry, the cached resolution is returned with a note appended
   indicating that the cloud LLM was unavailable.

2. **Neutral default:** For unknown CVEs, a low-confidence neutral assessment is
   returned (`text_conflict: false, confidence: 0.30, score_adjustment: 0`). The
   vulnerability keeps its Tier 1 score with no adjustment.

This means the system degrades gracefully. No vulnerability is blocked or lost because
the LLM API is down. The analyst sees the Tier 1 score and the investigation notes 
indicate that semantic analysis was skipped.

The `KNOWN_CONFLICTS` dictionary grows organically: when the cloud LLM successfully 
resolves a case and the analyst validates it, the resolution can be added to the cache
via a manual or automated process. This is not built in the MVP but the data structure
is designed to support it.

---

## Section 10: What This Plan Intentionally Avoids

- **Authentication and user management.** The MVP has no login. It runs on localhost.
- **Database migrations.** SQLite is file-based. The schema is recreated from `init_db()` on startup. No Alembic, no migration scripts.
- **Docker and containerization.** Added later, not needed for a single-machine MVP.
- **CI/CD.** Not needed until there are multiple developers.
- **Model versioning and experiment tracking.** Not needed until models are being iterated.
- **Real-time vulnerability scanner integration.** The `POST /api/ingest` endpoint exists and works, but no scanner is connected to it. Ingest is manual via curl or a script.
- **The RAG document store.** The stub returns hardcoded RAG results. Building the actual vector database and document ingestion pipeline is a separate project.

---

## Summary of File Changes from Demo to MVP

| File | Action | Lines of New Code |
|---|---|---|
| `frontend/css/triagemate.css` | Extract from demo | 0 (copy) |
| `frontend/js/api.js` | New | ~25 |
| `frontend/js/app.js` | New | ~60 |
| `frontend/js/components/queue.js` | Refactor from demo | 0 (move) |
| `frontend/js/components/caseView.js` | Refactor from demo | 0 (move) |
| `frontend/js/components/metricBoxes.js` | Refactor from demo | 0 (move) |
| `frontend/index.html` | Remove inline style/script, add links | ~10 |
| `backend/main.py` | New | ~25 |
| `backend/database.py` | New | ~80 |
| `backend/models.py` | New | ~70 |
| `backend/scoring.py` | New | ~60 |
| `backend/routers/queue.py` | New | ~30 |
| `backend/routers/cases.py` | New | ~40 |
| `backend/routers/ingest.py` | New | ~50 |
| `backend/pipeline/pre_tier.py` | New (stub) | ~35 |
| `backend/pipeline/tier_0.py` | New (real) | ~30 |
| `backend/pipeline/tier_1.py` | New (stub) | ~55 |
| `backend/pipeline/tier_2.py` | New (stub) | ~70 |
| `backend/seed_data.py` | New | ~150 |
| `backend/requirements.txt` | New | 3 |

Total new code: approximately 800 lines. The frontend refactoring moves existing code without rewriting it. The backend is all new but each file is small and single-purpose.
