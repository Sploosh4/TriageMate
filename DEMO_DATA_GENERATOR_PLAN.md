# Demo Data Generator — Implementation Plan

> **Based on:** `DEMO_DATA_GENERATOR_SCOPE.md` (Intel Team, 1 July 2026)
> **Current state:** Codebase studied. 5 dependency phases, ~13 hrs. Each phase broken into sub-tasks with exact file paths, function signatures, and implementation logic.
> **Convention:** Match existing patterns — `joblib` for ML artifacts, `json` for data files, vanilla JS for frontend, FastAPI routers for endpoints, `logging.getLogger()` for logs.

---

## Phase 0: Prerequisites (Commander)

| # | Action | Details |
|---|---|---|
| 0.1 | **NVD API key** | Sign up at nvd.nist.gov, put `NVD_API_KEY=...` in `backend/.env` |
| 0.2 | **Review hostnames in §2.1** | Approve/amend before implementation. 25-30 fictional WA gov hosts. |

---

## Phase 1: Foundation — Mock CMDB + Pre-Tier Retrain

### 1.1 — Mock CMDB as Data File (`backend/data/mock_cmdb.json`)

**Rationale:** The 7 hardcoded hosts in `backend/integrations/cmdb.py:17-129` become a JSON file. The CMDB adapter reads from the file when `DEMO_MODE=true`, falls back to the Python dict for backward compat. This lets us have 25-30 hosts without polluting the Python source.

**Implementation:**

1. **Create `backend/data/mock_cmdb.json`** — JSON array of 28 host objects. Each object has exactly the same keys as the current `KNOWN_HOSTS` dict values:
   ```json
   [
     {
       "hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au",
       "data_classification": "Category 3",
       "internet_facing": true,
       "network_zone": "DMZ-Health-External",
       "operating_system": "Windows Server 2019 Standard",
       "role": "Managed File Transfer Server — Inter-Hospital Health Information Exchange",
       "business_owner": "WA Health — Health Support Services, ICT Operations",
       "technical_owner": "Health Support Services — Infrastructure Platforms Team",
       "interface_type": "Internet-facing HTTPS (no VPN required)",
       "patch_cycle": "Monthly (second Sunday, 0200-0600 AWST)",
       "last_patch_date": "14 May 2026",
       "last_scan_date": "27 June 2026",
       "registered_applications": "Progress MOVEit Transfer 2023.0.0, IIS 10.0",
       "dependent_assets": "PRD-SQL-CLUSTER01.health.wa.gov.au, PRD-FILE-SAN01.health.wa.gov.au",
       "service_account": ""
     }
   ]
   ```
   - Preserve the 7 original hosts verbatim (copy from `KNOWN_HOSTS` dict).
   - Add 21 new hosts across departments per scope §4.1.

2. **Modify `backend/integrations/cmdb.py`** — Add file-based loading:
   ```python
   import json
   from pathlib import Path

   _MOCK_CMDB_PATH = Path(__file__).parent.parent / "data" / "mock_cmdb.json"
   _FILE_CMDB: dict[str, dict] | None = None

   def _load_file_cmdb() -> dict[str, dict]:
       """Load the mock CMDB from JSON file, keyed by hostname."""
       global _FILE_CMDB
       if _FILE_CMDB is not None:
           return _FILE_CMDB
       try:
           with open(_MOCK_CMDB_PATH) as f:
               hosts = json.load(f)
           _FILE_CMDB = {h["hostname"]: h for h in hosts}
           logger.info("Loaded %d hosts from mock_cmdb.json", len(_FILE_CMDB))
           return _FILE_CMDB
       except (FileNotFoundError, json.JSONDecodeError) as e:
           logger.warning("mock_cmdb.json not loaded: %s", e)
           _FILE_CMDB = {}
           return _FILE_CMDB
   ```

3. **Modify `_stub_lookup()`** in `cmdb.py:178` — Check file CMDB first, fall through to `KNOWN_HOSTS` dict, then defaults:
   ```python
   def _stub_lookup(hostname: str) -> dict:
       file_db = _load_file_cmdb()
       if hostname in file_db:
           return dict(file_db[hostname])
       if hostname in KNOWN_HOSTS:
           return dict(KNOWN_HOSTS[hostname])
       return { /* existing defaults */ }
   ```
   This preserves backward compat — the 7 originals are in both places, but any new host from the JSON file is also found.

**Files changed:** `backend/data/mock_cmdb.json` (NEW), `backend/integrations/cmdb.py` (modified)

---

### 1.2 — Pre-Tier Training Data Expansion

**Rationale:** The pre-tier model (`pre_tier_model.pkl`) was trained on 242+300 hostnames. With 28 new hosts in the mock CMDB, we need training records for them.

**Implementation:**

1. **Add 28 records to `backend/ml/pretier_training_data.json`** — Each new host gets a record with:
   ```json
   {
     "hostname": "PRD-EHR-APP01.health.wa.gov.au",
     "mission_prevalence": "Core",
     "public_wellbeing_impact": "Severe"
   }
   ```
   Tag assignments derived from department/role:
   - Health patient-facing → Core/Severe
   - Transport marine safety → Core/Moderate
   - Education student systems → Support/Moderate
   - Communities child protection → Core/Severe
   - WA Police CAD/dispatch → Core/Severe  
   - Finance ITSM → Support/Minimal
   - Justice court systems → Core/Moderate
   - Water SCADA → Core/Severe

2. **Update `KNOWN_TAGS` dict in `backend/pipeline/pre_tier.py:28-36`** with the 28 new hosts (add to existing dict).

3. **Retrain the pre-tier model:**
   ```bash
   cd backend && python -m ml.train_pre_tier
   ```
   This reads the updated `pretier_training_data.json`, produces a new `pre_tier_model.pkl`.

**Files changed:** `backend/ml/pretier_training_data.json` (modified), `backend/pipeline/pre_tier.py` (KNOWN_TAGS expanded), `backend/ml/pre_tier_model.pkl` (regenerated)

---

## Phase 2: Data Caches

### 2.1 — NVD Cache Builder (`backend/scripts/refresh_caches.py`)

**Rationale:** Generate `backend/data/nvd_cache.json` — a flat JSON file with NVD enrichment data for ~500-1000 CVEs relevant to the mock CMDB's operating systems and applications.

**Implementation:**

1. **Create `backend/scripts/` directory** (if not exists). Add `__init__.py`.

2. **Create `backend/scripts/refresh_caches.py`** — Unified CLI script:
   ```python
   """
   Cache refresh CLI for demo data sources.

   Usage:
       python -m scripts.refresh_caches              # All sources
       python -m scripts.refresh_caches --source nvd  # NVD only
       python -m scripts.refresh_caches --source kev  # KEV only
   """

   import argparse
   import sys
   from pathlib import Path

   DATA_DIR = Path(__file__).parent.parent / "data"

   def refresh_nvd_cache(cve_ids: list[str], api_key: str = ""):
       """Fetch NVD enrichment for each CVE ID, write to nvd_cache.json."""
       ...

   def refresh_kev_cache():
       """Fetch CISA KEV catalog, filter to relevant CVEs, write to kev_cache.json."""
       ...

   def refresh_epss_cache():
       """Re-use existing EPSS fetch from ml.fetch_epss_data."""
       ...

   def _resolve_cve_list() -> list[str]:
       """Walk mock_cmdb.json → registered_applications → map software to CVE IDs."""
       ...
   ```

3. **NVD Cache Fetch Logic** (inside `refresh_nvd_cache`):
   - Input: list of CVE IDs (sourced from mock CMDB + curated list)
   - For each CVE ID, call NVD API 2.0 `/rest/json/cves/2.0?cveId={id}`
   - Rate limit: 5 req/s without API key, 50 req/s with key
   - Extract fields into the schema defined in scope §3.1:
     ```python
     entry = {
         "cvss_v3_score": ...,
         "cvss_v3_vector": ...,
         "cwe_class": "CWE-787",
         "description": "...",
         "vulnerability_age_days": ...,
         "patch_available": True/False,   # from reference_tags including "Patch"
         "exploitdb_has_poc": True/False,  # from reference_tags including "Exploit"
         "metasploit_has_payload": True/False,
         "nvd_reference_count": ...,
         "cvss_exploitability_sub": ...,
         "cvss_impact_sub": ...,
         "vendor": "...",
         "product": "...",
     }
     ```
   - Write all entries to `backend/data/nvd_cache.json` as `{cve_id: entry, ...}` dict.
   - Cache ~500-1000 CVEs. First pass: gather from mock CMDB `registered_applications`. Second pass: top-500 by CVSS from NVD's `/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=100`.

4. **CVE List Resolution** (`_resolve_cve_list`):
   - Load `mock_cmdb.json`
   - For each host, parse `registered_applications` string
   - Build a `{vendor: [products], ...}` map
   - Query NVD `/cves/2.0?keywordSearch={product}&resultsPerPage=5` per product
   - Collect all returned CVE IDs
   - Deduplicate
   - Also hardcode a list of 50 "greatest hits" CVEs with known exploits (CISA KEV overlap, widely reported)

**Environment:** Reads `NVD_API_KEY` from `os.getenv`. No-key mode works but is slower.

---

### 2.2 — EPSS Cache (Existing, No Changes)

The EPSS cache at `backend/data/epss_cache.json` already exists and works. The existing `backend/ml/epss_substitutor.py` reads from it. No changes needed here — the cache is pre-shipped with ~250K CVE records.

---

### 2.3 — KEV Cache Builder

**Implementation:** Part of `refresh_caches.py`:

1. **`refresh_kev_cache()` function:**
   - Fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - Filter to CVEs present in `nvd_cache.json` (KEV list is ~1,100 CVEs; only keep relevant ones)
   - Write to `backend/data/kev_cache.json` in format:
     ```json
     {
       "CVE-2024-3094": {
         "known_exploited": true,
         "date_added": "2024-04-17",
         "due_date": "2024-05-08",
         "action": "...",
         "note": "..."
       }
     }
     ```

**Files changed:** `backend/scripts/refresh_caches.py` (NEW, handles all 3 sources)

---

### 2.4 — Pre-Bundled Cache Data

After running `refresh_caches.py`, three JSON files exist at:
- `backend/data/nvd_cache.json` (~500-1000 entries)
- `backend/data/epss_cache.json` (already exists)
- `backend/data/kev_cache.json` (~50-200 entries filtered)

All three are committed to the repo. The refresh script exists for periodic updates but demo mode runs entirely from local caches — no network calls during demo.

---

## Phase 3: Generator Engine

### 3.1 — Curated Scenarios (`backend/data/demo_scenarios.json`)

**File:** `backend/data/demo_scenarios.json` — JSON array of scenario objects.

**Six scenarios defined:**

| ID | Name | Findings | Demo Purpose |
|---|---|---|---|
| `ransomware-incident` | Ransomware Incident — Health Sector | 5 critical CVEs on MOVEit + file server | Show clustering, priority escalation |
| `perimeter-breach` | Perimeter Breach — Transport | 4 CVEs on Citrix ADC + marine systems | Internet-facing focus, MITRE techniques |
| `insider-exfil` | Insider Data Exfiltration — Communities | 4 CVEs on file server + casemgt app | Category 4 data, high wellbeing impact |
| `supply-chain` | Supply Chain Attack — Finance | 3 CVEs on ITSM tool + budget DB | Show medium-severity triage |
| `low-severity-hygiene` | Low-Severity Hygiene — Education | 5 CVEs on print server + student DB | Auto-resolve demo, filter by severity |
| `mixed-tier-demo` | Mixed Tier Demo (Original 7) | Re-uses 7 seed row CVEs + hosts | Backward compat, showcases all tiers |

**Scenario object format:**
```json
{
  "id": "ransomware-incident",
  "name": "Ransomware Incident — Health Sector",
  "description": "Simulates a ransomware precursor: 5 critical CVEs on MOVEit + file server",
  "findings": [
    {"hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au", "cve_id": "CVE-2023-34362"},
    {"hostname": "PRD-MOVEIT-WEB01.health.wa.gov.au", "cve_id": "CVE-2024-5806"},
    ...
  ]
}
```

---

### 3.2 — Generator Logic (`backend/integrations/demo_generator.py`)

**File:** `backend/integrations/demo_generator.py` (NEW)

**Exported functions:**

```python
def load_scenarios() -> list[dict]:
    """Load curated scenarios from demo_scenarios.json."""

def get_scenarios_list() -> list[dict]:
    """Return scenario summaries (id, name, description, finding_count) for the UI."""

def generate_scenario_findings(scenario_id: str, cmdb_hosts: dict) -> list[dict]:
    """Given a scenario ID, produce a list of Tenable-format payloads.

    For each finding in the scenario:
    1. Look up hostname in CMDB → get OS, apps, IP
    2. Look up CVE in nvd_cache.json → get CVSS, CWE, description
    3. Look up CVE in epss_cache.json → get EPSS score
    4. Look up CVE in kev_cache.json → get CISA KEV flag
    5. Construct Tenable v2 export JSON (matching the format in Scope §5.3)
    6. Return list of Tenable payload dicts
    """

def generate_random_wave(size: str, cmdb_hosts: dict) -> list[dict]:
    """Generate a batch of host-appropriate findings.

    size: "small" (5-10), "medium" (15-30), "large" (40-60)

    Algorithm:
    1. For each host in CMDB:
       a. Extract OS keyword (e.g. "Windows Server 2019")
       b. Parse registered_applications string → list of app names
       c. Query nvd_cache for CVEs matching (os + apps)
       d. Score relevance: exact product match = high, vendor match = medium, keyword in description = low
    2. Weight host selection by internet_facing (2x weight for exposed hosts)
    3. Sample findings from the matched pool with severity distribution:
       - 20% Critical (CVSS 9.0+)
       - 30% High (CVSS 7.0-8.9)
       - 30% Medium (CVSS 4.0-6.9)
       - 20% Low (CVSS <4.0)
    4. For each sampled CVE+host pair, construct Tenable payload (same as scenario mode)
    """

def generate_tenable_payload(cve_id: str, hostname: str, cmdb_host: dict,
                              nvd_entry: dict, epss_entry: dict | None,
                              kev_entry: dict | None) -> dict:
    """Construct a single Tenable v2 export JSON record.

    Uses the template from Scope §5.3. Fills in:
    - asset.fqdn, asset.hostname, asset.ipv4, asset.operating_system
    - plugin.cve, plugin.cvss3_base_score, plugin.cvss3_vector
    - plugin.description, plugin.synopsis, plugin.exploit_available
    - output (generated realistic scanner output text)
    - Picks a sensible plugin.id and plugin.family based on CVE metadata

    Keys decision: Do NOT include EPSS in the Tenable payload (Tenable doesn't provide it).
    EPSS is fetched separately by the pipeline via the existing substitution engine.
    cisa_kev is NOT in the Tenable payload — it's set via a separate lookup.
    """

def generate_realistic_scanner_output(cve_id: str, description: str) -> str:
    """Generate realistic Nessus-style scanner output for a CVE.

    Template:
    ```
    Plugin Output:
    The remote host is running {vendor} {product} version {version} which is
    affected by a critical vulnerability (CVE-{cve_id}).

    Description:
    {description}

    Risk Factor: {severity}

    Solution:
    Upgrade to version {fixed_version} or apply the vendor-supplied patch.

    References:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
    ```
    """
```

**Cache loading (internal helpers):**
```python
def _load_nvd_cache() -> dict:
    """Lazy-load nvd_cache.json, cached in module memory."""

def _load_epss_cache() -> dict:
    """Lazy-load epss_cache.json."""

def _load_kev_cache() -> dict:
    """Lazy-load kev_cache.json."""

def _load_cmdb() -> dict:
    """Lazy-load mock_cmdb.json, keyed by hostname."""
```

All caches are loaded once per process lifetime and cached in module-level variables.

**IP address assignment:**
- Each host in `mock_cmdb.json` doesn't have `ipv4` but the Tenable payload needs one.
- The generator assigns **deterministic fake IPs** based on host index: `10.{dept_index}.{host_index % 255}.{50 + (host_index % 200)}`
- This ensures the same host gets the same IP across all waves and scenarios.

---

### 3.3 — Integration with Ingest Router

**Modify `backend/routers/ingest.py`:**

Add two new endpoints:

```python
@router.get("/api/demo/scenarios")
async def list_demo_scenarios():
    """Return available demo scenarios for the UI picker."""
    from integrations.demo_generator import get_scenarios_list
    return get_scenarios_list()


@router.post("/api/demo/generate")
async def generate_demo_findings(request: Request):
    """Generate and ingest demo findings.

    Accepts JSON body:
    - {"mode": "scenario", "scenario_id": "ransomware-incident"}
    - {"mode": "random", "size": "medium"}

    Internally:
    1. Generates Tenable-format payloads via demo_generator
    2. Submits each to the existing ingest_tenable logic
    3. Returns list of CaseResponse
    """
    body = await request.json()
    mode = body.get("mode", "scenario")

    from integrations.demo_generator import (
        generate_scenario_findings,
        generate_random_wave,
    )

    if mode == "scenario":
        scenario_id = body.get("scenario_id")
        if not scenario_id:
            return JSONResponse(status_code=400, content={"detail": "scenario_id required"})
        findings = generate_scenario_findings(scenario_id)
    elif mode == "random":
        size = body.get("size", "small")
        findings = generate_random_wave(size)
    else:
        return JSONResponse(status_code=400, content={"detail": f"Unknown mode: {mode}"})

    if not findings:
        return JSONResponse(status_code=400, content={"detail": "No findings generated"})

    # Submit via the existing Tenable pipeline
    from integrations.tenable import parse_tenable_batch
    requests_list = parse_tenable_batch(findings)
    return await ingest_vulnerability_batch(requests_list)
```

**Modify `backend/main.py`:**

Add the demo mode indicator to the health endpoint:
```python
# In health() function, add:
"demo_mode": os.getenv("DEMO_MODE", "false").lower() == "true",
```

Add a `/api/demo/` route prefix or rely on the ingest router already handling it (they're just new endpoints on the existing router).

---

## Phase 4: Clear Endpoint + Archive Table

### 4.1 — Archive Table Migration (`backend/database.py`)

**Add to `init_db()`:**

```sql
CREATE TABLE IF NOT EXISTS resolved_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id INTEGER,
    vulnerability_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    cvss_vector TEXT,
    cisa_kev BOOLEAN DEFAULT FALSE,
    epss_score REAL,
    mission_prevalence TEXT,
    mission_prevalence_conf REAL,
    public_wellbeing_impact TEXT,
    public_wellbeing_conf REAL,
    tier_0_routing TEXT,
    tier_0_resolution TEXT,
    tier_1_confidence REAL,
    tier_1_exploitation_prob REAL,
    tier_1_routing TEXT,
    tier_2_text_conflict BOOLEAN DEFAULT FALSE,
    tier_2_conflict_note TEXT,
    tier_2_rag_result TEXT,
    tier_2_confidence REAL,
    tier_2_resolution_summary TEXT,
    priority_score INTEGER NOT NULL,
    risk_band TEXT NOT NULL,
    cvss_contribution INTEGER,
    epss_contribution INTEGER,
    asset_criticality_contribution INTEGER,
    exposure_contribution INTEGER,
    patch_remediation_contribution INTEGER,
    epss_substituted BOOLEAN DEFAULT FALSE,
    epss_substituted_value REAL,
    epss_substitution_confidence REAL,
    epss_substitution_reason TEXT,
    data_classification TEXT,
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
    detection_tier TEXT,
    detection_reason TEXT,
    scanner_output_raw TEXT,
    weakness_template_raw TEXT,
    advisory_ref_id TEXT,
    advisory_quote TEXT,
    investigation_notes TEXT,
    mitre_techniques_json TEXT,
    scoring_weights_json TEXT,
    asset_registry_json TEXT,
    summary_paragraphs_json TEXT,
    created_at TEXT,
    updated_at TEXT,
    last_recheck_date TEXT,
    audit_selected BOOLEAN DEFAULT FALSE,
    audit_result TEXT,
    audit_date TEXT,
    resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolution_reason TEXT DEFAULT 'demo_clear'
);
```

This mirrors `vulnerabilities` exactly plus `resolved_at` and `resolution_reason`.

### 4.2 — Clear Endpoint (`backend/routers/ingest.py`)

```python
@router.post("/api/ingest/clear")
async def clear_all_findings():
    """Archive all findings and clear the queue.

    1. Copy all rows from vulnerabilities → resolved_vulnerabilities
    2. DELETE FROM vulnerabilities
    3. Return count of archived rows + confirmation
    """
    conn = get_db()
    cursor = conn.cursor()

    # Copy rows
    cursor.execute("""
        INSERT INTO resolved_vulnerabilities (
            original_id, vulnerability_id, hostname, cvss_score, cvss_vector,
            cisa_kev, epss_score, mission_prevalence, mission_prevalence_conf,
            public_wellbeing_impact, public_wellbeing_conf,
            tier_0_routing, tier_0_resolution, tier_1_confidence,
            tier_1_exploitation_prob, tier_1_routing, tier_2_text_conflict,
            tier_2_conflict_note, tier_2_rag_result, tier_2_confidence,
            tier_2_resolution_summary, priority_score, risk_band,
            cvss_contribution, epss_contribution, asset_criticality_contribution,
            exposure_contribution, patch_remediation_contribution,
            epss_substituted, epss_substituted_value, epss_substitution_confidence,
            epss_substitution_reason, data_classification, network_zone,
            interface_type, patch_cycle, last_patch_date, last_scan_date,
            operating_system, role, business_owner, technical_owner,
            registered_applications, dependent_assets, service_account,
            detection_tier, detection_reason, scanner_output_raw,
            weakness_template_raw, advisory_ref_id, advisory_quote,
            investigation_notes, mitre_techniques_json, scoring_weights_json,
            asset_registry_json, summary_paragraphs_json,
            created_at, updated_at, last_recheck_date,
            audit_selected, audit_result, audit_date,
            resolution_reason
        )
        SELECT
            id, vulnerability_id, hostname, cvss_score, cvss_vector,
            cisa_kev, epss_score, mission_prevalence, mission_prevalence_conf,
            public_wellbeing_impact, public_wellbeing_conf,
            tier_0_routing, tier_0_resolution, tier_1_confidence,
            tier_1_exploitation_prob, tier_1_routing, tier_2_text_conflict,
            tier_2_conflict_note, tier_2_rag_result, tier_2_confidence,
            tier_2_resolution_summary, priority_score, risk_band,
            cvss_contribution, epss_contribution, asset_criticality_contribution,
            exposure_contribution, patch_remediation_contribution,
            epss_substituted, epss_substituted_value, epss_substitution_confidence,
            epss_substitution_reason, data_classification, network_zone,
            interface_type, patch_cycle, last_patch_date, last_scan_date,
            operating_system, role, business_owner, technical_owner,
            registered_applications, dependent_assets, service_account,
            detection_tier, detection_reason, scanner_output_raw,
            weakness_template_raw, advisory_ref_id, advisory_quote,
            investigation_notes, mitre_techniques_json, scoring_weights_json,
            asset_registry_json, summary_paragraphs_json,
            created_at, updated_at, last_recheck_date,
            audit_selected, audit_result, audit_date,
            'demo_clear'
        FROM vulnerabilities
    """)
    archived_count = cursor.rowcount

    # Delete all vulnerabilities
    cursor.execute("DELETE FROM vulnerabilities")
    deleted_count = cursor.rowcount

    conn.commit()
    conn.close()

    return {
        "status": "ok",
        "archived_count": archived_count,
        "deleted_count": deleted_count,
        "message": f"{archived_count} findings archived. Queue cleared."
    }
```

---

## Phase 5: Demo Mode UI

### 5.1 — Frontend Demo Controls (`frontend/js/components/demoControls.js`)

**File:** `frontend/js/components/demoControls.js` (NEW)

**Component responsibilities:**
- Renders the demo mode toggle button
- Renders the demo controls panel (scenario picker, wave generator, clear button)
- Handles API calls to `/api/demo/scenarios`, `/api/demo/generate`, `/api/ingest/clear`

**Functions:**

```javascript
var demoState = {
  active: false,
  scenarios: [],
  generating: false
};

async function fetchDemoScenarios() {
  const res = await fetch('/api/demo/scenarios');
  if (!res.ok) throw new Error('Failed to fetch scenarios');
  return res.json();
}

async function generateDemoWave(mode, payload) {
  const res = await fetch('/api/demo/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Generate failed: ' + res.status);
  return res.json();
}

async function clearAllFindings() {
  const res = await fetch('/api/ingest/clear', { method: 'POST' });
  if (!res.ok) throw new Error('Clear failed: ' + res.status);
  return res.json();
}

function toggleDemoMode() {
  demoState.active = !demoState.active;
  var panel = document.getElementById('demo-controls-panel');
  var badge = document.getElementById('demo-mode-badge');

  if (demoState.active) {
    panel.classList.remove('hidden');
    badge.classList.remove('hidden');
    renderDemoControls();
    fetchDemoScenarios().then(function(scenarios) {
      demoState.scenarios = scenarios;
      populateScenarioPicker(scenarios);
    });
  } else {
    panel.classList.add('hidden');
    badge.classList.add('hidden');
  }
}

function renderDemoControls() {
  // Inject HTML into #demo-controls-panel
  // Structure:
  //   Scenario picker dropdown
  //   Wave size dropdown (Small/Medium/Large)
  //   "Generate Wave" button
  //   "Clear All" button
}

function populateScenarioPicker(scenarios) {
  var picker = document.getElementById('scenario-picker');
  picker.innerHTML = '';
  scenarios.forEach(function(s) {
    var opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name + ' (' + s.finding_count + ' findings)';
    picker.appendChild(opt);
  });

  // Add "Random Wave" option
  var randomOpt = document.createElement('option');
  randomOpt.value = '_random_';
  randomOpt.textContent = '-- Random Wave (Host-Appropriate) --';
  picker.insertBefore(randomOpt, picker.firstChild);
}

function wireDemoEventListeners() {
  // Demo mode toggle
  document.getElementById('demo-toggle-btn').addEventListener('click', toggleDemoMode);

  // Generate wave
  document.getElementById('demo-generate-btn').addEventListener('click', async function() {
    var scenarioId = document.getElementById('scenario-picker').value;
    var size = document.getElementById('wave-size-select').value;

    demoState.generating = true;
    document.getElementById('demo-generate-btn').disabled = true;
    document.getElementById('demo-status').textContent = 'Generating...';

    try {
      var results;
      if (scenarioId === '_random_') {
        results = await generateDemoWave('random', { mode: 'random', size: size });
      } else {
        results = await generateDemoWave('scenario', { mode: 'scenario', scenario_id: scenarioId });
      }

      // Refresh queue
      var queueResponse = await fetchQueue();
      appState.queueData = queueResponse.rows;
      refreshQueue();

      document.getElementById('demo-status').textContent =
        'Generated ' + results.length + ' findings.';
    } catch (err) {
      document.getElementById('demo-status').textContent = 'Error: ' + err.message;
      console.error('Demo generate error:', err);
    } finally {
      demoState.generating = false;
      document.getElementById('demo-generate-btn').disabled = false;
    }
  });

  // Clear all
  document.getElementById('demo-clear-btn').addEventListener('click', async function() {
    if (!confirm('Archive all ' + appState.queueData.length + ' findings and clear the queue?')) {
      return;
    }
    try {
      var result = await clearAllFindings();
      appState.queueData = [];
      refreshQueue();
      document.getElementById('demo-status').textContent = result.message;
    } catch (err) {
      document.getElementById('demo-status').textContent = 'Error: ' + err.message;
    }
  });
}
```

### 5.2 — HTML Integration (`frontend/index.html`)

**Add to the `#top-bar` div (after the filter select):**
```html
<button id="demo-toggle-btn" class="demo-toggle-btn" title="Enter Demo Mode">
  <svg ...><!-- beaker/lab icon --></svg> Demo
</button>
<span id="demo-mode-badge" class="demo-mode-badge hidden">DEMO MODE</span>
```

**Add after `#metric-boxes-row`:**
```html
<div id="demo-controls-panel" class="demo-controls hidden">
  <div class="demo-controls-header">Demo Data Generator</div>
  <div class="demo-controls-body">
    <div class="demo-control-group">
      <label for="scenario-picker">Scenario</label>
      <select id="scenario-picker"></select>
    </div>
    <div class="demo-control-group">
      <label for="wave-size-select">Wave Size</label>
      <select id="wave-size-select">
        <option value="small">Small (5-10 findings)</option>
        <option value="medium" selected>Medium (15-30 findings)</option>
        <option value="large">Large (40-60 findings)</option>
      </select>
    </div>
    <div class="demo-control-buttons">
      <button id="demo-generate-btn" class="demo-generate-btn">Generate Wave</button>
      <button id="demo-clear-btn" class="demo-clear-btn danger">Clear All</button>
    </div>
    <div id="demo-status" class="demo-status"></div>
  </div>
</div>
```

**Add script include after other component scripts:**
```html
<script src="js/components/demoControls.js"></script>
```

### 5.3 — CSS Additions (`frontend/css/triagemate.css`)

Add styles for:
- `.demo-toggle-btn` — subtle button in the top bar, right-aligned, teal/accent color
- `.demo-mode-badge` — amber badge in the top bar, next to "TriageMate" title
- `.demo-controls` — collapsed panel, slide-down animation, distinct background (slight teal tint)
- `.demo-controls-header` — bold label
- `.demo-control-group` — label + select styling (match existing filter)
- `.demo-generate-btn` — primary action button
- `.demo-clear-btn.danger` — red-tinted subtle button
- `.demo-status` — small text for feedback messages

### 5.4 — App.js Integration

**In `wireEventListeners()`:** Add call to `wireDemoEventListeners()` at the end (guarded — only if demo controls exist in DOM).

---

## Phase 6: Testing

### 6.1 — Generator Unit Tests (`backend/tests/test_demo_generator.py`)

**File:** `backend/tests/test_demo_generator.py` (NEW)

**Tests:**

```python
def test_load_scenarios():
    """Scenarios JSON loads and has expected structure."""
    scenarios = load_scenarios()
    assert len(scenarios) >= 6
    for s in scenarios:
        assert "id" in s
        assert "name" in s
        assert "findings" in s
        assert len(s["findings"]) > 0

def test_generate_scenario_findings_returns_list_of_dicts():
    """Scenario generation returns valid Tenable-format list."""
    scenarios = load_scenarios()
    from integrations.demo_generator import generate_scenario_findings
    findings = generate_scenario_findings(scenarios[0]["id"])
    assert isinstance(findings, list)
    assert len(findings) > 0
    for f in findings:
        assert "asset" in f
        assert "plugin" in f
        assert "output" in f

def test_generate_tenable_payload_has_required_fields():
    """Single payload has all Tenable export fields."""
    from integrations.demo_generator import generate_tenable_payload
    payload = generate_tenable_payload(
        cve_id="CVE-2024-3094",
        hostname="PRD-MOVEIT-WEB01.health.wa.gov.au",
        ...
    )
    assert payload["asset"]["fqdn"]
    assert payload["plugin"]["cve"]
    assert payload["plugin"]["cvss3_base_score"]
    assert payload["plugin"]["description"]
    assert payload["output"]

def test_random_wave_respects_size():
    """Small/medium/large produce expected count ranges."""
    from integrations.demo_generator import generate_random_wave
    small = generate_random_wave("small")
    medium = generate_random_wave("medium")
    large = generate_random_wave("large")
    assert 5 <= len(small) <= 10
    assert 15 <= len(medium) <= 30
    assert 40 <= len(large) <= 60

def test_clear_endpoint_archives_rows():
    """POST /api/ingest/clear archives and empties queue."""
    # Requires FastAPI TestClient

def test_demo_generate_endpoint_returns_case_responses():
    """POST /api/demo/generate returns valid CaseResponse list."""
    # Requires FastAPI TestClient

def test_scenario_findings_map_to_valid_ingest_requests():
    """Every scenario finding produces a parseable Tenable record."""
    from integrations.demo_generator import generate_scenario_findings
    from integrations.tenable import parse_tenable_batch
    for scenario in load_scenarios():
        findings = generate_scenario_findings(scenario["id"])
        ingests = parse_tenable_batch(findings)
        assert len(ingests) == len(findings)
        for ir in ingests:
            assert ir.vulnerability_id
            assert ir.hostname
            assert ir.cvss_score > 0
```

---

## Phase 7: Audit Checklist

After implementation, Audit Team verifies:

| # | Check | Method |
|---|---|---|
| 7.1 | `mock_cmdb.json` has 25-30 hosts with all 15 fields | Read file, count |
| 7.2 | All hosts resolve via `get_asset_context()` | `curl` + backend log inspection |
| 7.3 | Pre-tier model retrained successfully | Run `train_pre_tier.py`, check accuracy |
| 7.4 | `KNOWN_TAGS` includes all 28 hosts | Read `pre_tier.py` |
| 7.5 | `nvd_cache.json` has 500+ entries | `python3 -c "import json; print(len(json.load(open('backend/data/nvd_cache.json'))))"` |
| 7.6 | `kev_cache.json` has 50+ entries | Same method |
| 7.7 | `refresh_caches.py` runs without errors | `python -m scripts.refresh_caches --source kev` |
| 7.8 | Generator produces valid Tenable payloads | Run `test_demo_generator.py` |
| 7.9 | `POST /api/demo/generate` with scenario → returns CaseResponse list | curl |
| 7.10 | `POST /api/demo/generate` with random → returns CaseResponse list | curl |
| 7.11 | Generated findings appear in queue with real scores | curl queue, verify not all same score |
| 7.12 | `POST /api/ingest/clear` archives + clears queue | curl clear, verify queue empty |
| 7.13 | Clear counts match; `resolved_vulnerabilities` has the rows | SQLite query |
| 7.14 | Demo toggle renders in frontend | Browser |
| 7.15 | Scenario picker populates from API | Browser |
| 7.16 | "Generate Wave" triggers queue refresh | Browser |
| 7.17 | "Clear All" archives + empties visually | Browser |
| 7.18 | 7 seed rows still score within ±3 of expected (94, 87, 71, 55, 63, 41, 22) | curl + compare |
| 7.19 | All 20+ existing tests still pass | `pytest backend/tests/ -v` |
| 7.20 | New tests pass | `pytest backend/tests/test_demo_generator.py -v` |
| 7.21 | Unknown hostname ingest still works (defaults) | curl with made-up hostname |
| 7.22 | `/docs` shows new endpoints: `/api/demo/scenarios`, `/api/demo/generate`, `/api/ingest/clear` | Browser |

---

## Dependency Order (Strike Team Execution)

```
Day 1:
  ┌── 1.1 Mock CMDB JSON + cmdb.py adapter ────── (1 hr)
  ├── 1.2 Pre-tier training data + retrain ─────── (1 hr, after 1.1)
  ├── 2.3 KEV cache script ─────────────────────── (0.5 hr, parallel)
  └── 2.1 NVD cache script ─────────────────────── (2 hrs, parallel with 1.1/1.2)

Day 2:
  ├── 2.4 Run all cache scripts (populate data) ── (0.5 hr, needs 2.1+2.3)
  ├── 3.1 Scenarios JSON ───────────────────────── (1 hr, needs cache data)
  └── 3.2 Generator logic ──────────────────────── (3 hrs, needs 3.1 + caches)

Day 3:
  ├── 4.1 Archive table migration ──────────────── (0.5 hr)
  ├── 4.2 Clear endpoint ───────────────────────── (0.5 hr)
  ├── 5.1 Demo controls JS ─────────────────────── (1.5 hrs)
  ├── 5.2 HTML integration ─────────────────────── (0.25 hr)
  ├── 5.3 CSS additions ────────────────────────── (0.25 hr)
  └── 6.1 Generator tests ──────────────────────── (1.5 hrs)
```

**Parallel opportunities:**
- 1.1 + 2.1 + 2.3 all start simultaneously (no shared dependencies)
- 3.1 + cache population can run in parallel
- 4.1 + 4.2 are sequential (migration before endpoint)
- 5.1 + 5.2 + 5.3 can run in parallel
- 6.1 can start as soon as 3.2 is done (generator tests don't need UI)

**Total: ~13 hrs** across 3 days.

---

## Files Summary

| File | Action | Phase |
|---|---|---|
| `backend/data/mock_cmdb.json` | NEW — 28 host objects | 1.1 |
| `backend/integrations/cmdb.py` | MODIFY — file-based lookup | 1.1 |
| `backend/ml/pretier_training_data.json` | MODIFY — +28 records | 1.2 |
| `backend/pipeline/pre_tier.py` | MODIFY — KNOWN_TAGS expanded | 1.2 |
| `backend/ml/pre_tier_model.pkl` | REGENERATE — retrained | 1.2 |
| `backend/scripts/__init__.py` | NEW — package init | 2.1 |
| `backend/scripts/refresh_caches.py` | NEW — unified refresh CLI | 2.1+2.3 |
| `backend/data/nvd_cache.json` | NEW — 500-1000 NVD entries | 2.1 |
| `backend/data/kev_cache.json` | NEW — 50-200 KEV entries | 2.3 |
| `backend/data/demo_scenarios.json` | NEW — 6 curated scenarios | 3.1 |
| `backend/integrations/demo_generator.py` | NEW — generator engine | 3.2 |
| `backend/routers/ingest.py` | MODIFY — `/api/demo/*` + `/api/ingest/clear` | 3.3+4.2 |
| `backend/database.py` | MODIFY — `resolved_vulnerabilities` table | 4.1 |
| `backend/main.py` | MODIFY — health returns `demo_mode` | 4.3 |
| `frontend/js/components/demoControls.js` | NEW — demo controls component | 5.1 |
| `frontend/index.html` | MODIFY — toggle + controls panel | 5.2 |
| `frontend/css/triagemate.css` | MODIFY — demo UI styles | 5.3 |
| `backend/tests/test_demo_generator.py` | NEW — 7+ tests | 6.1 |
