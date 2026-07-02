# Demo Data Generator — Implementation Plan (Revision 1)

> **Based on:** `DEMO_DATA_GENERATOR_SCOPE.md` (Intel Team, 1 July 2026)
> **External Audit:** 2 BLOCKERs, 2 HIGH findings, 15 MEDIUM/LOW concerns identified. All addressed in this revision.
> **Revised estimate:** ~21 hrs (was 13; +8 hrs for BLOCKER fixes, parser robustness, gating, tests)
> **Current state:** Codebase studied. 5 dependency phases, each broken into sub-tasks with exact file paths, function signatures, and implementation logic.
> **Convention:** Match existing patterns — `joblib` for ML artifacts, `json` for data files, vanilla JS for frontend, FastAPI routers for endpoints, `logging.getLogger()` for logs.

---

## Auditor Findings Summary

| Finding | Severity | Resolution |
|---|---|---|
| **B5** — `cisa_kev` never injected; KEV cache dead data | **BLOCKER** | New `inject_enrichment()` in demo_generator.py patches KEV + EPSS into IngestRequest before ingest (Phase 3.3) |
| **D5** — Pipeline hits live NVD, not `nvd_cache.json` | **BLOCKER** | New `_read_from_demo_cache()` in nvd.py; when `DEMO_MODE=true`, reads from `nvd_cache.json` instead of live API (Phase 2.5 — NEW) |
| **B4** — `exploitdb_has_poc`/`metasploit_has_payload` dead in cache | **HIGH** | Fixed by D5 — patch-level references_raw synthesis makes exploitdb/metasploit helpers work from cache |
| **F3** — Audit checklist missing critical checks | **HIGH** | 9 missing checks added to Phase 7 checklist |
| **A3** — No deduplication on repeated Generate | MEDIUM | `generate_random_wave()` samples without replacement against current queue; "Generate" disabled during flight |
| **A4** — `mixed-tier-demo` duplicates seed rows with wrong scores | MEDIUM | Scenario **dropped**. Seed rows ARE the mixed-tier demo. No generation needed. |
| **B1** — Missing `patch_publication_date` → all `vendor_patch_status=0` | MEDIUM | Added to Tenable payload template + generator |
| **C1** — `registered_applications` parser fragile | MEDIUM | Explicit normaliser with 28-host test fixture; OS-level fallback |
| **C4** — Low-severity scenario CVEs not validated <4.0 | MEDIUM | CVEs constrained in scenario definition; audit check added |
| **D3** — No `DEMO_MODE` gate on endpoints or cmdb | MEDIUM | `DEMO_MODE` env var gates cmdb file-load and all demo/clear endpoints |
| **E2** — Clear endpoint no rate limit | MEDIUM | Server-side rate limit (1 per 30s); `confirm_token` param |
| **G3** — 13h estimate under-scoped | — | Revised to ~21 hrs |

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

3. **Modify `_stub_lookup()`** in `cmdb.py:178` — Check file CMDB first (only if `DEMO_MODE=true`), fall through to `KNOWN_HOSTS` dict, then defaults:
   ```python
   def _stub_lookup(hostname: str) -> dict:
       demo_mode = os.getenv("DEMO_MODE", "").lower() == "true"
       if demo_mode:
           file_db = _load_file_cmdb()
           if hostname in file_db:
               return dict(file_db[hostname])
       if hostname in KNOWN_HOSTS:
           return dict(KNOWN_HOSTS[hostname])
       return { /* existing defaults */ }
   ```
   This preserves backward compat — the 7 originals are in both places. When `DEMO_MODE` is unset, file CMDB is never loaded, preventing mock hosts from polluting a production database. When `DEMO_MODE=true`, the expanded 28-host CMDB is active.

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

### 2.5 — Cache-to-Pipeline Wiring (`backend/integrations/nvd.py`)

**Rationale (External Auditor BLOCKER D5):** The plan's `nvd_cache.json` is consumed only by the demo generator to build Tenable payloads. The ingest pipeline (`build_feature_vector`, `get_cwe`, `exploitdb.has_poc`, `metasploit.has_payload`) all call live `nvd.get_nvd_data()` — which hits the NVD API over HTTP. The `nvd_cache.json` enrichment fields (`cwe_class`, `nvd_reference_count`, `vulnerability_age_days`, `cvss_exploitability_sub`, `cvss_impact_sub`, `patch_available`) are completely dead. An offline demo produces degenerate zero-valued XGBoost features and empty CWE → no MITRE techniques. This section adds a file-backed read path so the pipeline consumes the same cache the generator builds.

**Modify `backend/integrations/nvd.py`:**

Add at module level:
```python
import os as _os
_DEMO_MODE = _os.getenv("DEMO_MODE", "").lower() == "true"
_DEMO_CACHE_PATH = Path(__file__).parent.parent / "data" / "nvd_cache.json"
_DEMO_CACHE: dict | None = None

def _load_demo_cache() -> dict:
    """Lazy-load nvd_cache.json, cached in module memory."""
    global _DEMO_CACHE
    if _DEMO_CACHE is not None:
        return _DEMO_CACHE
    try:
        with open(_DEMO_CACHE_PATH) as f:
            _DEMO_CACHE = json.load(f)
        logger.info("Loaded %d CVE entries from nvd_cache.json for demo mode", len(_DEMO_CACHE))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Demo cache not loaded: %s", e)
        _DEMO_CACHE = {}
    return _DEMO_CACHE

def _read_from_demo_cache(cve_id: str) -> dict | None:
    """Read a CVE entry from nvd_cache.json and convert to pipeline dict shape.

    Translates the flat cache schema (scope §3.1) to the dict shape
    get_nvd_data() returns, so all downstream consumers work unchanged.

    Returns None if the CVE is not in the cache.
    """
    cache = _load_demo_cache()
    entry = cache.get(cve_id)
    if entry is None:
        return None

    # Synthesize references_raw so exploitdb.has_poc() and
    # metasploit.has_payload() work from cache data
    references_raw = []
    if entry.get("exploitdb_has_poc"):
        references_raw.append({"url": f"https://www.exploit-db.com/search?cve={cve_id}", "tags": ["Exploit"]})
    if entry.get("metasploit_has_payload"):
        references_raw.append({"url": f"https://www.rapid7.com/db/search?q={cve_id}", "tags": ["Exploit", "Metasploit"]})

    return {
        "cwe_class": entry.get("cwe_class", ""),
        "nvd_reference_count": entry.get("nvd_reference_count", 0),
        "vulnerability_age_days": entry.get("vulnerability_age_days", 0),
        "cvss_exploitability_sub": entry.get("cvss_exploitability_sub", 0.0),
        "cvss_impact_sub": entry.get("cvss_impact_sub", 0.0),
        "patch_available": entry.get("patch_available", False),
        "references_raw": references_raw,
    }
```

**Modify `get_nvd_data()`** in `nvd.py:115` — add demo-mode check at top:
```python
def get_nvd_data(cve_id: str) -> dict:
    """Fetch NVD enrichment data for a CVE with 24h in-memory TTL cache.

    In DEMO_MODE, reads from nvd_cache.json instead of the live NVD API.
    Falls through to live API if the CVE is not in the demo cache.
    """
    # Demo mode: read from file cache first
    if _DEMO_MODE:
        cached = _read_from_demo_cache(cve_id)
        if cached is not None:
            # Still update the in-memory TTL cache so nvd_freshness works
            now = time.time()
            _CACHE[cve_id] = (now, cached)
            return dict(cached)
        # CVE not in demo cache — fall through to live API
        logger.warning("CVE %s not in nvd_cache.json — falling back to live NVD", cve_id)

    # Original live-path code follows...
    now = time.time()
    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < _TTL_SECONDS:
            return dict(data)
    # ... rest of existing function unchanged
```

**Impact on other integrations:**
- `integrations/exploitdb.has_poc()` calls `get_nvd_data()` → reads `references_raw` → checks for "Exploit" tag → works from synthetic references
- `integrations/metasploit.has_payload()` same pattern — checks for "Metasploit" tag
- `ingest_helpers.build_feature_vector()` calls `get_nvd_data()` directly → gets all fields from cache
- `ingest_cwe.get_cwe()` calls `get_nvd_data()` → gets `cwe_class` from cache → MITRE techniques resolve

**Backward compat:** When `DEMO_MODE` is unset, the function behaves exactly as before (live API only). The `_read_from_demo_cache` path is only entered when the env var is set.

**Files changed:** `backend/integrations/nvd.py` (modify `get_nvd_data`, add `_read_from_demo_cache`, `_load_demo_cache`)

**Effort:** ~3 hrs (was missing from original plan; now on critical path)

---

## Phase 3: Generator Engine

### 3.1 — Curated Scenarios (`backend/data/demo_scenarios.json`)

**File:** `backend/data/demo_scenarios.json` — JSON array of scenario objects.

**Six scenarios defined:**

| ID | Name | Findings | Demo Purpose |
|---|---|---|---|
| `ransomware-incident` | Ransomware Incident — Health Sector | 5 critical CVEs on MOVEit + file server | Show clustering, priority escalation, KEV auto-resolve |
| `perimeter-breach` | Perimeter Breach — Transport | 4 CVEs on Citrix ADC + marine systems | Internet-facing focus, MITRE techniques, KEV auto-resolve |
| `insider-exfil` | Insider Data Exfiltration — Communities | 4 CVEs on file server + casemgt app | Category 4 data, high wellbeing impact |
| `supply-chain` | Supply Chain Attack — Finance | 3 CVEs on ITSM tool + budget DB | Show medium-severity triage |
| `low-severity-hygiene` | Low-Severity Hygiene — Education | 5 CVEs on print server + student DB | Auto-resolve demo, filter by severity |

**NOT included: `mixed-tier-demo`.** The 7 seed rows from `seed_data.py` already serve as the mixed-tier demo — they are inserted at startup, score correctly (94, 87, 71, 55, 63, 41, 22), and cover all four tiers. Regenerating them via the generator would create duplicate rows with degraded scores (because `cisa_kev` and `epss_score` flow through different paths). The seed rows are always present; no scenario needed. If the queue was cleared, re-run `python seed_data.py`.

**Scenario CVE validation rules:**
- Every CVE in `ransomware-incident` and `perimeter-breach` MUST be in `kev_cache.json` (KEV-listed) so the deterministic "Very Critical" auto-resolve fires.
- Every CVE in `low-severity-hygiene` MUST have `cvss_v3_score < 4.0` in `nvd_cache.json` so auto-resolve "low" fires.
- Every CVE's `vendor`/`product` in `nvd_cache.json` MUST be compatible with the target host's `operating_system` and `registered_applications` (no Linux-only CVEs on Windows hosts).
- **Intel Team must review and sign off the exact CVE list for each scenario before `demo_scenarios.json` is written.** This is a pre-build gate.
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

def generate_random_wave(size: str, existing_queue: list[dict] | None = None) -> list[dict]:
    """Generate a batch of host-appropriate findings.

    size: "small" (5-10), "medium" (15-30), "large" (40-60)

    Deduplication: If existing_queue is provided, samples without replacement
    against current (vulnerability_id, hostname) pairs. Repeated generates
    will not produce duplicates unless the pool is exhausted.

    Algorithm:
    1. For each host in CMDB:
       a. Extract OS keyword via _extract_os_keyword() (e.g. "Windows Server 2019" → "windows")
       b. Parse registered_applications via _parse_applications() (normalised vendor/product list)
       c. Query nvd_cache for CVEs matching (os + apps)
       d. Score relevance: exact product match = 3, vendor match = 2, OS match = 1, keyword in description = 0.5
       e. If a host yields zero matches, fall back to OS-level CVEs (e.g., Windows→windows CVEs)
    2. Weight host selection by internet_facing (2x weight for exposed hosts)
    3. Sample findings from the matched pool with severity distribution:
       - 10% Critical (CVSS 9.0+) — bias toward internet-facing
       - 20% High (CVSS 7.0-8.9)
       - 40% Medium (CVSS 4.0-6.9)
       - 30% Low (CVSS <4.0)
       This matches real enterprise scan distributions better than the original 20/30/30/20.
    4. Exclude any (cve_id, hostname) already in existing_queue
    5. For each sampled CVE+host pair, construct Tenable payload (same as scenario mode)
    """

def _extract_os_keyword(operating_system: str) -> str:
    """Extract a normalised OS keyword from the CMDB OS string.

    Examples:
        "Windows Server 2019 Standard" → "windows"
        "Ubuntu 22.04.3 LTS" → "linux"
        "Citrix NetScaler ADC VPX 13.1-49.13 (FreeBSD-based)" → "freebsd"
    """
    os_lower = operating_system.lower()
    if "windows" in os_lower:
        return "windows"
    if any(distro in os_lower for distro in ("ubuntu", "debian", "centos", "rhel", "linux")):
        return "linux"
    if "freebsd" in os_lower:
        return "freebsd"
    if "solaris" in os_lower:
        return "solaris"
    return os_lower.split()[0] if os_lower else "unknown"

def _parse_applications(registered_apps: str) -> list[dict]:
    """Parse the registered_applications string into a list of normalised
    {name, vendor, product} dicts for NVD cache matching.

    Examples:
        "Progress MOVEit Transfer 2023.0.0, IIS 10.0"
        → [{"name": "Progress MOVEit Transfer", "vendor": "progress", "product": "moveit transfer"},
           {"name": "IIS", "vendor": "microsoft", "product": "internet information services"}]

    Normalisation:
        1. Split on commas
        2. Strip version tokens (\\d+(\\.\\d+)*)
        3. Lowercase
        4. Map known product aliases to canonical NVD vendor/product names
    """
    if not registered_apps:
        return []

    import re
    apps = []
    KNOWN_ALIASES = {
        "iis": ("microsoft", "internet information services"),
        "apache httpd": ("apache", "http server"),
        "confluence": ("atlassian", "confluence"),
        "postgresql": ("postgresql", "postgresql"),
        "connectwise screenconnect": ("connectwise", "screenconnect"),
        "papercut mf": ("papercut", "papercut mf"),
        "papercut": ("papercut", "papercut mf"),
        "manageengine servicedesk plus": ("zoho", "manageengine servicedesk plus"),
        "servicedesk plus": ("zoho", "manageengine servicedesk plus"),
        "moveit transfer": ("progress", "moveit transfer"),
        "moveit": ("progress", "moveit transfer"),
        "microsoft office": ("microsoft", "office"),
        "microsoft sql server": ("microsoft", "sql server"),
        "citrix gateway": ("citrix", "gateway"),
        "citrix adc": ("citrix", "application delivery controller"),
        "netscaler": ("citrix", "netscaler"),
        "java": ("oracle", "jre"),
    }

    for segment in registered_apps.split(","):
        stripped = re.sub(r"\d+(\.\d+)*(-\d+)?", "", segment).strip()
        clean = re.sub(r"\s+", " ", stripped).lower()
        if not clean or len(clean) < 3:
            continue

        # Check known aliases
        matched = False
        for alias_key, (vendor, product) in KNOWN_ALIASES.items():
            if alias_key in clean or clean in alias_key:
                apps.append({"name": segment.strip(), "vendor": vendor, "product": product})
                matched = True
                break
        if not matched:
            # Best-effort: treat as vendor=product=clean
            apps.append({"name": segment.strip(), "vendor": clean, "product": clean})

    return apps

def generate_tenable_payload(cve_id: str, hostname: str, cmdb_host: dict,
                              nvd_entry: dict, epss_entry: dict | None,
                              kev_entry: dict | None) -> dict:
    """Construct a single Tenable v2 export JSON record.

    Uses the template from Scope §5.3. Fills in:
    - asset.fqdn, asset.hostname, asset.ipv4, asset.operating_system
    - plugin.cve, plugin.cvss3_base_score, plugin.cvss3_vector
    - plugin.description, plugin.synopsis, plugin.exploit_available,
      plugin.exploit_framework_metasploit, plugin.has_patch,
      plugin.patch_publication_date  ← REQUIRED for vendor_patch_status
    - output (generated realistic scanner output text)

    Keys decisions:
    - EPSS is NOT in the Tenable payload — injected post-parse via inject_enrichment()
    - cisa_kev is NOT in the Tenable payload — injected post-parse via inject_enrichment()
    - plugin.id is a stable hash of the CVE ID (cosmetic, not used by pipeline)
    - plugin.family derived from CWE class (cosmetic)
    - patch_publication_date set to a recent date when has_patch is true
      (required by _compute_vendor_patch_status() which checks BOTH fields)
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
- The generator assigns **deterministic fake IPs** via a stable hash of the hostname:
  ```python
  # Dept index mapped explicitly (not from JSON position)
  DEPT_NETWORKS = {
      "health": 1, "transport": 2, "education": 3, "communities": 4,
      "wapol": 5, "finance": 6, "justice": 7, "water": 8,
      "sharedservices": 9, "parliament": 10, "dpird": 11, "dfes": 12,
  }

  def _assign_ip(hostname: str) -> str:
      """Stable, deterministic IP per hostname."""
      dept = _extract_department(hostname)  # parse from domain
      dept_idx = DEPT_NETWORKS.get(dept, 0)
      host_hash = abs(hash(hostname)) % 255
      return f"10.{dept_idx}.{host_hash}.50"
  ```
- This ensures the same host gets the same IP across all waves, scenarios, and runs. Hash-based (not array-position-based) so re-ordering `mock_cmdb.json` does not change IPs.

---

### 3.3 — Enrichment Injection + API Integration

**Rationale (External Auditor BLOCKER B5):** `parse_tenable_finding()` hardcodes `cisa_kev=False` and `epss_score=None`. The KEV and EPSS caches exist but are never injected into the IngestRequest before ingest. Without KEV, no generated finding can trigger Tier 0's "Very Critical" deterministic auto-resolve — the headline demo behaviour. This section adds an explicit injection step.

**New function in `backend/integrations/demo_generator.py`:**

```python
def inject_enrichment(ingest_requests: list) -> list:
    """Patch IngestRequest objects with KEV and EPSS from local caches.

    Args:
        ingest_requests: List of IngestRequest produced by parse_tenable_batch()

    Returns:
        Same list, mutated in place, with cisa_kev and epss_score patched
        where cache data is available.
    """
    kev = _load_kev_cache()
    epss = _load_epss_cache()

    for ir in ingest_requests:
        cve_id = ir.vulnerability_id
        if cve_id in kev:
            ir.cisa_kev = True
        if cve_id in epss:
            ir.epss_score = epss[cve_id].get("epss", None)

    return ingest_requests
```

**New/modified endpoints in `backend/routers/ingest.py`:**

All demo endpoints are gated behind `DEMO_MODE=true`. When unset, they return 404.

```python
import os

def _demo_only():
    """Return 404 if DEMO_MODE is not enabled."""
    if os.getenv("DEMO_MODE", "").lower() != "true":
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@router.get("/api/demo/scenarios")
async def list_demo_scenarios():
    """Return available demo scenarios for the UI picker."""
    gate = _demo_only()
    if gate:
        return gate
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
    2. Parses to IngestRequest via parse_tenable_batch
    3. Injects KEV + EPSS enrichment from local caches (inject_enrichment)
    4. Submits to ingest_vulnerability_batch
    5. Returns list of CaseResponse
    """
    gate = _demo_only()
    if gate:
        return gate

    body = await request.json()
    mode = body.get("mode", "scenario")

    from integrations.demo_generator import (
        generate_scenario_findings,
        generate_random_wave,
        inject_enrichment,
    )

    if mode == "scenario":
        scenario_id = body.get("scenario_id")
        if not scenario_id:
            return JSONResponse(status_code=400, content={"detail": "scenario_id required"})
        findings = generate_scenario_findings(scenario_id)
    elif mode == "random":
        size = body.get("size", "small")
        # Read current queue to avoid duplicates
        from database import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT vulnerability_id, hostname FROM vulnerabilities")
        existing = [{"vulnerability_id": r[0], "hostname": r[1]} for r in cursor.fetchall()]
        conn.close()
        findings = generate_random_wave(size, existing_queue=existing)
    else:
        return JSONResponse(status_code=400, content={"detail": f"Unknown mode: {mode}"})

    if not findings:
        return JSONResponse(status_code=400, content={"detail": "No findings generated"})

    # Parse Tenable payloads → IngestRequest list
    from integrations.tenable import parse_tenable_batch
    requests_list = parse_tenable_batch(findings)

    # Inject KEV + EPSS from local caches
    requests_list = inject_enrichment(requests_list)

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
# Server-side rate limit: max 1 clear per 30 seconds
_CLEAR_LAST_TIME: float = 0.0
_CLEAR_MIN_INTERVAL: float = 30.0  # seconds

@router.post("/api/ingest/clear")
async def clear_all_findings():
    """Archive all findings and clear the queue.

    Gated behind DEMO_MODE=true (returns 404 otherwise).
    Rate-limited to prevent abuse (1 per 30s).

    1. Copy all rows from vulnerabilities → resolved_vulnerabilities (atomic)
    2. DELETE FROM vulnerabilities
    3. Return count of archived rows + confirmation
    """
    gate = _demo_only()
    if gate:
        return gate

    global _CLEAR_LAST_TIME
    import time as _time
    now = _time.time()
    if now - _CLEAR_LAST_TIME < _CLEAR_MIN_INTERVAL:
        return JSONResponse(
            status_code=429,
            content={"detail": f"Rate limited. Try again in {int(_CLEAR_MIN_INTERVAL - (now - _CLEAR_LAST_TIME))}s."}
        )
    _CLEAR_LAST_TIME = now

    conn = get_db()

    # Wrapped in explicit transaction for atomicity
    with conn:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO resolved_vulnerabilities (
                original_id, vulnerability_id, hostname, cvss_score, cvss_vector,
                ...all columns..., resolution_reason
            )
            SELECT id, vulnerability_id, hostname, cvss_score, cvss_vector,
                   ...all columns..., 'demo_clear'
            FROM vulnerabilities
        """)
        archived_count = cursor.rowcount

        cursor.execute("DELETE FROM vulnerabilities")
        deleted_count = cursor.rowcount

        if archived_count != deleted_count:
            raise RuntimeError(f"Clear mismatch: archived {archived_count} but deleted {deleted_count}")

    conn.close()

    return {
        "status": "ok",
        "archived_count": archived_count,
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

**Important — X-API-Key compatibility (E1):** The demo controls (and existing `api.js`) do not send the `X-API-Key` header. If `TRIAGEMATE_API_KEY` is set, both the existing UI and demo controls will receive 401s. **For the demo, run with auth unset (localhost).** This is consistent with how the rest of the frontend works — it's a pre-existing gap, not introduced by this plan. If auth is needed in future, `api.js` should be enhanced with a shared `apiFetch()` wrapper that reads the key from a meta tag or `localStorage`.

---

## Phase 6: Testing

### 6.1 — Generator Unit Tests (`backend/tests/test_demo_generator.py`)

**File:** `backend/tests/test_demo_generator.py` (NEW)

**Tests:**

```python
# ─── Structural tests ────────────────────────────────────────────────

def test_load_scenarios():
    """Scenarios JSON loads and has expected structure (5 scenarios, not 6)."""
    scenarios = load_scenarios()
    assert len(scenarios) == 5  # mixed-tier-demo dropped
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
    """Single payload has all Tenable export fields including patch_publication_date."""
    from integrations.demo_generator import generate_tenable_payload
    payload = generate_tenable_payload(...)
    assert payload["asset"]["fqdn"]
    assert payload["plugin"]["cve"]
    assert payload["plugin"]["cvss3_base_score"]
    assert payload["plugin"]["description"]
    assert payload["plugin"]["has_patch"] is not None
    assert "patch_publication_date" in payload["plugin"]  # B1 fix
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

def test_scenario_findings_map_to_valid_ingest_requests():
    """Every scenario finding produces a parseable Tenable → IngestRequest pipeline."""
    from integrations.demo_generator import generate_scenario_findings, inject_enrichment
    from integrations.tenable import parse_tenable_batch
    for scenario in load_scenarios():
        findings = generate_scenario_findings(scenario["id"])
        ingests = parse_tenable_batch(findings)
        ingests = inject_enrichment(ingests)  # B5 — verify injection works
        assert len(ingests) == len(findings)
        for ir in ingests:
            assert ir.vulnerability_id
            assert ir.hostname
            assert ir.cvss_score > 0

# ─── B5: KEV injection test ─────────────────────────────────────────

def test_kev_injection_marks_cisa_kev_true_for_known_cves():
    """KEV-listed CVEs in scenario findings get cisa_kev=True after inject_enrichment."""
    from integrations.demo_generator import generate_scenario_findings, inject_enrichment
    from integrations.tenable import parse_tenable_batch

    # ransomware-incident should have KEV CVEs
    findings = generate_scenario_findings("ransomware-incident")
    ingests = parse_tenable_batch(findings)
    ingests = inject_enrichment(ingests)

    kev_found = any(ir.cisa_kev for ir in ingests)
    assert kev_found, "No CVE in ransomware-incident was KEV-listed — injection failed or scenario is misconfigured"

# ─── D5: offline NVD enrichment test ────────────────────────────────

def test_demo_cache_nvd_lookup_returns_cwe_class():
    """When DEMO_MODE=true, get_nvd_data() reads from nvd_cache.json."""
    os.environ["DEMO_MODE"] = "true"
    try:
        from integrations.nvd import get_nvd_data
        # Pick a CVE known to be in nvd_cache.json
        data = get_nvd_data("CVE-2023-34362")
        assert data["cwe_class"] != "", "CWE class is empty — cache not being read"
        assert data["nvd_reference_count"] > 0
        assert "references_raw" in data
    finally:
        del os.environ["DEMO_MODE"]

def test_demo_cache_synthesizes_references_for_exploits():
    """When cache has exploitdb_has_poc=True, references_raw has Exploit tag."""
    os.environ["DEMO_MODE"] = "true"
    try:
        from integrations.nvd import get_nvd_data
        from integrations.exploitdb import has_poc
        # Pick a CVE with exploitdb_has_poc=True in the cache
        result = has_poc("CVE-2023-34362")
        assert result is True, "exploitdb.has_poc() returned False from demo cache"
    finally:
        del os.environ["DEMO_MODE"]

# ─── A3: deduplication test ─────────────────────────────────────────

def test_random_wave_deduplicates_against_existing_queue():
    """Repeated generate excludes CVEs already in queue."""
    from integrations.demo_generator import generate_random_wave
    first = generate_random_wave("small")
    existing = [{"vulnerability_id": f["plugin"]["cve"][0],
                  "hostname": f["asset"]["fqdn"]} for f in first]
    second = generate_random_wave("small", existing_queue=existing)
    # All second-wave findings should be novel
    first_pairs = {(f["plugin"]["cve"][0], f["asset"]["fqdn"]) for f in first}
    second_pairs = {(f["plugin"]["cve"][0], f["asset"]["fqdn"]) for f in second}
    assert first_pairs.isdisjoint(second_pairs), "Duplicate findings in second wave"

# ─── B1: vendor_patch_status test ───────────────────────────────────

def test_generated_finding_with_patch_has_vendor_patch_status_1():
    """When nvd_cache says patch_available=True AND patch_publication_date is set,
    _compute_vendor_patch_status() returns 1."""
    from integrations.tenable import _compute_vendor_patch_status
    plugin = {"has_patch": True, "patch_publication_date": "2026-01-01"}
    assert _compute_vendor_patch_status(plugin) == 1

def test_tenable_payload_includes_patch_publication_date():
    """Every generated finding with has_patch has a non-empty patch_publication_date."""
    from integrations.demo_generator import generate_tenable_payload
    # Test with a nvd_cache entry that has patch_available=True
    payload = generate_tenable_payload("CVE-2023-34362", "PRD-MOVEIT-WEB01.health.wa.gov.au", ...)
    if payload["plugin"]["has_patch"]:
        assert payload["plugin"]["patch_publication_date"], "patch_publication_date missing"

# ─── C1: app parser test ────────────────────────────────────────────

def test_parse_applications_normalises_moveit():
    """Progress MOVEit Transfer normalises to (progress, moveit transfer)."""
    from integrations.demo_generator import _parse_applications
    apps = _parse_applications("Progress MOVEit Transfer 2023.0.0")
    assert any(a["vendor"] == "progress" for a in apps)
    assert any(a["product"] == "moveit transfer" for a in apps)

def test_parse_applications_normalises_iis():
    """IIS normalises to microsoft internet information services."""
    from integrations.demo_generator import _parse_applications
    apps = _parse_applications("IIS 10.0")
    assert any(a["vendor"] == "microsoft" for a in apps)

def test_all_cmdb_hosts_yield_at_least_one_application():
    """Every host in mock_cmdb.json has parseable registered_applications."""
    import json
    from integrations.demo_generator import _parse_applications
    cmdb = json.load(open("data/mock_cmdb.json"))
    for host in cmdb:
        apps = _parse_applications(host.get("registered_applications", ""))
        assert len(apps) > 0, f"Host {host['hostname']} yielded zero apps"

# ─── C4: low-severity auto-resolve test ─────────────────────────────

def test_low_severity_scenario_cves_are_under_cvss_4():
    """All CVEs in low-severity-hygiene scenario have cvss_v3_score < 4.0."""
    from integrations.demo_generator import load_scenarios, _load_nvd_cache
    nvd = _load_nvd_cache()
    scenarios = load_scenarios()
    for s in scenarios:
        if s["id"] == "low-severity-hygiene":
            for f in s["findings"]:
                cve_entry = nvd.get(f["cve_id"], {})
                score = cve_entry.get("cvss_v3_score", 99)
                assert score < 4.0, f"CVE {f['cve_id']} has CVSS {score} — won't auto-resolve low"

# ─── D3: DEMO_MODE gating test ──────────────────────────────────────

def test_demo_endpoints_return_404_when_demo_mode_off():
    """When DEMO_MODE is unset, /api/demo/* and /api/ingest/clear return 404."""
    # Requires FastAPI TestClient

def test_demo_mode_off_cmdb_does_not_load_file():
    """When DEMO_MODE is unset, _stub_lookup does not read mock_cmdb.json."""
    # Requires FastAPI TestClient

# ─── D2: clear atomicity test ────────────────────────────────────────

def test_clear_endpoint_is_atomic():
    """POST /api/ingest/clear archives and deletes same count."""
    # Requires FastAPI TestClient
```

**Effort:** ~2 hrs (was 1.5; +0.5 for the 7 new BLOCKER-targeted tests)

---

## Phase 7: Audit Checklist

After implementation, Audit Team verifies:

| # | Check | Method |
|---|---|---|
| 7.1 | `mock_cmdb.json` has 28 hosts with all 15 fields | Read file, count |
| 7.2 | All hosts resolve via `get_asset_context()` when DEMO_MODE=true | `curl` + backend log inspection |
| 7.3 | Pre-tier model retrained successfully (accuracy >0.80 on both labels) | Run `train_pre_tier.py`, check accuracy |
| 7.4 | `KNOWN_TAGS` includes all 28 hosts | Read `pre_tier.py` |
| 7.5 | `nvd_cache.json` has 500+ entries | `python3 -c "import json; print(len(json.load(open('backend/data/nvd_cache.json'))))"` |
| 7.6 | `kev_cache.json` has 50+ entries | Same method |
| 7.7 | `refresh_caches.py` runs without errors | `python -m scripts.refresh_caches --source kev` |
| 7.8 | Generator produces valid Tenable payloads | Run `test_demo_generator.py` |
| 7.9 | `POST /api/demo/generate` with scenario → returns CaseResponse list | curl |
| 7.10 | `POST /api/demo/generate` with random → returns CaseResponse list | curl |
| 7.11 | Generated findings appear in queue with non-degenerate scores (not all 0, not all identical) | curl queue, verify score variance |
| 7.12 | `POST /api/ingest/clear` archives + clears queue | curl clear, verify queue empty |
| 7.13 | Clear counts match; `resolved_vulnerabilities` has the rows | SQLite query |
| 7.14 | Demo toggle renders in frontend | Browser |
| 7.15 | Scenario picker populates from API | Browser |
| 7.16 | "Generate Wave" triggers queue refresh without duplicates | Browser — generate same scenario twice, verify no duplicate rows |
| 7.17 | "Clear All" archives + empties visually | Browser |
| 7.18 | 7 seed rows still score within ±3 of expected (94, 87, 71, 55, 63, 41, 22) | curl + compare |
| 7.19 | All 20+ existing tests still pass | `pytest backend/tests/ -v` |
| 7.20 | New tests pass (17+ tests) | `pytest backend/tests/test_demo_generator.py -v` |
| 7.21 | Unknown hostname ingest still works (defaults) | curl with made-up hostname |
| 7.22 | `/docs` shows new endpoints: `/api/demo/scenarios`, `/api/demo/generate`, `/api/ingest/clear` | Browser |
| **7.23** | **OFFLINE demo works** — disable network, generate scenario, verify non-degenerate scores + MITRE techniques populate | Run server with `DEMO_MODE=true`, no network, generate `ransomware-incident`, check case view has MITRE techniques and score is not 0 |
| **7.24** | **KEV auto-resolve triggers** — generate `ransomware-incident`; at least one finding has `tier_0_routing="auto_resolved"` and `detection_tier="Deterministic"` | curl queue, grep for "Deterministic" in ransomware findings |
| **7.25** | **`nvd_cache.json` fields reach XGBoost** — in DEMO_MODE, verify `get_nvd_data()` returns non-zero `nvd_reference_count` and `cwe_class` for a known CVE | Python REPL in backend/ |
| **7.26** | **`low-severity-hygiene` auto-resolves** — all 5 findings produce `tier_0_routing="auto_resolved"` with `resolution="low"` | curl queue after generating that scenario |
| **7.27** | **No duplicate seed rows** — after running all scenarios, verify each `(vulnerability_id, hostname)` appears at most once in the queue (seed rows included) | SQL query: `SELECT vulnerability_id, hostname, COUNT(*) FROM vulnerabilities GROUP BY 1,2 HAVING COUNT(*)>1` |
| **7.28** | **Archive table column parity** — `PRAGMA table_info(vulnerabilities)` matches `PRAGMA table_info(resolved_vulnerabilities)` minus the 2 archive-specific columns | SQLite compare |
| **7.29** | **Clear is rate-limited** — call `POST /api/ingest/clear` twice within 30s; second call returns 429 | curl |
| **7.30** | **DEMO_MODE gates endpoints** — with `DEMO_MODE` unset, `/api/demo/scenarios` returns 404 | curl |
| **7.31** | **DEMO_MODE gates cmdb** — with `DEMO_MODE` unset, a host only in `mock_cmdb.json` (not in `KNOWN_HOSTS`) returns default Category 1 | curl ingest with new hostname, check defaults |
| **7.32** | **`patch_publication_date` in payload** — generated Tenable findings have non-empty `patch_publication_date` when `has_patch=true` | Inspect raw Tenable payload from generator

---

## Dependency Order (Strike Team Execution) — Revised for Auditor Fixes

```
Day 1: Foundation + Caches
  ┌── 1.1 Mock CMDB JSON + cmdb.py adapter (DEMO_MODE gate) ─── (1.5 hrs)
  ├── 1.2 Pre-tier training data + retrain ───────────────────── (1 hr, after 1.1)
  ├── 2.1 NVD cache script ───────────────────────────────────── (2 hrs, parallel)
  ├── 2.3 KEV cache script ───────────────────────────────────── (0.5 hr, parallel)
  └── 2.4 Run all cache scripts (populate data) ──────────────── (0.5 hr, after 2.1+2.3)

Day 2: Generator + Pipeline Wiring (critical path)
  ├── 2.5 Cache-to-pipeline wiring (nvd.py _read_from_demo_cache) ─ (3 hrs, BLOCKER D5)
  ├── 3.1 Scenarios JSON (5 scenarios, CVE validation, Intel review) (1.5 hrs, needs cache data)
  └── 3.2 Generator logic (with inject_enrichment, app parser, dedup, B1/B2/B5 fixes) (3.5 hrs, needs 3.1 + 2.5)

Day 3: API + UI
  ├── 3.3 API endpoints (DEMO_MODE gates, inject_enrichment, dedup) (1.5 hrs, needs 3.2)
  ├── 4.1 Archive table migration ──────────────────────────────── (0.5 hr)
  ├── 4.2 Clear endpoint (DEMO_MODE gate, rate limit, atomic) ── (1 hr)
  ├── 5.1 Demo controls JS ────────────────────────────────────── (1.5 hrs)
  ├── 5.2 HTML integration ────────────────────────────────────── (0.25 hr)
  ├── 5.3 CSS additions ───────────────────────────────────────── (0.25 hr, parallel with 5.1/5.2)

Day 4: Tests + Audit
  └── 6.1 Generator tests (17 tests including BLOCKER-targeted) ── (2 hrs)
```

**Parallel opportunities (preserved):**
- 1.1 + 2.1 + 2.3 all start simultaneously
- 3.1 + cache population can overlap
- 5.1 + 5.2 + 5.3 can run in parallel
- 6.1 can start as soon as 3.2 is done

**New critical path:** 2.5 (cache wiring) → 3.2 (generator) → 3.3 (endpoints) — these are sequential and account for 8 of the 21 hours.

**Total: ~21 hrs** across 4 days. (Original: ~13 hrs; +8 hrs for BLOCKER fixes, app parser, DEMO_MODE gating, additional tests/audit checks.)

---

## Files Summary

| File | Action | Phase |
|---|---|---|
| `backend/data/mock_cmdb.json` | NEW — 28 host objects | 1.1 |
| `backend/integrations/cmdb.py` | MODIFY — file-based lookup + DEMO_MODE gate | 1.1 |
| `backend/ml/pretier_training_data.json` | MODIFY — +28 records | 1.2 |
| `backend/pipeline/pre_tier.py` | MODIFY — KNOWN_TAGS expanded | 1.2 |
| `backend/ml/pre_tier_model.pkl` | REGENERATE — retrained | 1.2 |
| `backend/scripts/__init__.py` | NEW — package init | 2.1 |
| `backend/scripts/refresh_caches.py` | NEW — unified refresh CLI | 2.1+2.3 |
| `backend/data/nvd_cache.json` | NEW — 500-1000 NVD entries | 2.1 |
| `backend/data/kev_cache.json` | NEW — 50-200 KEV entries | 2.3 |
| `backend/integrations/nvd.py` | MODIFY — `_read_from_demo_cache()` + demo gate in `get_nvd_data()` | **2.5 (NEW — BLOCKER D5)** |
| `backend/data/demo_scenarios.json` | NEW — 5 curated scenarios (Intel-reviewed) | 3.1 |
| `backend/integrations/demo_generator.py` | NEW — generator engine + inject_enrichment + app parser + dedup | 3.2 |
| `backend/routers/ingest.py` | MODIFY — `/api/demo/*` + `/api/ingest/clear` (all DEMO_MODE gated, rate-limited) | 3.3+4.2 |
| `backend/database.py` | MODIFY — `resolved_vulnerabilities` table | 4.1 |
| `backend/main.py` | MODIFY — health returns `demo_mode` | 4.3 |
| `frontend/js/components/demoControls.js` | NEW — demo controls component (auth-aware) | 5.1 |
| `frontend/index.html` | MODIFY — toggle + controls panel | 5.2 |
| `frontend/css/triagemate.css` | MODIFY — demo UI styles | 5.3 |
| `backend/tests/test_demo_generator.py` | NEW — 17 tests (incl. BLOCKER-targeted) | 6.1 |
