# Sprint 9 Briefing — Data Supremacy

> **Status: ARCHIVED** — Sprint 9 historical record

> **Date:** 2 July 2026
> **Commander:** Sprint 9
> **Goal:** Fill every ML feature field with real data, research retraining needs, build a massive vulnerability corpus surpassing all requirements.

---

## Intel Addendum — NVD API Status (2 July 2026)

The NVD API 2.0 is currently returning **503 Service Unavailable**. This is NOT a bug in our code — confirmed by two independent web fetches and the research agent. 

**Root cause:** NVD deployed a massive schema expansion on June 16-17, 2026 (SSVC v2.0.3 + CVE Affected data) that touched ~95% of all records. The API has been unreliable since.

**Workaround:** The NVD website is up. The MITRE CVE API (`https://cveawg.mitre.org/api/cve/{CVE-ID}`) is up. But neither provides the bulk download capability we need for 200K CVEs in reasonable time.

**Recommendation:** Continue with the data we have (EPSS: 344K, KEV: 1,631, ExploitDB: 25K, NVD cache: 175, OSV.dev real-time) to build the training corpus now. Re-run the NVD corpus fetch when the API recovers — the script's checkpoint/resume will pick up cleanly.

---

## Intel Research Findings (Wave 1 Complete)

**I1 — 18 of 36 tabular features have ZERO importance.** Hardcoded constants in training = features the model never learned from. Real feature importances:
- `epss_score`: 26.4%
- CVSS components: ~29% combined
- Text PCA (description encoding): 33.8%
- Everything else: near-zero

**I2 — 15 hardcoded features in training.** All 93K records have `patch_available=1`, `exploitdb_has_poc=0`, `metasploit_has_payload=0`, `internet_scan_detected=0`, etc. Retrain target: **50K-200K CVEs** with real distributions everywhere.

**I3 — Data source volumes confirmed:**
| Source | Records | Notes |
|---|---|---|
| NVD API 2.0 | ~200K CVEs (2019-2025, CVSSv3) | 50 req/s with key, 5 req/s without |
| EPSS | 344,853 scores | 10MB CSV, daily download |
| KEV | 1,631 entries | JSON download, free |
| ExploitDB CSV | 47,089 exploits, 25,037 mapped CVEs | 10MB, git clone |
| OSV.dev | ~400K records | Free API, **no rate limit** |
| CWE Database | 944 types | 2MB ZIP download |

**I4 — Target corpus:** 200K CVEs, ~679MB total, **2-4 hours** fetch with NVD API key. All sources can run in parallel.

---

## 9.1 Situation

### What We Have (After Sprint 8)

| Resource | Current Volume | Target |
|---|---|---|
| nvd_cache.json | 175 entries | 200K+ |
| kev_cache.json | 48 entries | 1,200+ |
| ExploitDB data | NVD tag scraping (inaccurate) | Direct CVE-to-exploit mapping |
| vendor_popularity_index | 20-entry hardcoded dict | Full NVD vendor distribution |
| patch_available | NVD reference tags (binary) | OSV.dev precise fixed-in-version |
| Training data | 93K records, hardcoded patch features | Real distributions everywhere |
| CWE data | Single label per CVE | Full weakness hierarchy |

### The 37-Feature Audit

Feature order matches `backend/ml/xgboost_predictor.py:56-93`:

| # | Feature | Current Source | Gap |
|---|---|---|---|
| 1-8 | cvss_av/ac/pr/ui/s/c/i/a | CVSS vector from payload | Real — no action needed |
| 9 | cvss_score | From payload | Real — no action needed |
| 10 | epss_score | EPSS cache | Real — full refresh needed |
| 11 | patch_available | NVD reference tags (binary) | **IMPROVABLE** — OSV.dev gives precise data |
| 12 | patch_applied | Synthetic from CMDB | Synthetic — acceptable (SOC-specific) |
| 13 | internet_facing | CMDB | Real — no action needed |
| 14 | domain_joined | Hostname pattern | Real — no action needed |
| 15 | data_classification | CMDB → WAICP | Real — no action needed |
| 16 | mission_prevalence | Pre-tier tags | Real — no action needed |
| 17 | public_wellbeing_impact | Pre-tier tags | Real — no action needed |
| 18 | lateral_reachability | Synthetic from CMDB | Synthetic — acceptable |
| 19 | boundary_reachability | Synthetic from CMDB | Synthetic — acceptable |
| 20 | downstream_assets | Synthetic from CMDB | Synthetic — acceptable |
| 21 | patch_lag_days | Computed | Real — no action needed |
| 22 | exploitdb_has_poc | NVD reference tags (binary) | **IMPROVABLE** — direct EDB CSV mapping |
| 23 | metasploit_has_payload | NVD reference tags (binary) | **IMPROVABLE** — direct EDB CSV mapping |
| 24 | internet_scan_detected | Synthetic (KEV + EPSS heuristic) | Synthetic — acceptable |
| 25 | threat_intel_pulses | OTX API | Real — API-configured only |
| 26 | nvd_reference_count | NVD API | Real — bulk refresh needed |
| 27 | cve_desc_tokens | Computed from description | Real — no action needed |
| 28 | vulnerability_age_days | NVD API | Real — bulk refresh needed |
| 29 | vendor_popularity_index | 20-entry hardcoded dict | **IMPROVABLE** — full NVD vendor distribution |
| 30 | cvss_exploitability_sub | NVD API | Real — bulk refresh needed |
| 31 | cvss_impact_sub | NVD API | Real — bulk refresh needed |
| 32 | is_top_25_cwe | NVD CWE → MITRE Top 25 check | Real — could enrich with full CWE hierarchy |
| 33 | is_rce_signature | Regex on CVE description | Real — no action needed |
| 34 | is_privesc_signature | Regex on CVE description | Real — no action needed |
| 35 | is_bypass_signature | Regex on CVE description | Real — no action needed |
| 36 | is_dos_signature | Regex on CVE description | Real — no action needed |
| 37 | is_traversal_signature | Regex on CVE description | Real — no action needed |

**Key takeaway:** 4 improvable fields + 3 that need mass data refresh. The rest are either real or synthetic-by-design.

---

## 9.2 Commander Workflow

```
WAVE 0: SETUP
  git checkout -b sprint-9/master master
  Read this document fully. Understand the 37 features.
  Verify: 37/37 tests pass, clean working tree.

WAVE 1: RESEARCH (Intel — read only)
  Launch: Intel Team prompt (see §9.3)
  Purpose: Determine how much data each field needs.
           Survey all data sources for volumes and rates.
  Output: A research report the Commander uses to size Wave 3.
  Gate: Research must complete before Wave 3 starts.
        Wave 2 can start in parallel.

WAVE 2: FILL EVERY FIELD (Strike — builds code)
  Launch: Strike Team — Wave 2 prompt (see §9.4)
  Builds: OSV.dev integration, ExploitDB CSV parser,
          vendor popularity expansion, CWE hierarchy
  Files touched: integrations/osv.py (new), integrations/exploitdb.py,
                 integrations/metasploit.py, ingest_helpers.py
  Verification: All 4 improvable fields produce real data.

WAVE 3: FLOOD (Strike — builds code + runs data scripts)
  Launch: Strike Team — Wave 3 prompt (see §9.5)
  Builds: Bulk NVD fetcher, KEV/EPSS refresh, unified dataset builder,
          training data regenerator (fixes AI_PROBLEMS #10)
  Runs: Data fetching scripts (may take hours)
  Output: Massive nvd_cache.json, full kev_cache.json,
          regenerated training_data.npz with real distributions

WAVE 4: AUDIT
  Launch: Audit Team prompt (see §9.6)
  Verifies: All 37 fields produce real/synthetic data,
            37/37 tests pass, scores within ±3 of expected,
            new integrations don't crash on missing keys,
            training data regenerates with real distributions

FINAL: COMMIT
  git add + git commit
  Update ROADMAP.md §9 (new Sprint 9 section)
  Tag release
```

---

## 9.3 Intel Team Prompt

Copy-paste this into an Intel Team session:

```
You are Intel Team on TriageMate Sprint 9. Your role: RESEARCH the data
requirements and data source landscape. READ-ONLY — you research,
question, and validate. You never write code.

READ FIRST:
  - SPRINT_9_BRIEFING.md (this document — the full sprint plan)
  - SPRINT_8_HANDOFF.md §3 (remaining gaps, Gap 3 data sources)
  - ROADMAP.md (master status)
  - backend/ml/xgboost_predictor.py (full file — understand the 37 features)
  - backend/ml/train_xgboost.py (full file — understand training pipeline)
  - backend/integrations/nvd.py (current NVD integration)
  - backend/integrations/exploitdb.py (current ExploitDB)
  - backend/integrations/metasploit.py (current Metasploit)
  - backend/ingest_helpers.py (full 37-feature build_feature_vector)

ITEMS:

ITEM I1 — Feature Importance Analysis
  - Load backend/ml/xgboost_model.pkl with joblib
  - Extract model.feature_importances_ (36 tabular features)
  - Rank all 36 features by importance. List top 10 and bottom 10.
  - Which features drive the score? Which are near-zero impact?
  - Return the ranked list with importance scores.

ITEM I2 — Training Data Requirements
  - Read backend/ml/train_xgboost.py §build_tabular_features()
    to understand which features are hardcoded in training.
  - AI_PROBLEMS #10: patch_features are hardcoded (patch_available=1,
    patch_applied=0 for ALL 93K records). What impact does this have?
  - For each feature, determine what distribution the training pipeline
    actually produced vs what production sees.
  - Estimate: how many records are needed for a retrain where ALL
    features have realistic distributions?

ITEM I3 — Data Source Survey
  For each data source below, answer: total records, usable fields,
  API format, rate limits, estimated time to fetch full corpus,
  auth requirements.

  a) NVD API 2.0 — total CVEs? rate limits (5 req/s no key, 50 req/s with key)?
     Can we pull vendor/product per CVE? Bulk download alternatives?

  b) OSV.dev — total vulnerabilities? API format (POST /v1/query)?
     Can we batch? What fixed-in-version data does it provide?

  c) ExploitDB — files_exploits.csv format? CVE mapping? How many exploits?
     Where to download (git clone https://gitlab.com/exploit-database/exploitdb)?
     File size of the CSV metadata?

  d) CISA KEV — full catalog size? Download URL?
     (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

  e) EPSS (FIRST.org) — daily file size? Download URL?
     (https://epss.cyentia.com/epss_scores-current.csv.gz)

  f) MITRE ATT&CK — CWE-to-technique mappings? STIX format? Download URL?

  g) CWE Database — full hierarchy XML? Download URL?
     (https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

  h) GitHub Security Advisories (GHSA) — API format? CVE mapping?

  i) CISA Advisories — ICS advisory feed? Download format?

  j) CAPEC — attack pattern catalog? CWE mapping? Download URL?

ITEM I4 — Corpus Sizing Recommendation
  Based on items I2-I3, recommend:
    - Target NVD corpus size (how many CVEs to fetch)
    - Which additional data sources to integrate
    - Estimated total data volume (MB/GB)
    - Estimated fetch time for each source
    - Which sources can run in parallel

Deliverable: A single research report covering all four items.
Return numbers, URLs, and clear recommendations.
```

---

## 9.4 Strike Team — Wave 2 Prompt (Fill Every Field)

Copy-paste this into a Strike Team session. Launch AFTER Intel returns (or in parallel
if you're confident — Wave 2 items don't depend on Intel research).

```
You are Strike Team on TriageMate Sprint 9, Wave 2: Fill Every Field.

Your role: BUILD and IMPLEMENT. Write all code. Intel validates domain
decisions. Audit verifies after you finish.

READ FIRST:
  - SPRINT_9_BRIEFING.md (full sprint plan, 37-feature audit)
  - backend/integrations/nvd.py (pattern for API integrations)
  - backend/integrations/otx.py (pattern for cached API clients)
  - backend/integrations/exploitdb.py (current file — you will modify)
  - backend/integrations/metasploit.py (current file — you will modify)
  - backend/ingest_helpers.py (build_feature_vector — you will modify)
  - SPRINT_8_HANDOFF.md §4 (How to Add a New Data Source)

RULES:
  - Read existing code conventions from files you modify — match style.
  - Never assume a library is available. Check backend/requirements.txt first.
  - Module-level in-memory _CACHE dict with TTL (3600s = 1hr).
  - API keys via os.getenv("TRIAGEMATE_*", "").strip().
  - If no API key → return safe defaults immediately (no crash).
  - try/except wrapping ALL API calls → log warning, return safe defaults.
  - Structured logging: logger.info(msg, extra={"event": "...", "cve_id": cve_id}).
  - requests.get() with timeout=10 (requests is already in requirements.txt).
  - NEVER commit backend/.env.

---

ITEM 2.1 — OSV.dev Integration (Precise Patch Data)

Goal: Replace the vague NVD-based patch_available boolean with precise
"fixed in version X" data from OSV.dev. Fills the patch_available field
with real data about whether a fix version exists for open-source packages.

Create: backend/integrations/osv.py

Architecture (copy pattern from otx.py):
  - Module-level _CACHE: dict[str, tuple[float, dict]] with TTL=3600
  - No API key needed (OSV.dev is free, no auth)
  - Function: query_osv(cve_id: str) → dict
    Returns: {fixed_available: bool, fixed_versions: list[str],
              package_name: str, package_ecosystem: str, queried: bool}
  - POST https://api.osv.dev/v1/query
    Body: {"version": cve_id} — OSV accepts CVE IDs as version queries
  - If OSV returns no results, fall back to GET
    https://api.osv.dev/v1/vulns/{cve_id}
  - Parse response for "affected" → "ranges" → "fixed" events
  - Extract package name and ecosystem
  - Return safe defaults on error: {fixed_available: False, queried: False}

Modify: backend/integrations/nvd.py
  - In get_nvd_data(), after parsing NVD data but before caching:
    Call query_osv(cve_id)
    If osv_result["fixed_available"] is True:
      Override patch_available = True
      Store osv data in result dict: "osv_fixed_versions", "osv_package"
    If queried but no fixed version found: keep NVD's patch_available value

Modify: backend/ingest_helpers.py
  - Import: from integrations.osv import query_osv
  - In build_feature_vector(), call query_osv(payload.vulnerability_id)
  - Use osv_result to enrich the feature vector (store fixed_versions for
    case view display, but patch_available already handled by nvd.py)

Add to backend/.env.example:
  # OSV.dev is free — no API key needed
  # See backend/integrations/osv.py

Verify:
  - curl https://api.osv.dev/v1/vulns/CVE-2023-34362 → returns MOVEit data
  - curl https://api.osv.dev/v1/vulns/CVE-2021-44228 → returns Log4j data
  - Integration returns safe defaults for CVEs not in OSV.dev
  - uvicorn main:app starts without import errors

---

ITEM 2.2 — Full ExploitDB Integration (Direct CVE-to-Exploit Mapping)

Goal: Replace NVD reference tag scraping with direct CVE-to-exploit
mapping from the ExploitDB CSV metadata file. Fills exploitdb_has_poc
and metasploit_has_payload with authoritative data.

Strategy: Download files_exploits.csv from the ExploitDB GitLab repo.
Parse it offline into a CVE-to-exploit lookup table. The CSV is ~5MB
and contains ~50K exploit entries with CVE mappings.

Modify: backend/integrations/exploitdb.py

Add module-level:
  import csv
  from pathlib import Path

  _EDB_CSV_PATH = Path(__file__).parent.parent / "data" / "files_exploits.csv"
  _EDB_CVE_MAP: dict[str, list[dict]] | None = None  # cve_id → [exploit entries]
  _EDB_LOADED: bool = False

Add function _load_edb_csv():
  - If _EDB_LOADED, return
  - Check if _EDB_CSV_PATH exists
  - If not exists: log warning, _EDB_LOADED = True, return (fail gracefully)
  - Parse CSV with csv.DictReader
  - For each row: if "codes" column contains CVE ID, add to _EDB_CVE_MAP
  - CSV columns: id, file, description, date, author, type, platform, port, codes
  - codes column contains semicolon-separated CVE IDs
  - Log: "Loaded N CVE mappings from ExploitDB CSV"
  - Set _EDB_LOADED = True

Add function _lookup_edb(cve_id: str) → list[dict]:
  - Calls _load_edb_csv() if not loaded
  - Returns _EDB_CVE_MAP.get(cve_id, [])
  - Each entry: {edb_id, description, date, type, platform, author}

Modify has_poc(cve_id: str) → bool:
  - Keep existing NVD reference check as fallback
  - Add: exploits = _lookup_edb(cve_id)
  - If len(exploits) > 0: return True
  - Still fall through to NVD reference check

Modify: backend/integrations/metasploit.py

Add to has_payload(cve_id: str) → bool:
  - Keep existing NVD reference check as fallback
  - Import _lookup_edb from integrations.exploitdb
  - Check: any(e["type"] == "dos" or "metasploit" in e.get("platform", "").lower()
           for e in _lookup_edb(cve_id))
  - Metasploit modules in ExploitDB typically have platform = "metasploit"
    or type = "remote" / "local"

Modify: backend/ingest_helpers.py
  - No change needed — already imports has_poc and has_payload

Add to backend/.env.example:
  # ExploitDB CSV: download files_exploits.csv from
  # https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
  # Place in backend/data/files_exploits.csv

Verify:
  - Without CSV file: has_poc falls back to NVD check, no crash
  - With CSV file: has_poc("CVE-2023-34362") returns True (MOVEit has EDB entry)
  - has_payload("CVE-2021-44228") returns True (Log4Shell has Metasploit module)
  - uvicorn main:app starts without import errors
  - 37/37 tests pass
```

---

## 9.5 Strike Team — Wave 2 continued (Vendor + CWE)

```
ITEM 2.3 — Expand vendor_popularity_index

Goal: Replace the 20-entry hardcoded _VENDOR_POPULARITY dict in
ingest_helpers.py with a data-derived lookup built from actual NVD
vendor frequency distribution.

Modify: backend/ingest_helpers.py

In _lookup_vendor_popularity():
  - Keep the hardcoded dict as fallback
  - Add: try to load backend/data/vendor_popularity.json (lazy, module-level)
  - vendor_popularity.json format: {vendor_lower: frequency_0_to_1}
  - Built from counting CPE vendor fields across all CVEs in nvd_cache.json
  - If JSON exists and contains the vendor from operating_system/hostname:
    return the JSON value
  - Fall through to hardcoded dict
  - Fall through to default 0.1

Build script: backend/scripts/build_vendor_index.py (new)

Functions:
  - load_nvd_cache() → dict — reads nvd_cache.json
  - count_vendors() → dict[str, int] — counts vendor occurrences across all CVEs
  - normalize_frequencies(counts, max_val=0.95) → dict[str, float]
  - save_index() → writes vendor_popularity.json
  - CLI: just run it — python -m scripts.build_vendor_index

  The nvd_cache.json entries have "vendor" and "product" fields.
  Lowercase the vendor, count occurrences across all CVEs.
  Normalize to 0.0-1.0 range where the most common vendor = 0.95.
  Save as {"microsoft": 0.95, "linux": 0.78, ...}

Create: backend/scripts/__init__.py (if not exists — empty package init)

Verify:
  - Run build_vendor_index.py with existing 175-entry nvd_cache.json
  - Output vendor_popularity.json has 50+ vendors
  - _lookup_vendor_popularity("Windows Server 2019", "per-PRD-DC01") returns ~0.90
  - Unknown vendor returns 0.1
  - script runs without import errors

---

ITEM 2.4 — CWE Hierarchy Enrichment

Goal: Enrich the is_top_25_cwe field with full CWE hierarchy context.
Currently is_top_25_cwe is a binary check against MITRE Top 25.
Add parent/child weakness relationships and CWE abstraction level.

Create: backend/data/cwe_hierarchy.json (small JSON, built offline)

Structure:
{
  "CWE-89": {"name": "SQL Injection", "abstraction": "Base", "parent": "CWE-943"},
  ...
}

Build script: backend/scripts/build_cwe_hierarchy.py (new)

  Download: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  Parse the XML with xml.etree.ElementTree
  For each <Weakness>:
    Extract: ID, Name, Abstraction (Pillar/Class/Base/Variant/Compound)
    Extract: <Relationship><Relationship_Target_Form>ChildOf</...>
    → store parent CWE ID
  Save as cwe_hierarchy.json with ~944 entries
  CLI: python -m scripts.build_cwe_hierarchy [--download]

Modify: backend/ingest_helpers.py

In build_feature_vector(), after determining is_top_25:
  - Load cwe_hierarchy.json (lazy, module-level)
  - If cwe_class is in hierarchy:
    Add "cwe_name": ..., "cwe_abstraction": ..., "cwe_parent": ...
    to the feature vector for case view display
  - is_top_25_cwe stays the same (binary check)

Verify:
  - build_cwe_hierarchy.py produces 900+ entries
  - cwe_hierarchy.json loads without blocking startup
  - is_top_25_cwe unchanged for existing CVEs
  - Case view can display CWE name + abstraction level
```

---

## 9.6 Strike Team — Wave 3 Prompt (Massive Corpus)

```
You are Strike Team on TriageMate Sprint 9, Wave 3: Flood.

Your role: BUILD tools to generate a MASSIVE vulnerability data corpus.
The goal is to fetch 200K+ CVEs with all metadata fields, create a
comprehensive dataset that surpasses what the ML model needs for retraining.

READ FIRST:
  - SPRINT_9_BRIEFING.md (full sprint plan, Commander workflow)
  - backend/ml/train_xgboost.py (full file — pattern for NVD fetching)
  - backend/scripts/refresh_caches.py (if exists — current cache refresh)
  - backend/data/nvd_cache.json (current schema — 13 fields per CVE)
  - backend/integrations/nvd.py (pattern for API client)
  - Intel Team's research report (Commander will provide)

RULES:
  - All scripts go in backend/scripts/
  - All data goes in backend/data/
  - Scripts must support checkpoint/resume (don't lose progress on interrupt)
  - Rate-limit all API calls (NVD: 5 req/s without key, 50 req/s with key)
  - Log progress every 100 CVEs
  - NEVER commit nvd_cache.json, kev_cache.json, or training_data.npz

---

ITEM 3.1 — Bulk NVD Corpus Builder

Goal: Fetch 200K+ CVEs from NVD API 2.0 and store full metadata for each.

Create: backend/scripts/fetch_nvd_corpus.py

Architecture (copy pattern from train_xgboost.py Phase 1):
  - Date range chunking: 2019-01-01 to 2025-12-31, 3-month chunks
  - NVD API 2.0 pagination: startIndex + resultsPerPage (max 2000)
  - Rate limit: sleep 0.2s between pages with key, 1.2s without
  - Checkpoint: save progress after each chunk to nvd_fetch_checkpoint.json
  - Resume: detect existing checkpoint, skip completed chunks
  - Output: nvd_corpus.json — {cve_id: {all 13 fields}, ...}
  - Target: 200K+ entries (all CVEs 2019-2025 with CVSS v3 scores)

Schema per CVE (match existing nvd_cache.json schema):
  {
    "cve_id": {
      "cvss_v3_score": 9.8,
      "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe_class": "CWE-89",
      "description": "...",
      "vulnerability_age_days": 365,
      "patch_available": true,
      "exploitdb_has_poc": false,     -- placeholder, filled by Item 3.4
      "metasploit_has_payload": false, -- placeholder, filled by Item 3.4
      "nvd_reference_count": 12,
      "cvss_exploitability_sub": 3.9,
      "cvss_impact_sub": 5.9,
      "vendor": "progress",
      "product": "moveit_transfer"
    }
  }

Extraction logic:
  - vendor: first CPE node's cpeMatch → criteria → split(":")[3]
  - product: first CPE node's cpeMatch → criteria → split(":")[4]
  - Filter: only include CVEs with cvss_v3_score > 0 (skip pre-CVSS vulns)
  - API key: os.getenv("NVD_API_KEY", "")

CLI:
  cd backend
  python -m scripts.fetch_nvd_corpus
    [--start 2019-01-01] [--end 2025-12-31]
    [--chunk-months 3] [--resume]
    [--limit 1000]  -- for testing

  Output: backend/data/nvd_corpus.json

Verify:
  - Script runs for 1 chunk (limit flag) without errors
  - Output matches existing nvd_cache.json schema (13 fields)
  - Checkpoint file saves/loads correctly
  - Resume picks up from last completed chunk
  - Total fetch time estimate: ~4-8 hours for 200K CVEs (with API key)

---

ITEM 3.2 — Full KEV + EPSS Cache Refresh

Goal: Refresh KEV and EPSS caches with the complete datasets.

Modify/Create: backend/scripts/refresh_caches.py (if it exists, enhance it;
  if not, create it)

Functions:
  refresh_kev_cache():
    - Download https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    - Parse: for each vulnerability, extract cveID, dateAdded, shortDescription
    - Filter: only include CVEs present in nvd_corpus.json (optional — keep all if corpus doesn't exist)
    - Output: backend/data/kev_cache.json
      Format: {cve_id: {known_exploited: true, date_added: "...", action: "...", note: "..."}}
    - Total: ~1,200+ KEV entries

  refresh_epss_cache():
    - Download https://epss.cyentia.com/epss_scores-current.csv.gz
    - Gunzip in memory or to temp file
    - Parse CSV: cve, epss, percentile
    - Filter: only include CVEs present in nvd_corpus.json (optional)
    - Output: backend/data/epss_cache.json
      Format: {cve_id: {epss: 0.12345, percentile: 0.87654}}
    - Total: ~240K+ EPSS scores
    - NOTE: This may already be handled by ml/train_xgboost.py — check.
      If so, update paths and ensure it's callable standalone.

CLI:
  cd backend
  python -m scripts.refresh_caches --source kev
  python -m scripts.refresh_caches --source epss

Verify:
  - kev_cache.json has 1,000+ entries
  - epss_cache.json has 200K+ entries
  - Both scripts run standalone without import errors
  - Scripts work regardless of whether nvd_corpus.json exists

---

ITEM 3.3 — Unified Feature Vector Dataset Builder

Goal: Combine all data sources into a single training-ready dataset
where every feature field has real data.

Create: backend/scripts/build_training_corpus.py

This is the master orchestration script. It reads nvd_corpus.json,
kev_cache.json, epss_cache.json, and files_exploits.csv (if present),
then produces a training_data.npz file with real distributions for
ALL features.

Architecture:
  Phase 1: Load all sources
    - Load nvd_corpus.json → {cve_id: {13 fields}}
    - Load kev_cache.json → {cve_id: {KEV fields}}
    - Load epss_cache.json → {cve_id: {epss, percentile}}
    - Load ExploitDB CSV → {cve_id: [exploit entries]} (lazy, only if present)
    - Load vendor_popularity.json → {vendor: frequency}

  Phase 2: Build feature vectors
    For each CVE in nvd_corpus.json:
      1. Parse cvss_v3_vector into av/ac/pr/ui/s/c/i/a components
      2. cvss_score = cvss_v3_score
      3. epss_score = from epss_cache (0.0 if missing)
      4. patch_available = patch_available from NVD (enhanced by OSV if available)
      5. patch_applied = random sample from realistic distribution:
         - If patch_available and CVSS ≥ 9.0: 0.80 chance applied
         - If patch_available and CVSS ≥ 7.0: 0.60 chance applied
         - If patch_available and CVSS < 7.0: 0.30 chance applied
         - Else: False
         (This is the fix for AI_PROBLEMS #10)
      6. exploitdb_has_poc = from ExploitDB CSV if loaded, else NVD flag
      7. metasploit_has_payload = from ExploitDB CSV if loaded, else NVD flag
      8. internet_scan_detected = if in KEV → True, elif EPSS ≥ 0.5 + has_poc → True
      9. nvd_reference_count = from NVD
      10. cve_desc_tokens = len(description)
      11. vulnerability_age_days = from NVD
      12. vendor_popularity_index = from vendor_popularity.json, fallback 0.1
      13. cvss_exploitability_sub = from NVD
      14. cvss_impact_sub = from NVD
      15. is_top_25_cwe = CWE in MITRE Top 25 set
      16-20. regex signatures = from description text
      21-36. Asset-specific features (internet_facing, domain_joined, etc.):
           Generate random WA-government-plausible distributions
           (These are per-asset, not per-CVE; the model trains on the
            distribution, not specific hosts)

  Phase 3: Label
    - Label = 1 if cve_id in KEV cache, else 0
    - Apply the same quality filters as train_xgboost.py:
      - Exclude CVEs published before 2021-11-01 (pre-KEV era)
      - Exclude CVEs published within 30 days of today (too recent)

  Phase 4: SBERT encode descriptions
    - Use ml/encoder.py encode_batch() for all descriptions
    - Fit PCA to the text vectors (768 → 32 dims)

  Phase 5: Save
    - X: numpy array [n_samples, 68] (36 tabular + 32 text PCA)
    - y: numpy array [n_samples] (binary label)
    - feature_names: list of 68 strings
    - Save as backend/ml/training_data_v2.npz
    - Also save backend/ml/pca_reducer_v2.pkl

CLI:
  cd backend
  python -m scripts.build_training_corpus
    [--nvd-corpus nvd_corpus.json]
    [--output training_data_v2.npz]
    [--limit 1000]  -- for testing
    [--skip-sbert]  -- skip text encoding (faster testing)

Verify:
  - Script runs on 1000-CVE limit without errors
  - Output training_data_v2.npz has shape (n, 68) for X and (n,) for y
  - patch_available and patch_applied have realistic distributions
    (not all 1 and 0 like the old training data)
  - Label distribution: ~2-5% positive (KEV), ~95-98% negative
  - No hardcoded feature values anywhere

---

ITEM 3.4 — Wire ExploitDB CSV into Corpus Pipeline

Goal: After downloading files_exploits.csv (one-time manual step),
ensure all corpus-building scripts use it.

Modify: backend/scripts/build_training_corpus.py
  - In Phase 1 (load sources), add:
    from integrations.exploitdb import _load_edb_csv, _lookup_edb
    Call _load_edb_csv() to populate the module-level CVE map
    Use _lookup_edb(cve_id) to fill exploitdb_has_poc and metasploit_has_payload

Add to ROADMAP.md:
  - One-time manual step: download files_exploits.csv (~5MB)
    curl -o backend/data/files_exploits.csv \
      https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
  - Place in backend/data/files_exploits.csv

Verify:
  - Integration works end-to-end: CSV → has_poc → feature vector
  - Without CSV: graceful fallback to NVD-based check
```

---

## 9.7 Audit Team Prompt

Copy-paste this into an Audit session AFTER all Strike waves complete:

```
You are Audit Team on TriageMate Sprint 9. Your role: VERIFY correctness
AFTER all code is built. Nothing is "done" until you sign off.

READ FIRST:
  - SPRINT_9_BRIEFING.md (full sprint plan)
  - SPRINT_8_HANDOFF.md §7 (verification commands)
  - ROADMAP.md §7 (remaining work) and §9 (known bugs)

RULES:
  - You are read-mostly. You can run curl, pytest, and Python one-liners.
  - Catch regressions, edge cases, and silent failures.
  - Every check must have a PASS/FAIL result with evidence.

---

AUDIT ROUND 1 — Integration Health (after Wave 2)

A1. uvicorn startup:
    cd backend && source venv/bin/activate && uvicorn main:app
    → No import errors, no crash. All new integrations load.

A2. OSV.dev integration:
    python3 -c "
    from integrations.osv import query_osv
    r = query_osv('CVE-2023-34362')  # MOVEit — should have OSV entry
    print('fixed_available:', r['fixed_available'])
    print('queried:', r['queried'])
    "
    → Returns queried=True, fixed_available=True or False (depends on OSV data).

A3. OSV.dev missing CVE:
    python3 -c "
    from integrations.osv import query_osv
    r = query_osv('CVE-9999-99999')  # non-existent
    assert r['queried'] == True or r['queried'] == False
    assert 'fixed_available' in r
    print('Graceful fallback OK')
    "

A4. ExploitDB CSV (if CSV present):
    python3 -c "
    from integrations.exploitdb import has_poc, _lookup_edb
    print(has_poc('CVE-2023-34362'))  # should be True if CSV loaded
    "

A5. ExploitDB no CSV (graceful fallback):
    # Rename files_exploits.csv temporarily
    # Reload Python, call has_poc('CVE-2023-34362')
    → Returns True or False (from NVD fallback), no crash.

A6. Vendor popularity expansion:
    python3 -c "
    from ingest_helpers import _lookup_vendor_popularity
    print(_lookup_vendor_popularity('Windows Server 2019', 'per-PRD-DC01'))
    print(_lookup_vendor_popularity('Ubuntu 22.04', 'per-PRD-APP01'))
    print(_lookup_vendor_popularity('Unknown OS', 'unknown-host'))
    "
    → Returns values 0.0-1.0. Unknown returns 0.1.

A7. All 37 tests pass:
    cd backend && python -m pytest tests/ -v
    → 37/37 pass.

A8. OSV query doesn't crash ingest:
    curl -X POST http://localhost:8000/api/ingest \
      -H 'Content-Type: application/json' \
      -d '{"vulnerability_id":"CVE-2023-34362","hostname":"per-PRD-MOVEIT-WEB01.health.wa.gov.au","cvss_score":9.8,"description":"MOVEit Transfer SQL Injection","epss_score":0.97,"cisa_kev":true,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
    → Returns 200, no crash, case has data.

---

AUDIT ROUND 2 — Corpus Health (after Wave 3)

B1. fetch_nvd_corpus.py runs for test limit:
    cd backend && python -m scripts.fetch_nvd_corpus --limit 100 --start 2025-01-01 --end 2025-03-31
    → Completes without errors. Output has ~50-100 CVEs.

B2. nvd_corpus.json schema matches existing nvd_cache.json:
    python3 -c "
    import json
    with open('backend/data/nvd_corpus.json') as f:
        corpus = json.load(f)
    sample = next(iter(corpus.values()))
    required = ['cvss_v3_score','cvss_v3_vector','cwe_class','description',
                'vulnerability_age_days','patch_available','nvd_reference_count',
                'cvss_exploitability_sub','cvss_impact_sub','vendor','product']
    for key in required:
        assert key in sample, f'Missing key: {key}'
    print(f'Schema OK — {len(sample)} keys, sample CVE has {len(sample)} fields')
    "

B3. KEV cache refresh:
    cd backend && python -m scripts.refresh_caches --source kev
    → Produces kev_cache.json with 1,000+ entries.

B4. EPSS cache refresh:
    cd backend && python -m scripts.refresh_caches --source epss
    → Produces epss_cache.json with 200K+ entries.

B5. build_training_corpus.py test run:
    cd backend && python -m scripts.build_training_corpus \
      --nvd-corpus data/nvd_corpus.json \
      --output ml/training_data_v2.npz \
      --limit 500 \
      --skip-sbert
    → Completes without errors.

B6. Training data shape is correct:
    python3 -c "
    import numpy as np
    data = np.load('backend/ml/training_data_v2.npz')
    X = data['X']
    y = data['y']
    print(f'X shape: {X.shape}')  # (n, 68)
    print(f'y shape: {y.shape}')  # (n,)
    print(f'Label distribution: {np.mean(y):.3f} positive')
    assert X.shape[1] == 68, f'Expected 68 features, got {X.shape[1]}'
    "

B7. No hardcoded features in training data:
    python3 -c "
    import numpy as np
    data = np.load('backend/ml/training_data_v2.npz')
    X = data['X']
    # patch_available is index 9 (0-indexed: 10th feature)
    # patch_applied is index 10
    print(f'patch_available: {X[:,9].mean():.3f} mean, {X[:,9].std():.3f} std')
    print(f'patch_applied: {X[:,10].mean():.3f} mean, {X[:,10].std():.3f} std')
    # Both should have non-trivial variance (not all 1.0 or all 0.0)
    assert X[:,9].std() > 0.01, 'patch_available has zero variance'
    assert X[:,10].std() > 0.01, 'patch_applied has zero variance'
    print('AI_PROBLEMS #10 FIXED — real distributions for patch features')
    "

---

AUDIT ROUND 3 — End-to-End Integrity

C1. 7 demo row scores within ±3 of expected (94, 87, 71, 63, 55, 41, 22):
    curl -s http://localhost:8000/api/queue | python3 -c "
    import sys,json
    rows=json.load(sys.stdin)['rows'][:7]
    expected=[94,87,71,63,55,41,22]
    for r,e in zip(rows,expected):
        ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
        print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
    "

C2. Feature vector Liveness check — 37/37 fields have data:
    python3 -c "
    import sys; sys.path.insert(0,'backend')
    from ingest_helpers import build_feature_vector
    from models import IngestRequest
    from pipeline.pre_tier import predict_mission_tags
    from pipeline.tier_0 import evaluate_tier_0
    p = IngestRequest(
        vulnerability_id='CVE-2023-34362',
        hostname='per-PRD-MOVEIT-WEB01.health.wa.gov.au',
        cvss_score=9.8,
        description='MOVEit Transfer SQL Injection',
        raw_epss=0.97,
        cisa_kev=True,
        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    )
    tags = predict_mission_tags(p.hostname)
    t0 = evaluate_tier_0(p.cvss_score, p.cisa_kev, p.raw_epss or 0, 'OFFICIAL Sensitive', True)
    fv = build_feature_vector(p, tags, t0)
    dead = [k for k,v in fv.items() if k != 'description' and v in (0, 0.0, False, '')]
    total_fields = len(fv) - 1  # exclude description (text, not numeric)
    print(f'LIVE: {total_fields - len(dead)}, DEAD: {len(dead)}')
    if dead: print('Dead fields:', dead)
    assert len(dead) == 0, f'{len(dead)} dead fields remain'
    print('ALL 37 FIELDS PRODUCE DATA')
    "

C3. Health endpoint:
    curl -s http://localhost:8000/api/health | python3 -m json.tool
    → Returns 200 with all expected keys.

C4. Swagger UI:
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/docs
    → Returns 200.

C5. Unknown hostname ingest does not crash:
    curl -X POST http://localhost:8000/api/ingest \
      -H 'Content-Type: application/json' \
      -d '{"vulnerability_id":"CVE-2021-44228","hostname":"unknown-test-host.xyz","cvss_score":10.0,"description":"Log4Shell"}'
    → Returns 200. Defaults used. No crash.

C6. All 37 tests still pass:
    cd backend && python -m pytest tests/ -v
    → 37/37 pass.

C7. Pre-commit hooks:
    ruff check backend/ && ruff format --check backend/
    → No errors. No format changes needed.
```

---

## 9.8 Sprint 9 File Map

```
New/Modified files:
├── SPRINT_9_BRIEFING.md               ← THIS FILE
├── backend/
│   ├── integrations/
│   │   ├── osv.py                      NEW — OSV.dev API client
│   │   ├── exploitdb.py               MODIFY — add CSV loading
│   │   └── metasploit.py              MODIFY — use EDB CSV
│   ├── ingest_helpers.py              MODIFY — vendor expansion, OSV integration
│   ├── scripts/
│   │   ├── __init__.py                 NEW/MODIFY — package init
│   │   ├── fetch_nvd_corpus.py         NEW — bulk NVD fetcher
│   │   ├── refresh_caches.py           NEW/MODIFY — KEV + EPSS refresh
│   │   ├── build_vendor_index.py       NEW — vendor frequency extractor
│   │   ├── build_cwe_hierarchy.py      NEW — CWE hierarchy parser
│   │   └── build_training_corpus.py    NEW — unified dataset builder
│   └── data/
│       ├── nvd_corpus.json             NEW — 200K+ CVE entries (gitignored)
│       ├── files_exploits.csv          NEW — ExploitDB metadata (gitignored)
│       ├── vendor_popularity.json      NEW — vendor frequencies
│       └── cwe_hierarchy.json          NEW — CWE weakness tree
```

---

## 9.9 Dependencies & Parallelism

```
WAVE 1 (Intel): No dependencies — launch immediately.
  Can run in parallel with Wave 2.

WAVE 2 (Fill):
  Items 2.1-2.4 all touch different files — can run in parallel.
  2.1 (OSV):      integrations/osv.py (NEW), ingest_helpers.py
  2.2 (ExploitDB): integrations/exploitdb.py, integrations/metasploit.py
  2.3 (Vendor):   ingest_helpers.py, scripts/build_vendor_index.py (NEW)
  2.4 (CWE):      ingest_helpers.py, scripts/build_cwe_hierarchy.py (NEW)
  CONFLICT: items 2.1, 2.3, 2.4 all touch ingest_helpers.py.
  RECOMMENDATION: Launch them sequentially in Strike,
  or have them write to separate sections of ingest_helpers.py.

WAVE 3 (Flood): Depends on Intel research report (sizing decisions).
  Items 3.1-3.4 can be launched as a single Strike session
  (same agent builds all scripts).

WAVE 4 (Audit): Depends on Waves 2 + 3 complete.
  Launch as single Audit session.
```

---

## 9.10 One-Time Manual Steps (Commander)

These are not automated — you do them once:

```bash
# 1. Download ExploitDB CSV metadata (~5MB)
curl -o backend/data/files_exploits.csv \
  https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv

# 2. Run the bulk NVD corpus fetch (4-8 hours with API key)
cd backend && source venv/bin/activate
export NVD_API_KEY=your-key-here
python -m scripts.fetch_nvd_corpus --resume

# 3. Refresh KEV and EPSS
python -m scripts.refresh_caches --source kev
python -m scripts.refresh_caches --source epss

# 4. Build training corpus
python -m scripts.build_training_corpus

# 5. Regenerate vendor index and CWE hierarchy
python -m scripts.build_vendor_index
python -m scripts.build_cwe_hierarchy --download
```
