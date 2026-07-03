# Chapter 11: External Integrations

TriageMate doesn't operate in a vacuum. Every alert that lands in the queue carries with it a ghost of context — CVSS scores from NVD, exploit availability from ExploitDB, threat intelligence pulses from AlienVault, asset ownership from CMDB, and a dozen other enrichment dimensions that turn a raw vulnerability notice into a fully characterized incident. This chapter walks through every external integration, how it works, what it contributes to the feature vector, and how it fails without breaking the pipeline.

---

## The Integration Contract

Before we visit individual integrations, it's worth understanding the pattern they all share. Every integration in `backend/integrations/` follows a consistent contract:

1. **TTL cache** — Each source has a time-to-live. Some cache for an hour, some for 24 hours, some for the lifetime of the process. Nobody hits the same API twice for the same CVE inside the cache window.
2. **Graceful degradation** — Every query function returns safe defaults when the source is unreachable. An NVD outage doesn't crash the pipeline; it just means `cvss_score: 0.0` for that cycle.
3. **Independently skippable** — If one integration panics, it doesn't take down its neighbors. Each call is isolated, caught, and logged.
4. **Structured logging** — Every integration logs its queries, cache hits, cache misses, and errors with a consistent `source=` tag so you can trace exactly which data came from where.

The beauty of this contract is that you can rip out any single integration — delete the file, comment the import, pull the API key — and the rest of the pipeline hums along. It's designed for a world where APIs sunset, rate limits change, and budgets shrink.

---

## NVD API 2.0 (`nvd.py`, 329 lines)

The National Vulnerability Database is the beating heart of CVE enrichment. TriageMate's NVD integration hits the NVD API 2.0 endpoint to pull CVSS scores, CVSS vectors, CWE classifications, reference URLs, and publication dates for every CVE it encounters.

The integration is built around a single function: `query_nvd(cve_id)`. You hand it a CVE ID, and it returns a dictionary with `cvss_score`, `cvss_vector`, `cwe_id`, `references`, `published_date`, and a `queried` boolean. Every field has a safe default — `cvss_score` defaults to `0.0`, `cwe_id` defaults to `"NVD-CWE-Other"`, and so on.

Rate limiting is handled by an NVD API key. If you set the `NVD_API_KEY` environment variable, you get the full 50 requests per 30-second window. Without it, TriageMate throttles to the anonymous rate limit of 5 requests per 30 seconds. Either way, results are cached in-memory with a 24-hour TTL, so repeated queries for the same CVE within the same day hit the cache, not the wire.

DEMO_MODE is worth a special mention. When the flag is set, `query_nvd` skips the network entirely and reads from `backend/integrations/nvd_cache.json` — a pre-seeded file containing NVD data for the CVEs used in demo scenarios. This means the demo works offline, runs fast, and produces consistent results regardless of NVD's current uptime.

On error — timeout, HTTP 500, garbage response — the function logs the failure with `source=nvd` and returns the safe-defaults dictionary with `queried: False`. The caller never knows the difference.

---

## OSV.dev (`osv.py`, 147 lines)

Open Source Vulnerabilities (OSV.dev) is Google's database of vulnerability-to-fix mappings. TriageMate uses it to answer one specific question: *Has a fix been released, and what version do I need to upgrade to?*

The `query_osv(cve_id)` function hits the OSV API with a CVE ID and gets back a list of affected packages, each with the fixed version, the ecosystem (PyPI, npm, Maven, etc.), and the package name. No authentication required — OSV is free and open.

The data feeds directly into the feature vector as `osv_fixed_versions` and `osv_affected_packages`. A non-empty `osv_fixed_versions` list is a strong signal that remediation exists, which influences the scoring model toward treatability.

The cache TTL is one hour — aggressive enough to catch newly published fixes during an active incident response, relaxed enough to avoid hammering the API. On error, the integration returns `{'queried': False, 'fixed_versions': [], 'affected_packages': []}`.

One subtle design choice: OSV data is never treated as authoritative for *presence* of a vulnerability, only for *remediation*. Just because OSV doesn't list a CVE doesn't mean it's not real — it might mean the CVE hasn't been ingested by OSV yet, or the package isn't tracked by OSV's ecosystem scoping. The scoring model accounts for this by downweighting missing OSV data rather than treating it as negative evidence.

---

## ExploitDB (`exploitdb.py`, 128 lines)

The ExploitDB integration is the simplest and probably the most impactful. It answers the question every incident responder asks first: *Is there a public exploit?*

At import time, the module loads `files_exploits.csv` — a CSV file that ships with the ExploitDB repository containing 47,089 exploits, of which roughly 25,037 have CVE mappings. The entire file is loaded into a Python dictionary mapping CVE IDs to lists of exploit EDB-IDs. No authentication, no API calls, no TTL — it's loaded once and lives in memory for the process lifetime.

The query function, `query_exploitdb(cve_id)`, does a dictionary lookup and returns a dict with `has_exploit` (boolean), `exploit_count` (integer), and `exploit_ids` (list of EDB-IDs). The lookup is O(1) — essentially free.

If the CSV file isn't found (maybe the ExploitDB submodule hasn't been initialized), the integration falls back to scraping NVD reference URLs for keywords like "exploit," "PoC," and "proof of concept." This fallback is slower and less reliable, but it means the integration never silently returns "no exploit" when a real exploit exists.

The `has_exploit` flag is one of the highest-weighted features in the risk scoring model. A CVE with a public exploit is, all else equal, substantially more urgent than one without.

---

## Metasploit (`metasploit.py`, 45 lines)

Metasploit integration is practically a one-liner wrapped in a function. It checks whether a given CVE has an associated Metasploit module, returning a simple boolean.

Rather than maintaining a separate Metasploit module database, TriageMate reuses the ExploitDB CSV — the same file loaded by `exploitdb.py`. The ExploitDB CSV includes a column indicating whether an exploit has a Metasploit module, so `query_metasploit(cve_id)` filters the in-memory exploit list for entries where `is_metasploit` is true.

Process-lifetime cache, no authentication, no external calls. The result is a single boolean stored in the feature vector as `metasploit_module`.

A Metasploit module is a stronger signal than a generic PoC exploit — it means the exploit is weaponized, tested, and available in a framework that automates the entire attack chain. The scoring model weights `metasploit_module` higher than `has_exploit` for this reason.

---

## AlienVault OTX (`otx.py`, 115 lines)

AlienVault Open Threat Exchange (OTX) provides threat pulse intelligence. TriageMate uses it to answer: *Is this CVE being actively discussed or targeted in the wild?*

The `query_otx(cve_id)` function hits the OTX API and returns the number of pulses referencing the CVE, along with any targeted sectors (government, finance, healthcare, etc.) mentioned in those pulses. The `TRIAGEMATE_OTX_API_KEY` environment variable is optional — without it, the integration returns empty data with `queried: False`.

The 1-hour TTL cache strikes the same balance as OSV: fresh enough for incident response, relaxed enough to respect rate limits. On error, the integration returns `{'queried': True, 'pulse_count': 0, 'targeted_sectors': []}`.

The pulse count feeds into the feature vector as `otx_pulse_count`. A high pulse count — especially when combined with targeted sectors matching the organization's industry — is a strong signal that a CVE is being actively exploited in the wild. The case view displays this as a "Threat Pulse" badge that goes from gray (no pulses) to red (10+ pulses).

---

## GreyNoise (`greynoise.py`, 112 lines)

GreyNoise is the one integration that's currently deprecated. It was intended to provide internet-wide scan detection — answering the question "Is this CVE being scanned for on the open internet?" — but the free tier's rate limits proved too restrictive. Some endpoints were limited to one request per day, which made real-time enrichment impractical.

The code still exists in the repository, but it's not called from `build_feature_vector()` and its import is commented out in `ingest_helpers.py`. The `TRIAMATE_GREYNOISE_API_KEY` environment variable (note the missing "G" — an artifact from an earlier naming convention) is recognized but unused.

There's a real possibility GreyNoise returns in a future MVP release. The free tier rate limits have been increasing over time, and the data it provides — internet-wide scan detection — is genuinely valuable for distinguishing between "this CVE is being actively probed" and "this CVE is theoretical noise." If the rate limits improve to even 10 requests per hour, it would be worth reinstating.

For now, synthetic internet scan detection is handled by `ingest_helpers.py` using a simpler heuristic: if a finding comes from an internet-facing host and the CVE has a public exploit, it's treated as having "elevated scan likelihood."

---

## CMDB Adapter (`cmdb.py`, 233 lines)

The CMDB (Configuration Management Database) adapter provides asset context. It's what turns a bare IP address and CVE into a meaningful incident — *this is a classified system in the DMZ running a database server owned by the Finance team.*

The integration is a stub, but a carefully designed one. It loads two data sources:

1. **`mock_cmdb.json`** — A fictional CMDB containing 31 Western Australian Government hosts with full asset attributes: data classification (OFFICIAL, PROTECTED, CONFIDENTIAL), network zone (DMZ, Internal, Restricted), interface type (Server, Workstation, Network), operating system, business owner, technical owner, registered applications, and dependent assets.
2. **`KNOWN_HOSTS`** — A small inline dictionary of 7 demo hosts used in the interactive demo scenarios.

The `get_asset_info(host)` function looks up a host by IP address or hostname. If found, it returns the full asset record. If not found, it returns conservative defaults: classification "UNKNOWN," zone "UNTRUSTED," interface type "Unknown." This ensures that unknown hosts are treated with maximum suspicion by the scoring model.

The asset data feeds directly into several feature vector keys: `host_data_classification`, `host_network_zone`, `host_interface_type`, `host_os`, `business_owner`, `tech_owner`, `registered_apps`, and `dependent_assets`. These features are particularly important for the prioritization model because a vulnerability on a PROTECTED-classified DMZ host with internet-facing applications is treated very differently from the same vulnerability on an internal developer workstation.

Process-lifetime cache — the JSON file is loaded once and kept in memory. No authentication, no external calls, no rate limits.

---

## MITRE ATT&CK Mapping (`mitre_mapping.py`, 210 lines)

The MITRE ATT&CK mapping is a static lookup table that maps CWEs to ATT&CK technique IDs. It covers 24 CWEs, each mapped to a specific technique such as T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), and T1203 (Exploitation for Client Execution).

This integration has no network calls, no cache, no authentication. It's a pure Python dictionary at module level. The `cwe_to_mitre_technique(cwe_id)` function returns the technique ID and name for a given CWE, or `("T1068", "Exploitation for Privilege Escalation")` as a generic fallback for unmapped CWEs.

The mapping is used primarily in the case view's Panel 1 display, where it shows the ATT&CK technique name next to each CVE. This helps analysts who think in ATT&CK terms quickly understand the likely attack vector without cross-referencing external tools.

---

## Advisories (`advisories.py`, 58 lines)

The advisories module is the smallest integration — 58 lines, one dictionary, one function. It provides WASOC (Western Australian Security Operations Centre) advisory references for a curated set of CVEs.

The dictionary maps 7 CVE IDs to advisory objects containing an advisory ID, a summary quote, and a reference URL. These are manually curated advisories that the WASOC team has published internally.

The `get_advisory(cve_id)` function returns the advisory for a known CVE, or a generic string for unknown ones. It's used in the case view to display "WASOC Advisory Available" badges that link directly to internal guidance.

No cache needed — it's a static dictionary loaded once. No authentication. No API calls.

---

## Tenable Parser (`tenable.py`, 181 lines)

The Tenable parser is different from every other integration in this chapter. It doesn't call an external API, doesn't cache results, and doesn't provide enrichment data for the feature vector. Instead, it parses Tenable.io export files (CSV or JSON format) into TriageMate's internal `IngestRequest` format.

The parser is stateless. You hand it a file path, it detects whether the file is CSV or JSON, validates each finding against the expected schema, and yields `IngestRequest` objects that can be fed directly into the ingestion pipeline. Each finding is enriched with default values for missing fields — unknown plugins, unparsed CVEs, and placeholder descriptions.

The CSV parser (`_parse_csv`) handles the column-based export format with flexible column matching — it finds the right columns by name rather than position, so the parser doesn't break if Tenable reorders its export columns. The JSON parser (`_parse_json`) handles the nested object format that Tenable uses for its API exports.

Because the parser is stateless, it can be run multiple times in parallel on different files without any shared state. It's also trivially testable — you give it a fixture file and check the output.

---

## Demo Data Generator (`demo_generator.py`, 868 lines)

The demo data generator is the largest integration by line count and arguably the most complex. It generates realistic demo findings for `DEMO_MODE`, creating plausible vulnerabilities that look like they came from a real Tenable scan of WA Government infrastructure.

The generator works by:

1. Loading local caches — NVD data from `nvd_cache.json`, EPSS scores from `epss_cache.json`, KEV (Known Exploited Vulnerabilities) catalog from `kev_cache.json`, and CMDB data from `mock_cmdb.json`.
2. Reading `demo_scenarios.json` — a JSON file that defines named scenarios, each with a list of hosts and a list of CVEs or CVE patterns to apply to those hosts.
3. For each host-CVE combination, constructing a full `IngestRequest` with realistic plugin IDs, plugin names, severity levels, and CVSS scores pulled from the cached NVD data.
4. Applying WA Government context — hostnames like `dpaw-web-01.vic.wa.gov.au`, IPs in the `10.` and `172.16.` ranges, and asset attributes from `mock_cmdb.json`.

The result is a demo environment that produces findings indistinguishable from a real Tenable scan, without exposing any real infrastructure data or requiring live API connections.

---

## Feature Vector Integration

Every integration feeds into `build_feature_vector()` in `ingest_helpers.py`. The function orchestrates all the enrichment calls, catches exceptions per-source, and assembles a flat dictionary of features. Here's how the integration contract maps to practice:

```python
# Pseudocode showing the orchestration pattern
def build_feature_vector(cve_id, host):
    features = {}
    
    # Each integration is called independently, errors caught individually
    try:
        features.update(query_nvd(cve_id))
    except Exception:
        log("nvd query failed", level=ERROR)
        features.update({'cvss_score': 0.0, 'queried': False})
    
    try:
        features.update(query_osv(cve_id))
    except Exception:
        log("osv query failed", level=ERROR)
        features.update({'osv_queried': False})
    
    # ... repeat for each integration
```

Each integration adds 1-3 keys to the feature vector. Adding a new source means adding one try/except block to this function and regenerating the training corpus with `build_training_corpus.py`. The pattern is designed for extensibility.

---

## Authentication Patterns

One of the nice things about TriageMate's integration layer is that you can get meaningful enrichment without configuring a single API key. Here's the breakdown:

**No authentication required:**
- ExploitDB — loads a local CSV
- Metasploit — reuses the ExploitDB CSV
- OSV.dev — free, no-auth API
- MITRE ATT&CK Mapping — static dictionary
- CMDB Adapter — local JSON file
- Tenable Parser — local file parser
- Advisories — static dictionary

**Optional API key (env var):**
- NVD API 2.0 — `NVD_API_KEY` for higher rate limits
- AlienVault OTX — `TRIAGEMATE_OTX_API_KEY`

**Deprecated:**
- GreyNoise — `TRIAMATE_GREYNOISE_API_KEY` (note the typo — legacy artifact)

The optional-key pattern means you can run the full pipeline with zero configuration. API keys just make it faster or richer.

---

## Cache TTL Summary

| Integration | TTL | Storage |
|---|---|---|
| NVD | 24 hours | In-memory dict |
| OSV | 1 hour | In-memory dict |
| OTX | 1 hour | In-memory dict |
| LanceDB RAG | 60 seconds | In-memory with threading lock |
| ExploitDB | Process lifetime | Module-level dict |
| Metasploit | Process lifetime | Module-level dict (shared with ExploitDB) |
| CMDB | Process lifetime | Module-level dict |
| MITRE Mapping | Process lifetime | Module-level dict |
| Advisories | Process lifetime | Module-level dict |

The TTLs reflect a tradeoff between freshness and efficiency. NVD data changes slowly — a CVE's CVSS score rarely changes after the initial publication — so 24 hours is fine. OSV and OTX data changes faster (new fixes published, new threat pulses) so they refresh hourly. LanceDB RAG data, used for the semantic search feature, refreshes every 60 seconds because it's local and cheap.

---

## What's Planned

The integration pattern is designed to be extensible, and there are several directions it could grow:

**GreyNoise reinstatement** — If GreyNoise's free tier rate limits improve to even 10-20 requests per hour, the existing code (112 lines, already written) could be re-enabled with a simple configuration change. The internet scan detection it provides is genuinely useful and not easily replicated by the synthetic heuristic in `ingest_helpers.py`.

**New sources** — The 4-step pattern (create the integration file, register in `ingest_helpers.py`, slot into `build_feature_vector()`, regenerate the training corpus) makes adding a new source straightforward. Candidates for future integration include Shodan for internet exposure data, Censys for certificate and service fingerprinting, and VirusTotal for file hash reputation.

**CMDB real connection** — The CMDB adapter is currently a stub backed by a JSON file. Connecting it to a real CMDB API (ServiceNow, BMC Helix, or a custom REST API) would unlock live asset context without changing the integration contract.

---

## Design Philosophy

The external integrations layer reflects a deliberate philosophy: **enrichment is additive, never essential.** Every integration is optional. Every integration has safe defaults. Every integration can fail without cascading.

This isn't just defensive programming — it's a recognition that in security operations, the data sources are always in flux. APIs get deprecated. API keys expire. Network policies change. A pipeline that requires all its sources to be healthy is a pipeline that's perpetually broken.

By making every integration independently skippable, TriageMate ensures that the alert queue keeps moving even when the NVD is down, the OTX API key has expired, and the ExploitDB submodule hasn't been updated in six months. The enrichment gets sparser, but the triage never stops.
