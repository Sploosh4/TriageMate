---
name: intel-toolbox
description: Threat intelligence integration modules, data sources, cache files, API endpoints. Use when researching CVEs, querying threat intel sources, checking cache freshness, or understanding available enrichment data.
---

# Intel Toolbox — Data Sources & Integrations

## Integration Modules (`backend/integrations/`)

| Module | Data Source | What It Provides |
|---|---|---|
| `nvd.py` | NIST NVD API v2 | CVE metadata, CVSS scores, CWE classification |
| `osv.py` | OSV.dev | Open source vulnerability data, package fix versions |
| `exploitdb.py` | ExploitDB CSV | Public exploit availability (PoC indicator) |
| `metasploit.py` | Metasploit | Payload/module availability |
| `greynoise.py` | GreyNoise | Internet scan detection |
| `otx.py` | AlienVault OTX | Threat intelligence pulses |
| `mitre_mapping.py` | MITRE ATT&CK | Technique/tactic mapping |
| `tenable.py` | Tenable.io | Scanner result parsing |
| `cmdb.py` | CMDB (stub) | Asset context and criticality |
| `advisories.py` | Vendor advisories | Vendor security bulletins |
| `network_context.py` | Network peer / blast radius | Peer discovery, zone exposure, blast-radius context |
| `synthetic_telemetry.py` | Security telemetry (Sentinel + EDR) | Sentinel incidents, EDR alerts, process evidence |

## Cache Files (`backend/data/`)

| File | Source | TTL | Notes |
|---|---|---|---|
| `nvd_cache.json` | NVD API v2 | Configurable | Offline demo mode when empty |
| `epss_cache.json` | FIRST.org | Configurable | EPSS probability scores |
| `kev_cache.json` | CISA | Configurable | Known Exploited Vulnerabilities |
| `files_exploits.csv` | ExploitDB | Static | PoC exploit listing |
| `mock_cmdb.json` | Internal stub | N/A | Asset inventory for dev |
| `demo_scenarios.json` | Internal | N/A | Demo scenario definitions |
| `vendor_popularity.json` | Built from NVD | Static | Vendor deployment frequency |

## Cache Refresh

Intel agents cannot run shell commands. Request cache refresh via commander → strike.

```bash
# Command strike would run:
python -m scripts.refresh_caches                     # all
python -m scripts.refresh_caches --source nvd        # NVD only
python -m scripts.refresh_caches --source kev        # KEV only
python -m scripts.refresh_caches --source epss       # EPSS only
```

## API Keys
- NVD API key: `NVD_API_KEY` env var (rate-limited without one)
- OTX API key: `TRIAGEMATE_OTX_API_KEY` env var

## Integration Pattern
New integrations follow the `new-integration-pattern` skill. Each module is independently skippable — fails gracefully to safe defaults.
