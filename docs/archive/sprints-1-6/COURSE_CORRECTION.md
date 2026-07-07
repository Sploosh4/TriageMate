# TriageMate — Course Correction Plan

> **Status: ARCHIVED** — Course Correction historical record

> **STATUS: COMPLETE** — All 11/11 items implemented and audited. See ROADMAP.md §7b for per-item status.
> **Commits:** `11dd427` (Phases 1-4), `5ce731e` (post-audit fixes, test isolation, fixable-now enrichments).
> Created: 30 June 2026 · Completed: 1 July 2026
> Source: Input Gap Analysis (difference between what the system needs vs. what planned sources provide)
> Next: `PRE_DEMO_PLAN.md` — pre-demo hardening (auth, Tenable webhook, degradation visibility, demo logistics)

---

## Why This Exists

The MVP delivers the 7-row demo correctly. But when you feed it a real vulnerability from a real scanner on a real WA government host that isn't in the 7-entry `KNOWN_HOSTS` dict, the pipeline silently degrades across multiple dimensions. This document maps the path from MVP → production-ready, ordered by dependency.

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

## Phase 1 — Foundation (unblocks everything downstream)

### 1.1 Replace KNOWN_HOSTS with a proper CMDB adapter `[STRIKE][INTEL]`

**Intel pre-build questions:**
- What are the standard CMDB field names in WA government (ServiceNow? iTop?)?
- What PRIS Act data classifications map to what level numbers?
- Should `domain_joined` be a CMDB field or derived from hostname conventions?
- What network zone taxonomy does WA SOC use (DMZ, Restricted, Protected, Management)?

**Strike builds:**
**File:** New — `backend/integrations/cmdb.py`
**Deprecates:** `backend/ingest_helpers.py:11-124` (KNOWN_HOSTS dict)

**What:** An abstract CMDB adapter that accepts hostname and returns full asset context. Ships with the 7-entry stub as the default implementation. Swappable via env var (`TRIAGEMATE_CMDB_PROVIDER`).

**Interface contract:**
```python
def get_asset_context(hostname: str) -> dict:
    """Returns: {data_classification, internet_facing, network_zone,
                 operating_system, role, business_owner, technical_owner,
                 interface_type, patch_cycle, last_patch_date, last_scan_date,
                 registered_applications, dependent_assets, service_account}"""
```

**Why first:** This unlocks correct values for `data_classification`, `internet_facing`, `network_zone`, `domain_joined`, `patch_lag_days`, and `downstream_assets`. These feed into Tier 0 rules (35% of scoring weight), Tier 1 feature vector, and the Case View asset registry. Currently every unknown host gets wrong defaults.

**Audit checks:**
- Does `get_asset_context()` return correct values for all 7 known hosts?
- Does an unknown hostname return safe defaults (not crash)?
- Does the env var switch between stub and real adapter?
- Do `lookup_data_classification()` and `is_internet_facing()` in `ingest_helpers.py` now delegate to `cmdb.py`?

**Effort:** ~2 hrs

### 1.2 Add scanner output fields to IngestRequest `[STRIKE]`

**Strike builds:**
**File:** `backend/models.py`

**What:** Add two optional fields to `IngestRequest`:
- `scanner_output_raw: str = ""` — raw scanner finding text (Nessus/Tenable/Qualys plugin output)
- `weakness_template_raw: str = ""` — weakness/detection template

**Why:** The Case View Pane 2 shows scanner output and weakness templates. For the 7 demo rows, these are populated from seed data. For every ingested case, they're empty (or filled with the CVE description as a placeholder). Without these fields, the analyst sees useless Pane 2 content.

**Audit checks:**
- Do both fields appear in Swagger UI at `/docs` for `POST /api/ingest`?
- Does the database store them correctly?
- Does the Case View render them in Pane 2 (replacing the CVE-description placeholder)?
- Do existing 7 demo rows still render without regressions?

**Effort:** ~30 min

---

## Phase 2 — Tier 1 Data Enrichment (the 17 zeroed features)

### 2.1 NVD API client for CVE metadata `[STRIKE][INTEL]`

**Intel pre-build questions:**
- Does the NVD API 2.0 rate limit allow per-ingest queries, or should we cache aggressively?
- Which CWE field from NVD (`cwe_id`, `cwe_description`) is most useful for downstream consumers?
- Should this client share the caching strategy with `train_xgboost.py`'s NVD fetch?

**Strike builds:**
**File:** New — `backend/integrations/nvd.py`

**What:** Fetches additional CVE metadata not in IngestRequest:
- `nvd_reference_count` — reference links count
- `vulnerability_age_days` — days since CVE published
- `cvss_exploitability_sub` — exploitability sub-score
- `cvss_impact_sub` — impact sub-score
- CWE classification from NVD (bypassing the broken local classifier)

Wire these values into `build_feature_vector()` in `ingest_helpers.py`, replacing the hardcoded zeros.

**Why:** These 5 features are currently hardcoded to zero/0.0 in `build_feature_vector()`. The XGBoost model was trained on real values for all of them. Single NVD API call per CVE, cacheable.

**Audit checks:**
- Ingest a known CVE (e.g., CVE-2023-34362). Are `nvd_reference_count`, `vulnerability_age_days`, sub-scores non-zero?
- Does the cache hit on a second ingest of the same CVE (no second API call)?
- Do the 7 demo rows still score within ±3 of expected values?
- Does `build_feature_vector()` output all 37 features with no hardcoded zeros (except the 9 that genuinely have no source)?

**Effort:** ~3 hrs

### 2.2 Threat intel enrichment `[STRIKE][INTEL]`

**Intel pre-build questions:**
- Which threat intel sources are WA SOC already using? (Don't add GreyNoise if they use Recorded Future.)
- What's the operational impact of a `False` for `greynoise_active_scan` when the API key isn't configured? (Should we distinguish "not configured" from "no activity"?)
- Are there free-tier API rate limits that conflict with per-ingest queries?

**Strike builds:**
**File:** New — `backend/integrations/threat_intel.py`

**What:** Fetches from external APIs to populate threat-intel features:
| Feature | Source | API |
|---|---|---|
| `exploitdb_has_poc` | ExploitDB | Free, no key |
| `metasploit_has_payload` | Rapid7 DB | Free |
| `greynoise_active_scan` | GreyNoise | Community tier (free) |
| `otx_threat_pulses` | AlienVault OTX | Free |

Each API client should be independently skippable (fail gracefully to default).

**Why:** 4 features currently hardcoded to zero/False. Each can be deferred individually — start with ExploitDB (highest value, lowest friction).

**Audit checks:**
- Ingest a well-known CVE with public exploits (e.g., CVE-2023-34362). Does `exploitdb_has_poc` return `True`?
- Does a truly obscure CVE return `False` for all 4?
- Does an unconfigured GreyNoise key produce a warning log, not a crash?
- Do all 4 API clients have appropriate timeouts (no hanging on slow responses)?

**Effort:** ~5 hrs

### 2.3 Patch feature real values `[STRIKE]`

**Strike builds:**
**File:** `backend/ingest_helpers.py:283-284`

**What:** Calculate `patch_lag_days` from CMDB `last_patch_date` (via 1.1) vs. CVE publish date (from 2.1 NVD client). Keep `vendor_popularity_index` as a static lookup table for top vendors (Microsoft, Cisco, Citrix, etc.).

**Why:** `patch_lag_days` is currently hardcoded to 0 for all cases. `vendor_popularity_index` is 0.0. Both were trained with real values.

**Audit checks:**
- Does `patch_lag_days` compute correctly for a known host with a known patch date?
- Does it handle missing `last_patch_date` gracefully (default to something safe)?
- Does the static vendor table cover the top 10 vendors in the demo data?

**Effort:** ~1 hr

---

## Phase 3 — Output Quality (what the analyst sees)

### 3.1 MITRE ATT&CK dynamic mapping `[STRIKE][INTEL]`

**Intel pre-build questions:**
- Which MITRE techniques are most relevant to WA government attack surface? Should we weight or filter?
- Is the CWE → CAPEC → ATT&CK mapping from MITRE accurate enough, or do we need manual overrides for common CVEs?
- Should we show techniques for all tiers, or only SLM Tier cases?

**Strike builds:**
**File:** New — `backend/integrations/mitre_mapping.py`

**What:** CWE → MITRE technique lookup table. MITRE provides this publicly (CAPEC → ATT&CK mapping). Simple static dict, no ML. Replaces `json.dumps([])` on line 311 of `ingest.py`.

**Why:** Every ingested case currently gets zero MITRE techniques. The demo rows have 3 each with case-specific descriptions. This is visible to the analyst in the Case View and makes the tool look incomplete.

**Audit checks:**
- Ingest CVE-2023-34362 (CWE-89 SQL Injection). Does it map to T1190 or T1505?
- Do at least 2-3 techniques appear per case?
- Does a CVE with unknown CWE return an empty list (not crash)?
- Do the 7 demo rows still show their existing techniques (no regression)?

**Effort:** ~2 hrs

### 3.2 Summary paragraph generation `[STRIKE][INTEL]`

**Intel pre-build questions:**
- What format do WA SOC analysts expect in summary paragraphs? (Bullet points? Narrative prose? Key facts only?)
- Should summaries be auto-generated only, or should the scanner/adapter be able to provide them too?
- Is the cost of LLM-generated summaries (~$0.0004/call) acceptable per ingest, or should we start with templates?

**Strike builds:**
**File:** `backend/routers/ingest.py` (response builder)

**What:** Either:
- (A) Use Tier 2 LLM to generate 2-3 narrative paragraphs from the case data, OR
- (B) Template-based: "CVE-X discovered on HOSTNAME. Asset is a ROLE in ZONE. CVSS Y, KEV status Z. Tier routing: T."

**Why:** Demo rows have rich 2-3 paragraph summaries. Ingested cases get a single-paragraph list containing only the raw CVE description.

**Audit checks:**
- Does a new ingest produce at least 2 paragraphs (not just the raw description)?
- Does the output format match the demo rows' summary style?
- For template mode: does it handle missing fields gracefully (e.g., unknown role)?

**Effort:** ~1 hr (template) or ~3 hrs (LLM)

### 3.3 Advisory reference enrichment `[STRIKE][INTEL]`

**Intel pre-build questions:**
- What advisory sources does WASOC actually reference? (CSA alerts? Vendor bulletins? WASOC internal threat intel?)
- What reference format do analysts expect? (URL? Ref ID? Quote excerpt?)
- Should we prioritize CISA KEV advisories, vendor advisories, or WASOC-specific advisories?

**Strike builds:**
**File:** New — `backend/integrations/advisories.py`

**What:** Stub adapter for CVE → advisory reference lookup. In production, this would query WASOC advisories, CSA alerts, or vendor bulletins. For now, a static mapping for the top CVEs.

**Why:** The Case View Pane 2 has `advisory_ref_id` and `advisory_quote` fields. They're always empty on ingestion.

**Audit checks:**
- Ingest a CISA KEV CVE (e.g., CVE-2023-34362). Does it return an advisory reference?
- Does a non-KEV CVE still populate (from vendor bulletin mapping)?
- Does the Case View render the advisory quote correctly?

**Effort:** ~1 hr

---

## Phase 4 — Scale & Fixes

### 4.1 Bulk ingest endpoint `[STRIKE]`

**Strike builds:**
**File:** `backend/routers/ingest.py`

**What:** `POST /api/ingest/batch` — accepts `list[IngestRequest]`, returns `list[CaseResponse]`. Simple loop wrapper with optional async fan-out for the pipeline stages.

**Why:** Network scanners produce hundreds/thousands of findings per scan. The single-ingest endpoint is unusable at scale.

**Audit checks:**
- Submit 3 ingestions in one batch. Do all 3 appear in the queue?
- Does a batch with one invalid payload return partial results or full rejection?
- Does the endpoint appear in Swagger UI?

**Effort:** ~2 hrs

### 4.2 Fix CWE classifier head naming `[STRIKE][INTEL]`

**Intel pre-build question:**
- Now that we have NVD CWE data (2.1), do we even need the local classifier? If NVD provides CWE at ingest time, fixing this becomes low-priority.

**Strike builds:**
**File:** `backend/ml/cwe_classifier.py:61`

**What:** The config.json uses `cwe_labels` but the code checks `cwe_options` as fallback. The head names already match. Verify which key SecureBERT2.0 actually uses and align.

**Why:** AI_PROBLEMS.md #1. The classifier is called from the ingest pipeline (line 55) and its output feeds EPSS substitution and RAG. Currently silently returns "Unknown."

**Audit checks:**
- Classify a known description (e.g., "SQL injection in web application"). Does it return `CWE-89`?
- Does the pipeline no longer log warnings about CWE being Unknown?
- Does EPSS substitution now receive real CWE classes?

**Effort:** ~30 min

### 4.3 Add `epss_available` boolean to IngestRequest `[STRIKE][INTEL]`

**Intel pre-build question:**
- What's the convention upstream? Do scanners (Nessus/Qualys) always fetch EPSS, or is it optional? What does "EPSS not available" mean operationally?

**Strike builds:**
**File:** `backend/models.py`

**What:** `epss_available: bool = True` — distinguishes "EPSS was fetched and is genuinely near-zero" from "EPSS was not fetched, needs substitution."

**Why:** Current `epss_score = 0.0` default is ambiguous. The substitution engine can't tell if it should substitute or if 0.0 is the real score.

**Audit checks:**
- Ingest with `epss_available: false, epss_score: 0.0`. Does substitution trigger?
- Ingest with `epss_available: true, epss_score: 0.001`. Does substitution NOT trigger?
- Does the existing demo data still work (default `epss_available: true`)?

**Effort:** ~15 min

---

## What Can Be Deferred

| Item | Reason |
|---|---|
| Active Directory LDAP integration | `domain_joined` can stay as CMDB-derived boolean. OU paths and group memberships are nice-to-have. |
| `boundary_reachability` / `lateral_reachability` | Require network topology model — months of engineering. Accept zero defaults for now. |
| Tier 2 local CWE encoder (ModernBERT) | Cloud LLM path works. Local encoder adds latency, cost savings marginal. |
| Pre-Tier RandomForest classifier | 7-host dict works for demo. Real model needs 200-500 labeled assets — a separate data collection project. |
| Vendor advisory scraping | `vendor_patch_status` is already in IngestRequest — just needs upstream adapter to populate it. |
| Database migration to PostgreSQL | Single-user SQLite is fine until multi-analyst deployment. |

---

## Dependency Graph

```
Phase 1 (Foundation)
├── 1.1 CMDB adapter [STRIKE][INTEL] ────► 2.3 (patch_lag_days needs CMDB)
│                                       ► feeds Tier 0, Tier 1, Case View
└── 1.2 Scanner fields [STRIKE]         No dependencies

Phase 2 (Tier 1 enrichment)
├── 2.1 NVD API [STRIKE][INTEL] ───────► 2.3 (patch_lag_days needs CVE date)
│                                       ► feeds 5 features in Tier 1 vector
├── 2.2 Threat intel [STRIKE][INTEL]    Parallel to 2.1, shares cache pattern
└── 2.3 Patch features [STRIKE]         Depends on 1.1 + 2.1

Phase 3 (Output quality)
├── 3.1 MITRE mapping [STRIKE][INTEL]   Depends on CWE source (2.1 or 4.2)
├── 3.2 Summaries [STRIKE][INTEL]       No dependencies (uses pipeline outputs)
└── 3.3 Advisories [STRIKE][INTEL]      No dependencies

Phase 4 (Scale & fixes)
├── 4.1 Bulk ingest [STRIKE]            No dependencies
├── 4.2 Fix CWE [STRIKE][INTEL]         ► Unblocks 3.1 if NVD path isn't taken
└── 4.3 EPSS flag [STRIKE][INTEL]       No dependencies
```

**Recommended execution order:** 1.1 → 1.2 → 4.2 → 2.1 → 2.2 → 2.3 → 3.1 → 3.2 → 3.3 → 4.1 → 4.3

---

## Total Estimated Effort

| Phase | Hours |
|---|---|
| Phase 1 (Foundation) | 2.5 |
| Phase 2 (Tier 1 enrichment) | 9 |
| Phase 3 (Output quality) | 4–6 |
| Phase 4 (Scale & fixes) | 3 |
| **Total** | **18.5–20.5 hrs** |

---

## Team Workload Summary

| Team | Items owned | Pre-build gates | Post-build gates |
|---|---|---|---|
| **Intel** | 7 items need pre-validation | 1.1, 2.1, 2.2, 3.1, 3.2, 3.3, 4.2, 4.3 | — |
| **Strike** | All 11 items | — | — |
| **Audit** | All 11 items | — | Every item has specific audit checks |
