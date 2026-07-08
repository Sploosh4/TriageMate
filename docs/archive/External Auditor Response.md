> **Status: ARCHIVED** — Historical external audit report for Demo Data Generator. Preserved for provenance.

# External Audit Report — Demo Data Generator

> **Auditor:** External (independent, read-only)
> **Subject:** `DEMO_DATA_GENERATOR_SCOPE.md` (Intel) + `DEMO_DATA_GENERATOR_PLAN.md` (Commander)
> **Method:** Read both documents in full, then grounded every finding against the actual codebase (`tenable.py`, `ingest.py`, `nvd.py`, `ingest_helpers.py`, `exploitdb.py`, `metasploit.py`, `ingest_cwe.py`, `cmdb.py`, `pre_tier.py`, `tier_0.py`, `database.py`, `main.py`, `models.py`, `seed_data.py`, `conftest.py`, frontend `api.js`/`app.js`, `ROADMAP.md` §7c).

A central architectural fact shapes many findings below: **the ingest pipeline enriches via live NVD API calls (`integrations/nvd.py:get_nvd_data()`, in-memory 24h TTL cache), NOT from any JSON file on disk.** The plan's `nvd_cache.json` is consumed only by the demo generator to *build* the Tenable payload; it is never read by `build_feature_vector`, `get_cwe`, `exploitdb.has_poc`, or `metasploit.has_payload`. This single fact drives findings B4, B5, D5, and F3.

---

## Section A: Plan vs Scope Completeness

### A1 — [FINDING: PASS] [SEVERITY: LOW]
Every node in the Scope §10 dependency graph is present in the plan:1.1→1.2, 2.1/2.2/2.3/2.4, 3.1/3.2, 4.1/4.2/4.3/4.4, and the test phase (plan renumbers the scope's "Phase 5" as "Phase 6", and folds scope 4.3/4.4 into plan §5.1–5.4 — cosmetic only). No scope item is dropped. The only drift is naming, not coverage.

### A2 — [FINDING: CONCERN] [SEVERITY: MEDIUM]
The plan's six scenario IDs (§3.1) match the scope's six stories, and counts are consistent. **However, the CVE/host pairings are only plausible for some scenarios and the plan defers exact CVE selection to the author.** The scope's own example (§5.1) pairs `CVE-2024-3094` (XZ Utils backdoor — a Linux/libxz supply-chain issue) with `PRD-MOVEIT-WEB01` (a Windows Server 2019 + IIS + MOVEit host). That pairing is domain-implausible: an analyst stakeholder will recognise that XZ Utils has no business on a Windows MOVEit box. The plan's `ransomware-incident` example (line 275) correctly uses `CVE-2023-34362` / `CVE-2024-5806` (real MOVEit CVEs), but the plan never enumerates the full CVE list per scenario, so the implausibility risk is left to whoever writes `demo_scenarios.json` later.
**Recommendation:** Intel must review and sign off the exact CVE list for each scenario *before* `demo_scenarios.json` is written. Add an audit check (see F3) that asserts every scenario's CVE `vendor`/`product` (from `nvd_cache.json`) is compatible with the target host's `operating_system` + `registered_applications`.

### A3 — [FINDING: GAP] [SEVERITY: MEDIUM]
Wave size is necessary but not sufficient. There is **no deduplication logic anywhere** in the plan or the codebase. The `vulnerabilities` table has no UNIQUE constraint on `(vulnerability_id, hostname)` (confirmed in `database.py:15-105` and the INSERT in `ingest.py:285`), and `ingest_vulnerability()` always inserts. Hitting "Generate Wave" repeatedly appends N new rows each time, even if the same CVE+host is re-sampled. A demonstrator who clicks twice to "show it again" will balloon the queue with duplicates, distort the metric boxes, and inflate the 7.5% audit sample. The plan's own risk register (scope §13) flags archive-table growth but never addresses queue-side duplication.
**Recommendation:** Either (a) make `generate_random_wave()` sample *without replacement* against the current queue contents (read existing `(cve_id, hostname)` pairs and exclude them), or (b) add an "Replace existing" mode that clears-then-generates in one action, or (c) add a UNIQUE index + `INSERT OR IGNORE` semantics. At minimum, the UI should disable "Generate" while a generation is in flight and warn if the queue already contains the scenario's CVEs.

### A4 — [FINDING: CONCERN] [SEVERITY: MEDIUM]
The `mixed-tier-demo` scenario re-uses the 7 seed CVEs + hostnames (plan §3.1, line 266). The7 originals are already inserted by `seed_data.py` at startup (`seed()` is called in `main.py` startup and in `conftest.py`). Selecting this scenario will therefore create **7 duplicate rows** with new IDs but identical `(vulnerability_id, hostname)`. Worse, because `parse_tenable_finding()` hardcodes `cisa_kev=False` and `epss_score=None` (tenable.py:134-135), the regenerated rows will score **differently** from the originals — e.g. Row 1 (MOVEit, CVSS 9.8, KEV) originally auto-resolved as "Very Critical" via the `cisa_kev + cvss≥9.0 + internet_facing` Tier 0 rule (tier_0.py:39); the regenerated copy has `cisa_kev=False`, so it will *escalate* to Tier 1/2 instead of auto-resolving. The queue will then show the same CVE twice with divergent scores and bands, which directly contradicts audit check 7.18's spirit (±3 of expected) and undermines the "Original 7" framing.
**Recommendation:** Either (a) make `mixed-tier-demo` *clear-then-generate* so it replaces rather than duplicates, or (b) inject `cisa_kev` and `epss_score` into the payload for this scenario (see B5), or (c) drop the scenario and instead document "the 7 seed rows already in the queue ARE the mixed-tier demo; no generation needed." Option (c) is cleanest.

---

## Section B: Architecture & Integration Risks

### B1 — [FINDING: CONCERN] [SEVERITY: MEDIUM]
The generator's `generate_tenable_payload()` (plan §3.2, scope §5.3) constructs most fields `parse_tenable_finding()` reads, but **one required pairing is incomplete and several fields are dead.** `tenable.py:_compute_vendor_patch_status()` (lines 76-86) returns `1` only if **both** `has_patch` *and* `patch_publication_date` are truthy. The scope template (§5.3) and the plan's generator description include `has_patch` but **not** `patch_publication_date`. Consequently every generated finding will have `vendor_patch_status=0` even when a patch is claimed — a silent mis-calibration of a Tier 1 feature. Separately, `plugin.cvss_base_score`, `cvss_vector` (v2), `plugin.id`, `plugin.name`, `plugin.family`, `severity`, `severity_id`, `state`, `first_found`, `last_found` are emitted by the generator but **never read** by `parse_tenable_finding()` (it consumes only `cve`, `cvss3_base_score`, `cvss3_vector`, `description`, `synopsis`, `output`, `exploit_available`, `exploit_framework_metasploit`, `has_patch`). They are harmless cargo but inflate the generator's surface area and give a false impression of completeness.
**Recommendation:** Add `patch_publication_date` to the payload template and to `generate_tenable_payload()`. Prune the unread fields from the template or document them as "Tenable-fidelity cosmetic only." Add a unit test asserting `vendor_patch_status==1` for a generated finding whose CVE has a patch.

### B2 — [FINDING: CONCERN] [SEVERITY: LOW]
The IP formula `10.{dept_index}.{host_index % 255}.{50 + (host_index % 200)}` (plan §3.2) leaves `dept_index` derivation **unspecified**. The mock hostnames span 8 departmental domains (`health`, `transport`, `education`, `communities`, `wapol`, `finance`, `justice`, `water`). The plan does not say whether `dept_index` is parsed from the FQDN's second-level label, from an enum, or hardcoded per host. "Host index" is also undefined — is it the position in `mock_cmdb.json`, a hash of the hostname, or something else? With only 28 hosts the collision risk is negligible (octet 3 = `host_index % 255` is unique for ≤255 hosts), but **stability across runs** depends on the JSON array order being preserved, which is fragile if someone re-sorts the file. Two hosts in the same department cannot collide on octet 3 (different indices), but if `dept_index` is mis-derived (e.g., always 0), all hosts land in `10.0.x.y` and the "departmental subnet" realism claim collapses.
**Recommendation:** Define `dept_index` explicitly (e.g., a fixed dict mapping department label → 1..8) and derive `host_index` from a stable hash of the hostname (not array position). Add a test asserting the same hostname always yields the same IP and that two distinct hosts never share an IP.

### B3 — [FINDING: CONCERN] [SEVERITY: LOW]
`plugin.id`, `plugin.name`, and `plugin.family` are **not surfaced anywhere** in the pipeline output or UI. `parse_tenable_finding()` uses `plugin.id` only to synthesise a fake CVE when the `cve` array is empty (tenable.py:40-41); `plugin.name`/`family` are never read. The `vulnerability_id`, `scanner_output_raw`, and `weakness_template_raw` columns store the CVE ID, the generated `output` text, and `synopsis` respectively — none reference `plugin.id`. So a deterministic-but-meaningless `plugin.id` (e.g. `99999`) is invisible to the stakeholder *in the app*, but it **will appear in the raw Tenable JSON** if a stakeholder inspects `/docs` payloads or the DB's `scanner_output_raw`. If the same `plugin.id` repeats across unrelated CVEs, an analyst cross-referencing real Tenable exports may notice. Low credibility risk.
**Recommendation:** Map `plugin.id` to a per-CVE stable value (e.g., the integer portion of the CVE ID, or a hash) and set `plugin.family` from CWE class (e.g. `CWE-787` → "Gain Privilege"). Document that these are cosmetic. No urgency.

### B4 — [FINDING: RISK] [SEVERITY: HIGH]
The plan specifies `exploitdb_has_poc` and `metasploit_has_payload` in `nvd_cache.json` (plan §2.1, lines 184-186) and implies they flow through the generator into the pipeline. **They do not.** The data flow is:
generator reads `nvd_cache.json` → builds Tenable payload (these two fields are **not** placed in the Tenable payload; scope §5.3 only emits `exploit_available`, `exploit_framework_metasploit`, `has_patch`) → `parse_tenable_finding()` maps to `IngestRequest` (which has `has_public_poc` and `exploit_maturity`, set from `exploit_available`/`exploit_framework_metasploit`) → `build_feature_vector()` (ingest_helpers.py:261-262) computes `exploitdb_has_poc` and `metasploit_has_payload` by calling `integrations/exploitdb.has_poc()` and `integrations/metasploit.has_payload()`, **both of which call live `nvd.get_nvd_data()`** and re-derive from NVD reference tags. The `nvd_cache.json` values are **silently dropped** — dead data. If the demo is run offline, `get_nvd_data()` returns empty and both features default to `False`, degrading XGBoost input regardless of what the cache says.
**Recommendation:** Either (a) wire `nvd_cache.json` into a file-backed `get_nvd_data()` path (see D5 — the proper fix), or (b) have the generator inject `exploit_available` and `exploit_framework_metasploit` into the Tenable payload *from* the cache so `parse_tenable_finding()` propagates them into `has_public_poc`/`exploit_maturity` (this covers the IngestRequest-level fields but still leaves the XGBoost-level `exploitdb_has_poc`/`metasploit_has_payload` re-derived from live NVD). Option (a) is the only complete fix. Until then, remove `exploitdb_has_poc`/`metasploit_has_payload` from the cache schema or explicitly mark them as "generator-hint only, not pipeline-consumed."

### B5 — [FINDING: RISK] [SEVERITY: BLOCKER]
This is the most severe finding. The plan states (§3.2, line 343): *"cisa_kev is NOT in the Tenable payload — it's set via a separate lookup."* **There is no separate lookup designed or implemented anywhere in the plan.** `parse_tenable_finding()` hardcodes `cisa_kev=False` (tenable.py:134). The `kev_cache.json` built in Phase 2.3 is **never read by the ingest pipeline** — confirmed by grepping the plan and the codebase: `ingest.py` and `ingest_helpers.py` never import or reference a KEV cache. The `IngestRequest.cisa_kev` field therefore is always `False` for every generated finding.

The downstream consequence is severe for demo credibility: Tier 0's "Very Critical" auto-resolve requires `cisa_kev AND cvss≥9.0 AND internet_facing` (tier_0.py:39) or `cisa_kev AND epss≥0.90 AND Category 3/4` (tier_0.py:44). With `cisa_kev=False`, **no generated finding can ever auto-resolve as "Very Critical" deterministically** — they all escalate to Tier 1/2. The `ransomware-incident` and `perimeter-breach` scenarios (whose headline CVEs — MOVEit CVE-2023-34362, Citrix CVE-2023-3519, etc. — are all CISA KEV-listed) will *not* demonstrate the deterministic auto-resolve beat that is the strongest part of the TriageMate story. They'll instead crawl through Tier 1 → Tier 2 LLM calls, costing money and latency, and emerge with ML-derived scores rather than the clean "Deterministic: KEV + CVSS 9 + internet-facing →94" message the demo script (PRE_DEMO_PLAN §3.1) is built around.

On EPSS: `parse_tenable_finding()` sets `epss_score=None`; `ingest.py:96-111` then sets `raw_epss=0.0` and calls `calculate_substitution()`. The substitutor reads `epss_cache.json` (per plan §2.2, and `epss_substitutor.py` exists) — so EPSS substitution is the one enrichment path that genuinely works from cache. But because `cisa_kev=False` is also fed to `calculate_substitution()`, the substitutor's KEV-aware logic is also fed wrong input.
**Recommendation (must-fix before Strike execution):** Add an explicit KEV-injection step. The cleanest design: after `parse_tenable_batch()` produces `IngestRequest` objects, the demo endpoint (or a new `demo_generator.inject_enrichment()`) patches each `IngestRequest.cisa_kev` by looking up `kev_cache.json`, and optionally patches `epss_score` from `epss_cache.json`. This is ~30 lines and closes the BLOCKER. Without it, three of the six scenarios cannot demonstrate their stated purpose, and the `mixed-tier-demo` cannot reproduce the 7 seed scores.

---

## Section C: Data Quality & Demo Credibility

### C1 — [FINDING: RISK] [SEVERITY: MEDIUM]
Parsing `registered_applications` (a free-text string like `"Progress MOVEit Transfer 2023.0.0, IIS 10.0"`) into vendor/product tokens that match NVD cache `vendor`/`product` fields is **fragile and unspecified**. The plan's algorithm (§3.2, "Parse registered_applications string → list of app names") gives no parser grammar. Real strings include version numbers, role qualifiers ("Microsoft Print Server role"), and multi-word products. NVD `vendor`/`product` fields are lowercase, space-separated canonical names (e.g. `"progress"`, `"moveit transfer"`). Bridging `"Progress MOVEit Transfer 2023.0.0"` → `("progress", "moveit transfer")` requires stripping version, lowercasing, and fuzzy matching. If parsing fails for a host, the plan's algorithm (§3.2 step c) yields "zero matching CVEs" for that host, and the host is silently skipped — so a "medium wave" of 15-30 may draw only from the 50-CDVE "greatest hits" pool, producing CVEs that have nothing to do with the host's actual software. A stakeholder who reads the case view's "Registered Applications" field and sees a macOS CVE on a Windows print server will notice.
**Recommendation:** Define the parser explicitly with a test fixture of all 28 hosts' `registered_applications` strings. Implement a normaliser: split on comma, strip version tokens (`\d+\.\d+\.\d+`), lowercase, map known aliases (`MOVEit Transfer`→`moveit transfer`, `IIS`→`microsoft internet information services`). When a host yields zero matches, fall back to OS-level CVEs (Windows/Linux) rather than the global "greatest hits" list. Add a test asserting every CMDB host yields ≥1 host-appropriate CVE.

### C2 — [FINDING: CONCERN] [SEVERITY: MEDIUM]
The 20/30/30/20 Critical/High/Medium/Low split is **too severe** versus a real WA-government Tenable scan. Real enterprise scans are dominated by Medium/Low (patch lag, TLS config, information disclosure, unsupported software enumeration); Critical is typically <10%. A stakeholder who has run a Tenable scan will read the demo queue as "this network is on fire," which either (a) erodes credibility ("this isn't what my queue looks like") or (b) over-promises the tool's typical input. The auto-resolve "Low" demo (scenario5) also needs Low findings to exist, so 20% Low may be too few to showcase that path in a small wave.
**Recommendation:** Shift to ~10% Critical / 20% High / 40% Medium / 30% Low, and bias Critical toward internet-facing hosts (the plan already weights internet-facing 2x — extend that to severity). Make the distribution a configurable constant so it can be tuned per stakeholder audience.

### C3 — [FINDING: CONCERN] [SEVERITY: LOW]
The generator's `generate_realistic_scanner_output()` (plan §3.2) produces Nessus-style boilerplate ("Plugin Output: The remote host is running…"). The 7 seed rows' `scanner_output_raw` (see `index.html:818`, `seed_data.py:60`) are hand-written, richer, analyst-style narratives with explicit KEV/EPSS/exploit-maturity lines tailored per CVE. A stakeholder toggling between a seed row and a generated row in the case view's "Scanner Output" accordion will see a tonal cliff: seed = bespoke intelligence summary; generated = generic Nessus paste. This is a small but visible seam in the demo.
**Recommendation:** Either (a) align the generator's output template closer to the seed style (include `CISA KEV: TRUE/FALSE`, `EPSS Score:`, `Exploit Maturity:` lines populated from cache), or (b) accept the difference and document it. Low priority but cheap to fix.

### C4 — [FINDING: RISK] [SEVERITY: MEDIUM]
The `low-severity-hygiene` scenario's stated purpose is "Auto-resolve demo, filter by severity" (plan §3.1). Tier 0 auto-resolve "low" requires `not cisa_kev AND cvss < 4.0 AND epss < 0.10` (tier_0.py:53-58). For generated findings, `cisa_kev=False` (always, per B5) and `epss_score=None → raw_epss=0.0` (always, per the parse path), so the binding constraint is **CVSS < 4.0**. The plan does **not** list which CVEs are in this scenario; it only says "5 CVEs on print server + student DB." If the author later picks CVEs with CVSS ≥ 4.0 (very common — most "low" real CVEs are 3.x to 5.x), the auto-resolve will **not fire** and the scenario will silently escalate to Tier 1 instead of demonstrating the low-auto-resolve beat. There is no test or audit check guarding this.
**Recommendation:** Constrain the `low-severity-hygiene` scenario in `demo_scenarios.json` to CVEs with `cvss_v3_score < 4.0` (verifiable against `nvd_cache.json`), and add an audit check + unit test asserting that all 5 findings in this scenario produce `tier_0_routing == "auto_resolved"` with `resolution == "low"`.

---

## Section D: Operational & Edge Cases

### D1 — [FINDING: CONCERN] [SEVERITY: LOW]
`nvd_cache.json` at 500-1000 entries × ~15 fields is realistically 500KB-2MB; `epss_cache.json` is already ~250K records and is the larger file (already shipped, so not the plan's new concern). 2MB does not materially slow `git clone` and is well under GitHub's 100MB hard limit; LFS is **not** warranted. However, the plan commits generated binary-ish data to the repo with no `.gitattributes` delta strategy, so every refresh produces a large diff and `git blame`/history bloat.
**Recommendation:** Add a `.gitattributes` entry marking `backend/data/nvd_cache.json` and `kev_cache.json` as `merge=ours` (avoid merge conflicts on refresh) and document the refresh cadence (see D4). No LFS. Low priority.

### D2 — [FINDING: CONCERN] [SEVERITY: LOW]
The clear endpoint (plan §4.2) issues `INSERT ... SELECT` then `DELETE` then `conn.commit()`. Because Python's `sqlite3` module opens an implicit transaction on the first DML and does not autocommit, the INSERT and DELETE are **in the same transaction** and atomic — a crash between them rolls both back. The prompt's stated risk ("state where the same CVE appears in both tables") is therefore mostly mitigated by SQLite's default isolation. The residual concern is cosmetic: `archived_count` and `deleted_count` are reported as separate rowcount values but are always equal; if they ever diverge it indicates a bug, but nothing alerts on divergence. There is also no `BEGIN`/`BEGIN IMMEDIATE` so under concurrent requests two clears could interleave (SQLite serialises writes, so low risk).
**Recommendation:** Wrap in an explicit `with conn:` context manager (auto-commit on success, auto-rollback on exception) and add an `assert archived_count == deleted_count` guard returning 500 on mismatch. Add a test that calls clear twice concurrently.

### D3 — [FINDING: RISK] [SEVERITY: MEDIUM]
`DEMO_MODE` is referenced in the plan (§3.3, §main.py health addition) and scope (§4.3 "reads from this file when `DEMO_MODE=true`") but is **never used as a gate.** The cmdb.py modification (plan §1.1) **always** loads `mock_cmdb.json` if present — there is no `if os.getenv("DEMO_MODE")` check. The demo endpoints (`/api/demo/scenarios`, `/api/demo/generate`, `/api/ingest/clear`) are registered unconditionally on the ingest router with no `DEMO_MODE` guard. This has two consequences: (1) in a non-demo (production-style) deployment that still has the file present, the CMDB silently returns mock hosts for any matching hostname — a data-integrity hazard; (2) `/api/ingest/clear` is **always live** — any caller with a valid `X-API-Key` (or anyone if auth is unset) can wipe the entire `vulnerabilities` queue in a real deployment. The scope §9 explicitly says "Authentication for demo endpoints" is out of scope because "Demo mode runs behind the existing `X-API-Key` auth middleware," but that only addresses *who* can call it, not *whether the destructive endpoint should exist* outside demo mode.
**Recommendation:** Gate `/api/demo/*` and `/api/ingest/clear` behind `if os.getenv("DEMO_MODE","").lower()=="true"` returning 404 otherwise. Gate the cmdb.py file-load behind the same env var (fall back to KNOWN_HOSTS only when not in demo mode). Document that `DEMO_MODE=true` is required for the generator. This is important before any deployment that isn't a pure localhost demo.

### D4 — [FINDING: GAP] [SEVERITY: MEDIUM]
The plan is internally contradictory about cache provisioning. Phase 0.1 requires the Commander to obtain an NVD API key; Phase 2.1's `refresh_nvd_cache()` reads `NVD_API_KEY` from env; Phase 2.4 says caches are "pre-bundled" and "committed to the repo" and "demo mode runs entirely from local caches — no network calls during demo." So: is the cache built once by the Commander (key needed only by Commander, end users get a snapshot) or built by each end user at install time? If pre-built-and-shipped, the cache is a stale snapshot the moment a new CVE is published, and the plan specifies **no refresh cadence** (scope §13 risk register mentions "daily update cron available" but the plan has no cron, no CI job, no documented schedule). If built at install, the Phase 0 NVD-key requirement applies to every installer, contradicting "no network calls during demo" (the build happens before the demo, but the key is still needed).
**Recommendation:** Decide explicitly. Recommended: Commander builds and commits the cache before each stakeholder demo (the 13h plan already includes this); end users do not need an NVD key. Add a `CACHE_SNAPSHOT_DATE` field to each cache file and surface it in `/api/health` ("demo cache age: N days"). Define a refresh cadence (e.g., "within 7 days of any stakeholder demo, or monthly"). Remove the implication that end users must run `refresh_caches.py`.

### D5 — [FINDING: RISK] [SEVERITY: BLOCKER]
This is the second BLOCKER and the architectural root of B4. Tracing the XGBoost feature flow for a generated finding:

1. Generator builds Tenable payload from `nvd_cache.json` (CVSS, CVE, description only — not CWE, not ref count, not patch_available, not exploitdb, not metasploit).
2. `parse_tenable_finding()` → `IngestRequest` (no CWE, no NVD metadata).
3. `ingest_vulnerability()` calls `get_cwe()` → `ingest_cwe.get_cwe()` → **`nvd.get_nvd_data(cve_id)` LIVE API call** (ingest_cwe.py:45).
4. If escalated, `build_feature_vector()` (ingest_helpers.py:230) calls **`nvd.get_nvd_data()` LIVE again** to populate `cwe_class`, `nvd_reference_count`, `vulnerability_age_days`, `cvss_exploitability_sub`, `cvss_impact_sub`, `patch_available`; and calls **`exploitdb.has_poc()` and `metasploit.has_payload()` which each call `nvd.get_nvd_data()` LIVE** to populate `exploitdb_has_poc`, `metasploit_has_payload`.

The XGBoost model's 36 tabular features include ~10 that come exclusively from **live NVD**. The plan's `nvd_cache.json` — which already contains all of these fields per scope §3.1 — is **never read by the pipeline.** The plan's claim (§2.4 line 247) that "demo mode runs entirely from local caches — no network calls during demo" is **false**: every generated finding triggers 3-4 live NVD HTTP calls on first ingest (mitigated only by the 24h in-memory TTL cache, which is empty at process start). If the demo machine loses internet (hotel WiFi, conference firewall, NVD rate-limit), `get_nvd_data()` returns `{}` and every one of those features defaults to zero/empty: `cwe_class=""` (→ no MITRE techniques in the case view — a visible regression), `nvd_reference_count=0`, `vulnerability_age_days=0`, `patch_available=True` (hardcoded fallback in nvd.py:137 — note this is *True* even on failure, a separate latent bug), `exploitdb_has_poc=False`, `metasploit_has_payload=False`, `cvss_exploitability_sub=0`, `cvss_impact_sub=0`. The XGBoost model, trained on real feature distributions, will receive a degenerate all-zero tabular vector and produce a meaningless exploitation probability. The demo's "real scores" (audit check 7.11) will be artefacts of a broken feature pipeline, not credible triage.
**Recommendation (must-fix):** Introduce a file-backed path in `nvd.py`: rename the current `get_nvd_data()` to `get_nvd_data_live()` and add a new `get_nvd_data(cve_id)` that checks `nvd_cache.json` first (if `DEMO_MODE=true` or if the file exists) and returns the cached entry (mapped to the same dict shape: `cwe_class`, `nvd_reference_count`, `vulnerability_age_days`, `cvss_exploitability_sub`, `cvss_impact_sub`, `patch_available`, plus synthesise `references_raw` from `exploitdb_has_poc`/`metasploit_has_payload` so the exploitdb/metasploit helpers work offline). This is a ~2-3 hour refactor not present in the plan. Without it, the demo is not offline-capable and the XGBoost path is not credible. Alternatively, *accept* the live-NVD dependency, delete the offline claim from the plan, and require solid internet at the demo venue — but then `nvd_cache.json`'s NVD-enrichment fields are dead weight and should be pruned.

---

## Section E: Security & Auth

### E1 — [FINDING: PASS] [SEVERITY: LOW]
The new demo routes **are** auto-protected. `main.py:22-34` registers an HTTP middleware that checks `path.startswith("/api/") and not path.startswith("/api/health")`. `/api/demo/scenarios`, `/api/demo/generate`, and `/api/ingest/clear` all start with `/api/` and are not `/api/health`, so when `TRIAGEMATE_API_KEY` is set they require `X-API-Key`. The plan does not exempt them, which is correct. **However**, see E2/G2: the frontend demo controls (and the existing `api.js`) do **not** send the `X-API-Key` header, so if auth is enabled the demo UI will receive 401s. This is a pre-existing frontend gap, not introduced by the plan, but the plan inherits it without addressing it.
**Recommendation:** Confirm the demo runs with `TRIAGEMATE_API_KEY` unset (localhost), or add an `apiFetch()` wrapper in `api.js`/`demoControls.js` that injects the key from a meta tag or prompt. Add an audit check that the demo works both with auth-on and auth-off.

### E2 — [FINDING: CONCERN] [SEVERITY: MEDIUM]
`/api/ingest/clear` is an unauthenticated-when-auth-unset, un-rate-limited, idempotent-destructive endpoint. The only guard is the frontend `confirm()` dialog (plan §5.1 line 746), which is trivially bypassed by a direct `curl`. Combined with D3 (no `DEMO_MODE` gate), a valid key holder can DoS by clearing repeatedly, and each clear grows `resolved_vulnerabilities` unboundedly (scope §13 acknowledges this but offers only manual `DELETE FROM`). For a localhost demo this is acceptable; for any networked deployment it is a real risk.
**Recommendation:** Add server-side rate limiting (e.g., `slowapi` or a simple in-memory token bucket: max 1 clear per 30s), require a `confirm_token` query param echoed from a prior `GET` (CSRF-lite), and gate behind `DEMO_MODE` (D3). Log every clear with a timestamp and count.

### E3 — [FINDING: CONCERN] [SEVERITY: LOW]
`demoControls.js` is served to all users regardless of demo mode. The scenario picker uses `document.createElement('option')` + `textContent` (plan §5.1 line 695) — safe against XSS from scenario names. But `renderDemoControls()` (line 681) is specified to "Inject HTML into #demo-controls-panel" via (presumably) `innerHTML` — if scenario `description` strings are ever injected as HTML rather than text, a malicious `demo_scenarios.json` (which is author-controlled but committed to the repo) could carry script. No CSRF token is sent on the POSTs, but the app is same-origin and the CORS is `*` (pre-existing) — a cross-origin form POST could in theory trigger `/api/ingest/clear` if auth is unset. Realistically localhost-only, low risk.
**Recommendation:** Use `textContent` for all dynamic strings in `renderDemoControls` (never `innerHTML` for scenario data). Add the `SameSite=Lax` attribute consideration to the existing CORS review (out of this plan's scope but worth flagging).

---

## Section F: Testing & Verification

### F1 — [FINDING: GAP] [SEVERITY: MEDIUM]
The 7 listed tests cover structure and counts but miss the behaviours most likely to break the demo:
- No test that a **KEV-listed scenario CVE** produces `tier_0_routing == "auto_resolved"` with `resolution == "very_critical"` (would catch B5).
- No test that generated findings produce **non-degenerate XGBoost features** offline (would catch D5).
- No test that `nvd_cache.json` fields actually reach `build_feature_vector()` (would catch B4).
- No test for the **duplicate-seed-row** behaviour of `mixed-tier-demo` (would catch A4).
- No test for **repeated generate** producing duplicates (would catch A3).
- No test that `vendor_patch_status == 1` when the cache says `patch_available` (would catch B1).
- No test that the archive table has **column parity** with `vulnerabilities` (would catch a schema-drift bug in the hand-written INSERT…SELECT).
- No test for clear **atomicity** under concurrent calls.
- No test that `low-severity-hygiene` findings all auto-resolve low (would catch C4).

**Recommendation:** Add the 9 tests above. Each maps to a specific finding in this report.

### F2 — [FINDING: CONCERN] [SEVERITY: LOW]
The existing suite (20 tests across `test_ingest.py`, `test_queue.py`, `test_health.py`, `test_integration.py`, per ripgrep) should mostly survive. `conftest.py` calls `database.init_db()` (archive table is added via `CREATE TABLE IF NOT EXISTS`, so additive and safe) and `seed()`. The modified `_stub_lookup()` falls back gracefully when `mock_cmdb.json` is absent (`_load_file_cmdb` returns `{}` on `FileNotFoundError`, plan §1.1 line 70-73) so tests that don't ship the JSON still pass. `KNOWN_TAGS` expansion is additive. The one test-host (`PRD-PATIENT-EMR01.health.wa.gov.au`) is **not** in the new CMDB list, so its pre-tier prediction is unaffected by retraining as long as it isn't added to `pretier_training_data.json` — the plan should explicitly exclude test hosts from training data. The pre-tier retrain could shift predictions for *real* demo hosts, but no existing test asserts specific mission-tag values for those. Risk is low but non-zero.
**Recommendation:** Add a guard comment in `pretier_training_data.json`'s generator: "do not add `PRD-PATIENT-EMR01` or any `CVE-TEST-*` host." Add a smoke test that runs the full existing suite post-retrain as part of CI (audit check 7.19 already covers this).

### F3 — [FINDING: GAP] [SEVERITY: HIGH]
The 22-item audit checklist is thorough on *visibility* but blind to the architectural flaws. Critical missing checks:
- **No check that the demo runs offline** (disable network, run a scenario, assert scores are non-degenerate and MITRE techniques populate). This would catch D5/B4 — the most severe findings.
- **No check that a KEV scenario triggers Tier 0 auto-resolve** ("Generate `ransomware-incident`; assert at least one finding has `tier_0_routing=auto_resolved, resolution=very_critical`"). This would catch B5.
- **No check that `nvd_cache.json`'s `exploitdb_has_poc`/`metasploit_has_payload` influence the XGBoost feature vector** (would catch the dead-data issue).
- **No check that `mixed-tier-demo` does not duplicate seed rows** or that its scores match the originals (would catch A4).
- **No check that `resolved_vulnerabilities` has column parity** with `vulnerabilities` (compare PRAGMA table_info).
- **No check that clear is idempotent / atomic** under double-call.
- **No check that `DEMO_MODE` gates the destructive endpoints** (would catch D3).
- **No check that the frontend sends `X-API-Key`** when auth is enabled (would catch E1/E2 frontend gap).
- **No check that `low-severity-hygiene` auto-resolves all5 findings as low** (would catch C4).

The checklist as written would pass **all22 green** while B5 and D5 remain broken — a false-confidence trap.
**Recommendation:** Add the 9 checks above before Strike execution begins; they encode the acceptance criteria for the BLOCKER findings.

---

## Section G: Overall Assessment

### G1 — Top 3 Credibility Risks
1. **`cisa_kev` is never injected (B5).** The ransomware, perimeter-breach, and mixed-tier-demo scenarios cannot demonstrate the deterministic "KEV + CVSS 9 + internet-facing → Very Critical" auto-resolve — the single most compelling TriageMate behaviour. Three of six scenarios are partially broken; the demo script's headline beat silently fails.
2. **The pipeline enriches from live NVD, not `nvd_cache.json` (D5).** An offline or rate-limited demo produces empty CWE (→ no MITRE techniques in the case view — a visible regression) and a degenerate all-zero XGBoost input (→ meaningless scores). The plan's "no network calls during demo" claim is false.
3. **`mixed-tier-demo` duplicates the 7 seed rows with degraded inputs (A4).** Side-by-side, the same CVE on the same host shows two divergent scores; the ±3 validated originals sit next to mis-scored regenerations, inviting the stakeholder's question "why does this one say 94 and that one say 61 for the same CVE?"

### G2 — Top 3 Integrity Risks
1. **`/api/ingest/clear` is ungated and unrate-limited (D3 + E2).** No `DEMO_MODE` guard, no rate limit, only a frontend `confirm()`. A valid key holder (or anyone if auth is unset) can wipe the production queue; `resolved_vulnerabilities` grows unbounded with repeated clears.
2. **No deduplication (A3).** Repeated "Generate" balloons the queue with duplicate `(cve_id, hostname)` rows, distorting metrics, the 7.5% audit sample, and any future re-check scheduler run. There is no UNIQUE index and no upsert.
3. **Frontend does not send `X-API-Key` (E1/E2).** If the demonstrator enables auth (recommended for any networked setting), both the existing UI and the new demo controls will 401; the plan does not reconcile this, risking a dead demo on the day if auth is switched on.

### G3 — Effort Estimate Review
The 13-hour estimate is **under-scoped by roughly 40-50%.** It omits the work that the BLOCKER findings require:
- **Cache-to-pipeline wiring (D5/B4):** a file-backed `get_nvd_data()` refactor + `references_raw` synthesis + tests ≈ **3 hrs** — entirely absent from the plan.
- **KEV injection "separate lookup" (B5):** design + implement + test ≈ **1.5 hrs** — described in a single sentence but not built.
- **`registered_applications` parser (C1):** robust normaliser + 28-host test fixture ≈ **2 hrs** — the plan hand-waves this as "parse."
- **Dedup logic (A3) + `mixed-tier-demo` replace semantics (A4):** ≈ **1 hr**.
- **`DEMO_MODE` gating (D3) + frontend auth header (E1):** ≈ **1 hr**.
- **Additional tests/audit checks (F1/F3):** the 9 missing tests + 9 missing audit checks ≈ **2 hrs** on top of the 1.5h already budgeted.

**Realistic estimate: ~20-22 hrs**, not 13. The plan's parallelisation assumptions also break: D5's refactor is on the critical path (everything depends on the cache actually being consumed) and cannot be parallelised away.

### G4 — Go/No-Go Recommendation
**Conditional NO-GO.** The plan should not be approved for Strike execution as written. Two BLOCKERs (B5, D5) mean the demo, executed verbatim, cannot reliably produce its headline behaviours offline and will mis-score its flagship scenarios. Before green-lighting, the Commander must require the Strike Team to amend the plan to address:

1. **B5 — KEV injection:** Add an explicit `inject_enrichment()` step that patches `IngestRequest.cisa_kev` (and optionally `epss_score`) from `kev_cache.json`/`epss_cache.json` before ingest. (~1.5h)
2. **D5/B4 — cache-to-pipeline wiring:** Either implement a file-backed `get_nvd_data()` so the pipeline reads `nvd_cache.json` in demo mode, **or** explicitly drop the "no network calls" claim, require solid internet at the venue, and prune the dead `exploitdb_has_poc`/`metasploit_has_payload`/`patch_available`/`cwe_class`/`nvd_reference_count`/age/sub-score fields from the cache schema (since they'd be re-derived live anyway). Pick one; document it. (~3h or ~0.5h)
3. **A4 — `mixed-tier-demo` semantics:** Decide replace-vs-duplicate-vs-drop and document. (~0.5h)
4. **D3 — `DEMO_MODE` gating:** Add the env-var guard to cmdb file-loading and the three demo/clear endpoints. (~1h)
5. **F3 — Audit checklist additions:** Add the 9 missing checks (esp. the offline-run check and the KEV-auto-resolve check) so the audit cannot pass green while the BLOCKERs persist. (~1h)

Items 1, 2, 3 are **must-fix before execution**; items 4 and 5 should be added to the plan but can be implemented in parallel. With these amendments, the plan is sound and the architecture is credible; without them, the demo risks failing in front of the stakeholder for reasons the audit checklist would not catch.

---

## Summary

| Section | PASS | CONCERN | GAP | RISK |
|---|---|---|---|---|
| A: Completeness | 1 | 3 (A2, A4, A3-as-concern) | 1 (A3) | 0 |
| B: Architecture | 0 | 3 (B1, B2, B3) | 0 | 2 (B4 HIGH, B5 BLOCKER) |
| C: Data Quality | 0 | 2 (C2, C3) | 0 | 2 (C1, C4) |
| D: Operational | 0 | 2 (D1, D2) | 1 (D4) | 2 (D3, D5 BLOCKER) |
| E: Security | 1 (E1) | 2 (E2, E3) | 0 | 0 |
| F: Testing | 0 | 1 (F2) | 2 (F1, F3 — F3 HIGH) | 0 |
| G: Overall | — | — | — | 2 BLOCKERs (B5, D5), 2 HIGH (B4, F3) |

**Bottom line:** Two BLOCKERs (B5: KEV never injected; D5: pipeline enriches from live NVD, not the cache the plan builds) mean the plan as written will mis-score its flagship scenarios and cannot run offline. The 13h estimate under-counts by ~7-9h. Amend the plan for the five items in G4, then approve.
