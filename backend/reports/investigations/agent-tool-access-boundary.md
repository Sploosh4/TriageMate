# Investigation: PIPE-HIGH-5 — Agent Tool Access Boundary Review

**Date:** 2026-07-14  
**Investigator:** Strike Team  
**Status:** Needs product decision  

---

## Executive Summary

The Tier 2 agentic pipeline exposes 12 tools to the LLM for multi-step CVE investigation. These tools are all **read-only** and query local caches, synthetic data generators, and static mappings. The only active access control is a **hostname binding check** in `execute_tool()` that prevents the LLM from querying hostname-scoped tools for hosts other than the one under investigation.

No authentication, authorisation, rate limiting, or audit-layer exists on individual tool executions. However, because (a) the tools are only reachable via the agent loop which is gated by a feature flag, (b) no HTTP/API endpoint exposes `execute_tool()` externally, and (c) all tools are read-only, the risk is **moderate** — prompt injection could exfiltrate CMDB data for the authorised host or probe the RAG vector store, but cannot mutate data or access unauthorised hosts.

**Recommendation:** Accept current posture for MVP. Consider adding per-tool authorisation and an audit table when the agent path graduates from feature-flag to default.

---

## Tool Inventory

### Legend

| Column | Meaning |
|---|---|
| Data source | What file/API/service the tool reads from |
| Arbitrary input | Can the LLM pass any value (not just the case CVE/hostname)? |
| Hostname-bound | Is the tool subject to the `case_hostname` binding check? |
| Sensitivity | What's the worst data this tool could return? |

| # | Tool | Data source | Parameters | Arbitrary input? | Hostname-bound? | Information sensitivity |
|---|---|---|---|---|---|---|
| 1 | `search_kev` | `data/kev_cache.json` (local) | `cve_id` | Yes — any CVE ID | No | Public CISA KEV data (public) |
| 2 | `search_nvd` | `integrations.nvd.get_nvd_data()` → NVD API or `nvd_cache.json` | `cve_id` | Yes — any CVE ID | No | Public NVD data (public) |
| 3 | `search_epss` | `data/epss_cache.json` (local) | `cve_id` | Yes — any CVE ID | No | Public EPSS data (public) |
| 4 | `search_cwe` | `ingest_cwe.get_cwe()` (local mapping) | `cve_id` | Yes — any CVE ID | No | Public CWE classification (public) |
| 5 | `search_mitre` | `integrations.mitre_mapping.lookup_mitre()` (static mapping) | `cve_id` | Yes — any CVE ID | No | Public ATT&CK techniques (public) |
| 6 | `query_network` | `integrations.network_context.get_network_context()` + `cmdb.get_asset_context()` | `hostname` | Yes — any hostname | **Yes** | Blast radius, zone, peer count, exposure level (internal) |
| 7 | `query_telemetry` | `integrations.synthetic_telemetry.get_telemetry_context()` (synthetic) | `cve_id`, `hostname`, `cvss_score`, `cisa_kev`, `epss_score`, `description` | Yes — any CVE/hostname | **Yes** (on hostname) | Synthetic Sentinel incidents + EDR alerts (synthetic, but mimics real alert data) |
| 8 | `query_advisories` | `integrations.advisories.get_advisory()` (static mapping) | `cve_id` | Yes — any CVE ID | No | WASOC advisory text (semi-public) |
| 9 | `search_exploitdb` | `integrations.exploitdb` (local CSV + NVD refs) | `cve_id` | Yes — any CVE ID | No | Public exploit metadata (public) |
| 10 | `search_metasploit` | `integrations.metasploit.has_payload()` (mapping) | `cve_id` | Yes — any CVE ID | No | Public module metadata (public) |
| 11 | `search_cmdb` | `integrations.cmdb.get_asset_context()` (mock CMDB JSON file) | `hostname` | Yes — any hostname | **Yes** | **HIGH** — `data_classification`, `business_owner`, `operating_system`, `internet_facing`, `registered_applications` |
| 12 | `rag_query` | `ingest_helpers.query_rag()` → LanceDB vector store | `query_text` (free text) | Yes — any string | **No** | Asset documentation, patch records, config notes |

---

## Existing Access Controls

### 1. Hostname Binding Check (the only control)

**Location:** `pipeline/tier_2/tools.py`, lines 710–731 in `execute_tool()`

```python
if case_hostname and params.get("hostname") and params["hostname"] != case_hostname:
    return {"success": False, "error": "not the case under investigation"}
```

**What it does:** When the agent loop calls `execute_tool()`, it passes `case_hostname=self._case_hostname` (set from `agent.evaluate(hostname=...)`). If a tool accepts a `hostname` parameter and it doesn't match the case hostname, the call is rejected.

**Applicable tools:** `query_network` (#6), `query_telemetry` (#7 — partial, only hostname param), `search_cmdb` (#11)

**Not covered:** `rag_query` (#12) accepts `query_text` not `hostname`, so it is **not bound**. The LLM could probe the vector store with arbitrary text.

### 2. Step Limit

**Maximum 15 steps** per evaluation (`AGENT_MAX_STEPS`, configurable via env var). Each step can call up to **5 tools per turn** (`_MAX_TOOLS_PER_TURN`). Maximum theoretical tool calls: 15 × 5 = 75 per evaluation.

### 3. Cost Budget

**Default $0.50** per evaluation (`AGENT_COST_BUDGET`). This only limits LLM API spend, not tool executions.

### 4. Consecutive Failure Termination

After **3 consecutive tool failures**, the agent terminates with a neutral default. This prevents infinite retry loops.

### 5. Conversation History Trimming

When conversation history exceeds 50KB (`_MAX_CONVERSATION_HISTORY_CHARS`), oldest tool result pairs are removed. This bounds memory usage but does not affect access control.

---

## What's NOT Protected

| Gap | Detail | Severity |
|---|---|---|
| **No authentication** | `execute_tool()` has no caller authentication. Any code importing from `pipeline.tier_2` can call it. | **Low** — no external entry point exports it |
| **No authorisation** | No role/permission checks on any tool. Every tool is equally available. | **Low** — all tools are read-only |
| **No rate limiting** | No per-tool or per-CVE rate limiting. Agent could probe 75+ times per evaluation. | **Low-Medium** — cost budget limits LLM spend, but tool calls are free |
| **No audit table** | Tool calls are logged via Python `logging` but not persisted to a queryable table. | **Low** — logs exist on disk |
| **`rag_query` binding bypass** | The `rag_query` tool accepts `query_text` but is not subject to the hostname binding check, even when the query text is a hostname. | **Low-Medium** — RAG returns read-only documentation |
| **CVE probing** | Tools that accept `cve_id` are not bound to the case CVE. LLM could probe any CVE in the database. | **Low** — all CVE data sources are public or derived from public data |
| **Public API export** | `execute_tool`, `TOOL_DEFINITIONS`, and `get_tool_names` are exported in `pipeline/tier_2/__init__.py`'s `__all__`. | **Low** — no evidence of external misuse, but broadens the attack surface |

---

## Risk Assessment

### Worst-Case Abuse Scenario

**Precondition:** An attacker controls the `description` field of a CVE being evaluated (e.g., via a crafted NVD entry that the pipeline ingests). The LLM is prompt-injected to deviate from its investigation instructions.

**Attack sequence:**

```
Step 1: search_cmdb(hostname="per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        ✓ Allowed by binding check (matches case hostname)
        → Returns: data_classification="OFFICIAL Sensitive",
                    business_owner="WA Health — Health Support Services",
                    operating_system="Windows Server 2019 Standard",
                    internet_facing=True,
                    registered_applications="Progress MOVEit Transfer 2022.0.4"

Step 2: query_network(hostname="per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        ✓ Allowed by binding check
        → Returns: blast_radius_score, zone, peer_count, exposure_level

Step 3: query_telemetry(hostname="per-PRD-MOVEIT-WEB01.health.wa.gov.au", ...)
        ✓ Allowed by binding check
        → Returns: synthetic threat_score, incident_count, alert_count, process_evidence

Step 4: search_cmdb(hostname="secret-doj-HR-DB01.justice.wa.gov.au")
        ✗ Blocked by binding check → "not the case under investigation"

Step 5: rag_query(query_text="per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        ✓ NOT blocked — rag_query uses query_text not hostname
        → Returns: vector store documents for the asset (patch records, config notes)
```

**Impact:**
- Full CMDB metadata for the authorised host (sensitive but limited to one host)
- Network topology data for the authorised host (zone, peers, blast radius)
- RAG documentation for the authorised host (patch history, config notes)
- Inability to pivot to other hosts (binding check prevents this)

**Limitations:**
- All tools are read-only — no data mutation possible
- Hostname binding check is server-side and cannot be bypassed by the LLM
- The LLM cannot pivot to other hosts
- RAG returns documentation, not credentials or secrets (unless seeded with them — **Assumption:** RAG documents do not contain secrets)

### Blast Radius

| Affected | Detail |
|---|---|
| Data confidentiality | **Moderate** — a prompt-injected agent could exfiltrate CMDB data for the authorised host via the LLM's output |
| Data integrity | **None** — all tools are read-only |
| Data availability | **None** — no tool modifies or deletes data |
| Cross-host pivot | **None** — hostname binding check prevents queries to other hosts |
| LLM API key theft | **Low** — the API key is sent to the LLM provider in the HTTP header, not in the tool-call parameters |

---

## Proposed Next Action

### Option A: Accept (Recommended for MVP)

**Rationale:** The hostname binding check is the critical control and it works correctly. All tools are read-only. No external HTTP endpoint exposes `execute_tool()`. The agent path is feature-flagged off by default (`TRIAGEMATE_AGENT_ENABLED=false`). The risk is contained.

**Status label:** Not a defect — design choice requiring product acknowledgment

### Option B: Harden (Enhancement for post-MVP)

| Enhancement | Effort | Impact |
|---|---|---|
| Add hostname binding to `rag_query` (parameter name check or a separate regex-based check) | 15 min | Closes the one binding bypass |
| Add a database-backed audit table `agent_tool_log` with timestamps, CVE ID, tool name, params, and result code | 2 hr | Enables forensic analysis |
| Add per-evaluation rate limiting (max N calls per tool) to prevent LLM from hammering a single integration | 1 hr | Adds defence in depth |
| Add `execute_tool` to a private/internal-only module (remove from `__all__`) | 5 min | Reduces public API surface |

### Option C: Remove export of `execute_tool` from `__init__.py`

**Effort:** 5 minutes. Remove `"execute_tool"` from `__all__` and the `from ... import execute_tool` line in `__init__.py`. The agent imports directly from `tools.py`.

**Recommendation:** Do this regardless — it costs nothing and reduces the public API surface.

---

## Appendix: Search Results

```
rg 'auth|permission|role|access|admin' backend/pipeline/tier_2/ -i
```

**Result:** Zero matches for auth, permission, role, access, or admin in any file under `backend/pipeline/tier_2/`.

The only access control found was the hostname binding check in `execute_tool()`, which does not use any of the above keywords.
