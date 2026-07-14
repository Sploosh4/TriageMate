"""
Tool definitions and implementations for the Tier 2 agentic CVE investigation.

Each tool wraps an existing TriageMate integration and returns structured JSON:
    {"success": bool, "data": ... | None, "error": str | None}

All tools are READ-ONLY — they query existing data sources and return results.
No tool creates, updates, or deletes any data.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("triagemate.tier_2.tools")

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"

# ── Tool Definitions (for LLM function/tool_use API) ──────────────────────

TOOL_DEFINITIONS = [
    {
        "name": "search_kev",
        "description": "Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_nvd",
        "description": "Fetch NVD (National Vulnerability Database) enrichment data for a CVE including CVSS vector, score, reference count, CWE ID, and description",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_epss",
        "description": "Look up EPSS (Exploit Prediction Scoring System) score and percentile for a CVE",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_cwe",
        "description": "Look up CWE (Common Weakness Enumeration) classification for a CVE",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_mitre",
        "description": "Look up MITRE ATT&CK techniques mapped to a CVE's CWE classification",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "query_network",
        "description": "Get network context (blast radius, zone, peer count) for a hostname",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Fully qualified hostname (e.g. per-PRD-MOVEIT-WEB01.health.wa.gov.au)",
                }
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "query_telemetry",
        "description": "Get synthetic Sentinel and EDR telemetry data for a CVE+hostname combination",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                },
                "hostname": {
                    "type": "string",
                    "description": "Fully qualified hostname",
                },
                "cvss_score": {
                    "type": "number",
                    "description": "CVSS score of the vulnerability",
                },
                "cisa_kev": {
                    "type": "boolean",
                    "description": "Whether the CVE is in CISA KEV",
                },
                "epss_score": {
                    "type": "number",
                    "description": "EPSS score of the vulnerability",
                },
                "description": {
                    "type": "string",
                    "description": "CVE description text",
                },
            },
            "required": ["cve_id", "hostname"],
        },
    },
    {
        "name": "query_advisories",
        "description": "Look up WASOC (Western Australian Security Operations Centre) advisory for a CVE",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_exploitdb",
        "description": "Check if a CVE has public exploit code on ExploitDB",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_metasploit",
        "description": "Check if a CVE has a Metasploit framework module available",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID like CVE-2023-36884",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_cmdb",
        "description": "Get asset context from the CMDB (Configuration Management Database) for a hostname",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Fully qualified hostname (e.g. per-PRD-MOVEIT-WEB01.health.wa.gov.au)",
                }
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "rag_query",
        "description": "Query the RAG vector store for asset context and documentation for the case under investigation",
        "parameters": {
            "type": "object",
            "properties": {
                "cwe_class": {
                    "type": "string",
                    "description": "Optional CWE class to narrow the RAG search context",
                },
            },
            "required": [],
        },
    },
]


# ── EPSS Cache Helper ─────────────────────────────────────────────────────

_EPSS_CACHE: dict | None = None


def _load_epss_cache() -> dict:
    """Lazy-load epss_cache.json into module memory."""
    global _EPSS_CACHE
    if _EPSS_CACHE is not None:
        return _EPSS_CACHE
    path = _DATA_DIR / "epss_cache.json"
    try:
        with open(path) as f:
            _EPSS_CACHE = json.load(f)
        logger.info("Loaded %d EPSS entries", len(_EPSS_CACHE))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.warning("EPSS cache not loaded: %s", e)
        _EPSS_CACHE = {}
    return _EPSS_CACHE


# ── KEV Cache Helper ──────────────────────────────────────────────────────

_KEV_CACHE: dict | None = None


def _load_kev_cache() -> dict:
    """Lazy-load kev_cache.json into module memory."""
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    path = _DATA_DIR / "kev_cache.json"
    try:
        with open(path) as f:
            _KEV_CACHE = json.load(f)
        logger.info("Loaded %d KEV entries", len(_KEV_CACHE))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.warning("KEV cache not loaded: %s", e)
        _KEV_CACHE = {}
    return _KEV_CACHE


# ── Tool Implementations ──────────────────────────────────────────────────


def _search_kev(cve_id: str) -> dict:
    """Check if a CVE is in the CISA KEV catalog (via kev_cache.json)."""
    logger.info(
        "Tool search_kev called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_kev",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        cache = _load_kev_cache()
        entry = cache.get(cve_id.upper())
        if entry and entry.get("known_exploited"):
            return {
                "success": True,
                "data": {
                    "is_kev": True,
                    "date_added": entry.get("date_added", ""),
                    "action": entry.get("action", ""),
                    "note": entry.get("note", ""),
                },
                "error": None,
            }
        return {
            "success": True,
            "data": {"is_kev": False, "date_added": None},
            "error": None,
        }
    except Exception as e:
        logger.warning("KEV tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_nvd(cve_id: str) -> dict:
    """Fetch NVD enrichment data for a CVE."""
    logger.info(
        "Tool search_nvd called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_nvd",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        from integrations.nvd import get_nvd_data

        nvd = get_nvd_data(cve_id)
        return {
            "success": True,
            "data": {
                "cve_id": cve_id,
                "cvss_vector": "",  # NVD doesn't return raw vector directly; stored in cache
                "cvss_score": None,
                "reference_count": nvd.get("nvd_reference_count", 0),
                "cwe_id": nvd.get("cwe_class", ""),
                "description": "",
                "vulnerability_age_days": nvd.get("vulnerability_age_days", 0),
                "patch_available": nvd.get("patch_available", False),
                "cvss_exploitability_sub": nvd.get("cvss_exploitability_sub", 0.0),
                "cvss_impact_sub": nvd.get("cvss_impact_sub", 0.0),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("NVD tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_epss(cve_id: str) -> dict:
    """Look up EPSS score and percentile for a CVE."""
    logger.info(
        "Tool search_epss called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_epss",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        cache = _load_epss_cache()
        entry = cache.get(cve_id.upper())
        if entry:
            return {
                "success": True,
                "data": {
                    "epss_score": entry.get("epss", 0.0),
                    "epss_percentile": entry.get("percentile", 0.0),
                },
                "error": None,
            }
        # Not found in cache
        return {
            "success": True,
            "data": {"epss_score": 0.0, "epss_percentile": 0.0},
            "error": None,
        }
    except Exception as e:
        logger.warning("EPSS tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_cwe(cve_id: str) -> dict:
    """Look up CWE classification for a CVE."""
    logger.info(
        "Tool search_cwe called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_cwe",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        from ingest_cwe import get_cwe

        cwe_result = get_cwe(cve_id, "")
        cwe_class = cwe_result.get("cwe_class", "")
        return {
            "success": True,
            "data": {
                "cwe_id": cwe_class,
                "cwe_pillar": "",
                "cwe_class": cwe_class,
                "cwe_base": "",
                "cwe_variant": "",
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("CWE tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_mitre(cve_id: str) -> dict:
    """Look up MITRE ATT&CK techniques via CWE classification."""
    logger.info(
        "Tool search_mitre called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_mitre",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        # Need to get CWE first, then look up MITRE techniques
        from ingest_cwe import get_cwe
        from integrations.mitre_mapping import lookup_mitre

        cwe_result = get_cwe(cve_id, "")
        cwe_class = cwe_result.get("cwe_class", "")
        techniques = lookup_mitre(cwe_class)
        tactics = list(
            {t.get("id", "").split(".")[0] for t in techniques if t.get("id")}
        )
        return {
            "success": True,
            "data": {
                "cwe_id": cwe_class,
                "techniques": techniques,
                "tactics": tactics,
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("MITRE tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _query_network(hostname: str) -> dict:
    """Get network context (blast radius, zone, peer count) for a hostname."""
    logger.info(
        "Tool query_network called for %s",
        hostname,
        extra={
            "event": "agent_tool_call",
            "tool": "query_network",
            "params": {"hostname": hostname},
        },
    )
    try:
        from integrations.network_context import get_network_context
        from integrations.cmdb import get_asset_context

        asset_ctx = get_asset_context(hostname)
        ctx = get_network_context(hostname, asset_ctx)
        return {
            "success": True,
            "data": {
                "blast_radius_score": ctx.get("blast_radius_score", 0.0),
                "zone": ctx.get("zone", "internal"),
                "zone_display": ctx.get("zone_display", "Internal Network"),
                "peer_count": ctx.get("peer_count", 0),
                "exposure_level": ctx.get("exposure_level", "low"),
                "internet_facing_peers": ctx.get("internet_facing_peers", 0),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("Network context tool failed for %s: %s", hostname, e)
        return {"success": False, "data": None, "error": str(e)}


def _query_telemetry(
    cve_id: str,
    hostname: str,
    cvss_score: float = 0.0,
    cisa_kev: bool = False,
    epss_score: float = 0.0,
    description: str = "",
) -> dict:
    """Get synthetic Sentinel + EDR telemetry for a CVE+hostname."""
    logger.info(
        "Tool query_telemetry called for %s on %s",
        cve_id,
        hostname,
        extra={
            "event": "agent_tool_call",
            "tool": "query_telemetry",
            "params": {"cve_id": cve_id, "hostname": hostname},
        },
    )
    try:
        from integrations.synthetic_telemetry import get_telemetry_context

        telemetry = get_telemetry_context(
            cve_id=cve_id,
            hostname=hostname,
            cvss_score=cvss_score,
            cisa_kev=cisa_kev,
            epss_score=epss_score,
            description=description,
        )
        return {
            "success": True,
            "data": {
                "threat_score": telemetry.get("threat_score", 0.0),
                "incident_count": len(telemetry.get("sentinel_incidents", [])),
                "alert_count": len(telemetry.get("edr_alerts", [])),
                "process_evidence": telemetry.get("process_evidence", {}),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("Telemetry tool failed for %s on %s: %s", cve_id, hostname, e)
        return {"success": False, "data": None, "error": str(e)}


def _query_advisories(cve_id: str) -> dict:
    """Look up WASOC advisory for a CVE."""
    logger.info(
        "Tool query_advisories called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "query_advisories",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        from integrations.advisories import get_advisory

        advisory = get_advisory(cve_id)
        return {
            "success": True,
            "data": {
                "advisory_text": advisory.get("quote", ""),
                "vendor": "",
                "affected_products": "",
                "ref_id": advisory.get("ref_id", ""),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("Advisory tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_exploitdb(cve_id: str) -> dict:
    """Check if a CVE has public exploit code on ExploitDB."""
    logger.info(
        "Tool search_exploitdb called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_exploitdb",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        from integrations.exploitdb import has_poc, _lookup_edb

        poc = has_poc(cve_id)
        # Try to get more detail
        try:
            details = _lookup_edb(cve_id)
        except Exception:
            details = []

        return {
            "success": True,
            "data": {
                "has_poc": poc,
                "exploit_count": len(details),
                "exploits": [
                    {
                        "edb_id": e.get("edb_id", ""),
                        "description": e.get("description", ""),
                        "type": e.get("type", ""),
                        "platform": e.get("platform", ""),
                    }
                    for e in details[:5]  # limit to 5 entries
                ],
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("ExploitDB tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_metasploit(cve_id: str) -> dict:
    """Check if a CVE has a Metasploit module."""
    logger.info(
        "Tool search_metasploit called for %s",
        cve_id,
        extra={
            "event": "agent_tool_call",
            "tool": "search_metasploit",
            "params": {"cve_id": cve_id},
        },
    )
    try:
        from integrations.metasploit import has_payload

        has_module = has_payload(cve_id)
        # Estimate count — we can't get exact count without the full EDB CSV
        module_count = 1 if has_module else 0
        return {
            "success": True,
            "data": {
                "has_module": has_module,
                "module_count": module_count,
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("Metasploit tool failed for %s: %s", cve_id, e)
        return {"success": False, "data": None, "error": str(e)}


def _search_cmdb(hostname: str) -> dict:
    """Get asset context from CMDB for a hostname."""
    logger.info(
        "Tool search_cmdb called for %s",
        hostname,
        extra={
            "event": "agent_tool_call",
            "tool": "search_cmdb",
            "params": {"hostname": hostname},
        },
    )
    try:
        from integrations.cmdb import get_asset_context

        ctx = get_asset_context(hostname)
        return {
            "success": True,
            "data": {
                "asset_type": ctx.get("role", ""),
                "department": ctx.get("business_owner", ""),
                "location": ctx.get("network_zone", ""),
                "data_classification": ctx.get("data_classification", "OFFICIAL"),
                "internet_facing": ctx.get("internet_facing", False),
                "operating_system": ctx.get("operating_system", "Unknown"),
                "registered_applications": ctx.get("registered_applications", ""),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("CMDB tool failed for %s: %s", hostname, e)
        return {"success": False, "data": None, "error": str(e)}


def _rag_query(hostname: str | None = None, cwe_class: str | None = None) -> dict:
    """Query the RAG vector store for asset context.

    The hostname is supplied by the server (execute_tool injects case_hostname).
    No model-controlled parameter can choose the asset hostname.
    """
    logger.info(
        "Tool rag_query called for hostname='%s', cwe_class='%s'",
        hostname,
        cwe_class,
        extra={
            "event": "agent_tool_call",
            "tool": "rag_query",
            "params": {"hostname": hostname, "cwe_class": cwe_class},
        },
    )
    try:
        from ingest_helpers import query_rag

        result = query_rag(hostname, cwe_class=cwe_class)
        rag_context = result.get("rag_context", "")
        documents = result.get("documents", [])
        return {
            "success": True,
            "data": {
                "results_count": len(documents),
                "context": rag_context,
                "status": result.get("status", ""),
            },
            "error": None,
        }
    except Exception as e:
        logger.warning("RAG query tool failed: %s", e)
        return {"success": False, "data": None, "error": str(e)}


# ── Tool Dispatch Map ─────────────────────────────────────────────────────

_TOOL_IMPLEMENTATIONS = {
    "search_kev": _search_kev,
    "search_nvd": _search_nvd,
    "search_epss": _search_epss,
    "search_cwe": _search_cwe,
    "search_mitre": _search_mitre,
    "query_network": _query_network,
    "query_telemetry": _query_telemetry,
    "query_advisories": _query_advisories,
    "search_exploitdb": _search_exploitdb,
    "search_metasploit": _search_metasploit,
    "search_cmdb": _search_cmdb,
    "rag_query": _rag_query,
}


def execute_tool(
    tool_name: str, params: dict, case_hostname: str | None = None
) -> dict:
    """Execute a tool by name with the given parameters.

    Args:
        tool_name: Name of the tool to execute (must be in TOOL_DEFINITIONS).
        params: Dictionary of parameters to pass to the tool.
        case_hostname: The hostname from the case under investigation.
            If set, tools that accept a ``hostname`` parameter will validate
            that the requested hostname matches the case hostname. This
            prevents a compromised or prompt-injected LLM from querying
            CMDB / network / telemetry data for hosts other than the one
            under investigation.

    Returns:
        dict with keys: success, data, error
    """
    impl = _TOOL_IMPLEMENTATIONS.get(tool_name)
    if impl is None:
        return {
            "success": False,
            "data": None,
            "error": f"Unknown tool: {tool_name}",
        }

    # ── Hostname binding check ──────────────────────────────────────────────
    # Bind check runs FIRST: if the attacker supplied a mismatched hostname,
    # reject before injection can mask it. Then injection sets the correct
    # hostname for tools that use server-enforced asset scope.
    if case_hostname and params.get("hostname") and params["hostname"] != case_hostname:
        logger.warning(
            "Hostname mismatch on tool '%s': requested '%s' != case '%s'",
            tool_name,
            params["hostname"],
            case_hostname,
            extra={
                "event": "hostname_mismatch",
                "tool": tool_name,
                "requested_hostname": params["hostname"],
                "case_hostname": case_hostname,
            },
        )
        return {
            "success": False,
            "data": None,
            "error": (
                f"Cannot query tool '{tool_name}' for host "
                f"'{params['hostname']}': not the case under investigation"
            ),
        }

    # ── Hostname injection for rag_query (server-enforced asset scope) ──────
    # After the bind check passes (or no hostname was supplied), inject the
    # case hostname so the tool queries only the asset under investigation.
    if tool_name == "rag_query" and case_hostname:
        params = {**params, "hostname": case_hostname}

    logger.info(
        "Executing tool %s with params: %s",
        tool_name,
        {k: v for k, v in params.items() if k != "api_key"},
        extra={"event": "agent_tool_execute", "tool": tool_name, "params": params},
    )

    try:
        return impl(**params)
    except TypeError as e:
        logger.warning("Tool %s parameter error: %s", tool_name, e)
        return {"success": False, "data": None, "error": f"Parameter error: {e}"}
    except Exception as e:
        logger.warning("Tool %s execution error: %s", tool_name, e)
        return {"success": False, "data": None, "error": str(e)}


def get_tool_names() -> list[str]:
    """Return the list of all defined tool names."""
    return [t["name"] for t in TOOL_DEFINITIONS]
