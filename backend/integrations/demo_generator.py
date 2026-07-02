"""
Demo Data Generator — TriageMate MVP.

Generates realistic Tenable-format vulnerability findings from:
  - Curated scenario definitions (``demo_scenarios.json``)
  - Random waves (weighted by CMDB asset criticality and severity
    distribution)
  - Cache enrichment (NVD, EPSS, KEV)

All outputs are compatible with ``integrations/tenable.py:parse_tenable_finding()``
so they can be fed directly into the ingest pipeline.

Design per DEMO_DATA_GENERATOR_PLAN.md §3.2 and §3.3.
"""

import json
import logging
import random
import re
from pathlib import Path

logger = logging.getLogger("triagemate.demo_generator")

DATA_DIR = Path(__file__).parent.parent / "data"

# ─── Caches (lazy-loaded, module-level) ───────────────────────────────

_NVD_CACHE: dict | None = None
_EPSS_CACHE: dict | None = None
_KEV_CACHE: dict | None = None
_CMDB: dict[str, dict] | None = None
_SCENARIOS: list[dict] | None = None

DEPT_NETWORKS = {
    "health": 1,
    "transport": 2,
    "education": 3,
    "communities": 4,
    "police": 5,
    "finance": 6,
    "justice": 7,
    "water": 8,
    "watercorporation": 8,
    "sharedservices": 9,
    "parliament": 10,
    "dpird": 11,
    "dfes": 12,
}

# ─── CWE → Plugin Family Mapping ─────────────────────────────────────

CWE_FAMILY_MAP = {
    "CWE-89": "Database",
    "CWE-787": "Buffer Overflow",
    "CWE-22": "Path Traversal",
    "CWE-287": "Authentication",
    "CWE-416": "Use After Free",
    "CWE-94": "Code Execution",
    "CWE-200": "Information Disclosure",
    "CWE-862": "Access Control",
    "CWE-506": "Backdoor",
}

# ─── Application name → (vendor, product) Aliases ────────────────────

KNOWN_ALIASES: dict[str, tuple[str, str]] = {
    "iis": ("microsoft", "internet information services"),
    "apache httpd": ("apache", "http server"),
    "confluence": ("atlassian", "confluence"),
    "postgresql": ("postgresql", "postgresql"),
    "connectwise screenconnect": ("connectwise", "screenconnect"),
    "papercut": ("papercut", "papercut mf"),
    "manageengine servicedesk plus": ("zoho", "manageengine servicedesk plus"),
    "moveit transfer": ("progress", "moveit transfer"),
    "microsoft office": ("microsoft", "office"),
    "citrix gateway": ("citrix", "gateway"),
    "citrix adc": ("citrix", "application delivery controller"),
    "netscaler": ("citrix", "netscaler"),
    "java": ("oracle", "jre"),
}

# ─── Version-stripping regex ──────────────────────────────────────────

_VERSION_RE = re.compile(r"\s+\d+([.\d]*\d)?$")


def _strip_version(app_name: str) -> str:
    """Remove trailing version numbers from an application name.

    Examples:
        "Progress MOVEit Transfer 2023.0.0" → "Progress MOVEit Transfer"
        "IIS 10.0"                          → "IIS"
        "Windows File Server role"          → "Windows File Server role"
    """
    return _VERSION_RE.sub("", app_name).strip()


# ======================================================================
# Cache loaders (lazy, module-level)
# ======================================================================


def _load_nvd_cache() -> dict:
    """Lazy-load ``DATA_DIR / "nvd_cache.json"``."""
    global _NVD_CACHE
    if _NVD_CACHE is not None:
        return _NVD_CACHE
    path = DATA_DIR / "nvd_cache.json"
    try:
        with open(path) as f:
            _NVD_CACHE = json.load(f)
        logger.info("Loaded %d entries from nvd_cache.json", len(_NVD_CACHE))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("nvd_cache.json not loaded: %s", exc)
        _NVD_CACHE = {}
    return _NVD_CACHE


def _load_epss_cache() -> dict:
    """Lazy-load ``DATA_DIR / "epss_cache.json"``."""
    global _EPSS_CACHE
    if _EPSS_CACHE is not None:
        return _EPSS_CACHE
    path = DATA_DIR / "epss_cache.json"
    try:
        with open(path) as f:
            _EPSS_CACHE = json.load(f)
        logger.info("Loaded %d entries from epss_cache.json", len(_EPSS_CACHE))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("epss_cache.json not loaded: %s", exc)
        _EPSS_CACHE = {}
    return _EPSS_CACHE


def _load_kev_cache() -> dict:
    """Lazy-load ``DATA_DIR / "kev_cache.json"``."""
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    path = DATA_DIR / "kev_cache.json"
    try:
        with open(path) as f:
            _KEV_CACHE = json.load(f)
        logger.info("Loaded %d entries from kev_cache.json", len(_KEV_CACHE))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("kev_cache.json not loaded: %s", exc)
        _KEV_CACHE = {}
    return _KEV_CACHE


def _load_cmdb() -> dict[str, dict]:
    """Lazy-load ``DATA_DIR / "mock_cmdb.json"``, keyed by hostname."""
    global _CMDB
    if _CMDB is not None:
        return _CMDB
    path = DATA_DIR / "mock_cmdb.json"
    try:
        with open(path) as f:
            hosts: list[dict] = json.load(f)
        _CMDB = {h["hostname"]: h for h in hosts}
        logger.info("Loaded %d hosts from mock_cmdb.json", len(_CMDB))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("mock_cmdb.json not loaded: %s", exc)
        _CMDB = {}
    return _CMDB


def load_scenarios() -> list[dict]:
    """Lazy-load ``DATA_DIR / "demo_scenarios.json"``."""
    global _SCENARIOS
    if _SCENARIOS is not None:
        return _SCENARIOS
    path = DATA_DIR / "demo_scenarios.json"
    try:
        with open(path) as f:
            _SCENARIOS = json.load(f)
        logger.info("Loaded %d scenarios from demo_scenarios.json", len(_SCENARIOS))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("demo_scenarios.json not loaded: %s", exc)
        _SCENARIOS = []
    return _SCENARIOS


# ======================================================================
# Scenario listing (for UI)
# ======================================================================


def get_scenarios_list() -> list[dict]:
    """Return a summary list of available scenarios for the UI.

    Each entry: ``{"id": ..., "name": ..., "description": ..., "finding_count": N}``
    """
    scenarios = load_scenarios()
    result = []
    for s in scenarios:
        result.append(
            {
                "id": s.get("id", ""),
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "finding_count": len(s.get("findings", [])),
            }
        )
    return result


# ======================================================================
# Helper utilities
# ======================================================================


def _extract_department(hostname: str) -> str:
    """Extract the department name from a hostname's domain.

    Splits the FQDN into parts and checks each domain component against
    the known department keys.  Longer keys (e.g. ``"watercorporation"``)
    are checked before shorter ones (e.g. ``"water"``) to avoid substring
    false matches.

    Examples:
        PRD-MOVEIT-WEB01.health.wa.gov.au                → ``"health"``
        PRD-CITRIX-ADC01.transport.wa.gov.au             → ``"transport"``
        PRD-WTR-SCADA01.watercorporation.com.au          → ``"watercorporation"``
    """
    lower = hostname.lower()
    parts = lower.split(".")
    # Check longest keys first to avoid substring collisions (e.g. water vs
    # watercorporation)
    for dept in sorted(DEPT_NETWORKS, key=len, reverse=True):
        if dept in parts:
            return dept
    return "unknown"


def _assign_ip(hostname: str) -> str:
    """Stable deterministic IP via department index + hostname hash.

    Format: ``10.{dept_idx}.{hash(hostname) % 255}.50``
    """
    dept = _extract_department(hostname)
    dept_idx = DEPT_NETWORKS.get(dept, 99)
    host_hash = abs(hash(hostname)) % 255
    return f"10.{dept_idx}.{host_hash}.50"


def _extract_os_keyword(operating_system: str) -> str:
    """Normalise an operating system string to a keyword.

    Returns one of: ``"windows"``, ``"linux"``, ``"freebsd"``, ``"solaris"``,
    or ``"unknown"``.
    """
    os_lower = operating_system.lower()
    if "windows" in os_lower:
        return "windows"
    for kw in ("ubuntu", "debian", "centos", "rhel", "linux"):
        if kw in os_lower:
            return "linux"
    if "freebsd" in os_lower:
        return "freebsd"
    if "solaris" in os_lower:
        return "solaris"
    return "unknown"


def _parse_applications(registered_apps: str) -> list[dict]:
    """Parse a comma-separated registered-applications string.

    Strips version numbers, maps known aliases, and returns a list of
    ``{"name": ..., "vendor": ..., "product": ...}`` dicts.

    Examples:
        "Progress MOVEit Transfer 2023.0.0, IIS 10.0"
        → [{"name": "Progress MOVEit Transfer", "vendor": "progress",
            "product": "moveit transfer"},
           {"name": "IIS", "vendor": "microsoft",
            "product": "internet information services"}]
    """
    if not registered_apps:
        return []

    results: list[dict] = []
    parts = [p.strip() for p in registered_apps.split(",") if p.strip()]

    for part in parts:
        name_stripped = _strip_version(part)
        name_lower = name_stripped.lower()

        # Check known aliases
        matched_alias = None
        for alias_key, (vendor, product) in KNOWN_ALIASES.items():
            # match if the alias key appears anywhere in the lowercased name
            if alias_key in name_lower:
                matched_alias = (vendor, product)
                break

        if matched_alias:
            vendor, product = matched_alias
        else:
            vendor = ""
            product = ""

        results.append(
            {
                "name": name_stripped,
                "vendor": vendor,
                "product": product,
            }
        )

    return results


# ======================================================================
# Scanner output template
# ======================================================================


def generate_realistic_scanner_output(
    cve_id: str,
    description: str,
    vendor: str = "",
    product: str = "",
) -> str:
    """Build a Nessus-style scanner output text block.

    Sections: Synopsis, Description, Risk Factor, Solution, References.
    """
    score = 0.0
    nvd = _load_nvd_cache().get(cve_id, {})
    if nvd:
        score = nvd.get("cvss_v3_score", 0.0)

    if score >= 9.0:
        risk_factor = "CRITICAL"
    elif score >= 7.0:
        risk_factor = "HIGH"
    elif score >= 4.0:
        risk_factor = "MEDIUM"
    else:
        risk_factor = "LOW"

    solution = (
        f"Apply the vendor-supplied patch for {vendor} {product}. "
        if vendor and product
        else "Apply the vendor-supplied patch. "
        "Review vendor advisory for specific mitigation guidance."
    )

    synopsis = description[:200] if description else f"{cve_id} detected."
    refs = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    lines = [
        f"[{risk_factor}] {cve_id}" + (f" — {vendor}/{product}" if vendor else ""),
        "",
        f"  Synopsis : {synopsis}",
        "",
        "  Description :",
        f"    {description}" if description else "    No description available.",
        "",
        f"  Risk Factor : {risk_factor}",
        f"  CVSS v3.1  : {score}",
        "",
        "  Solution :",
        f"    {solution}",
        "",
        "  References :",
        f"    {refs}",
    ]
    return "\n".join(lines)


# ======================================================================
# Tenable payload builder
# ======================================================================


def _cve_to_plugin_id(cve_id: str) -> int:
    """Stable numeric plugin ID derived from a CVE string."""
    return (abs(hash(cve_id)) % 90000) + 100000


def _cwe_to_family(cwe_class: str) -> str:
    """Map a CWE ID to a Nessus plugin family name."""
    return CWE_FAMILY_MAP.get(cwe_class, "Misc.")


def _score_to_risk_factor(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _score_to_severity_id(score: float) -> int:
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    return 1


def _pick_port(apps: list[dict]) -> dict:
    """Pick a plausible port, protocol, and service name from parsed apps.

    Returns ``{"port": int, "protocol": str, "service": str}``.
    """
    port = 443
    app_names_lower = " ".join(a["name"].lower() for a in apps)
    app_products_lower = " ".join(a.get("product", "").lower() for a in apps)
    combined = app_names_lower + " " + app_products_lower

    if any(kw in combined for kw in ("smb", "file server", "cifs")):
        port = 445
    elif any(kw in combined for kw in ("rdp", "terminal", "remote desktop")):
        port = 3389
    elif any(kw in combined for kw in ("sql", "database", "postgresql", "mssql")):
        port = 1433
    elif any(
        kw in combined
        for kw in ("web", "http", "https", "iis", "apache", "nginx", "sharepoint")
    ):
        port = 443

    port_to_service = {
        443: "HTTP",
        445: "SMB",
        3389: "RDP",
        1433: "SQL Server",
    }
    return {
        "port": port,
        "protocol": "TCP",
        "service": port_to_service.get(port, "unknown"),
    }


def _short_hostname(fqdn: str) -> str:
    """Extract the short hostname (first component) from an FQDN."""
    return fqdn.split(".")[0] if fqdn else fqdn


def generate_tenable_payload(
    cve_id: str,
    hostname: str,
    cmdb_host: dict,
    nvd_entry: dict,
    epss_entry: dict | None = None,
    kev_entry: dict | None = None,
) -> dict:
    """Build a Tenable v2 export JSON record matching the format expected
    by ``integrations/tenable.py:parse_tenable_finding()``.

    Args:
        cve_id:        The CVE identifier (e.g. "CVE-2023-34362").
        hostname:      Fully-qualified hostname.
        cmdb_host:     CMDB metadata dict for this host.
        nvd_entry:     NVD cache entry for this CVE.
        epss_entry:    Optional EPSS cache entry.
        kev_entry:     Optional KEV cache entry.

    Returns:
        A dict with ``asset``, ``plugin``, ``port``, ``severity``,
        ``output``, etc. — matching the Tenable v2 export schema.
    """
    cvss_score = nvd_entry.get("cvss_v3_score", 0.0)
    cvss_vector = nvd_entry.get("cvss_v3_vector", "")
    cwe_class = nvd_entry.get("cwe_class", "")
    description = nvd_entry.get("description", "")
    exploitdb_poc = nvd_entry.get("exploitdb_has_poc", False)
    metasploit = nvd_entry.get("metasploit_has_payload", False)
    has_patch = nvd_entry.get("patch_available", False)
    vendor = nvd_entry.get("vendor", "")
    product = nvd_entry.get("product", "")

    # Plugin name
    if vendor and product:
        plugin_name = f"{cve_id} — {vendor}/{product}"
    else:
        plugin_name = cve_id

    exploit_available = bool(kev_entry) or bool(exploitdb_poc)
    risk_factor = _score_to_risk_factor(cvss_score)
    severity_id = _score_to_severity_id(cvss_score)

    # IP and port
    ipv4 = _assign_ip(hostname)
    apps = _parse_applications(cmdb_host.get("registered_applications", ""))
    port_info = _pick_port(apps)

    # Short hostname
    short_name = _short_hostname(hostname)

    # Generate a stable-ish UUID
    host_hash = abs(hash(hostname)) % 10000
    plugin_hash = _cve_to_plugin_id(cve_id)
    uuid = f"mock-uuid-{host_hash:04d}-{plugin_hash}"

    # Scanner output
    output = generate_realistic_scanner_output(
        cve_id=cve_id,
        description=description,
        vendor=vendor,
        product=product,
    )

    # OS list
    os_val = cmdb_host.get("operating_system", "Unknown")
    os_list = [os_val] if os_val else ["Unknown"]

    payload = {
        "asset": {
            "fqdn": hostname,
            "hostname": short_name,
            "ipv4": ipv4,
            "operating_system": os_list,
            "uuid": uuid,
            "tracked": True,
        },
        "plugin": {
            "id": plugin_hash,
            "name": plugin_name,
            "family": _cwe_to_family(cwe_class),
            "description": description,
            "synopsis": description[:200] if description else "",
            "cve": [cve_id],
            "cvss3_base_score": cvss_score,
            "cvss3_vector": cvss_vector,
            "cvss_base_score": round(cvss_score * 0.85, 1),  # v2 approximation
            "cvss_vector": cvss_vector,
            "risk_factor": risk_factor,
            "exploit_available": exploit_available,
            "exploit_framework_metasploit": metasploit,
            "has_patch": has_patch,
            "patch_publication_date": "2026-01-15" if has_patch else None,
        },
        "port": port_info["port"],
        "protocol": port_info["protocol"],
        "service": port_info["service"],
        "severity": risk_factor,
        "severity_id": severity_id,
        "state": "OPEN",
        "first_found": "2026-06-15",
        "last_found": "2026-06-30",
        "output": output,
    }

    return payload


# ======================================================================
# Scenario-based finding generation
# ======================================================================


def generate_scenario_findings(scenario_id: str) -> list[dict]:
    """Generate Tenable payloads for a given scenario.

    Loads the scenario definition, looks up each finding's CVE in the NVD
    cache, EPSS cache, KEV cache, and its hostname in the CMDB.  Skips
    any finding where a required lookup fails (logging a warning).

    Returns a list of Tenable payload dicts.
    """
    scenarios = load_scenarios()
    scenario = None
    for s in scenarios:
        if s.get("id") == scenario_id:
            scenario = s
            break

    if scenario is None:
        logger.warning("Scenario '%s' not found in demo_scenarios.json", scenario_id)
        return []

    nvd = _load_nvd_cache()
    epss = _load_epss_cache()
    kev = _load_kev_cache()
    cmdb = _load_cmdb()

    findings = scenario.get("findings", [])
    results: list[dict] = []

    for finding in findings:
        cve_id = finding.get("cve_id", "")
        hostname = finding.get("hostname", "")

        # Lookup NVD entry
        nvd_entry = nvd.get(cve_id)
        if nvd_entry is None:
            logger.warning(
                "Scenario '%s': CVE %s not in nvd_cache.json — skipping",
                scenario_id,
                cve_id,
            )
            continue

        # Lookup CMDB entry
        cmdb_host = cmdb.get(hostname)
        if cmdb_host is None:
            logger.warning(
                "Scenario '%s': hostname '%s' not in mock_cmdb.json — skipping",
                scenario_id,
                hostname,
            )
            continue

        # Optional enrichments
        epss_entry = epss.get(cve_id)
        kev_entry = kev.get(cve_id)

        payload = generate_tenable_payload(
            cve_id=cve_id,
            hostname=hostname,
            cmdb_host=cmdb_host,
            nvd_entry=nvd_entry,
            epss_entry=epss_entry,
            kev_entry=kev_entry,
        )
        results.append(payload)

    logger.info(
        "Scenario '%s': generated %d / %d findings",
        scenario_id,
        len(results),
        len(findings),
    )
    return results


# ======================================================================
# Random wave generation
# ======================================================================


def _severity_bucket(cvss_score: float) -> str:
    """Classify a CVSS score into a severity bucket."""
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"


_SEVERITY_DISTRIBUTION = {
    "critical": 0.10,
    "high": 0.20,
    "medium": 0.40,
    "low": 0.30,
}

_SIZE_RANGES = {
    "small": (5, 10),
    "medium": (15, 30),
    "large": (40, 60),
}


def generate_random_wave(
    size: str,
    existing_queue: list[dict] | None = None,
) -> list[dict]:
    """Generate a random wave of findings with realistic distributions.

    Args:
        size: One of ``"small"`` (5-10), ``"medium"`` (15-30),
              ``"large"`` (40-60).
        existing_queue: Optional list of existing findings (dicts with
            ``vulnerability_id`` and ``hostname`` keys) to avoid duplicates.

    Returns:
        List of Tenable payload dicts.
    """
    count_range = _SIZE_RANGES.get(size, (5, 10))
    target_count = random.randint(*count_range)

    nvd = _load_nvd_cache()
    epss = _load_epss_cache()
    kev = _load_kev_cache()
    cmdb = _load_cmdb()

    if not cmdb or not nvd:
        logger.warning("CMDB or NVD cache empty — cannot generate random wave")
        return []

    # Build a set of existing (cve_id, hostname) pairs to skip
    existing_set: set[tuple[str, str]] = set()
    if existing_queue:
        for item in existing_queue:
            c = item.get("vulnerability_id") or item.get("cve_id") or ""
            h = item.get("hostname") or ""
            if c and h:
                existing_set.add((c, h))

    # Pre-compute host weights: internet-facing hosts get 2x weight
    hostnames = list(cmdb.keys())
    host_weights = []
    for h in hostnames:
        host = cmdb[h]
        weight = 2 if host.get("internet_facing", False) else 1
        host_weights.append(weight)

    # For each host, find matching CVEs
    #   - App-level: CVE vendor/product matches host app vendor/product
    #   - OS-level: description contains OS keyword
    host_cve_pool: list[tuple[str, str, float]] = []  # (hostname, cve_id, cvss)

    for hostname in hostnames:
        host = cmdb[hostname]
        os_keyword = _extract_os_keyword(host.get("operating_system", ""))
        apps = _parse_applications(host.get("registered_applications", ""))
        app_vendors = {a["vendor"].lower() for a in apps if a["vendor"]}
        app_products = {a["product"].lower() for a in apps if a["product"]}

        for cve_id, nvd_entry in nvd.items():
            # Skip already-queued
            if (cve_id, hostname) in existing_set:
                continue

            cvss = nvd_entry.get("cvss_v3_score", 0.0)
            cve_vendor = nvd_entry.get("vendor", "").lower()
            cve_product = nvd_entry.get("product", "").lower()
            desc = nvd_entry.get("description", "").lower()

            # App-level match: vendor AND product both match
            app_match = cve_vendor in app_vendors and cve_product in app_products

            # OS-level fallback match
            os_match = False
            if os_keyword != "unknown" and os_keyword in desc:
                os_match = True

            if app_match or os_match:
                host_cve_pool.append((hostname, cve_id, cvss))

    if not host_cve_pool:
        logger.warning("No matching CVE-host combinations found for random wave")
        return []

    # Weighted host selection for the pool
    host_idx_map = {h: i for i, h in enumerate(hostnames)}
    weighted_pool = []
    for hostname, cve_id, cvss in host_cve_pool:
        idx = host_idx_map.get(hostname, 0)
        w = host_weights[idx] if idx < len(host_weights) else 1
        weighted_pool.extend([(hostname, cve_id, cvss)] * w)

    if not weighted_pool:
        weighted_pool = host_cve_pool

    # Apply severity distribution
    # Build buckets
    buckets: dict[str, list[tuple[str, str, float]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for hostname, cve_id, cvss in weighted_pool:
        bucket = _severity_bucket(cvss)
        buckets[bucket].append((hostname, cve_id, cvss))

    # Shuffle each bucket
    for b in buckets.values():
        random.shuffle(b)

    # Calculate how many to draw from each bucket
    target_by_severity: dict[str, int] = {}
    for sev, frac in _SEVERITY_DISTRIBUTION.items():
        target_by_severity[sev] = max(1, int(target_count * frac))

    # Draw from buckets (with wrap-around if not enough in a bucket)
    selected: list[tuple[str, str, float]] = []
    for sev, target in target_by_severity.items():
        pool = buckets[sev]
        for _ in range(target):
            if pool:
                selected.append(pool.pop(0))

    # Shuffle selected order
    random.shuffle(selected)

    # Trim to target count
    selected = selected[:target_count]

    if not selected:
        logger.warning("Random wave produced zero findings after filtering")
        return []

    # Generate Tenable payloads
    results: list[dict] = []
    for hostname, cve_id, _cvss in selected:
        nvd_entry = nvd.get(cve_id, {})
        cmdb_host = cmdb.get(hostname, {})
        if not nvd_entry or not cmdb_host:
            continue

        epss_entry = epss.get(cve_id)
        kev_entry = kev.get(cve_id)

        payload = generate_tenable_payload(
            cve_id=cve_id,
            hostname=hostname,
            cmdb_host=cmdb_host,
            nvd_entry=nvd_entry,
            epss_entry=epss_entry,
            kev_entry=kev_entry,
        )
        results.append(payload)

    logger.info("Generated random wave '%s': %d findings", size, len(results))
    return results


# ======================================================================
# Enrichment injection
# ======================================================================


def inject_enrichment(ingest_requests: list) -> list:
    """Patch IngestRequest objects with CISA KEV and EPSS data from caches.

    For each request:
      - Sets ``cisa_kev`` to ``True`` if the CVE appears in the KEV cache.
      - Sets ``epss_score`` from the EPSS cache (if available).

    Imports ``IngestRequest`` from ``models`` via deferred import to avoid
    circular dependencies at module level.

    Returns the same list (mutated in place).
    """
    # Deferred import to avoid circular dependency
    from models import IngestRequest  # noqa: F811

    kev = _load_kev_cache()
    epss = _load_epss_cache()

    for req in ingest_requests:
        if not isinstance(req, IngestRequest):
            continue
        cve_id = req.vulnerability_id
        # KEV enrichment
        if cve_id in kev:
            req.cisa_kev = True
        # EPSS enrichment
        epss_entry = epss.get(cve_id)
        if epss_entry and isinstance(epss_entry, dict):
            epss_val = epss_entry.get("epss")
            if epss_val is not None:
                try:
                    req.epss_score = float(epss_val)
                except (ValueError, TypeError):
                    pass

    return ingest_requests
