"""
Network Context — peers, blast radius, and exposure level for a host.

Queries synthetic_assets for real peer data with heuristic fallback.
Always returns valid data — never crashes on missing DB or unknowns.
"""

import logging

logger = logging.getLogger("triagemate.network_context")

ZONE_BASELINE = {"protected": 40, "restricted": 25, "dmz": 15, "management": 8}

ZONE_DISPLAY_MAP = {
    "dmz": "DMZ",
    "internal": "Internal Network",
    "protected": "Protected Network",
    "restricted": "Restricted Zone",
    "management": "Management Segment",
    "mgmt": "Management Segment",
}

AGENCY_MAP = {"doj": "communities", "wapol": "police"}

_CMDB_ZONE_PREFIXES = {"DMZ", "EDU", "SSC"}


def _extract_agency(hostname: str) -> str:
    """Parse agency short code from a WA government hostname."""
    if not hostname or not isinstance(hostname, str):
        return "unknown"
    h = hostname.strip().lower()
    parts = h.split(".")
    if len(parts) >= 4 and (h.endswith(".wa.gov.au") or h.endswith(".wa.edu.au")):
        agency = parts[1]
        return AGENCY_MAP.get(agency, agency)
    return "unknown"


def _normalize_zone(zone: str) -> str:
    """Map CMDB-style zone (e.g. 'DMZ-Health-External') to simple code."""
    if not zone:
        return "internal"
    z = zone.lower()
    if "dmz" in z:
        return "dmz"
    if "mgmt" in z or "management" in z:
        return "mgmt"
    if "restricted" in z:
        return "restricted"
    if "protected" in z:
        return "protected"
    if "internal" in z:
        return "internal"
    return "internal"


def _query_peer_data(agency: str, zone: str):
    """Query synthetic_assets for peers; returns rows or None on failure."""
    db = None
    try:
        from database import get_db as _get_db

        db = _get_db()
        rows = db.execute(
            "SELECT hostname, is_internet_facing, is_dc, "
            'COALESCE(mission_prevalence, "Unknown") as mp, '
            'COALESCE(public_wellbeing_impact, "Unknown") as pwi '
            "FROM synthetic_assets "
            "WHERE agency = ? AND network_zone LIKE ? AND in_holdout = 0",
            (agency, f"%{zone}%"),
        ).fetchall()
        return rows
    except Exception:
        logger.debug("synthetic_assets query failed — will use heuristic", exc_info=True)
        return None
    finally:
        if db is not None:
            db.close()


def _heuristic_peer_data(zone: str) -> dict:
    """Fallback zone-based peer estimates when DB is unavailable."""
    peer_count = ZONE_BASELINE.get(zone, 5)
    return {
        "peer_count": peer_count,
        "internet_facing_peers": max(1, peer_count // 10),
        "dc_peers": max(0, peer_count // 20),
        "peer_classifications": {
            "OFFICIAL": peer_count // 2,
            "OFFICIAL Sensitive": max(1, peer_count // 4),
            "Category 1": max(1, peer_count // 4),
        },
    }


def _compute_blast_radius(peer_count: int, internet_facing_peers: int) -> float:
    """Normalised blast-radius score (0.0–1.0)."""
    if peer_count == 0:
        return 0.0
    score = (min(peer_count, 100) / 100) * 0.5
    score += (internet_facing_peers / max(peer_count, 1)) * 0.5
    return min(1.0, score)


def _get_exposure_level(blast_radius: float) -> str:
    return "high" if blast_radius >= 0.5 else "medium" if blast_radius >= 0.2 else "low"


def _get_zone_display(zone: str, hostname: str = "") -> str:
    """Human-readable zone string (e.g. 'DMZ-Health-External' → 'DMZ (Health — External)')."""
    if not zone or zone == "Unknown":
        return zone or "Unknown"
    parts = zone.split("-")
    first = parts[0].upper()
    if first in _CMDB_ZONE_PREFIXES and len(parts) >= 3:
        suffix = parts[-1].split("(")[0].strip()
        return f"{parts[0]} ({parts[1]} — {suffix})"
    zone_lower = zone.lower().split()[0].split("(")[0].strip()
    return ZONE_DISPLAY_MAP.get(zone_lower, zone)


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------


def get_network_context(hostname: str, asset_ctx: dict) -> dict:
    """Compute network context — peers, blast radius, exposure — for hostname.

    DB-first via synthetic_assets; falls back to heuristic zone estimates.
    Always returns valid data; never raises.
    """
    result = {
        "zone": "internal",
        "zone_display": "Internal Network",
        "peer_count": 0,
        "internet_facing_peers": 0,
        "dc_peers": 0,
        "peer_classifications": {},
        "blast_radius_score": 0.0,
        "exposure_level": "low",
        "data_source": "heuristic",
    }

    try:
        raw_zone = (asset_ctx or {}).get("network_zone", "")
        zone = _normalize_zone(raw_zone)
        result["zone"] = zone
        result["zone_display"] = _get_zone_display(raw_zone, hostname)
    except Exception:
        logger.debug("Zone extraction failed", exc_info=True)
        zone = "internal"

    try:
        agency = _extract_agency(hostname)
    except Exception:
        agency = "unknown"

    # DB-first peer discovery
    if agency != "unknown":
        try:
            rows = _query_peer_data(agency, zone)
        except Exception:
            rows = None
    else:
        rows = None

    if rows is not None and len(rows) > 0:
        result["peer_count"] = len(rows)
        result["internet_facing_peers"] = sum(
            1 for r in rows if bool(r["is_internet_facing"])
        )
        result["dc_peers"] = sum(1 for r in rows if bool(r["is_dc"]))
        classifications: dict[str, int] = {}
        for r in rows:
            mp = str(r["mp"])
            classifications[mp] = classifications.get(mp, 0) + 1
        result["peer_classifications"] = classifications
        result["data_source"] = "synthetic_assets"
    else:
        result.update(_heuristic_peer_data(zone))
        result["data_source"] = "heuristic"

    try:
        result["blast_radius_score"] = _compute_blast_radius(
            result["peer_count"], result["internet_facing_peers"]
        )
        result["exposure_level"] = _get_exposure_level(result["blast_radius_score"])
    except Exception:
        logger.debug("Blast-radius computation failed", exc_info=True)

    return result
