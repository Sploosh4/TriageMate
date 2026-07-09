"""
Synthetic Sentinel + EDR Telemetry Generator — TriageMate MVP.

Generates realistic but entirely synthetic Microsoft Sentinel incidents and
EDR alerts for any CVE+hostname combination. Uses a deterministic seed so
the same inputs always produce the same output.
"""

import hashlib
import logging
import random
from datetime import datetime, timedelta

logger = logging.getLogger("triagemate.synthetic_telemetry")

MITRE_TECHNIQUES = [
    "T1190",
    "T1210",
    "T1059",
    "T1505",
    "T1078",
    "T1133",
    "T1053",
    "T1027",
    "T1071",
    "T1566",
]
SEVERITIES = ["High", "Medium", "Low", "Informational"]
STATUSES = ["Active", "Resolved", "Investigating"]
USERS = [
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\NETWORK SERVICE",
    "IIS APPPOOL\\DefaultAppPool",
]
RCE_KW = ["remote code execution", "rce", "arbitrary code", "code execution"]
SVC_KW = ["service", "daemon", "server", "web", "portal", "gateway", "application"]
LIB_KW = [
    "library",
    "module",
    "component",
    "dependency",
    "package",
    "framework",
    "dll",
    "so",
]
EPOCH = datetime(2024, 1, 1)
_STOP = frozenset(
    {
        "the",
        "a",
        "an",
        "in",
        "of",
        "for",
        "to",
        "and",
        "or",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "on",
        "at",
        "by",
        "with",
        "from",
        "as",
        "into",
        "through",
        "during",
        "before",
        "after",
        "above",
        "below",
        "between",
        "such",
        "this",
        "that",
        "allows",
        "attacker",
        "vulnerability",
        "remote",
        "local",
        "via",
    }
)
_KNOWN_KW = frozenset(
    {
        "moveit",
        "exchange",
        "sharepoint",
        "confluence",
        "iis",
        "apache",
        "nginx",
        "tomcat",
        "openssh",
        "solarwinds",
        "log4j",
        "java",
    }
)


def _seed(cve_id: str, hostname: str) -> random.Random:
    """Deterministic RNG from SHA-256(CVE+hostname+salt)."""
    return random.Random(
        int(hashlib.sha256(f"{cve_id}:{hostname}:telemetry".encode()).hexdigest(), 16)
    )


def _compute_probabilities(
    cvss_score: float, cisa_kev: bool, epss_score: float, description: str
) -> dict:
    """Compute base probabilities for telemetry generation."""
    dl = description.lower()
    p_sa, p_hs = (
        (0.85, 0.80)
        if cisa_kev
        else (
            (0.50, 0.30)
            if epss_score > 0.5
            else (
                (0.20, 0.30)
                if epss_score > 0.1
                else ((0.35, 0.50) if cvss_score >= 9.0 else (0.05, 0.30))
            )
        )
    )
    hr = any(k in dl for k in RCE_KW)
    hs = any(k in dl for k in SVC_KW)
    hl = any(k in dl for k in LIB_KW)
    p_pr, p_pl = (
        (0.70, 0.85)
        if hr and hs
        else ((0.60, 0.70) if hs else ((0.30, 0.50) if hl else (0.15, 0.25)))
    )
    return {
        "p_sentinel_active": p_sa,
        "p_high_severity": p_hs,
        "p_process_running": p_pr,
        "p_process_loaded": p_pl,
    }


def _extract_product_keyword(description: str) -> str:
    """Extract product keyword: known → capitalised → first word → "unknown"."""
    if not description:
        return "unknown"
    dl = description.lower()
    for kw in _KNOWN_KW:
        if kw in dl:
            return kw
    for ch in ",.()[]{}:;\"'!":
        description = description.replace(ch, " ")
    words = description.split()
    for w in words:
        c = w.strip()
        if len(c) >= 3 and c.lower() not in _STOP and (c[0].isupper() or c.isupper()):
            return c.lower()
    for w in words:
        c = w.strip()
        if len(c) >= 3 and c.lower() not in _STOP:
            return c.lower()
    return "unknown"


def _keyword_to_process_names(keyword: str) -> tuple[str, str]:
    """Map product keyword to (exe_name, dll_name)."""
    KNOWN = {
        "moveit": ("moveitdmz.exe", "moverequesthandler.dll"),
        "exchange": ("w3wp.exe", "Microsoft.Exchange.Common.dll"),
        "sharepoint": ("w3wp.exe", "Microsoft.SharePoint.dll"),
        "confluence": ("confluence.exe", "atlassian-extras-legacy.jar"),
        "iis": ("w3wp.exe", "iis.dll"),
        "apache": ("httpd.exe", "mod_cgi.so"),
        "nginx": ("nginx.exe", "ngx_http_core_module.so"),
        "tomcat": ("java.exe", "catalina.jar"),
        "openssh": ("sshd.exe", "ssh.dll"),
        "solarwinds": ("SolarWinds.Orion.WebApi.exe", "SolarWinds.Orion.Core.dll"),
        "log4j": ("java.exe", "log4j-core.jar"),
        "java": ("java.exe", "rt.jar"),
    }
    kl = keyword.lower()
    for kk, (exe, dll) in KNOWN.items():
        if kk in kl:
            return exe, dll
    b = keyword.rstrip("s")
    return f"{b}.exe", f"{b}_module.dll"


def _ts(rng: random.Random, extra: int = 0) -> str:
    """Deterministic ISO-8601 timestamp."""
    d = rng.randint(0, 365) + extra * 7
    return (
        EPOCH
        + timedelta(
            days=d,
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_sentinel_incidents(
    rng: random.Random, cve_id: str, hostname: str, probs: dict
) -> list[dict]:
    """Generate 0-2 synthetic Sentinel incidents."""
    if rng.random() >= probs["p_sentinel_active"]:
        return []
    incidents = []
    for i in range(rng.randint(1, 2)):
        is_high = rng.random() < probs["p_high_severity"]
        sev = "High" if is_high else rng.choice(SEVERITIES[1:])
        incidents.append(
            {
                "incident_id": f"SEN-{2024 + rng.randint(0, 2)}-{rng.randint(1, 999999):06d}",
                "title": f"Suspected exploitation of {cve_id}",
                "severity": sev,
                "status": rng.choice(STATUSES),
                "detected_at": _ts(rng, extra=i),
                "assigned_to": "SOC Tier 2" if sev == "High" else "SOC Tier 1",
                "related_entities": [hostname],
                "mitre_techniques": rng.sample(MITRE_TECHNIQUES, rng.randint(1, 3)),
            }
        )
    return incidents


def _generate_edr_alerts(
    rng: random.Random,
    cve_id: str,
    hostname: str,
    is_running: bool,
    is_loaded: bool,
    probs: dict,
    product_keyword: str,
) -> list[dict]:
    """Generate synthetic EDR alerts based on process evidence."""
    alerts = []
    exe, dll = _keyword_to_process_names(product_keyword)
    dp = _ts(rng)[:10].replace("-", "")
    path = f"C:\\Program Files\\{product_keyword.title()}"
    if is_running:
        sev = "High" if rng.random() < probs["p_high_severity"] else "Medium"
        alerts.append(
            {
                "alert_id": f"EDR-{dp}-{rng.randint(1, 9999):04d}",
                "alert_type": "process_execution",
                "severity": sev,
                "process_name": exe,
                "process_path": f"{path}\\{exe}",
                "user": rng.choice(USERS),
                "timestamp": _ts(rng),
                "details": f"Suspicious process execution of {exe} related to {cve_id}",
            }
        )
    if is_loaded and rng.random() < 0.40:
        alerts.append(
            {
                "alert_id": f"EDR-{dp}-{rng.randint(1, 9999):04d}",
                "alert_type": "module_load",
                "severity": "Medium",
                "process_name": dll,
                "process_path": f"{path}\\{dll}",
                "user": rng.choice(USERS),
                "timestamp": _ts(rng),
                "details": f"Suspicious module load of {dll} in {exe}",
            }
        )
    if rng.random() < 0.30:
        alerts.append(
            {
                "alert_id": f"EDR-{dp}-{rng.randint(1, 9999):04d}",
                "alert_type": "network_connection",
                "severity": "Low",
                "process_name": exe,
                "process_path": f"{path}\\{exe}",
                "user": "NT AUTHORITY\\SYSTEM",
                "timestamp": _ts(rng),
                "details": f"Outbound connection from {exe} to external IP address",
            }
        )
    return alerts


def _compute_threat_score(
    incidents: list[dict], is_running: bool, is_loaded: bool, rng: random.Random
) -> float:
    """Composite threat score 0.0-1.0: incidents + process evidence + noise."""
    score = (
        0.6
        if any(i["severity"] == "High" for i in incidents)
        else (0.3 if incidents else 0.0)
    )
    score += (
        0.4 if is_running and is_loaded else (0.2 if is_running or is_loaded else 0.0)
    )
    return max(0.0, min(1.0, score + rng.uniform(-0.1, 0.1)))


def get_telemetry_context(
    cve_id: str,
    hostname: str,
    cvss_score: float,
    cisa_kev: bool,
    epss_score: float,
    description: str,
) -> dict:
    """Generate synthetic Sentinel + EDR telemetry for a CVE+hostname pair.

    Returns dict with keys: sentinel_incidents, edr_alerts, process_evidence, threat_score.
    Deterministic for the same arguments.
    """
    cvss_score = max(0.0, min(10.0, float(cvss_score if cvss_score else 0.0)))
    epss_score = max(0.0, min(1.0, float(epss_score if epss_score else 0.0)))
    description = description or ""
    rng = _seed(cve_id, hostname)
    probs = _compute_probabilities(cvss_score, cisa_kev, epss_score, description)
    is_running = rng.random() < probs["p_process_running"]
    is_loaded = rng.random() < probs["p_process_loaded"]
    kw = _extract_product_keyword(description)
    exe, dll = _keyword_to_process_names(kw)
    rp = ([exe] if is_running else []) + ([dll] if is_loaded else [])
    eq = (
        "high"
        if is_running and is_loaded
        else ("medium" if is_running or is_loaded else "none")
    )
    incidents = _generate_sentinel_incidents(rng, cve_id, hostname, probs)
    alerts = _generate_edr_alerts(
        rng, cve_id, hostname, is_running, is_loaded, probs, kw
    )
    threat_score = _compute_threat_score(incidents, is_running, is_loaded, rng)
    logger.info(
        "Synthetic telemetry for %s on %s: incidents=%d, alerts=%d, threat_score=%.2f",
        cve_id,
        hostname,
        len(incidents),
        len(alerts),
        threat_score,
        extra={
            "event": "synthetic_telemetry",
            "cve_id": cve_id,
            "hostname": hostname,
            "incident_count": len(incidents),
            "alert_count": len(alerts),
            "threat_score": threat_score,
        },
    )
    return {
        "sentinel_incidents": incidents,
        "edr_alerts": alerts,
        "process_evidence": {
            "is_running": is_running,
            "is_loaded": is_loaded,
            "running_processes": rp,
            "evidence_quality": eq,
        },
        "threat_score": threat_score,
    }
