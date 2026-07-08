"""
Locust load test for TriageMate ingestion pipeline.

Loads ~50 real CVEs from the NVD corpus, categorised as:
  - ~20% KEV (CISA Known Exploited) — should auto-resolve at Tier 0
  - ~30% very-low severity (CVSS < 4.0, EPSS < 0.05) — should auto-resolve at Tier 0
  - ~50% ambiguous (CVSS 4.0-8.0, varied EPSS) — should flow to Tier 1 / Tier 2

Results are written to a stress test SQLite database for post-hoc analysis.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from locust import HttpUser, between, task

# Ensure analysis/stress_db is importable
_script_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_script_dir))

from analysis.stress_db import create_db, insert_result, insert_run, update_run_end  # noqa: E402

# ── Data paths ────────────────────────────────────────────────────────────
DATA_DIR = _script_dir / "data"

# ── Seed for reproducibility ──────────────────────────────────────────────
random.seed(42)


# ── Load CVE data ─────────────────────────────────────────────────────────
def _load_cve_data():
    """Load NVD corpus, EPSS cache, and KEV cache; return categorised CVE list."""
    nvd_path = DATA_DIR / "nvd_corpus.json"
    epss_path = DATA_DIR / "epss_cache.json"
    kev_path = DATA_DIR / "kev_cache.json"

    if not nvd_path.exists():
        print(f"[locust] WARNING: {nvd_path} not found. Using minimal fallback CVEs.")
        return _fallback_cves()

    nvd = json.loads(nvd_path.read_text())
    epss_data = json.loads(epss_path.read_text()) if epss_path.exists() else {}
    kev_data = json.loads(kev_path.read_text()) if kev_path.exists() else {}

    kev_cves, low_cves, ambig_cves = [], [], []

    for cve_id, entry in nvd.items():
        cvss = entry.get("cvss_v3_score")
        if cvss is None:
            continue
        epss_entry = epss_data.get(cve_id, {})
        epss_val = epss_entry.get("epss", 0.0) if isinstance(epss_entry, dict) else 0.0
        is_kev = cve_id in kev_data

        if is_kev:
            kev_cves.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "epss_score": epss_val,
                    "cisa_kev": True,
                    "description": entry.get("description", ""),
                    "cvss_vector": entry.get("cvss_v3_vector", ""),
                }
            )
        elif cvss < 4.0 and epss_val < 0.05:
            low_cves.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "epss_score": epss_val,
                    "cisa_kev": False,
                    "description": entry.get("description", ""),
                    "cvss_vector": entry.get("cvss_v3_vector", ""),
                }
            )
        elif 4.0 <= cvss <= 8.0:
            ambig_cves.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "epss_score": epss_val,
                    "cisa_kev": False,
                    "description": entry.get("description", ""),
                    "cvss_vector": entry.get("cvss_v3_vector", ""),
                }
            )

    # Shuffle each category for variety
    random.shuffle(kev_cves)
    random.shuffle(low_cves)
    random.shuffle(ambig_cves)

    # Select ~20% KEV (10 of 50), ~30% low (15 of 50), ~50% ambiguous (25 of 50)
    selected = []
    selected.extend(kev_cves[:10])
    selected.extend(low_cves[:15])
    selected.extend(ambig_cves[:25])

    random.shuffle(selected)
    print(
        f"[locust] Loaded {len(selected)} CVEs ({len(kev_cves[:10])} KEV, "
        f"{len(low_cves[:15])} low, {len(ambig_cves[:25])} ambiguous)"
    )
    return selected


def _fallback_cves():
    """Fallback CVEs when NVD corpus isn't available."""
    return [
        {
            "cve_id": "CVE-2023-36884",
            "cvss_score": 8.1,
            "epss_score": 0.05,
            "cisa_kev": True,
            "description": "Office Memory Corruption Vulnerability",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        },
        {
            "cve_id": "CVE-2022-47966",
            "cvss_score": 9.8,
            "epss_score": 0.95,
            "cisa_kev": True,
            "description": "ManageEngine RCE",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        {
            "cve_id": "CVE-2023-22515",
            "cvss_score": 10.0,
            "epss_score": 0.95,
            "cisa_kev": True,
            "description": "Confluence RCE",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    ]


# ── Hostname generation ───────────────────────────────────────────────────
_HOSTNAME_TEMPLATES = [
    "per-{dept}-{role}{num:02d}.health.wa.gov.au",
    "prd-{dept}-{app}{num:02d}.health.wa.gov.au",
    "per-{dept}-{sys}{num:02d}.transport.wa.gov.au",
    "prd-{dept}-{svc}{num:02d}.finance.wa.gov.au",
    "per-{dept}-{node}{num:02d}.education.wa.edu.au",
    "syd-{dept}-{role}{num:02d}.transport.wa.gov.au",
    "per-{dept}-{svc}{num:02d}.communities.wa.gov.au",
    "prd-{dept}-{app}{num:02d}.water.wa.gov.au",
]

_DEPARTMENTS = ["PRD", "TST", "DEV"]
_ROLES = ["WEB", "APP", "DB", "DC", "FS", "EMR", "MOVEIT", "PACS", "RIS", "VNA"]
_APPS = ["PATIENT", "STAFF", "BILLING", "HR", "PAYROLL", "PORTAL", "API"]
_SYS = ["NETWORK", "STORAGE", "BACKUP", "MONITOR", "LOG", "AUTH"]
_SVCS = ["ERP", "CRM", "LDAP", "DNS", "DHCP", "VPN", "PROXY"]
_NODES = ["CAMPUS", "ADMIN", "LIBRARY", "LAB", "CLASSROOM"]


def _rand_hostname() -> str:
    template = random.choice(_HOSTNAME_TEMPLATES)
    dept = random.choice(_DEPARTMENTS)
    num = random.randint(1, 50)
    field = random.choice(_ROLES + _APPS + _SYS + _SVCS + _NODES)
    return template.format(
        dept=dept,
        role=field,
        num=num,
        app=field,
        sys=field,
        svc=field,
        node=field,
    )


# ── Global state ──────────────────────────────────────────────────────────
_CVE_POOL = _load_cve_data()
_SEQ_COUNTER = 0
_RUN_ID: str = ""
_DB_PATH: str = ""


def _get_run_id() -> str:
    """Return run ID from env or generate one."""
    rid = os.environ.get("STRESS_RUN_ID", "").strip()
    if rid:
        return rid
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")


def _get_db_path(run_id: str) -> str:
    reports_dir = _script_dir / "reports" / "stress"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return str(reports_dir / f"{run_id}.db")


# ── Locust events ─────────────────────────────────────────────────────────
from locust import events  # noqa: E402


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    global _RUN_ID, _DB_PATH
    _RUN_ID = _get_run_id()
    _DB_PATH = _get_db_path(_RUN_ID)
    create_db(_DB_PATH)
    config = {
        "workers": getattr(environment.parsed_options, "processes", 1)
        if environment.parsed_options
        else 1,
        "host": environment.host or "",
    }
    insert_run(_DB_PATH, _RUN_ID, config)
    print(f"[locust] Stress test run {_RUN_ID} — DB: {_DB_PATH}")


@events.quitting.add_listener
def on_locust_quitting(environment, **kwargs):
    global _RUN_ID, _DB_PATH
    if not _RUN_ID or not _DB_PATH:
        return
    # Gather totals from environment stats
    stats = environment.stats
    total = stats.num_requests
    num_failures = stats.num_failures
    num_success = total - num_failures
    update_run_end(
        _DB_PATH,
        _RUN_ID,
        {
            "total_requests": total,
            "successful": num_success,
            "failed": num_failures,
        },
    )
    print(
        f"[locust] Run {_RUN_ID} ended: {total} req, {num_success} ok, {num_failures} failed"
    )


# ── HttpUser ──────────────────────────────────────────────────────────────
class TriageMateUser(HttpUser):
    wait_time = between(0.5, 3.0)

    @task(6)
    def ingest(self):
        """POST /api/ingest with verbose header, record result to stress DB."""
        global _SEQ_COUNTER, _RUN_ID, _DB_PATH

        cve = random.choice(_CVE_POOL)
        hostname = _rand_hostname()
        payload = {
            "vulnerability_id": cve["cve_id"],
            "hostname": hostname,
            "cvss_score": cve["cvss_score"],
            "cvss_vector": cve.get("cvss_vector", ""),
            "cisa_kev": cve["cisa_kev"],
            "epss_score": cve["epss_score"],
            "raw_description": cve.get("description", ""),
            "scanner_output_raw": cve.get("description", ""),
            "exploit_maturity": random.randint(0, 3),
            "has_public_poc": random.choice([True, False]),
            "vendor_patch_status": random.randint(0, 2),
        }

        start = time.monotonic()
        with self.client.post(
            "/api/ingest",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-TriageMate-Verbose": "true",
            },
            catch_response=True,
            name="/api/ingest",
        ) as response:
            elapsed_ms = (time.monotonic() - start) * 1000

            seq = _SEQ_COUNTER
            _SEQ_COUNTER += 1

            if response.status_code == 200:
                try:
                    data = response.json()
                    qr = data.get("queueRow", {})
                    trace = data.get("_trace", {})
                    tier_2_info = trace.get("tier_2", {}) if trace else {}
                    tier_2_called = (
                        tier_2_info.get("called", False)
                        if isinstance(tier_2_info, dict)
                        else False
                    )
                    llm_cost = 0.0
                    if isinstance(tier_2_info, dict) and tier_2_info.get("called"):
                        llm_cost = tier_2_info.get("cost_usd", 0.0)

                    tier_0_routing = (
                        trace.get("tier_0", {}).get("routing", "") if trace else ""
                    )
                    tier_1_info = trace.get("tier_1", {})
                    tier_1_routing = (
                        tier_1_info.get("routing", "") if tier_1_info else ""
                    )

                    insert_result(
                        db_path=_DB_PATH,
                        run_id=_RUN_ID,
                        seq=seq,
                        cve_id=cve["cve_id"],
                        hostname=hostname,
                        status="success",
                        priority_score=qr.get("priorityScore", 0),
                        risk_band=qr.get("riskBand", ""),
                        tier_0_routing=tier_0_routing,
                        tier_1_routing=tier_1_routing,
                        tier_2_called=tier_2_called,
                        total_latency_ms=elapsed_ms,
                        llm_cost_usd=llm_cost,
                        trace=trace,
                    )
                    response.success()
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    insert_result(
                        db_path=_DB_PATH,
                        run_id=_RUN_ID,
                        seq=seq,
                        cve_id=cve["cve_id"],
                        hostname=hostname,
                        status="parse_error",
                        priority_score=0,
                        risk_band="",
                        tier_0_routing="",
                        tier_1_routing="",
                        tier_2_called=False,
                        total_latency_ms=elapsed_ms,
                        llm_cost_usd=0.0,
                        trace={"error": str(e)},
                    )
                    response.failure(f"parse error: {e}")
            else:
                insert_result(
                    db_path=_DB_PATH,
                    run_id=_RUN_ID,
                    seq=seq,
                    cve_id=cve["cve_id"],
                    hostname=hostname,
                    status=f"http_{response.status_code}",
                    priority_score=0,
                    risk_band="",
                    tier_0_routing="",
                    tier_1_routing="",
                    tier_2_called=False,
                    total_latency_ms=elapsed_ms,
                    llm_cost_usd=0.0,
                    trace={"http_status": response.status_code},
                )
                response.failure(f"HTTP {response.status_code}")

    @task(3)
    def read_queue(self):
        """GET /api/queue"""
        with self.client.get(
            "/api/queue",
            headers={"Accept": "application/json"},
            catch_response=True,
            name="/api/queue",
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"HTTP {response.status_code}")

    @task(1)
    def health_check(self):
        """GET /api/health"""
        with self.client.get(
            "/api/health",
            headers={"Accept": "application/json"},
            catch_response=True,
            name="/api/health",
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"HTTP {response.status_code}")
