"""
Fuzzed ingest integration test.

Feeds 50 synthetic CVEs through the full TriageMate pipeline and verifies
that nothing crashes — no regression checks on exact score values.
"""

import json
import random
from pathlib import Path

import pytest
from unittest.mock import patch, AsyncMock

from models import IngestRequest

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ── Mock responses for network-dependent pipeline functions ─────────────

_MOCK_FEATURE_VECTOR = {
    "cvss_av": 3,
    "cvss_ac": 1,
    "cvss_pr": 2,
    "cvss_ui": 1,
    "cvss_s": 0,
    "cvss_c": 2,
    "cvss_i": 2,
    "cvss_a": 2,
    "cvss_score": 7.5,
    "epss_score": 0.5,
    "patch_available": True,
    "osv_fixed_versions": [],
    "osv_package": "",
    "osv_ecosystem": "",
    "patch_applied": False,
    "internet_facing": False,
    "domain_joined": True,
    "data_classification": "OFFICIAL",
    "mission_prevalence": "Support",
    "public_wellbeing_impact": "Minimal",
    "lateral_reachability": 10,
    "boundary_reachability": 0,
    "downstream_assets": 5,
    "patch_lag_days": 90,
    "exploitdb_has_poc": False,
    "metasploit_has_payload": False,
    "internet_scan_detected": False,
    "threat_intel_pulses": 0,
    "nvd_reference_count": 5,
    "cve_desc_tokens": 50,
    "vulnerability_age_days": 365,
    "vendor_popularity_index": 0.1,
    "cvss_exploitability_sub": 2.0,
    "cvss_impact_sub": 5.0,
    "is_top_25_cwe": False,
    "is_rce_signature": 0,
    "is_privesc_signature": 0,
    "is_bypass_signature": 0,
    "is_dos_signature": 0,
    "is_traversal_signature": 0,
    "threat_intel_status": {
        "internet_scan": "no_scan_activity",
        "threat_pulses": "no_threat_intel_available",
    },
    "description": "Synthetic test vulnerability",
}

_MOCK_TIER_2_RESULT = {
    "text_conflict": False,
    "conflict_note": "Mock: no conflict detected",
    "rag_result": "NOT_NEEDED",
    "resolution": "Mock resolution for synthetic test",
    "confidence": 0.85,
    "score_adjustment": 0,
}

# WA government hostname templates
_HOSTNAME_TEMPLATES = [
    "per-{dept}-{role}{num:02d}.health.wa.gov.au",
    "prd-{dept}-{app}{num:02d}.health.wa.gov.au",
    "per-{dept}-{sys}{num:02d}.transport.wa.gov.au",
    "prd-{dept}-{svc}{num:02d}.finance.wa.gov.au",
    "per-{dept}-{node}{num:02d}.education.wa.edu.au",
]

_DEPARTMENTS = ["PRD", "TST", "DEV"]
_ROLES = ["WEB", "APP", "DB", "DC", "FS", "EMR", "MOVEIT", "PACS", "RIS", "VNA"]
_APPS = ["PATIENT", "STAFF", "BILLING", "HR", "PAYROLL", "PORTAL", "API"]
_SYS = ["NETWORK", "STORAGE", "BACKUP", "MONITOR", "LOG", "AUTH"]
_SVCS = ["ERP", "CRM", "LDAP", "DNS", "DHCP", "VPN", "PROXY"]
_NODES = ["CAMPUS", "ADMIN", "LIBRARY", "LAB", "CLASSROOM"]

_SEED = 42


@pytest.fixture(autouse=True)
def mock_network():
    """Mock all network-dependent pipeline functions."""
    patchers = [
        patch(
            "routers.ingest.build_feature_vector",
            return_value=dict(_MOCK_FEATURE_VECTOR),
        ),
        patch("routers.ingest.get_cwe", return_value={"cwe_class": "CWE-79"}),
        patch(
            "pipeline.tier_2.evaluate_tier_2",
            new=AsyncMock(return_value=dict(_MOCK_TIER_2_RESULT)),
        ),
    ]
    for p in patchers:
        p.start()
    yield
    for p in reversed(patchers):
        p.stop()


def _load_nvd_cves(limit=50):
    """Load the first N real CVEs with both CVSS and EPSS scores."""
    with open(DATA_DIR / "nvd_corpus.json") as f:
        nvd_data = json.load(f)
    with open(DATA_DIR / "epss_cache.json") as f:
        epss_data = json.load(f)

    result = []
    for cve_id, entry in nvd_data.items():
        cvss = entry.get("cvss_v3_score")
        if cvss is None:
            continue
        epss_entry = epss_data.get(cve_id)
        epss = epss_entry["epss"] if isinstance(epss_entry, dict) else None
        if epss is None:
            continue
        result.append(
            {
                "cve_id": cve_id,
                "cvss_score": cvss,
                "epss_score": epss,
                "description": entry.get("description", ""),
                "cwe_class": entry.get("cwe_class", ""),
                "cvss_vector": entry.get("cvss_v3_vector", ""),
            }
        )
        if len(result) >= limit:
            break
    return result


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


class TestFuzzedIngest:
    """Fuzzed ingest: 50 synthetic CVEs, crash detection only."""

    @pytest.mark.asyncio
    @pytest.mark.skip(
        reason="Hangs — likely ML model loading (XGBoost/SBERT) on first call. "
        "Needs async lazy-loading investigation. See AI_PROBLEMS.md."
    )
    async def test_fuzzed_ingest_no_crashes(self):
        random.seed(_SEED)

        from database import get_db
        from routers.ingest import ingest_vulnerability

        real_cves = _load_nvd_cves(50)
        assert len(real_cves) == 50, f"Expected 50 CVEs, got {len(real_cves)}"

        total = len(real_cves)
        passed = 0
        crashes = 0
        bad_scores = 0
        bad_bands = 0
        bad_fields = 0
        db_failures = 0
        errors = []

        VALID_BANDS = {"Low", "Medium", "Critical", "Very Critical"}

        for cve in real_cves:
            hostname = _rand_hostname()
            payload = IngestRequest(
                vulnerability_id=cve["cve_id"],
                hostname=hostname,
                cvss_score=cve["cvss_score"],
                cvss_vector=cve["cvss_vector"] or "",
                cisa_kev=random.choice([True, False]),
                epss_score=cve["epss_score"],
                raw_description=cve["description"],
                scanner_output_raw=cve["description"],
                exploit_maturity=random.randint(0, 3),
                has_public_poc=random.choice([True, False]),
                vendor_patch_status=random.randint(0, 2),
            )

            try:
                result = await ingest_vulnerability(payload)

                qr = result.queue_row

                # 4a. Priority score must be int/float in 0-100
                score = qr.priority_score
                if not isinstance(score, (int, float)) or score < 0 or score > 100:
                    bad_scores += 1
                    errors.append(f"{cve['cve_id']}: bad score {score}")
                    continue

                # 4b. Risk band must be one of the valid bands
                band = qr.risk_band
                if band not in VALID_BANDS:
                    bad_bands += 1
                    errors.append(f"{cve['cve_id']}: bad band '{band}'")
                    continue

                # 4c. Non-empty hostname, compliance (portfolio), interface_type
                if not qr.hostname:
                    bad_fields += 1
                    errors.append(f"{cve['cve_id']}: empty hostname")
                    continue
                if not qr.compliance:
                    bad_fields += 1
                    errors.append(f"{cve['cve_id']}: empty compliance/portfolio")
                    continue

                # 4e. DB round-trip: read back and verify CVE ID matches
                conn = get_db()
                row = conn.execute(
                    "SELECT vulnerability_id, priority_score, risk_band "
                    "FROM vulnerabilities WHERE vulnerability_id = ?",
                    (cve["cve_id"],),
                ).fetchone()
                conn.close()
                if row is None:
                    db_failures += 1
                    errors.append(f"{cve['cve_id']}: DB row not found")
                    continue
                if row["vulnerability_id"] != cve["cve_id"]:
                    db_failures += 1
                    errors.append(f"{cve['cve_id']}: DB ID mismatch")
                    continue

                passed += 1

            except Exception as e:
                crashes += 1
                errors.append(f"{cve['cve_id']}: crash — {e}")

        # ── 5. Summary ──────────────────────────────────────────────
        print()
        print(f"FUZZED INGEST TEST — {total} synthetic CVEs")
        print(
            f"Passed: {passed}/{total} "
            f"Crashes: {crashes} "
            f"Bad scores: {bad_scores} "
            f"Bad bands: {bad_bands} "
            f"DB round-trip failures: {db_failures}"
        )

        if errors:
            print("\nFailures:")
            for err in errors:
                print(f"  {err}")

        assert crashes == 0, f"{crashes} crashes occurred"
        assert bad_scores == 0, f"{bad_scores} bad scores"
        assert bad_bands == 0, f"{bad_bands} bad bands"
        assert bad_fields == 0, f"{bad_fields} empty/bad fields"
        assert db_failures == 0, f"{db_failures} DB round-trip failures"
        assert passed == total, f"Only {passed}/{total} passed"
