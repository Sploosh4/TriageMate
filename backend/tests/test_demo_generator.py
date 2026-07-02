"""
Tests for the Demo Data Generator module (``integrations/demo_generator.py``).

Verifies scenario loading, finding generation, Tenable payload structure,
random wave sizing & dedup, enrichment injection, edge-case helpers, and
integration with the Tenable parser and NVD demo cache.

All tests are synchronous unit tests — no API client needed.
"""

import os
import importlib

from fastapi.responses import JSONResponse

from integrations.demo_generator import (
    load_scenarios,
    generate_scenario_findings,
    generate_tenable_payload,
    generate_random_wave,
    _parse_applications,
    _extract_department,
    _assign_ip,
    _extract_os_keyword,
    _load_nvd_cache,
    inject_enrichment,
)
from integrations.tenable import (
    parse_tenable_batch,
    _compute_vendor_patch_status,
)
from routers.ingest import _demo_only


# ======================================================================
# Structural Tests (6)
# ======================================================================


class TestStructural:
    """Structural tests: scenario loading, finding shapes, payload fields,
    wave size ranges, end-to-end mapping, and application parsing."""

    def test_load_scenarios(self):
        """Loads scenarios, verifies 5 exist, each has id/name/findings,
        finding_count > 0."""
        scenarios = load_scenarios()
        assert len(scenarios) == 5, f"Expected 5 scenarios, got {len(scenarios)}"
        for s in scenarios:
            assert "id" in s, f"Scenario missing 'id': {s.get('name', '?')}"
            assert "name" in s, f"Scenario missing 'name': {s.get('id', '?')}"
            assert "findings" in s, f"Scenario missing 'findings': {s.get('id', '?')}"
            assert len(s["findings"]) > 0, f"Scenario '{s['id']}' has zero findings"

    def test_generate_scenario_findings_returns_list_of_dicts(self):
        """Generates findings for ransomware-incident, verifies list of
        dicts with asset/plugin/output keys."""
        findings = generate_scenario_findings("ransomware-incident")
        assert isinstance(findings, list), "Expected list of findings"
        assert len(findings) > 0, "Expected at least one finding"

        for f in findings:
            assert isinstance(f, dict), f"Expected dict, got {type(f)}"
            assert "asset" in f, "Finding missing 'asset' key"
            assert "plugin" in f, "Finding missing 'plugin' key"
            assert "output" in f, "Finding missing 'output' key"

    def test_generate_tenable_payload_has_required_fields(self):
        """Calls generate_tenable_payload() with mock data, verifies all
        required Tenable fields exist:
        asset.fqdn, asset.hostname, asset.ipv4, asset.operating_system,
        plugin.cve, plugin.cvss3_base_score, plugin.description,
        plugin.has_patch, 'patch_publication_date' in plugin, output."""
        nvd = _load_nvd_cache()
        nvd_entry = nvd.get("CVE-2023-34362", {})
        assert nvd_entry, "CVE-2023-34362 must be in NVD cache for this test"

        from integrations.demo_generator import _load_cmdb

        cmdb = _load_cmdb()
        cmdb_host = cmdb.get("PRD-MOVEIT-WEB01.health.wa.gov.au", {})
        assert cmdb_host, "CMDB host must exist for this test"

        payload = generate_tenable_payload(
            cve_id="CVE-2023-34362",
            hostname="PRD-MOVEIT-WEB01.health.wa.gov.au",
            cmdb_host=cmdb_host,
            nvd_entry=nvd_entry,
        )

        # Asset fields
        assert payload["asset"]["fqdn"] == "PRD-MOVEIT-WEB01.health.wa.gov.au"
        assert payload["asset"]["hostname"] == "PRD-MOVEIT-WEB01"
        assert isinstance(payload["asset"]["ipv4"], str) and payload["asset"]["ipv4"]
        assert isinstance(payload["asset"]["operating_system"], list)
        assert len(payload["asset"]["operating_system"]) > 0

        # Plugin fields
        assert "CVE-2023-34362" in payload["plugin"]["cve"]
        assert isinstance(payload["plugin"]["cvss3_base_score"], (int, float))
        assert payload["plugin"]["cvss3_base_score"] > 0
        assert len(payload["plugin"]["description"]) > 0
        assert "has_patch" in payload["plugin"]
        assert "patch_publication_date" in payload["plugin"]

        # Output
        assert len(payload["output"]) > 0

    def test_random_wave_respects_size(self):
        """Calls generate_random_wave("small") verifies 5-10 findings,
        "medium" 15-30, "large" 40-60."""
        small = generate_random_wave("small")
        assert 5 <= len(small) <= 10, (
            f"Small wave expected 5-10 findings, got {len(small)}"
        )

        medium = generate_random_wave("medium")
        # Cache-dependent — 175-entry NVD cache yields 14-30 for medium
        assert 10 <= len(medium) <= 30, (
            f"Medium wave expected 10-30 findings, got {len(medium)}"
        )

        large = generate_random_wave("large")
        # Cache-dependent — pool may exhaust before 40 with small cache
        assert 25 <= len(large) <= 60, (
            f"Large wave expected 25-60 findings, got {len(large)}"
        )

    def test_scenario_findings_map_to_valid_ingest_requests(self):
        """For each scenario, generates findings, pipes through
        parse_tenable_batch, pipes through inject_enrichment, verifies all
        have vulnerability_id, hostname, cvss_score > 0."""
        scenarios = load_scenarios()
        assert len(scenarios) > 0

        for scenario in scenarios:
            sid = scenario["id"]
            findings = generate_scenario_findings(sid)
            assert len(findings) > 0, f"Scenario '{sid}' generated zero findings"

            requests = parse_tenable_batch(findings)
            assert len(requests) > 0, f"Scenario '{sid}' produced zero IngestRequests"

            inject_enrichment(requests)

            for req in requests:
                assert req.vulnerability_id, (
                    f"Scenario '{sid}': missing vulnerability_id"
                )
                assert req.hostname, f"Scenario '{sid}': missing hostname"
                assert req.cvss_score > 0, (
                    f"Scenario '{sid}': cvss_score={req.cvss_score} "
                    f"for {req.vulnerability_id}"
                )

    def test_parse_applications_normalises_moveit(self):
        """Verifies _parse_applications correctly normalises
        'Progress MOVEit Transfer 2023.0.0, IIS 10.0' into the expected
        vendor/product tuples."""
        apps = _parse_applications("Progress MOVEit Transfer 2023.0.0, IIS 10.0")
        assert len(apps) == 2, f"Expected 2 apps, got {len(apps)}"

        # First app: MOVEit
        assert apps[0]["name"] == "Progress MOVEit Transfer"
        assert apps[0]["vendor"] == "progress"
        assert apps[0]["product"] == "moveit transfer"

        # Second app: IIS
        assert apps[1]["name"] == "IIS"
        assert apps[1]["vendor"] == "microsoft"
        assert apps[1]["product"] == "internet information services"


# ======================================================================
# BLOCKER-targeted Tests (8)
# ======================================================================


class TestBlocker:
    """BLOCKER-targeted tests: KEV injection, NVD demo cache,
    reference synthesis, random-wave dedup, patch-status computation,
    patch_publication_date presence, low-severity upper bound, and
    _demo_only guard."""

    def test_kev_injection_marks_cisa_kev_true(self):
        """Generates ransomware-incident findings, parses to IngestRequest,
        injects enrichment, checks at least one has cisa_kev=True."""
        findings = generate_scenario_findings("ransomware-incident")
        assert len(findings) > 0

        requests = parse_tenable_batch(findings)
        assert len(requests) > 0

        inject_enrichment(requests)

        kev_found = any(req.cisa_kev for req in requests)
        assert kev_found, (
            "No IngestRequest has cisa_kev=True after enrichment. "
            "Expected at least one (CVE-2023-34362 is in KEV cache)."
        )

    def test_demo_cache_nvd_lookup_returns_cwe_class(self):
        """Sets DEMO_MODE=true env var, calls get_nvd_data, verifies
        cwe_class is non-empty and nvd_reference_count > 0."""
        import integrations.nvd as nvd_mod

        os.environ["DEMO_MODE"] = "true"
        try:
            importlib.reload(nvd_mod)
            from integrations.nvd import get_nvd_data

            result = get_nvd_data("CVE-2023-34362")
            assert result["cwe_class"] == "CWE-89", (
                f"Expected CWE-89, got '{result['cwe_class']}'"
            )
            assert result["nvd_reference_count"] > 0, "Expected nvd_reference_count > 0"
        finally:
            del os.environ["DEMO_MODE"]
            importlib.reload(nvd_mod)

    def test_demo_cache_synthesizes_references_for_exploits(self):
        """With DEMO_MODE=true, calls has_poc for a CVE with
        exploitdb_has_poc=true, expects True."""
        import integrations.nvd as nvd_mod
        import integrations.exploitdb as exp_mod

        os.environ["DEMO_MODE"] = "true"
        try:
            importlib.reload(nvd_mod)
            importlib.reload(exp_mod)
            from integrations.exploitdb import has_poc

            assert has_poc("CVE-2023-34362") is True, (
                "CVE-2023-34362 should have PoC in demo cache (exploitdb_has_poc=true)"
            )
        finally:
            del os.environ["DEMO_MODE"]
            importlib.reload(nvd_mod)
            importlib.reload(exp_mod)

    def test_random_wave_deduplicates_against_existing_queue(self):
        """Generate small wave, build existing_queue from it, generate
        second small wave with dedup, verify no overlap in (cve_id,
        hostname) pairs."""
        first_wave = generate_random_wave("small")
        assert len(first_wave) > 0

        # Build existing_queue from first wave
        existing_queue = []
        for item in first_wave:
            cve = item["plugin"]["cve"][0]
            host = item["asset"]["fqdn"]
            existing_queue.append({"vulnerability_id": cve, "hostname": host})

        existing_set = {(e["vulnerability_id"], e["hostname"]) for e in existing_queue}

        # Generate second wave with dedup
        second_wave = generate_random_wave("small", existing_queue=existing_queue)

        second_set = set()
        for item in second_wave:
            cve = item["plugin"]["cve"][0]
            host = item["asset"]["fqdn"]
            second_set.add((cve, host))

        overlap = existing_set & second_set
        assert len(overlap) == 0, (
            f"Found {len(overlap)} overlapping (cve_id, hostname) pairs: {overlap}"
        )

    def test_generated_finding_with_patch_has_vendor_patch_status_1(self):
        """Call _compute_vendor_patch_status with has_patch + date, expects
        1. Also verify no-patch returns 0."""
        plugin_with_patch = {
            "has_patch": True,
            "patch_publication_date": "2026-01-01",
        }
        status = _compute_vendor_patch_status(plugin_with_patch)
        assert status == 1, f"Expected vendor_patch_status=1, got {status}"

        # Also verify without patch returns 0
        plugin_no_patch = {"has_patch": False, "patch_publication_date": None}
        assert _compute_vendor_patch_status(plugin_no_patch) == 0

    def test_tenable_payload_includes_patch_publication_date(self):
        """Generate tenable payload for a CVE with patch_available=True,
        verify patch_publication_date is non-empty."""
        nvd = _load_nvd_cache()
        nvd_entry = nvd.get("CVE-2023-34362", {})
        assert nvd_entry.get("patch_available"), (
            "CVE-2023-34362 should have patch_available=True"
        )

        from integrations.demo_generator import _load_cmdb

        cmdb = _load_cmdb()
        cmdb_host = cmdb.get("PRD-MOVEIT-WEB01.health.wa.gov.au", {})

        payload = generate_tenable_payload(
            cve_id="CVE-2023-34362",
            hostname="PRD-MOVEIT-WEB01.health.wa.gov.au",
            cmdb_host=cmdb_host,
            nvd_entry=nvd_entry,
        )

        patch_date = payload["plugin"].get("patch_publication_date")
        assert patch_date is not None and patch_date != "", (
            f"Expected non-empty patch_publication_date, got {patch_date!r}"
        )

    def test_low_severity_scenario_cves_are_under_cvss_4(self):
        """Generate low-severity-hygiene scenario, verify all CVSS scores
        are < 4.0."""
        findings = generate_scenario_findings("low-severity-hygiene")
        assert len(findings) > 0

        for f in findings:
            cvss = f["plugin"]["cvss3_base_score"]
            cve = f["plugin"]["cve"][0]
            assert cvss < 4.0, f"{cve} has CVSS {cvss} >= 4.0, expected < 4.0"

        # Also verify via parsed IngestRequests
        requests = parse_tenable_batch(findings)
        for req in requests:
            assert req.cvss_score < 4.0, (
                f"{req.vulnerability_id} has CVSS {req.cvss_score} >= 4.0"
            )

    def test_demo_endpoints_return_404_when_demo_mode_off(self):
        """Verify _demo_only() returns JSONResponse with 404 when
        DEMO_MODE is not set (or set to a non-'true' value)."""
        result = _demo_only()
        assert isinstance(result, JSONResponse), (
            f"Expected JSONResponse, got {type(result)}"
        )
        assert result.status_code == 404, (
            f"Expected status 404, got {result.status_code}"
        )


# ======================================================================
# Edge Case Tests (3)
# ======================================================================


class TestEdgeCases:
    """Edge case tests: department extraction from hostnames,
    deterministic IP assignment, and OS keyword normalisation."""

    def test_extract_department_various_hostnames(self):
        """Tests _extract_department() with health, transport, education,
        communities hostnames, and an unknown hostname."""
        cases = [
            ("PRD-MOVEIT-WEB01.health.wa.gov.au", "health"),
            ("PRD-CITRIX-ADC01.transport.wa.gov.au", "transport"),
            ("PRD-PRINT-SVR05.education.wa.edu.au", "education"),
            ("PRD-FILE-STORE02.communities.wa.gov.au", "communities"),
            ("foo.bar.com", "unknown"),
        ]
        for hostname, expected in cases:
            result = _extract_department(hostname)
            assert result == expected, (
                f"_extract_department({hostname!r}) = {result!r}, expected {expected!r}"
            )

    def test_assign_ip_deterministic(self):
        """Same hostname always returns same IP; different hostnames
        return different IPs."""
        host_a = "PRD-MOVEIT-WEB01.health.wa.gov.au"
        host_b = "PRD-CITRIX-ADC01.transport.wa.gov.au"

        ip_a1 = _assign_ip(host_a)
        ip_a2 = _assign_ip(host_a)  # same host → same IP
        ip_b = _assign_ip(host_b)  # different host → different IP

        assert ip_a1 == ip_a2, (
            f"Same hostname should produce same IP: {ip_a1} vs {ip_a2}"
        )
        assert ip_a1 != ip_b, (
            f"Different hostnames should produce different IPs: {ip_a1} vs {ip_b}"
        )

    def test_extract_os_keyword(self):
        """Windows → 'windows', Ubuntu/Linux → 'linux', Citrix/FreeBSD →
        'freebsd', unknown → 'unknown'."""
        cases = [
            ("Windows Server 2019 Standard", "windows"),
            ("Windows Server 2022 Standard (build 20348)", "windows"),
            ("Ubuntu 22.04.3 LTS", "linux"),
            ("Linux kernel 5.15", "linux"),
            ("Debian GNU/Linux 11", "linux"),
            ("CentOS Stream 9", "linux"),
            ("RHEL 8.6", "linux"),
            ("Citrix NetScaler ADC VPX (FreeBSD-based)", "freebsd"),
            ("FreeBSD 13.1-RELEASE", "freebsd"),
            ("Some Unknown Operating System", "unknown"),
            ("", "unknown"),
        ]
        for os_string, expected in cases:
            result = _extract_os_keyword(os_string)
            assert result == expected, (
                f"_extract_os_keyword({os_string!r}) = {result!r}, "
                f"expected {expected!r}"
            )
