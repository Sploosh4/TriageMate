"""
Pure-function tests for scripts.aggregate_tenable_sectors.

No async, no database, no client fixture.
"""

from scripts.aggregate_tenable_sectors import aggregate_findings


class TestAggregateSectors:
    """Test suite for aggregate_findings()."""

    def test_empty_input(self):
        """Empty list returns metadata-only dict with 0 findings."""
        result = aggregate_findings([])
        assert len(result) == 1  # only _metadata
        meta = result["_metadata"]
        assert meta["total_findings"] == 0
        assert meta["unique_cves"] == 0
        assert meta["unique_sectors"] == 0
        assert "generated_at" in meta

    def test_basic_aggregation(self):
        """Three findings, same CVE on same sector → count = 3."""
        findings = [
            {
                "asset": {"fqdn": "host1.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0001"]},
            },
            {
                "asset": {"fqdn": "host2.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0001"]},
            },
            {
                "asset": {"fqdn": "host3.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0001"]},
            },
        ]
        result = aggregate_findings(findings)
        assert result["CVE-2023-0001"]["health"] == 3
        assert result["_metadata"]["total_findings"] == 3
        assert result["_metadata"]["unique_cves"] == 1
        assert result["_metadata"]["unique_sectors"] == 1

    def test_multi_sector_grouping(self):
        """Same CVE across different sectors → separate counts per sector."""
        findings = [
            {
                "asset": {"fqdn": "host-a.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0002"]},
            },
            {
                "asset": {"fqdn": "host-b.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0002"]},
            },
            {
                "asset": {"fqdn": "host-c.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0002"]},
            },
            {
                "asset": {"fqdn": "host-d.education.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0002"]},
            },
        ]
        result = aggregate_findings(findings)
        assert result["CVE-2023-0002"]["health"] == 1
        assert result["CVE-2023-0002"]["transport"] == 2
        assert result["CVE-2023-0002"]["education"] == 1
        assert result["_metadata"]["unique_cves"] == 1
        assert result["_metadata"]["unique_sectors"] == 3
        assert result["_metadata"]["total_findings"] == 4

    def test_min_frequency_filter(self):
        """With min_frequency=2, pairs with count 1 are excluded."""
        findings = [
            {
                "asset": {"fqdn": "host-a.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0003"]},
            },
            {
                "asset": {"fqdn": "host-b.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0003"]},
            },
            {
                "asset": {"fqdn": "host-c.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0003"]},
            },
        ]
        result = aggregate_findings(findings, min_frequency=2)
        # health count = 2, transport count = 1 (excluded)
        assert "CVE-2023-0003" in result
        assert result["CVE-2023-0003"]["health"] == 2
        assert "transport" not in result["CVE-2023-0003"]
        # Metadata still reflects total (pre-filter)
        assert result["_metadata"]["total_findings"] == 3

    def test_missing_fqdn_fallback(self):
        """Finding with missing fqdn but present hostname still works."""
        findings = [
            {
                "asset": {"hostname": "srv01.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0004"]},
            },
            {
                "asset": {"hostname": "srv02.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0004"]},
            },
        ]
        result = aggregate_findings(findings)
        assert result["CVE-2023-0004"]["health"] == 1
        assert result["CVE-2023-0004"]["transport"] == 1
        assert result["_metadata"]["total_findings"] == 2

    def test_missing_cve_skipped(self):
        """Finding with empty/missing cve array is skipped with warning."""
        findings = [
            {
                "asset": {"fqdn": "host.health.wa.gov.au"},
                "plugin": {"cve": []},
            },
            {
                "asset": {"fqdn": "host2.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-0005"]},
            },
        ]
        result = aggregate_findings(findings)
        assert result["CVE-2023-0005"]["health"] == 1
        assert result["_metadata"]["total_findings"] == 1
        assert result["_metadata"]["unique_cves"] == 1

    def test_no_fqdn_or_hostname(self):
        """Finding with neither fqdn nor hostname maps to 'unknown' sector."""
        findings = [
            {
                "asset": {"ipv4": "10.0.0.1"},
                "plugin": {"cve": ["CVE-2023-0006"]},
            },
        ]
        result = aggregate_findings(findings)
        assert "CVE-2023-0006" in result
        assert result["CVE-2023-0006"]["unknown"] == 1
        assert result["_metadata"]["total_findings"] == 1

    def test_multiple_cves_different_sectors(self):
        """Multiple different CVEs across sectors — full cross-tabulation."""
        findings = [
            {
                "asset": {"fqdn": "h1.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-A001"]},
            },
            {
                "asset": {"fqdn": "h2.health.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-A002"]},
            },
            {
                "asset": {"fqdn": "t1.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-A001"]},
            },
            {
                "asset": {"fqdn": "t2.transport.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-A001"]},
            },
            {
                "asset": {"fqdn": "e1.education.wa.gov.au"},
                "plugin": {"cve": ["CVE-2023-A003"]},
            },
        ]
        result = aggregate_findings(findings)
        assert result["CVE-2023-A001"]["health"] == 1
        assert result["CVE-2023-A001"]["transport"] == 2
        assert result["CVE-2023-A002"]["health"] == 1
        assert result["CVE-2023-A003"]["education"] == 1
        assert result["_metadata"]["total_findings"] == 5
        assert result["_metadata"]["unique_cves"] == 3
        assert result["_metadata"]["unique_sectors"] == 3
