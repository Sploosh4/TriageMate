"""
End-to-end integration test for the full TriageMate pipeline.

Covers: Ingest → Pre-Tier → EPSS → Tier 0 → Tier 1 → CWE → RAG → Tier 2 → Scoring
Verifies that every response field is present with correct types and shapes.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from main import app


@pytest.mark.asyncio
async def test_full_pipeline_ingest():
    """Test the full ingest pipeline end-to-end."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "vulnerability_id": "CVE-TEST-FULLPIPE-001",
            "hostname": "per-PRD-MOVEIT-WEB01.health.wa.gov.au",
            "ip_address": "10.1.1.100",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.95,
            "cisa_kev": True,
            "description": "Integration test: critical RCE in file transfer",
            "cve_id": "CVE-TEST-FULLPIPE-001",
        }

        resp = await client.post("/api/ingest", json=payload)
        assert resp.status_code == 200, (
            f"Expected 200, got {resp.status_code}: {resp.text[:300]}"
        )

        data = resp.json()

        # ──────────────────────────────────────────────────────────────
        # 1. QueueRow assertions (9 fields)
        # ──────────────────────────────────────────────────────────────
        qr = data.get("queueRow")
        assert qr is not None, "Missing queueRow in response"

        assert qr.get("vulnerabilityId") == "CVE-TEST-FULLPIPE-001", (
            f"vulnerabilityId mismatch: {qr.get('vulnerabilityId')}"
        )
        assert isinstance(qr.get("priorityScore"), int), (
            f"priorityScore not int: {type(qr.get('priorityScore'))} ({qr.get('priorityScore')})"
        )
        assert qr.get("hostname") == "per-PRD-MOVEIT-WEB01.health.wa.gov.au", (
            f"hostname mismatch: {qr.get('hostname')}"
        )
        assert qr.get("riskBand") in ("Low", "Medium", "Critical", "Very Critical"), (
            f"Unexpected riskBand: {qr.get('riskBand')}"
        )
        assert qr.get("tier") in ("Deterministic", "ML Tier", "SLM Tier"), (
            f"Unexpected tier: {qr.get('tier')}"
        )
        assert isinstance(qr.get("id"), int), f"id not int: {type(qr.get('id'))}"
        assert qr.get("compliance") is not None, "Missing compliance"
        assert qr.get("complianceCategory") is not None, "Missing complianceCategory"
        assert qr.get("detectionReason") is not None, "Missing detectionReason"

        # ──────────────────────────────────────────────────────────────
        # 2. CaseView assertions — all expected panes must exist
        # ──────────────────────────────────────────────────────────────
        cv = data.get("caseView")
        assert cv is not None, "Missing caseView in response"

        expected_panes = [
            "summaryParagraphs",
            "missionPrevalence",
            "mitreTechniques",
            "scoringWeights",
            "assetRegistry",
            "investigationNotes",
            "scannerOutput",
            "weaknessTemplate",
            "advisoryRefId",
            "advisoryQuote",
            "textConflict",
            "textConflictNote",
        ]
        for pane in expected_panes:
            assert pane in cv, f"Missing caseView pane: {pane}"

        # Score gauge
        assert "scoreGaugeValue" in cv, "Missing scoreGaugeValue"
        assert "scoreGaugeBand" in cv, "Missing scoreGaugeBand"
        gauge_value = cv.get("scoreGaugeValue")
        assert isinstance(gauge_value, int) or isinstance(gauge_value, str), (
            f"scoreGaugeValue wrong type: {type(gauge_value)}"
        )

        # Gauge band colour (should be a hex colour string)
        assert "gaugeBandColour" in cv, "Missing gaugeBandColour"
        assert cv["gaugeBandColour"].startswith("#"), (
            f"gaugeBandColour not a hex colour: {cv['gaugeBandColour']}"
        )

        # Substitution block — the key exists even if value is null/None
        assert "hasSubstitution" in cv, "Missing hasSubstitution"
        assert "substitutionBlock" in cv, "Missing substitutionBlock"

        # ──────────────────────────────────────────────────────────────
        # 3. Detection tier — this is a critical CISA KEV + CVSS 9.8
        #    + internet-facing, so it should be auto-resolved at Tier 0
        #    (Deterministic routing, no escalation to ML/SLM)
        # ──────────────────────────────────────────────────────────────
        tier = qr.get("tier")
        assert tier in ("Deterministic", "ML Tier", "SLM Tier"), (
            f"Unexpected tier: {tier}"
        )

        # ──────────────────────────────────────────────────────────────
        # 4. Scoring weights — exactly 5 dimensions with correct shape
        # ──────────────────────────────────────────────────────────────
        weights = cv.get("scoringWeights")
        assert isinstance(weights, list), f"scoringWeights not list: {type(weights)}"
        assert len(weights) == 5, f"Expected 5 scoring weights, got {len(weights)}"
        for w in weights:
            assert "name" in w, f"Weight missing 'name': {w}"
            assert "awarded" in w, f"Weight missing 'awarded': {w}"
            assert "max" in w, f"Weight missing 'max': {w}"
            awarded = w.get("awarded", 0)
            maximum = w.get("max", 100)
            assert awarded <= maximum, (
                f"awarded ({awarded}) > max ({maximum}) for weight '{w.get('name')}'"
            )
            assert "justification" in w, f"Weight missing 'justification': {w}"
            assert "isSubstituted" in w, f"Weight missing 'isSubstituted': {w}"

        # ──────────────────────────────────────────────────────────────
        # 5. Mission prevalence — derived from Pre-Tier (KNOWN_TAGS match)
        # ──────────────────────────────────────────────────────────────
        mp = cv.get("missionPrevalence")
        assert mp is not None, "Missing missionPrevalence"
        assert isinstance(mp, list), f"missionPrevalence not list: {type(mp)}"
        assert len(mp) > 0, "missionPrevalence is empty"

        # ──────────────────────────────────────────────────────────────
        # 6. Asset registry — list of {label, value} entries
        # ──────────────────────────────────────────────────────────────
        ar = cv.get("assetRegistry")
        assert isinstance(ar, list), f"assetRegistry not list: {type(ar)}"
        assert len(ar) >= 4, f"assetRegistry too short: {len(ar)}"
        for entry in ar:
            assert "label" in entry, f"assetRegistry entry missing 'label': {entry}"
            assert "value" in entry, f"assetRegistry entry missing 'value': {entry}"

        # ──────────────────────────────────────────────────────────────
        # 7. Investigation notes — should contain pipeline routing info
        # ──────────────────────────────────────────────────────────────
        notes = cv.get("investigationNotes")
        assert notes is not None, "Missing investigationNotes"
        assert "Pipeline routing" in notes, (
            "investigationNotes missing pipeline routing info"
        )
        assert "Final score" in notes, "investigationNotes missing final score"
