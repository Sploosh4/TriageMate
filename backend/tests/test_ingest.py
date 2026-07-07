"""
Smoke test: POST /api/ingest endpoint.

Verifies the ingestion pipeline runs end-to-end for a new vulnerability,
producing both a queue row and case view in the response.

NOTE: Response keys are camelCase because the Pydantic models use
      `alias_generator = camel_case` (see backend/models.py).
"""

import pytest

pytestmark = pytest.mark.asyncio

INGEST_PAYLOAD = {
    "vulnerability_id": "CVE-TEST-0001",
    "hostname": "per-PRD-PATIENT-EMR01.health.wa.gov.au",
    "target_ip": "10.1.1.100",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.95,
    "raw_description": "Test vulnerability for smoke test",
}

TEST_VULN_ID = "CVE-TEST-0001"


@pytest.fixture(autouse=True)
async def cleanup_test_records():
    """Remove any previously created test records before each ingest test.

    This prevents data leaking between tests and avoids duplicate-key
    confusion when checking queue row counts.
    """
    from database import get_db

    conn = get_db()
    conn.execute(
        "DELETE FROM vulnerabilities WHERE vulnerability_id = ?",
        (TEST_VULN_ID,),
    )
    conn.commit()
    conn.close()
    yield


class TestIngestEndpoint:
    """Ingest endpoint smoke tests."""

    async def test_ingest_returns_200(self, client):
        """POST /api/ingest with valid payload returns 200."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text[:200]}"
        )

    async def test_ingest_returns_queue_row_and_case_view(self, client):
        """Response should contain both queueRow and caseView (camelCase)."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        assert "queueRow" in data, (
            f"Response missing 'queueRow'. Got keys: {list(data.keys())}"
        )
        assert "caseView" in data, (
            f"Response missing 'caseView'. Got keys: {list(data.keys())}"
        )

    async def test_ingest_queue_row_has_vulnerability_id(self, client):
        """queueRow must contain vulnerabilityId matching the payload."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        qr = data["queueRow"]
        assert qr["vulnerabilityId"] == TEST_VULN_ID, (
            f"Expected vulnerabilityId '{TEST_VULN_ID}', got '{qr['vulnerabilityId']}'"
        )

    async def test_ingest_queue_row_has_integer_priority_score(self, client):
        """queueRow.priorityScore must be an int."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        qr = data["queueRow"]
        assert "priorityScore" in qr, "queueRow missing priorityScore"
        assert isinstance(qr["priorityScore"], int), (
            f"priorityScore should be int, got {type(qr['priorityScore']).__name__}"
        )

    async def test_ingest_queue_row_has_risk_band(self, client):
        """queueRow must contain a non-empty riskBand string."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        qr = data["queueRow"]
        assert qr.get("riskBand"), "queueRow missing or empty riskBand"

    async def test_ingest_case_view_has_score_gauge(self, client):
        """caseView should contain scoreGaugeValue and scoreGaugeBand."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        cv = data["caseView"]
        assert "scoreGaugeValue" in cv, "caseView missing scoreGaugeValue"
        assert "scoreGaugeBand" in cv, "caseView missing scoreGaugeBand"

    async def test_ingest_case_view_has_asset_registry(self, client):
        """caseView should contain a non-empty assetRegistry list."""
        response = await client.post("/api/ingest", json=INGEST_PAYLOAD)
        data = response.json()

        cv = data["caseView"]
        assert "assetRegistry" in cv, "caseView missing assetRegistry"
        assert isinstance(cv["assetRegistry"], list), "assetRegistry must be a list"
        assert len(cv["assetRegistry"]) > 0, "assetRegistry should not be empty"
