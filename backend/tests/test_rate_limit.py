"""
Rate limit middleware tests.

Verifies that the TokenBucket rate limiter at the middleware layer
correctly blocks excess requests for the ingest and clear endpoints.

Uses a tiny burst bucket for ingest to keep test runs fast — the
production defaults (burst 50) would require 51+ concurrent pipeline
runs, which is too heavyweight for a unit test.
"""

import asyncio

import pytest

from middleware.rate_limit import TokenBucket, ingest_bucket

pytestmark = pytest.mark.asyncio

INGEST_PAYLOAD = {
    "vulnerability_id": "CVE-TEST-RL-0001",
    "hostname": "per-PRD-PATIENT-EMR01.health.wa.gov.au",
    "target_ip": "10.1.1.100",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.95,
    "raw_description": "Rate limit test",
}

INGEST_PAYLOAD_2 = {
    "vulnerability_id": "CVE-TEST-RL-0002",
    "hostname": "per-PRD-PATIENT-EMR01.health.wa.gov.au",
    "target_ip": "10.1.1.100",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.95,
    "raw_description": "Rate limit test 2",
}

INGEST_PAYLOAD_3 = {
    "vulnerability_id": "CVE-TEST-RL-0003",
    "hostname": "per-PRD-PATIENT-EMR01.health.wa.gov.au",
    "target_ip": "10.1.1.100",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.95,
    "raw_description": "Rate limit test 3",
}


def _cleanup_rl_records():
    """Delete CVE-TEST-RL-* records from the database."""
    from database import get_db

    conn = get_db()
    conn.execute(
        "DELETE FROM vulnerabilities WHERE vulnerability_id LIKE 'CVE-TEST-RL-%'"
    )
    conn.commit()
    conn.close()


class TestRateLimitIngest:
    """Rate limit tests for POST /api/ingest."""

    async def test_ingest_rate_limit_blocks_excess(self, client):
        """Send 5 rapid POST requests — at least 1 must return 429.

        The ingest bucket is temporarily replaced with a tiny bucket
        (burst=2, rate=1/min) so we can trigger rate limiting with
        just a few rapid requests instead of 50+.
        """
        tiny_bucket = TokenBucket(rate_per_minute=1, burst_size=2)
        import middleware.rate_limit as rl

        rl.ingest_bucket = tiny_bucket
        try:
            _cleanup_rl_records()
            responses = []
            for _ in range(5):
                responses.append(await client.post("/api/ingest", json=INGEST_PAYLOAD))

            n_429 = sum(1 for r in responses if r.status_code == 429)
            assert n_429 >= 1, (
                f"Expected at least 1 rate-limit block (429), got 0. "
                f"Status codes: {[r.status_code for r in responses]}"
            )
        finally:
            rl.ingest_bucket = ingest_bucket

    async def test_ingest_rate_limit_allows_normal_rate(self, client):
        """Send 3 requests spaced ~0.5s apart — all must return 200.

        Normal traffic well within the 30/min rate with burst 50.
        Uses unique IDs to avoid duplicate-key conflicts.
        """
        _cleanup_rl_records()
        payloads = [INGEST_PAYLOAD, INGEST_PAYLOAD_2, INGEST_PAYLOAD_3]

        for payload in payloads:
            resp = await client.post("/api/ingest", json=payload)
            assert resp.status_code == 200, (
                f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
            )
            await asyncio.sleep(0.5)


class TestRateLimitClear:
    """Rate limit tests for POST /api/ingest/clear."""

    async def test_clear_rate_limit_blocks_rapid(self, client):
        """Send 5 rapid POST requests to /api/ingest/clear — at least 1 must return 429.

        Default rate is 2/min with burst 3.  With 5 rapid requests,
        the 4th and 5th should be blocked.
        """
        responses = []
        for _ in range(5):
            responses.append(await client.post("/api/ingest/clear"))

        n_429 = sum(1 for r in responses if r.status_code == 429)
        assert n_429 >= 1, (
            f"Expected at least 1 rate-limit block (429), got 0. "
            f"Status codes: {[r.status_code for r in responses]}"
        )
