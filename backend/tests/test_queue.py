"""
Smoke test: /api/queue endpoint.

Verifies the vulnerability queue returns the expected demo rows with
correct structure and known priority scores.

NOTE: Response keys are camelCase because the Pydantic models use
      `alias_generator = camel_case` (see backend/models.py).
"""

import pytest

pytestmark = pytest.mark.asyncio

# Expected priority scores in descending order (matching the seed data)
EXPECTED_PRIORITY_SCORES = [94, 87, 71, 63, 55, 41, 22]

# Required keys on each queue row (camelCase — matches the Pydantic alias)
REQUIRED_ROW_KEYS = {
    "id",
    "vulnerabilityId",
    "hostname",
    "priorityScore",
    "riskBand",
    "detectionReason",
    "tier",
    "compliance",
    "complianceCategory",
}


class TestQueueEndpoint:
    """Queue endpoint smoke tests."""

    async def test_queue_returns_200(self, client):
        """GET /api/queue should return HTTP 200."""
        response = await client.get("/api/queue")
        assert response.status_code == 200

    async def test_queue_has_seven_or_more_rows(self, client):
        """With seed data loaded, the queue should contain at least 7 rows.

        Exactly 7 from seed data — may be more if ingest tests have run
        in the same session and left test records.
        """
        response = await client.get("/api/queue")
        rows = response.json().get("rows", [])
        assert len(rows) >= 7, (
            f"Expected at least 7 rows in queue, got {len(rows)}. "
            "Ensure seed data has been loaded (run `python seed_data.py`)."
        )

    async def test_queue_rows_have_required_keys(self, client):
        """Each queue row must have all required fields (camelCase)."""
        response = await client.get("/api/queue")
        rows = response.json()["rows"]

        for i, row in enumerate(rows):
            missing = REQUIRED_ROW_KEYS - set(row.keys())
            assert not missing, (
                f"Row {i} (id={row.get('id', '?')}) missing keys: {missing}"
            )

    async def test_queue_first_seven_scores_match_seed_data(self, client):
        """The first 7 rows should match the seed data priority scores.

        We check by vulnerability_id to be robust against test ordering —
        some test records may appear before the seed rows in edge cases.
        """
        response = await client.get("/api/queue")
        rows = response.json()["rows"]

        # Find seed rows by their known vulnerability IDs
        seed_ids = {
            "CVE-2023-34362",
            "CVE-2023-4966",
            "CVE-2023-27350",
            "CVE-2024-1709",
            "CVE-2023-36884",
            "CVE-2023-22515",
            "CVE-2022-47966",
        }

        seed_scores = [
            row["priorityScore"]
            for row in rows
            if row.get("vulnerabilityId") in seed_ids
        ]

        assert seed_scores == EXPECTED_PRIORITY_SCORES, (
            f"Seed data priority scores mismatch.\n"
            f"  Expected: {EXPECTED_PRIORITY_SCORES}\n"
            f"  Got:      {seed_scores}\n"
            f"  (matched {len(seed_scores)} seed rows out of {len(rows)} total)"
        )

    async def test_queue_hostnames_are_present(self, client):
        """Every row should have a non-empty hostname."""
        response = await client.get("/api/queue")
        rows = response.json()["rows"]

        for row in rows:
            assert row.get("hostname"), f"Row {row['id']} has empty hostname"

    async def test_queue_risk_bands_are_valid(self, client):
        """Risk band must be one of the known values (camelCase key)."""
        valid_bands = {"Low", "Medium", "Critical", "Very Critical"}
        response = await client.get("/api/queue")
        rows = response.json()["rows"]

        for row in rows:
            assert row["riskBand"] in valid_bands, (
                f"Row {row['id']}: unexpected riskBand '{row['riskBand']}'"
            )

    async def test_queue_items_ordered_by_priority(self, client):
        """Queue should be sorted by priority_score descending (then id asc)."""
        response = await client.get("/api/queue")
        rows = response.json()["rows"]

        scores = [row["priorityScore"] for row in rows]
        # Allow equal scores but no ascending pairs
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Queue not sorted by priority descending at index {i}: "
                f"{scores[i]} < {scores[i + 1]}"
            )
