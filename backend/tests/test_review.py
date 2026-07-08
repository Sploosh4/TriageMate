"""
Tests for review queue and review workflow endpoints.

Covers: GET /api/review/queue, POST /api/review/flag/{case_id},
        POST /api/case/{case_id}/review, GET /api/case/{case_id}/history

NOTE: Response keys are camelCase when the Pydantic model (response_model)
      is applied. The history endpoint returns raw dicts (snake_case) because
      it does not use a response_model. See backend/models.py for the alias
      generator configuration.
"""

import pytest

pytestmark = pytest.mark.asyncio


# Required keys for a review queue item (camelCase via ReviewQueueItem model)
REVIEW_QUEUE_ITEM_KEYS = {
    "id",
    "vulnerabilityId",
    "hostname",
    "priorityScore",
    "riskBand",
    "detectionTier",
    "flaggedForReview",
    "tier2TextConflict",
}


class TestReviewQueueEndpoint:
    """GET /api/review/queue smoke tests."""

    async def test_review_queue_returns_200(self, client):
        """GET /api/review/queue should return HTTP 200."""
        response = await client.get("/api/review/queue")
        assert response.status_code == 200

    async def test_review_queue_returns_expected_structure(self, client):
        """Response must contain 'total' (int) and 'rows' (list of items)."""
        response = await client.get("/api/review/queue")
        data = response.json()

        assert "total" in data, "Missing 'total' key"
        assert isinstance(data["total"], int), "'total' must be int"

        assert "rows" in data, "Missing 'rows' key"
        assert isinstance(data["rows"], list), "'rows' must be list"

        # Check that rows have the required keys if any exist
        for row in data["rows"]:
            missing = REVIEW_QUEUE_ITEM_KEYS - set(row.keys())
            assert not missing, f"Row missing keys: {missing}"

    async def test_review_queue_returns_conflicted_items(self, client):
        """With seed data, rows with tier_2_text_conflict=True should appear."""
        response = await client.get("/api/review/queue")
        data = response.json()

        # Seed rows 5, 6, 7 have tier_2_text_conflict = True
        assert data["total"] >= 3, (
            f"Expected at least 3 rows (tier_2_text_conflict=True rows), "
            f"got {data['total']}"
        )


class TestFlagForReviewEndpoint:
    """POST /api/review/flag/{case_id} tests."""

    async def _get_first_case_id(self, client) -> int:
        """Helper: get the first case ID from the queue."""
        response = await client.get("/api/queue")
        rows = response.json().get("rows", [])
        assert len(rows) > 0, "No cases found in queue"
        return rows[0]["id"]

    async def test_flag_for_review_returns_200(self, client):
        """POST /api/review/flag/{case_id} should return 200."""
        case_id = await self._get_first_case_id(client)
        response = await client.post(f"/api/review/flag/{case_id}")
        assert response.status_code == 200

    async def test_flag_for_review_returns_correct_body(self, client):
        """Response should contain status and flagged fields."""
        case_id = await self._get_first_case_id(client)
        response = await client.post(f"/api/review/flag/{case_id}")
        data = response.json()

        assert data["status"] == "ok"
        assert data["flagged"] is True

    async def test_flag_for_review_404_on_nonexistent(self, client):
        """Flagging a non-existent case should return 404."""
        response = await client.post("/api/review/flag/999999")
        assert response.status_code == 404


class TestSubmitReviewEndpoint:
    """POST /api/case/{case_id}/review tests."""

    async def _get_first_case_id(self, client) -> int:
        """Helper: get the first case ID from the queue."""
        response = await client.get("/api/queue")
        rows = response.json().get("rows", [])
        assert len(rows) > 0, "No cases found in queue"
        return rows[0]["id"]

    async def test_submit_review_returns_200(self, client):
        """Submit a basic review, expect 200."""
        case_id = await self._get_first_case_id(client)
        payload = {
            "analyst_decision": "confirmed",
            "override_score": None,
            "override_band": None,
            "notes": "Test review submission",
            "analyst_name": "test-analyst",
        }
        response = await client.post(f"/api/case/{case_id}/review", json=payload)
        assert response.status_code == 200

    async def test_submit_review_with_override(self, client):
        """Submit a review with override decision, expect 200."""
        case_id = await self._get_first_case_id(client)
        payload = {
            "analyst_decision": "override",
            "override_score": 85,
            "override_band": "Critical",
            "notes": "Overriding score based on env analysis",
            "analyst_name": "test-analyst",
        }
        response = await client.post(f"/api/case/{case_id}/review", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    async def test_submit_review_404_on_nonexistent(self, client):
        """Reviewing a non-existent case should return 404."""
        payload = {
            "analyst_decision": "confirmed",
            "override_score": None,
            "override_band": None,
            "notes": "Should not work",
            "analyst_name": "test-analyst",
        }
        response = await client.post("/api/case/999999/review", json=payload)
        assert response.status_code == 404


class TestCaseHistoryEndpoint:
    """GET /api/case/{case_id}/history tests.

    NOTE: This endpoint returns raw dicts (no response_model), so keys
    are snake_case, not camelCase.
    """

    async def _get_first_case_id(self, client) -> int:
        response = await client.get("/api/queue")
        rows = response.json().get("rows", [])
        assert len(rows) > 0, "No cases found in queue"
        return rows[0]["id"]

    async def test_history_returns_200(self, client):
        """GET /api/case/{case_id}/history should return 200."""
        case_id = await self._get_first_case_id(client)
        response = await client.get(f"/api/case/{case_id}/history")
        assert response.status_code == 200

    async def test_history_returns_list(self, client):
        """History response should be a list."""
        case_id = await self._get_first_case_id(client)
        response = await client.get(f"/api/case/{case_id}/history")
        data = response.json()
        assert isinstance(data, list)

    async def test_history_includes_review_after_submission(self, client):
        """After submitting a review, history should include it.

        Keys are snake_case because the history endpoint returns raw
        dicts without a Pydantic response_model.
        """
        # Submit a review first
        case_id = await self._get_first_case_id(client)
        payload = {
            "analyst_decision": "confirmed",
            "override_score": None,
            "override_band": None,
            "notes": "History test review",
            "analyst_name": "history-test",
        }
        await client.post(f"/api/case/{case_id}/review", json=payload)

        # Then check history
        response = await client.get(f"/api/case/{case_id}/history")
        data = response.json()
        assert len(data) >= 1
        # Keys are snake_case because this endpoint returns raw dicts
        assert data[0]["analyst_name"] == "history-test"
        assert data[0]["analyst_decision"] == "confirmed"
