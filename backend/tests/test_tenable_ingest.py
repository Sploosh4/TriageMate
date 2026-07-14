"""Regression tests for Tenable ingest request validation."""

import pytest


pytestmark = pytest.mark.asyncio


async def test_tenable_ingest_rejects_malformed_json(client):
    """Malformed webhook payloads are client errors, never unhandled 500s."""
    response = await client.post(
        "/api/ingest/tenable",
        content=b'{"asset":',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid JSON in request body"}
