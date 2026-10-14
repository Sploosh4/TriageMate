"""Synthetic discovery persistence, interruption and offline continuation."""

from contextlib import nullcontext

import pytest

from standalone.evidence_pipeline.collection import (
    github_discovery_collection as collection,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    from standalone.evidence_pipeline.collection import public_pacing

    monkeypatch.setattr(public_pacing, "paced", lambda source: nullcontext())
    monkeypatch.setattr(
        collection,
        "download_github_object",
        lambda *a: pytest.fail("Unexpected discovery network"),
    )
