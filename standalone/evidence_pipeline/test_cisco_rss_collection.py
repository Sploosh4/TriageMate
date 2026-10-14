"""Synthetic index receipts prove replay, source binding and interrupted-work safety."""

import pytest

from standalone.evidence_pipeline.collection import cisco_rss_collection as collection


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        collection,
        "_download_url",
        lambda *a, **kw: pytest.fail("Unexpected RSS network access"),
    )
