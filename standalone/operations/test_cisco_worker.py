"""Retained document failures do not starve other bounded RSS members."""

from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection import cisco_collection
from standalone.evidence_pipeline.test_cisco_collection import fixtures


@pytest.fixture
def batch(monkeypatch):
    index, documents = fixtures(tuple("cisco-sa-synthetic-" + x for x in "ABC"))
    imported = []
    monkeypatch.setattr(cisco_collection, "register", lambda scope: None)

    def ingest(snapshot):
        imported.append(snapshot)
        return {"replayed": False}

    def deny(*args, **kwargs):
        pytest.fail("Synthetic worker accessed the network")

    monkeypatch.setattr(cisco_collection, "ingest_public", ingest)
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.public_transport._download_url", deny
    )
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.cisco_rss_collection._download_url",
        deny,
    )
    return dict(
        origin="synthetic",
        execution_id=str(uuid4()),
        synthetic_index=index,
        synthetic_payloads=documents,
        record_limit=1,
    ), imported
