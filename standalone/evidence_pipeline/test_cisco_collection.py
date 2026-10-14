"""Generated RSS membership drives exact documents without broadening routes."""

import json
import pytest

from standalone.evidence_pipeline.collection import (
    cisco_rss_collection,
    public_transport,
)
from standalone.evidence_pipeline.parsing.cisco_rss import endpoint
from .test_cisco_rss import feed
from .test_cisco_advisories import example


def fixtures(names=("cisco-sa-synthetic-AbC", "cisco-sa-synthetic-Def")):
    documents = {}
    rss = None
    for name in names:
        _, document = example()
        document["document"]["tracking"]["id"] = name
        documents[name] = json.dumps(document).encode()
        wire = feed(endpoint(name), name)
        rss = (
            wire
            if rss is None
            else rss.replace(b"</rdf:RDF>", b"<item>" + wire.split(b"<item>", 1)[1])
        )
    return rss, documents


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*a, **kw):
        pytest.fail("Synthetic/replay used network")

    monkeypatch.setattr(cisco_rss_collection, "_download_url", deny)
    monkeypatch.setattr(public_transport, "_download_url", deny)
