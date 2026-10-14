"""Durable query replay uses generated fixtures and no upstream requests."""

from dataclasses import replace
from uuid import uuid4

import pytest
from standalone.evidence_pipeline.source_json import encode_source_records
from standalone.evidence_pipeline.collection import osv_query_collection as collector
from standalone.evidence_pipeline.parsing.osv_query import URL
from .test_osv import scope, document


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Replay or synthetic input called HTTP")

    monkeypatch.setattr(collector, "collect", forbidden)
    chosen = replace(scope(), scope_reference=URL)
    return chosen, str(uuid4()), tmp_path / "query"


def prepare(bundle, **kwargs):
    return collector.prepare(
        *bundle, name="synthetic-package", ecosystem="PyPI", **kwargs
    )


def pages():
    return (
        b'{"next_page_token":"synthetic-next"}',
        encode_source_records({"vulns": [document()]}),
    )
