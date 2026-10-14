"""Catalog completion needs the exact saved search and every committed detail."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection.catalog_collection import (
    collect,
    catalog_scope,
)
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.reference_records import normalize_references
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.test_catalog_discovery import payload, ID
from standalone.evidence_pipeline.test_update_catalog import payload as detail
from .catalog_proof import CatalogProof


def saved(tmp_path):
    run = str(uuid4())
    collect(
        tmp_path / run,
        origin="synthetic",
        execution_id=run,
        kb="KB9999991",
        synthetic_index=payload(),
        synthetic_payloads={ID: detail()},
    )
    return run


@pytest.mark.parametrize(
    "damage",
    [None, "missing", "duplicate", "fingerprint", "native", "receipt", "origin"],
)
def test_exact_catalog_receipt_is_required(tmp_path, damage):
    run = saved(tmp_path)
    proof = CatalogProof("KB9999991")
    bundle, _, entries = proof.saved_index(tmp_path, "synthetic", run)
    entry = entries[0]
    scope = catalog_scope("synthetic", entry.url)
    attempt = stable_id("catalog-discovered-attempt", run, scope.connection_id)
    snapshot = prepare(scope, attempt, bundle / attempt, replay_only=True)
    record = next(normalize_references(snapshot.feed()))
    revision = stable_id(
        "public-revision", scope.connection_id, entry.update_id, record.content_hash
    )
    row = [
        scope.connection_id,
        snapshot.input_fingerprint,
        entry.update_id,
        record.content_hash,
        stable_id("public-receipt", revision, attempt),
        entry.url,
        "synthetic",
    ]
    if damage in {"fingerprint", "native", "receipt", "origin"}:
        row[{"fingerprint": 1, "native": 2, "receipt": 4, "origin": 6}[damage]] = (
            "changed"
        )
    cursor = Mock()
    cursor.fetchall.return_value = (
        []
        if damage == "missing"
        else [tuple(row)] * (2 if damage == "duplicate" else 1)
    )
    assert proof.imports_committed(cursor, bundle, "synthetic", run, entries) is (
        damage is None
    )


@pytest.mark.parametrize(
    "damage", [None, "kb", "run", "contract", "index", "missing", "imports"]
)
def test_catalog_declaration_is_bound_to_kb_run_contract_and_imports(
    tmp_path, monkeypatch, damage
):
    run = saved(tmp_path)
    proof = CatalogProof("KB9999991")
    _, digest, _ = proof.saved_index(tmp_path, "synthetic", run)
    job = SimpleNamespace(input_id=str(uuid4()), run_id=run)
    event = proof.event(job, "synthetic", "a" * 64, digest)
    if damage == "missing":
        event = None
    elif damage in {"kb", "run", "contract", "index"}:
        event[
            {
                "kb": "kb",
                "run": "run_id",
                "contract": "worker_contract",
                "index": "index_sha256",
            }[damage]
        ] = "changed"
    monkeypatch.setattr(CatalogProof, "saved_event", lambda *args: event)
    monkeypatch.setattr(
        CatalogProof, "imports_committed", lambda *args: damage != "imports"
    )
    assert proof.committed(
        Mock(), "synthetic-proof", job, "synthetic", tmp_path, "a" * 64
    ) is (damage is None)
    with pytest.raises(ValueError):
        replace(proof, kb="KB9999992").saved_index(tmp_path, "synthetic", run)
