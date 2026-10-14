"""Catalog age must retain exact search, worker and detail receipt authority."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.catalog_discovery import search_url
from . import catalog_age
from .catalog_proof import CatalogProof
from .repository_recipe import RepositoryRecipe
from .provider_monitor import ProviderPolicy
from .test_catalog_proof import saved


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "contract",
        "input",
        "digest",
        "imports",
        "missing_file",
        "no_event",
        "no_definition",
        "empty",
        "unknown_date",
        "oldest",
    ],
)
def test_search_clock_requires_exact_membership_and_receipts(
    tmp_path, monkeypatch, damage
):
    if damage in {"empty", "unknown_date", "oldest"}:
        from standalone.evidence_pipeline.collection.catalog_collection import collect
        from standalone.evidence_pipeline.test_catalog_discovery import (
            payload,
            row,
            empty_payload,
            ID,
        )
        from standalone.evidence_pipeline.test_update_catalog import payload as detail

        run = str(uuid4())
        second = str(uuid4())
        index = (
            empty_payload()
            if damage == "empty"
            else payload(row() + row(second, index=1), "1 - 2 of 2 (page 1 of 1)")
        )
        records = (
            {}
            if damage == "empty"
            else {
                ID: detail(),
                second: detail()
                .replace(ID.encode(), second.encode())
                .replace(
                    b"9/16/2026",
                    b"unknown" if damage == "unknown_date" else b"9/1/2026",
                ),
            }
        )
        collect(
            tmp_path / run,
            origin="synthetic",
            execution_id=run,
            kb="KB9999991",
            synthetic_index=index,
            synthetic_payloads=records,
        )
    else:
        run = saved(tmp_path)
    scope = SourceScope(
        connection_id=str(uuid4()),
        source="Microsoft Update Catalog",
        input_kind="catalog_search",
        tenant_id=None,
        scope_reference=search_url("KB9999991"),
        origin="synthetic",
        provenance="TriageMate generated synthetic Catalog age test",
    )
    recipe = RepositoryRecipe(scope, tmp_path, kb="KB9999991")
    assert ProviderPolicy(recipe, 86400).recipe == recipe
    proof = CatalogProof(recipe.kb)
    _, digest, _ = proof.saved_index(tmp_path, scope.origin, run)
    declaration = proof.event(
        SimpleNamespace(input_id=scope.connection_id, run_id=run),
        scope.origin,
        "a" * 64,
        digest,
    )
    if damage in {"contract", "input", "digest"}:
        declaration[
            {
                "contract": "worker_contract",
                "input": "input_id",
                "digest": "index_sha256",
            }[damage]
        ] = "changed"
    state = SimpleNamespace(
        definitions={}
        if damage == "no_definition"
        else {scope.connection_id: SimpleNamespace(worker_contract="a" * 64)}
    )
    monkeypatch.setattr(catalog_age.store, "load", lambda *args: (1, state))
    checked = []

    def imports(*args):
        checked.append(True)
        return damage != "imports"

    monkeypatch.setattr(CatalogProof, "imports_committed", imports)
    sealed = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)
    cursor = Mock()
    cursor.fetchone.return_value = (
        None if damage == "no_event" else (declaration, sealed)
    )
    if damage == "missing_file":
        (tmp_path / run / "search.html").unlink()
    result = catalog_age.read_clock(cursor, "synthetic-catalog-age", recipe)
    if damage in {"no_event", "no_definition"}:
        assert result["attempt_id"] is None
    else:
        assert result["attempt_id"] == run
        assert result["collected_at"] == sealed.isoformat()
    assert result["provider_time"] == (
        "2026-09-16T00:00:00+00:00"
        if damage is None
        else "2026-09-01T00:00:00+00:00"
        if damage == "oldest"
        else None
    )
    assert result["health_basis"] == "sealed_collection_journal"
    assert result["health_time"] == (
        sealed.isoformat() if damage in {None, "empty", "oldest"} else None
    )
    if damage is None:
        assert (
            checked
            and result["basis"] == "record_last_modified"
            and result["precision"] == "date"
        )
    with pytest.raises(ValueError):
        ProviderPolicy(
            replace(
                recipe, scope=replace(scope, source="NVD", input_kind="repository")
            ),
            86400,
        )


def test_monitor_checks_committed_details_and_resolves_repaired_bundle(tmp_path):
    import json
    from datetime import timedelta
    from standalone.evidence_pipeline.collection.catalog_collection import (
        collect,
        catalog_scope,
    )
    from standalone.evidence_pipeline.parsing.catalog_discovery import parse_search
    from standalone.evidence_pipeline.commands import register, ingest_public
    from standalone.evidence_pipeline.parsing.devices import stable_id
    from standalone.evidence_pipeline.collection.public_collection import prepare
    from standalone.evidence_pipeline.runtime import local_database
    from standalone.evidence_pipeline.test_catalog_discovery import payload, ID
    from standalone.evidence_pipeline.test_update_catalog import payload as detail
    from .dispatch import Dispatcher, Definition
    from .scheduling import Interval
    from .supervisor import PostgresRepository
    from .provider_monitor import ProviderMonitor
    from .notifications import load

    identity, run, input_id = (str(uuid4()) for _ in range(3))
    index = payload().replace(ID.encode(), identity.encode())
    wire = detail().replace(ID.encode(), identity.encode())
    entry = parse_search(index, kb="KB9999991").hits[0]
    child = catalog_scope("synthetic", entry.url)
    scope = SourceScope(
        connection_id=input_id,
        source="Microsoft Update Catalog",
        input_kind="catalog_search",
        tenant_id=None,
        scope_reference=search_url("KB9999991"),
        origin="synthetic",
        provenance="TriageMate generated synthetic Catalog monitoring test",
    )
    recipe = RepositoryRecipe(scope, tmp_path, kb="KB9999991")
    key = "synthetic-catalog-age-" + str(uuid4())
    now = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)
    ticks = [0]
    monitor = ProviderMonitor(
        key, [ProviderPolicy(recipe, 172800)], clock=lambda: ticks[0]
    )
    try:
        collect(
            tmp_path / run,
            origin="synthetic",
            execution_id=run,
            kb=recipe.kb,
            synthetic_index=index,
            synthetic_payloads={identity: wire},
        )
        attempt = stable_id("catalog-discovered-attempt", run, child.connection_id)
        register(child)
        ingest_public(
            prepare(child, attempt, tmp_path / run / attempt, replay_only=True)
        )
        state = Dispatcher(
            [Definition(input_id, Interval(3600, now), worker_contract="a" * 64)],
            now=now,
        )
        PostgresRepository(key).commit(0, state)
        proof = CatalogProof(recipe.kb)
        _, digest, _ = proof.saved_index(tmp_path, "synthetic", run)
        event = proof.event(
            SimpleNamespace(input_id=input_id, run_id=run),
            "synthetic",
            "a" * 64,
            digest,
        )
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) VALUES(%s,1,%s,%s::jsonb)",
                (key, now, json.dumps(event)),
            )
        monitor.check(now)
        assert load(key) == []  # Healthy exact committed evidence.
        path = tmp_path / run / "search.html"
        original = path.read_bytes()
        path.write_bytes(b"invalid saved search")
        ticks[0] += 61
        monitor.check(now + timedelta(seconds=61))
        notices = load(key)
        assert len(notices) == 1 and notices[0]["status"] == "unresolved"
        assert "could not be verified" in notices[0]["message"]
        path.write_bytes(original)
        ticks[0] += 61
        monitor.check(now + timedelta(seconds=122))
        resolved = load(key)
        assert len(resolved) == 1 and resolved[0]["status"] == "resolved"
        assert resolved[0]["id"] == notices[0]["id"]
    finally:
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        clear_child(child)


def clear_child(scope):
    from standalone.evidence_pipeline.runtime import local_database
    from standalone.evidence_pipeline.test_commands import cleanup

    with local_database().connect() as conn, conn.cursor() as cursor:
        cursor.execute(
            "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s)",
            (scope.connection_id,),
        )
        cursor.execute(
            "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
            (scope.connection_id,),
        )
    cleanup(scope)
