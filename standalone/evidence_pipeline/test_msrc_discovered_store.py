"""Discovered synthetic months through the real writer/reader, always rolled back."""

from backend.database import schema as database_schema

import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection import (
    msrc_discovered_collection as collector,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_updates import document
from .test_msrc_publications import entry, CONTEXT
from .test_store import db as db


def test_discovered_months_persist_replay_and_preserve_last_success(
    db, tmp_path, monkeypatch
):
    from standalone.evidence_pipeline.collection import (
        public_collection,
        msrc_index_collection,
    )

    def no_network(*args, **kwargs):
        pytest.fail("Synthetic discovery attempted network")

    monkeypatch.setattr(public_collection, "download", no_network)
    monkeypatch.setattr(msrc_index_collection, "_download_url", no_network)
    with db.cursor() as cur:
        database_schema.verify(cur)
    registered = set()
    snapshots = []

    def transactional_import(snapshot):
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
            if snapshot.scope.connection_id not in registered:
                authorize_connection(cur, snapshot)
                registered.add(snapshot.scope.connection_id)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        snapshots.append(snapshot)
        return persist_public(db, snapshot)

    # Only redirect transaction ownership; real parsing, SQL and authority remain.
    monkeypatch.setattr(collector, "register", lambda scope: None)
    monkeypatch.setattr(collector, "ingest_public", transactional_import)
    index = json.dumps(
        {"@odata.context": CONTEXT, "value": [entry("2099-Mar")]}
    ).encode()
    args = dict(
        origin="synthetic",
        execution_id=str(uuid4()),
        starting_month="2099-Mar",
        retained_ids=frozenset(),
        synthetic_index=index,
        import_records=True,
        synthetic_payloads={"2099-Mar": json.dumps(document()).encode()},
    )
    root = tmp_path / args["execution_id"]
    first = collector.collect(root, **args)
    assert first["outcomes"][0]["database_imported"] is True
    assert first["outcomes"][0]["replayed"] is False
    replay = collector.collect(root, **args, replay_only=True)
    assert replay["outcomes"][0]["replayed"] is True
    assert snapshots[0] == snapshots[1]
    original = snapshots[0]
    from standalone.operations.msrc_proof import MsrcProof

    proof = MsrcProof("2099-Mar", frozenset())
    bundle, digest, entries = proof.saved_index(
        tmp_path, "synthetic", args["execution_id"]
    )
    assert len(digest) == 64
    with db.cursor() as cur:
        assert proof.imports_committed(
            cur, bundle, "synthetic", args["execution_id"], entries
        )
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SAVEPOINT proof_damage")
        cur.execute(
            "UPDATE evidence.collection_attempts SET input_fingerprint=%s WHERE id=%s",
            ("0" * 64, original.execution_id),
        )
        _, _, entries = proof.saved_index(tmp_path, "synthetic", args["execution_id"])
        assert not proof.imports_committed(
            cur, bundle, "synthetic", args["execution_id"], entries
        )
        cur.execute("ROLLBACK TO SAVEPOINT proof_damage")
    with pytest.raises(ValueError, match="policy differs"):
        MsrcProof(None, frozenset()).saved_index(
            tmp_path, "synthetic", args["execution_id"]
        )

    def visible():
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
            cur.execute(
                "SELECT source_product_id,source_patch_id FROM evidence_pipeline.current_msrc_patch_fixes "
                "WHERE connection_id=%s ORDER BY source_product_id,source_patch_id",
                (original.scope.connection_id,),
            )
            fixes = cur.fetchall()
            cur.execute(
                "SELECT domain,populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) "
                "ORDER BY domain",
                ([original.scope.connection_id],),
            )
            return fixes, cur.fetchall()

    expected = visible()
    assert expected[0] == [("p1", "KB9999991")]
    assert expected[1] and any(row[1] > 0 for row in expected[1])
    failed = collector.collect(
        tmp_path / "failed",
        **{
            **args,
            "execution_id": str(uuid4()),
            "synthetic_payloads": {"2099-Mar": b"{}"},
        },
    )
    assert failed["outcomes"][0]["database_imported"] is False
    assert visible() == expected
    recovered = collector.collect(
        tmp_path / "recovered",
        **{
            **args,
            "execution_id": str(uuid4()),
        },
    )
    assert recovered["outcomes"][0]["database_imported"] is True
    assert visible() == expected
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "SELECT outcome,complete,input_fingerprint FROM evidence.collection_attempts "
            "WHERE id=%s",
            (snapshots[-1].execution_id,),
        )
        assert cur.fetchone() == ("success", True, snapshots[-1].input_fingerprint)
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=%s",
            (original.scope.connection_id,),
        )
        assert cur.fetchone() == (
            3,
        )  # successful run, failed run, recovered run; replay adds none


@pytest.mark.parametrize("native_id", ["2018-FEB", "2017-May-B"])
def test_native_publication_spelling_survives_writer_and_reader(
    db, tmp_path, monkeypatch, native_id
):
    from standalone.evidence_pipeline.collection import (
        public_collection,
        msrc_index_collection,
    )

    from standalone.operations.msrc_proof import MsrcProof

    def forbidden(*args, **kwargs):
        pytest.fail("Synthetic native-ID test attempted network")

    monkeypatch.setattr(public_collection, "download", forbidden)
    monkeypatch.setattr(msrc_index_collection, "_download_url", forbidden)
    with db.cursor() as cur:
        database_schema.verify(cur)
    captured = []

    def import_transaction(snapshot):
        with db.cursor() as cur:
            authorize_connection(cur, snapshot)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        captured.append(snapshot)
        return persist_public(db, snapshot)

    monkeypatch.setattr(collector, "register", lambda scope: None)
    monkeypatch.setattr(collector, "ingest_public", import_transaction)
    run = str(uuid4())
    result = collector.collect(
        tmp_path / run,
        origin="synthetic",
        execution_id=run,
        starting_month=None,
        retained_ids=frozenset(),
        import_records=True,
        synthetic_index=json.dumps(
            {"@odata.context": CONTEXT, "value": [entry(native_id)]}
        ).encode(),
        synthetic_payloads={native_id: json.dumps(document()).encode()},
    )
    assert result["outcomes"][0]["database_imported"]
    proof = MsrcProof(None, frozenset())
    bundle, _, items = proof.saved_index(tmp_path, "synthetic", run)
    with db.cursor() as cur:
        assert proof.imports_committed(cur, bundle, "synthetic", run, items)
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT scope_reference FROM evidence.source_connections WHERE id=%s",
            (captured[0].scope.connection_id,),
        )
        assert cur.fetchone() == (
            "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + native_id,
        )
