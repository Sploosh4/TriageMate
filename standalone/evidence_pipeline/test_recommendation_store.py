"""Synthetic PostgreSQL advice: atomic links, replay and current-state semantics."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.recommendation_store import (
    persist_recommendations,
)
from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
    atomic,
)
from .test_store import db, snapshot  # noqa: F401


def test_recommendation_history_and_integrity(db, snapshot, monkeypatch):  # noqa: F811
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-device"}]',
    )
    source = replace(
        device,
        scope=replace(
            device.scope, connection_id=str(uuid4()), input_kind="recommendations"
        ),
        execution_id=str(uuid4()),
        payload=b'[{"id":"synthetic-advice","recommendationName":"Synthetic advice","remediationType":"ConfigurationChange","exposedMachinesCount":2}]',
    )
    links = b'{"synthetic-advice":["synthetic-device","synthetic-retired"]}'
    with db.cursor() as cur:
        database_schema.verify(cur)
        for item in (device, source):
            authorize_connection(cur, item)
        cur.execute(
            "INSERT INTO evidence_pipeline.recommendation_bindings VALUES(%s,%s)",
            (source.scope.connection_id, device.scope.connection_id),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, device)
    assert (
        persist_recommendations(db, source, device.execution_id, links)["records"] == 1
    )
    assert persist_recommendations(db, source, device.execution_id, links)["replayed"]
    with pytest.raises(ReplayConflict, match="context"):
        persist_recommendations(
            db, source, device.execution_id, b'{"synthetic-advice":[]}'
        )
    with pytest.raises(ValueError, match="Invalid recommendation device identifiers"):
        persist_recommendations(
            db,
            replace(source, execution_id=str(uuid4())),
            device.execution_id,
            b'{"synthetic-advice":[null]}',
        )
    from psycopg2.errors import InsufficientPrivilege

    with db.cursor() as cur:
        cur.execute(
            "SELECT r.id,r.receipt_id FROM evidence.recommendations r JOIN evidence.observation_receipts o ON o.id=r.receipt_id WHERE o.collection_attempt_id=%s",
            (source.execution_id,),
        )
        recommendation_id, received = cur.fetchone()
        with pytest.raises(InsufficientPrivilege), atomic(cur):
            cur.execute(
                "INSERT INTO evidence.recommendations(id,source_recommendation_id,title,receipt_id) VALUES(%s,'synthetic-advice','invented title',%s)",
                (str(uuid4()), received),
            )
        with pytest.raises(InsufficientPrivilege), atomic(cur):
            cur.execute(
                "UPDATE evidence.recommendations SET title='changed' WHERE id=%s",
                (recommendation_id,),
            )
    from psycopg2.errors import RaiseException
    from standalone.evidence_pipeline.persistence import recommendation_store

    original_insert = recommendation_store.insert
    for fault in ("missing_link", "changed_vendor"):

        def faulty_insert(cursor, table, values):
            if fault == "missing_link" and table == "recommendation_devices":
                return
            if fault == "changed_vendor" and table == "recommendations":
                values = {**values, "vendor": "invented vendor"}
            return original_insert(cursor, table, values)

        with monkeypatch.context() as patch:
            patch.setattr(recommendation_store, "insert", faulty_insert)
            with pytest.raises(RaiseException, match="Defender recommendation"):
                persist_recommendations(
                    db,
                    replace(source, execution_id=str(uuid4())),
                    device.execution_id,
                    links,
                )
    failed = replace(
        source,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="synthetic_failure",
        finished_at=source.finished_at + timedelta(hours=1),
    )
    persist_recommendations(db, failed, device.execution_id, None)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT remediation_type,claim->'source_counts'->>'exposedMachinesCount' FROM evidence_pipeline.current_defender_recommendations WHERE connection_id=%s",
            (source.scope.connection_id,),
        )
        assert cur.fetchall() == [("ConfigurationChange", "2")]
        cur.execute(
            "SELECT count(*) FROM evidence.recommendation_devices d JOIN evidence.recommendations r ON r.id=d.recommendation_id JOIN evidence.observation_receipts o ON o.id=r.receipt_id WHERE o.collection_attempt_id=%s",
            (source.execution_id,),
        )
        assert cur.fetchone() == (1,)
        cur.execute(
            "SELECT source_native_device_id,link_state,provider_device_id IS NULL FROM evidence_pipeline.recommendation_device_references WHERE collection_attempt_id=%s ORDER BY source_native_device_id",
            (source.execution_id,),
        )
        assert cur.fetchall() == [
            ("synthetic-device", "bound", False),
            ("synthetic-retired", "unbound", True),
        ]
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    empty = replace(
        source,
        execution_id=str(uuid4()),
        payload=b"[]",
        finished_at=source.finished_at + timedelta(hours=2),
    )
    persist_recommendations(db, empty, device.execution_id, b"{}")
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_defender_recommendations WHERE connection_id=%s",
            (source.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.recommendations r JOIN evidence.observation_receipts o ON o.id=r.receipt_id WHERE o.collection_attempt_id=%s",
            (source.execution_id,),
        )
        assert cur.fetchone() == (1,)

    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "recommendation_baseline_verify",
            Path(__file__).resolve().parents[2] / "ui-engine/postgres/epss/baseline.py",
        )
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        verifier.verify(cur)
