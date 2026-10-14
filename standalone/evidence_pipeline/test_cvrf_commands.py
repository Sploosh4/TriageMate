"""Committed CVRF input reaches the actual SQL reader with complete attribution."""

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

from psycopg2 import sql

from .commands import register, ingest_public
from .runtime import local_database
from .test_commands import cleanup
from .test_cvrf_store import snapshot
from .test_attribution import verify


def clear_updates(scope, cve):
    with local_database().connect() as conn, conn.cursor() as cur:
        for schema, table in [
            ("evidence", "patch_replacements"),
            ("evidence", "patch_applicability"),
            ("evidence", "patch_vulnerabilities"),
            ("evidence", "patches"),
            ("evidence_pipeline", "cvrf_projection"),
            ("evidence_pipeline", "cvrf_batches"),
        ]:
            cur.execute(
                sql.SQL(
                    "DELETE FROM {}.{} WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)"
                ).format(sql.Identifier(schema), sql.Identifier(table)),
                (scope.connection_id,),
            )
        cur.execute(
            "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
            (scope.connection_id,),
        )
        cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
    cleanup(scope)


def test_committed_update_import_replay_current_state_and_ui_reader():
    value = snapshot()
    cve = ("CVE-2099-" + str(uuid4().int))[:28]
    value = replace(
        value, payload=value.payload.replace(b"CVE-2026-12345", cve.encode())
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(value.scope)
        assert not register(value.scope)
        assert not ingest_public(value)["replayed"]
        assert ingest_public(value)["replayed"]
        query = PostgreSQLQueries()
        statement = (
            "SELECT cve_id,source_patch_id,source_product_id FROM evidence_pipeline.current_msrc_patch_fixes WHERE connection_id='"
            + value.scope.connection_id
            + "'::uuid"
        )
        data = json.loads(query.execute({"requestId": str(uuid4()), "sql": statement}))
        assert data["rows"] == [[cve, "KB9999991", "p1"]]
        failure = replace(
            value,
            execution_id=str(uuid4()),
            finished_at=value.finished_at + timedelta(seconds=1),
            outcome="failure",
            complete=False,
            payload=b"invalid",
            error_code="invalid_public_payload",
        )
        assert ingest_public(failure)["outcome"] == "failure"
        data = json.loads(query.execute({"requestId": str(uuid4()), "sql": statement}))
        assert data["rows"] == [[cve, "KB9999991", "p1"]]
        with local_database().connect() as conn, conn.cursor() as cur:
            verify(cur)
        raw = json.loads(value.payload)
        raw["Vulnerability"] = []
        empty = replace(
            value,
            execution_id=str(uuid4()),
            payload=json.dumps(raw).encode(),
            finished_at=value.finished_at + timedelta(seconds=2),
        )
        ingest_public(empty)
        data = json.loads(query.execute({"requestId": str(uuid4()), "sql": statement}))
        assert data["rows"] == []
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.current_msrc_patch_replacements WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == (0,)
            verify(cur)
    finally:
        clear_updates(value.scope, cve)
