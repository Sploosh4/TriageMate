"""Committed synthetic OSV imports are readable through the actual UI query path."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from psycopg2 import sql

from .commands import register, ingest_public
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from .runtime import local_database
from .test_commands import cleanup
from .test_osv import document, scope
from .test_attribution import verify


def clear(source, aliases):
    with local_database().connect() as conn, conn.cursor() as cur:
        for table in (
            "osv_affected_packages",
            "osv_aliases",
            "osv_advisory_observations",
        ):
            cur.execute(
                sql.SQL(
                    "DELETE FROM evidence.{} WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)"
                ).format(sql.Identifier(table)),
                (source.connection_id,),
            )
        cur.execute(
            "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
            (source.connection_id,),
        )
        for cve in aliases:
            cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
    cleanup(source)


@pytest.mark.parametrize("has_aliases", [False, True])
@pytest.mark.parametrize(
    "audit_full_baseline", [False, pytest.param(True, marks=pytest.mark.full_baseline)]
)
def test_committed_native_advisory_and_ui_reader(has_aliases, audit_full_baseline):
    source = scope()
    raw = document()
    raw["id"] = "x_synthetic-" + str(uuid4())
    raw["aliases"] = (
        [("CVE-2099-" + str(uuid4().int))[:28] for _ in range(2)] if has_aliases else []
    )
    now = datetime.now(timezone.utc)
    value = PublicSnapshot(
        source, str(uuid4()), now, now, "success", True, json.dumps(raw).encode()
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(source)
        assert not register(source)
        assert not ingest_public(value)["replayed"]
        assert ingest_public(value)["replayed"]
        query = PostgreSQLQueries()
        statement = (
            "SELECT advisory_id,withdrawn_text FROM evidence_pipeline.current_osv_advisories WHERE connection_id='"
            + source.connection_id
            + "'::uuid"
        )

        def read():
            return json.loads(
                query.execute({"requestId": str(uuid4()), "sql": statement})
            )["rows"]

        assert read() == [[raw["id"], None]]
        failure = replace(
            value,
            execution_id=str(uuid4()),
            finished_at=now + timedelta(seconds=1),
            outcome="failure",
            complete=False,
            payload=b"",
            error_code="public_transport_failed",
        )
        assert ingest_public(failure)["outcome"] == "failure"
        assert read() == [[raw["id"], None]]
        raw["withdrawn"] = "2026-09-14T02:00:00Z"
        withdrawn = replace(
            value,
            execution_id=str(uuid4()),
            finished_at=now + timedelta(seconds=2),
            payload=json.dumps(raw).encode(),
        )
        ingest_public(withdrawn)
        assert read() == [[raw["id"], raw["withdrawn"]]]
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT alias_id FROM evidence_pipeline.current_osv_aliases WHERE connection_id=%s ORDER BY alias_index",
                (source.connection_id,),
            )
            assert [row[0] for row in cur.fetchall()] == raw["aliases"]
            if audit_full_baseline:
                verify(cur)
    finally:
        clear(source, raw["aliases"])
