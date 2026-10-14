"""Committed synthetic catalogue import queried through the actual UI reader."""

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

from .commands import register, ingest_catalogue
from .runtime import local_database
from .test_commands import cleanup
from .test_vulnerability_catalogue import snapshot


def test_committed_catalogue_command_and_ui_reader():
    # Unique synthetic CVE avoids touching any pre-existing vulnerability row.
    cve = "CVE-2099-" + str(uuid4().int)[:18]
    source = snapshot([{"id": cve, "cvssV3": 0, "exposedMachines": 0}])
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(source.scope)
        assert not register(source.scope)
        assert ingest_catalogue(source)["records"] == 1
        assert ingest_catalogue(source)["replayed"]
        query = PostgreSQLQueries()

        def read():
            return json.loads(
                query.execute(
                    {
                        "requestId": str(uuid4()),
                        "sql": "SELECT cve_id,source_exposed_machines,origin FROM evidence_pipeline.current_vulnerability_catalogue WHERE connection_id='"
                        + source.scope.connection_id
                        + "'::uuid",
                    }
                )
            )["rows"]

        assert read() == [[cve, 0, "synthetic"]]
        invalid = replace(
            source,
            execution_id=str(uuid4()),
            finished_at=source.finished_at + timedelta(seconds=1),
            payload=b'[{"id":"bad"}]',
        )
        assert ingest_catalogue(invalid)["outcome"] == "failure"
        assert read() == [[cve, 0, "synthetic"]]
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.catalogue_observations o USING evidence.observation_receipts r,evidence.collection_attempts a WHERE o.receipt_id=r.id AND r.collection_attempt_id=a.id AND a.connection_id=%s",
                (source.scope.connection_id,),
            )
        cleanup(source.scope)
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
