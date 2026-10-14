"""Committed synthetic classification round trip; scoped records removed afterward."""

from uuid import uuid4
import json

from .commands import register, ingest
from .runtime import local_database
from .test_commands import cleanup
from .test_store import snapshot as snapshot_fixture
from .test_attribution import verify

snapshot = snapshot_fixture


def test_actual_api_writer_and_reader_preserve_source(snapshot):
    from app.services.classification_api import ClassificationAPI
    from app.services.postgres_query import PostgreSQLQueries

    try:
        register(snapshot.scope)
        ingest(snapshot)
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id::text FROM evidence.provider_devices WHERE connection_id=%s",
                (snapshot.scope.connection_id,),
            )
            device = cur.fetchone()[0]
        body = dict(
            decisionId=str(uuid4()),
            deviceId=device,
            selectedType="Workstation",
            reason="Explicit synthetic local operator acceptance check",
            expectedPrevious=None,
        )
        api = ClassificationAPI()
        assert api.save(body) == {"decisionId": body["decisionId"]}
        assert api.save(body) == {"decisionId": body["decisionId"]}
        result = json.loads(api.read(PostgreSQLQueries()))
        record = next(row for row in result["rows"] if row[0] == device)
        assert (
            record[7] is None
            and record[10] == "Workstation"
            and record[12] == "local operator"
        )
        with local_database().connect() as conn, conn.cursor() as cur:
            verify(cur)
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence.classification_decisions WHERE provider_device_id IN (SELECT id FROM evidence.provider_devices WHERE connection_id=%s)",
                (snapshot.scope.connection_id,),
            )
        cleanup(snapshot.scope)
