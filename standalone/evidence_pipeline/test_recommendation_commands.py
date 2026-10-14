"""Committed advice survives a new SQL-reader connection; generated rows are removed."""

from dataclasses import replace
import json
from uuid import uuid4

from .commands import register, ingest
from .recommendation_commands import ingest as ingest_recommendations
from .runtime import local_database
from .test_commands import cleanup
from .test_store import snapshot  # noqa: F401


def test_committed_recommendation_is_queryable(snapshot):  # noqa: F811
    device = replace(
        snapshot,
        scope=replace(snapshot.scope, source="Defender"),
        payload=b'[{"id":"synthetic-advice-device"}]',
    )
    source = replace(
        device,
        scope=replace(
            device.scope, connection_id=str(uuid4()), input_kind="recommendations"
        ),
        execution_id=str(uuid4()),
        payload=b'[{"id":"synthetic-advice","recommendationName":"Synthetic configuration advice","remediationType":"ConfigurationChange"}]',
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        register(device.scope)
        ingest(device)
        assert register(source.scope, device.scope.connection_id)
        assert not register(source.scope, device.scope.connection_id)
        links = b'{"synthetic-advice":["synthetic-advice-device"]}'
        assert (
            ingest_recommendations(source, device.execution_id, links)["records"] == 1
        )
        assert ingest_recommendations(source, device.execution_id, links)["replayed"]
        data = json.loads(
            PostgreSQLQueries().execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT r.title,r.origin,p.native_device_id FROM evidence_pipeline.current_defender_recommendations r JOIN evidence.recommendation_devices d ON d.recommendation_id=r.id JOIN evidence.provider_devices p ON p.id=d.provider_device_id WHERE r.connection_id='"
                    + source.scope.connection_id
                    + "'::uuid",
                }
            )
        )
        assert data["rows"] == [
            ["Synthetic configuration advice", "synthetic", "synthetic-advice-device"]
        ]
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            for table in (
                "evidence.recommendation_devices",
                "evidence.recommendations",
                "evidence_pipeline.recommendation_claims",
            ):
                # Fixed table identifiers; only this test's source is cleaned up.
                cur.execute(
                    f"DELETE FROM {table} t USING evidence.observation_receipts r,evidence.collection_attempts a WHERE t.receipt_id=r.id AND r.collection_attempt_id=a.id AND a.connection_id=%s",
                    (source.scope.connection_id,),
                )
            cur.execute(
                "DELETE FROM evidence_pipeline.recommendation_runs r USING evidence.collection_attempts a WHERE r.attempt_id=a.id AND a.connection_id=%s",
                (source.scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.recommendation_bindings WHERE connection_id=%s",
                (source.scope.connection_id,),
            )
        cleanup(source.scope)
        cleanup(device.scope)
