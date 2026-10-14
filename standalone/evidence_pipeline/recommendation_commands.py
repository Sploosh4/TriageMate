"""Owner registration and restricted committing recommendation imports."""

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from backend.database.schema import verify as verify_schema
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .contracts import Snapshot, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.recommendation_store import (
    persist_recommendations,
)
from .runtime import local_database, connect
from standalone.evidence_pipeline.persistence.store import (
    source_connection,
    ReplayConflict,
)


def register(scope, device_connection_id):
    device_connection_id = identifier(device_connection_id)
    if (scope.source, scope.input_kind) != ("Defender", "recommendations"):
        raise ValueError("Invalid recommendation source")
    now = datetime.now(timezone.utc)
    snapshot = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
    with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
        verify_schema(cur)
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        cur.execute(
            "SELECT c.source_name,c.input_kind,c.tenant_id::text,a.origin FROM evidence.source_connections c JOIN evidence_pipeline.authorized_connections a ON a.connection_id=c.id WHERE c.id=%s",
            (device_connection_id,),
        )
        if cur.fetchone() != (
            "Defender",
            "devices",
            stable_id("tenant", scope.origin, scope.tenant_id),
            scope.origin,
        ):
            raise ValueError(
                "Recommendations require a same-tenant/origin Defender device source"
            )
        cur.execute(
            "SELECT device_connection_id::text FROM evidence_pipeline.recommendation_bindings WHERE connection_id=%s",
            (scope.connection_id,),
        )
        existing = cur.fetchone()
        if existing is not None:
            source_connection(cur, snapshot)
            if existing != (device_connection_id,):
                raise ReplayConflict("Recommendation registration changed")
            return False
        authorize_connection(cur, snapshot)
        cur.execute(
            "INSERT INTO evidence_pipeline.recommendation_bindings VALUES(%s,%s)",
            (scope.connection_id, device_connection_id),
        )
        return True


def ingest(snapshot, device_attempt_id, association_bytes):
    with closing(connect()) as conn, conn:
        try:
            return persist_recommendations(
                conn, snapshot, device_attempt_id, association_bytes
            )
        except ReplayConflict:
            raise
        except ValueError:
            if not snapshot.complete:
                raise
            failed = replace(
                snapshot,
                outcome="failure",
                complete=False,
                error_code="invalid_recommendation_input",
            )
            return persist_recommendations(conn, failed, device_attempt_id, None)
