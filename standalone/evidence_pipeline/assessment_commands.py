"""Explicit source registration and committing assessment imports."""

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from standalone.evidence_pipeline.persistence.assessment_store import (
    persist_assessments,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .contracts import Snapshot, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from .runtime import local_database, connect
from standalone.evidence_pipeline.persistence.store import (
    source_connection,
    ReplayConflict,
)
from backend.database.schema import verify as verify_schema


def register(scope, device_connection_id, baseline_connection_id=None):
    device_connection_id = identifier(device_connection_id)
    events = scope.input_kind == "vulnerability_events"
    if scope.source != "Defender" or scope.input_kind not in (
        "vulnerability_baseline",
        "vulnerability_events",
    ):
        raise ValueError("Invalid assessment source")
    if events != (baseline_connection_id is not None):
        raise ValueError("Only delta inputs require a baseline source binding")
    if baseline_connection_id is not None:
        baseline_connection_id = identifier(baseline_connection_id)
    now = datetime.now(timezone.utc)
    snapshot = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
    with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
        verify_schema(cur)
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        tenant = stable_id("tenant", scope.origin, scope.tenant_id)
        cur.execute(
            "SELECT c.source_name,c.input_kind,c.tenant_id::text,a.origin FROM evidence.source_connections c JOIN evidence_pipeline.authorized_connections a ON a.connection_id=c.id WHERE c.id=%s",
            (device_connection_id,),
        )
        if cur.fetchone() != ("Defender", "devices", tenant, scope.origin):
            raise ValueError(
                "Assessment requires a registered same-tenant/origin Defender device source"
            )
        if events:
            cur.execute(
                "SELECT c.source_name,c.input_kind,c.tenant_id::text,b.device_connection_id::text,a.origin FROM evidence.source_connections c JOIN evidence_pipeline.assessment_bindings b ON b.connection_id=c.id JOIN evidence_pipeline.authorized_connections a ON a.connection_id=c.id WHERE c.id=%s",
                (baseline_connection_id,),
            )
            if cur.fetchone() != (
                "Defender",
                "vulnerability_baseline",
                tenant,
                device_connection_id,
                scope.origin,
            ):
                raise ValueError(
                    "Delta requires a baseline bound to the same device source"
                )
        cur.execute(
            "SELECT device_connection_id::text,baseline_connection_id::text FROM evidence_pipeline.assessment_bindings WHERE connection_id=%s",
            (scope.connection_id,),
        )
        existing = cur.fetchone()
        if existing is not None:
            source_connection(cur, snapshot)
            if existing != (device_connection_id, baseline_connection_id):
                raise ReplayConflict("Assessment registration changed")
            return False
        authorize_connection(cur, snapshot)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,%s)",
            (scope.connection_id, device_connection_id, baseline_connection_id),
        )
        return True


def ingest(snapshot, device_attempt_id, predecessor=None, since=None):
    with closing(connect()) as conn, conn:
        try:
            result = persist_assessments(
                conn, snapshot, device_attempt_id, predecessor, since
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
                error_code="invalid_assessment_input",
            )
            result = persist_assessments(conn, failed, device_attempt_id)
    from .enrichment_commands import after_findings_commit

    return after_findings_commit(snapshot, result)
