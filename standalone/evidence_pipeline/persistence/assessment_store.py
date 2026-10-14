"""Atomic baseline/event receipts and source request checkpoints."""

from dataclasses import asdict
from datetime import timedelta
import json

from standalone.evidence_pipeline.contracts import identifier, utc
from standalone.evidence_pipeline.persistence.exposure_store import receipt
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    stage_attempt,
    ReplayConflict,
)
from standalone.evidence_pipeline.parsing.vulnerability_events import (
    normalize_assessments,
)


def checkpoint(cursor, connection_id):
    cursor.execute(
        "SELECT attempt_id::text,next_since_time,finished_at FROM evidence_pipeline.assessment_checkpoints WHERE connection_id=%s",
        (connection_id,),
    )
    return cursor.fetchone()


def persist_assessments(
    connection, snapshot, device_attempt_id, predecessor=None, since=None
):
    if (
        connection.autocommit
        or snapshot.scope.source != "Defender"
        or snapshot.scope.input_kind
        not in ("vulnerability_baseline", "vulnerability_events")
    ):
        raise ValueError("Assessment requires a scoped transaction")
    events = snapshot.scope.input_kind == "vulnerability_events"
    device_attempt_id = identifier(device_attempt_id)
    if snapshot.complete:
        if events and (predecessor is None or since is None):
            raise ValueError("Delta requires its committed baseline/checkpoint")
        if not events and (predecessor is not None or since is not None):
            raise ValueError("Baseline cannot use a delta checkpoint")
        if predecessor is not None:
            predecessor = identifier(predecessor)
            since = utc(since)
            if (
                not snapshot.started_at - timedelta(days=14)
                <= since
                <= snapshot.started_at
            ):
                raise ValueError("Delta request exceeds available source history")
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        cur.execute(
            "SELECT device_connection_id::text,baseline_connection_id::text FROM evidence_pipeline.assessment_bindings WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        binding = cur.fetchone()
        if binding is None:
            raise ValueError("Assessment requires explicit source registration")
        cur.execute(
            "SELECT connection_id::text,complete,outcome FROM evidence.collection_attempts WHERE id=%s",
            (device_attempt_id,),
        )
        if cur.fetchone() != (binding[0], True, "success"):
            raise ValueError("Assessment requires the bound complete device snapshot")
        cur.execute(
            "SELECT DISTINCT p.native_device_id,p.id::text FROM evidence.provider_devices p JOIN evidence.device_observations o ON o.provider_device_id=p.id JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE p.connection_id=%s AND r.collection_attempt_id=%s",
            (binding[0], device_attempt_id),
        )
        providers = dict(cur.fetchall())
        items = (
            normalize_assessments(snapshot, set(providers)) if snapshot.complete else ()
        )
        replayed = stage_attempt(cur, snapshot)
        if snapshot.complete:
            context = (device_attempt_id, predecessor, since)
            if replayed:
                cur.execute(
                    "SELECT device_attempt_id::text,predecessor_attempt_id::text,since_time FROM evidence_pipeline.assessment_runs WHERE attempt_id=%s",
                    (snapshot.execution_id,),
                )
                if cur.fetchone() != context:
                    raise ReplayConflict("Assessment execution context changed")
            else:
                if events:
                    candidates = [
                        item
                        for key in (snapshot.scope.connection_id, binding[1])
                        if key
                        for item in [checkpoint(cur, key)]
                        if item
                    ]
                    latest = max(
                        candidates, key=lambda item: (item[2], item[0]), default=None
                    )
                    if latest is None or (latest[0], latest[1]) != (predecessor, since):
                        raise ReplayConflict(
                            "Assessment checkpoint changed; replan collection"
                        )
                # Request coverage is intentionally overlapped by a full provider
                # generation period. This is not a source-event timestamp claim.
                next_since = snapshot.started_at - timedelta(hours=6)
                if since is not None:
                    next_since = max(since, next_since)
                cur.execute(
                    "INSERT INTO evidence_pipeline.assessment_runs VALUES(%s,%s,%s,%s,%s)",
                    (snapshot.execution_id, *context, next_since),
                )
                for item in items:
                    claim = json.loads(json.dumps(asdict(item), default=str))
                    received = receipt(cur, snapshot, item.fingerprint, claim)
                    if item.cve_id is not None:
                        cur.execute(
                            "INSERT INTO evidence.vulnerabilities(cve_id) VALUES(%s) ON CONFLICT DO NOTHING",
                            (item.cve_id,),
                        )
                    cur.execute(
                        "INSERT INTO evidence_pipeline.assessment_observations VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                        (
                            received,
                            providers.get(item.native_device_id),
                            item.cve_id,
                            json.dumps(item.instance_key),
                            item.fingerprint,
                            item.event_kind,
                            item.event_time_raw,
                            item.event_time_utc,
                            json.dumps(claim),
                        ),
                    )
        return {
            "execution_id": snapshot.execution_id,
            "outcome": "success" if snapshot.complete else "failure",
            "records": len(items),
            "replayed": replayed,
        }
