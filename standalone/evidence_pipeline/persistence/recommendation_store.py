"""Atomic Defender advice and explicit device associations."""

import hashlib
import json

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.exposure_store import (
    associations,
    receipt,
)
from standalone.evidence_pipeline.parsing.recommendations import (
    normalize_recommendations,
)
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    insert,
    stage_attempt,
    ReplayConflict,
)


def persist_recommendations(connection, snapshot, device_attempt_id, association_bytes):
    if connection.autocommit or (snapshot.scope.source, snapshot.scope.input_kind) != (
        "Defender",
        "recommendations",
    ):
        raise ValueError("Recommendations require a scoped transaction")
    device_attempt_id = identifier(device_attempt_id)
    if not snapshot.complete and association_bytes is not None:
        raise ValueError("Failed recommendations cannot retain associations")
    links = associations(association_bytes) if snapshot.complete else {}
    digest = (
        hashlib.sha256(association_bytes).hexdigest() if snapshot.complete else None
    )
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        cur.execute(
            "SELECT device_connection_id::text FROM evidence_pipeline.recommendation_bindings WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        binding = cur.fetchone()
        if binding is None:
            raise ValueError("Recommendations require explicit source registration")
        cur.execute(
            "SELECT connection_id::text,complete,outcome FROM evidence.collection_attempts WHERE id=%s",
            (device_attempt_id,),
        )
        if cur.fetchone() != (binding[0], True, "success"):
            raise ValueError(
                "Recommendations require the bound complete device snapshot"
            )
        cur.execute(
            "SELECT DISTINCT p.native_device_id,p.id::text FROM evidence.provider_devices p JOIN evidence.device_observations o ON o.provider_device_id=p.id JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE p.connection_id=%s AND r.collection_attempt_id=%s",
            (binding[0], device_attempt_id),
        )
        providers = dict(cur.fetchall())
        items = (
            normalize_recommendations(snapshot, links, set(providers))
            if snapshot.complete
            else ()
        )
        replayed = stage_attempt(cur, snapshot)
        if snapshot.complete:
            if replayed:
                cur.execute(
                    "SELECT device_attempt_id::text,associations_hash FROM evidence_pipeline.recommendation_runs WHERE attempt_id=%s",
                    (snapshot.execution_id,),
                )
                if cur.fetchone() != (device_attempt_id, digest):
                    raise ReplayConflict("Recommendation execution context changed")
            else:
                cur.execute(
                    "INSERT INTO evidence_pipeline.recommendation_runs VALUES(%s,%s,%s)",
                    (snapshot.execution_id, device_attempt_id, digest),
                )
                for item in items:
                    claim = {
                        "source_id": item.source_id,
                        "fields": item.observation(),
                        "source_counts": dict(item.source_counts),
                        "native_device_ids": list(item.native_device_ids),
                    }
                    received = receipt(cur, snapshot, item.source_id, claim)
                    cur.execute(
                        "INSERT INTO evidence_pipeline.recommendation_claims VALUES(%s,%s::jsonb)",
                        (received, json.dumps(claim)),
                    )
                    key = stable_id("defender-recommendation", received)
                    insert(
                        cur,
                        "recommendations",
                        {
                            "id": key,
                            "source_recommendation_id": item.source_id,
                            "receipt_id": received,
                            **item.observation(),
                        },
                    )
                    for native in item.native_device_ids:
                        if native in item.unbound_native_device_ids:
                            continue
                        insert(
                            cur,
                            "recommendation_devices",
                            {
                                "recommendation_id": key,
                                "provider_device_id": providers[native],
                                "receipt_id": received,
                            },
                        )
        return {
            "execution_id": snapshot.execution_id,
            "outcome": "success" if snapshot.complete else "failure",
            "records": len(items),
            "replayed": replayed,
        }
