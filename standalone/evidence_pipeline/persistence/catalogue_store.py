"""Append complete catalogue revisions and failed attempts under restricted authority."""

import json

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.persistence.exposure_store import receipt
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    stage_attempt,
    require_lab_schema,
    require_input_migration,
)
from standalone.evidence_pipeline.parsing.vulnerability_catalogue import (
    normalize_catalogue,
)


def persist_catalogue(connection, snapshot):
    if not isinstance(snapshot, Snapshot) or connection.autocommit:
        raise ValueError("Catalogue requires a snapshot and explicit transaction")
    if (snapshot.scope.source, snapshot.scope.input_kind) != (
        "Defender",
        "vulnerability_catalogue",
    ):
        raise ValueError("Invalid catalogue source")
    records = normalize_catalogue(snapshot) if snapshot.complete else ()
    with connection.cursor() as cursor, atomic(cursor):
        require_lab_schema(cursor, snapshot.scope)
        require_input_migration(cursor, "catalogue")
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        replayed = stage_attempt(cursor, snapshot)
        if not replayed:
            for item in records:
                # Decimal claims use exact decimal text in JSON; the query view
                # exposes numeric casts without a binary-float round trip.
                claim = json.loads(json.dumps(item.observation(), default=str))
                received = receipt(
                    cursor,
                    snapshot,
                    json.dumps(["catalogue", item.cve_id], separators=(",", ":")),
                    claim,
                )
                cursor.execute(
                    "INSERT INTO evidence.vulnerabilities(cve_id) VALUES(%s) ON CONFLICT DO NOTHING",
                    (item.cve_id,),
                )
                cursor.execute(
                    "INSERT INTO evidence_pipeline.catalogue_observations VALUES(%s,%s,%s::jsonb)",
                    (received, item.cve_id, json.dumps(claim)),
                )
        return {
            "execution_id": snapshot.execution_id,
            "outcome": "success" if snapshot.complete else "failure",
            "records": len(records),
            "replayed": replayed,
        }
