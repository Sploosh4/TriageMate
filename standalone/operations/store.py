"""Atomic PostgreSQL checkpoints; the caller commits before starting any worker."""

import json

from psycopg2.extras import execute_values

from .checkpoint import decode, encode, wire


class CheckpointConflict(ValueError):
    pass


def service_key(value):
    if not isinstance(value, str) or not value or len(value) > 128 or "\x00" in value:
        raise ValueError("Invalid operational service identity")
    return value


def load(cursor, key):
    cursor.execute(
        "SELECT revision,document FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
        (service_key(key),),
    )
    row = cursor.fetchone()
    return None if row is None else (row[0], decode(row[1]))


def save(
    cursor,
    key,
    expected_revision,
    dispatcher,
    *,
    notices=(),
    repository_sources=None,
    enrichment_sources=None,
):
    key = service_key(key)
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Invalid expected checkpoint revision")
    document = encode(dispatcher)
    decode(document)  # Refuse inconsistent in-memory state before any write.
    payload = json.dumps(document, separators=(",", ":"), allow_nan=False)
    if len(payload.encode()) > 4_000_000:
        raise ValueError("Operational checkpoint exceeds storage bound")
    previous = (
        load(cursor, key)
        if (repository_sources or enrichment_sources) and expected_revision
        else None
    )
    if notices:
        # Reuse checkpoint validation for notice shape and identity/time invariants.
        from dataclasses import asdict

        records = [wire(asdict(notice)) for notice in notices]
        decode(dict(document, notices=records))
        for record in records:
            source = (repository_sources or {}).get(record.get("input_id"))
            if source is not None:
                from .repository_recipe import source_reference

                source_reference(source)
                record["repository_scope"] = source
            source = (enrichment_sources or {}).get(record.get("input_id"))
            if source is not None:
                from standalone.evidence_pipeline.persistence.enrichment_store import (
                    SOURCES,
                )

                if (
                    not isinstance(source, dict)
                    or set(source) != {"source", "origin"}
                    or source["source"] not in SOURCES
                    or source["origin"] not in {"synthetic", "public"}
                    or "repository_scope" in record
                ):
                    raise ValueError("Invalid enrichment notification source")
                record["enrichment_scope"] = source
    if expected_revision == 0:
        cursor.execute(
            """INSERT INTO evidence_pipeline.operation_checkpoints(service_key,revision,saved_at,document)
          VALUES(%s,1,%s,%s::jsonb) ON CONFLICT DO NOTHING RETURNING revision""",
            (key, dispatcher.clock, payload),
        )
    else:
        cursor.execute(
            """UPDATE evidence_pipeline.operation_checkpoints SET revision=revision+1,saved_at=%s,document=%s::jsonb
          WHERE service_key=%s AND revision=%s RETURNING revision""",
            (dispatcher.clock, payload, key, expected_revision),
        )
    result = cursor.fetchone()
    if result is None:
        raise CheckpointConflict(
            "Operational state changed; no worker may start from this decision"
        )
    if repository_sources or enrichment_sources:
        from .repository_failures import record as record_failures

        if repository_sources:
            record_failures(
                cursor,
                key,
                result[0],
                previous[1] if previous else None,
                dispatcher,
                repository_sources,
            )
        if enrichment_sources:
            record_failures(
                cursor,
                key,
                result[0],
                previous[1] if previous else None,
                dispatcher,
                enrichment_sources,
                enrichment=True,
            )
    if notices:
        execute_values(
            cursor,
            """INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event)
          VALUES %s""",
            [
                (key, result[0], dispatcher.clock, json.dumps(record))
                for record in records
            ],
            template="(%s,%s,%s,%s::jsonb)",
        )
    return result[0]
