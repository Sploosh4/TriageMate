"""Publish exact immutable CVE repository membership after complete imports."""

import json
from dataclasses import dataclass
from pathlib import Path
from psycopg2 import sql

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.cve_discovery import current_commit, decode
from standalone.evidence_pipeline.collection.github_completion import inspect_run
from standalone.evidence_pipeline.collection.github_discovery_collection import prepare


@dataclass(frozen=True)
class Publication:
    collection_complete: bool
    database_complete: bool
    published: bool

    def __bool__(self):
        return self.published


def publish(cursor, source, bundle, *, origin, execution_id):
    """Caller owns the transaction; replay retains the saved reference timestamp."""
    if source not in {"CVE", "CISA", "Ubuntu", "WA SOC"}:
        raise ValueError("Unsupported repository publication source")
    table = sql.Identifier(
        "evidence_pipeline",
        "wasoc_repository_snapshots"
        if source == "WA SOC"
        else (
            "ubuntu_repository_snapshots"
            if source == "Ubuntu"
            else "cve_repository_snapshots"
        ),
    )
    execution_id = identifier(execution_id)
    bundle = Path(bundle)
    branch = "heads/develop" if source == "CISA" else "heads/main"
    reference = prepare(
        "ref", branch, bundle / "head", source=source, origin=origin, replay_only=True
    )
    if not reference.complete:
        return Publication(False, False, False)
    if source in {"Ubuntu", "WA SOC"}:
        from standalone.evidence_pipeline.parsing.ubuntu_discovery import (
            current_commit as ubuntu_commit,
        )

        commit = ubuntu_commit(reference.payload)
    else:
        commit = current_commit(source, reference.payload)
    completion = inspect_run(
        commit,
        bundle,
        source=source,
        origin=origin,
        execution_id=execution_id,
        cursor=cursor,
    )
    if not completion["collection_complete"] or not completion["database_complete"]:
        return Publication(
            completion["collection_complete"], completion["database_complete"], False
        )
    members = sorted(
        (
            {"path": row["path"], "receipt_id": row["receipt_id"]}
            for row in completion["outcomes"]
        ),
        key=lambda row: row["path"],
    )
    payload = decode(reference.payload)
    expected = (origin, commit, reference.finished_at, payload, members)
    cursor.execute(
        sql.SQL(
            "INSERT INTO {} "
            "(source_name,run_id,origin,repository_commit,reference_observed_at,reference_payload,members) "
            "VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb) ON CONFLICT(source_name,run_id) DO NOTHING"
        ).format(table),
        (
            source,
            execution_id,
            origin,
            commit,
            reference.finished_at,
            json.dumps(payload),
            json.dumps(members),
        ),
    )
    cursor.execute(
        sql.SQL(
            "SELECT origin,repository_commit,reference_observed_at,reference_payload,members "
            "FROM {} WHERE source_name=%s AND run_id=%s"
        ).format(table),
        (source, execution_id),
    )
    if cursor.fetchone() != expected:
        raise ValueError("CVE snapshot replay changed immutable run membership")
    return Publication(True, True, True)
