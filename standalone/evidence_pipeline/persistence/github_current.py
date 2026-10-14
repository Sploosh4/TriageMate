"""Publish immutable repository membership only after verified complete imports."""

import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.github_completion import inspect_run
from standalone.evidence_pipeline.parsing.github_discovery import current_commit, decode
from standalone.evidence_pipeline.collection.github_discovery_collection import prepare


def publish(cursor, bundle, *, origin, execution_id):
    """Use the caller's transaction; replay never changes reference observation time.

    Schema installation is an explicit operator operation. Incomplete runs return
    False without changing the last usable snapshot. Invalid saved evidence raises.
    """
    execution_id = identifier(execution_id)
    bundle = Path(bundle)
    reference = prepare(
        "ref", "heads/main", bundle / "head", origin=origin, replay_only=True
    )
    if not reference.complete:
        return False
    commit = current_commit(reference.payload)
    completion = inspect_run(
        commit, bundle / "scan", origin=origin, execution_id=execution_id, cursor=cursor
    )
    if not completion["collection_complete"] or not completion["database_complete"]:
        return False
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
        "INSERT INTO evidence_pipeline.github_repository_snapshots "
        "(run_id,origin,repository_commit,reference_observed_at,reference_payload,members) "
        "VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb) ON CONFLICT(run_id) DO NOTHING",
        (
            execution_id,
            origin,
            commit,
            reference.finished_at,
            json.dumps(payload),
            json.dumps(members),
        ),
    )
    cursor.execute(
        "SELECT origin,repository_commit,reference_observed_at,reference_payload,members "
        "FROM evidence_pipeline.github_repository_snapshots WHERE run_id=%s",
        (execution_id,),
    )
    if cursor.fetchone() != expected:
        raise ValueError("GitHub snapshot replay changed immutable run membership")
    return True
