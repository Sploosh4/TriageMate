"""Shared active-job fence for exact saved discovery membership proofs."""

from contextlib import closing
import json

from standalone.evidence_pipeline.runtime import connect
from . import store


def seal(key, job, origin, root, *, contract):
    """Commit index binding only after exact imports, under the active job fence."""
    key = store.service_key(key)
    bundle, digest, files = contract.saved_index(root, origin, job.run_id)
    with closing(connect()) as conn, conn, conn.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        saved = store.load(cursor, key)
        if saved is None:
            raise ValueError("Discovery index requires persisted dispatch")
        revision, state = saved
        definition = state.definitions.get(job.input_id)
        current = state.inputs.get(job.input_id)
        if (
            definition is None
            or current is None
            or current.active != job
            or job.run_id not in state.control.active
            or job.prerequisite_snapshots
        ):
            raise ValueError("Discovery index requires its exact active job")
        declaration = contract.event(job, origin, definition.worker_contract, digest)
        previous = contract.saved_event(cursor, key, job.run_id)
        if previous is not None and previous != declaration:
            raise ValueError("Discovery index declaration changed")
        if not contract.imports_committed(cursor, bundle, origin, job.run_id, files):
            raise ValueError("Discovery index imports are incomplete")
        if previous is None:
            cursor.execute(
                "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
                "VALUES(%s,%s,%s,%s::jsonb)",
                (key, revision, state.clock, json.dumps(declaration)),
            )


def committed(cursor, key, job, origin, root, fingerprint, *, contract):
    declaration = contract.saved_event(cursor, key, job.run_id)
    if declaration is None:
        return False
    bundle, digest, files = contract.saved_index(root, origin, job.run_id)
    return declaration == contract.event(
        job, origin, fingerprint, digest
    ) and contract.imports_committed(cursor, bundle, origin, job.run_id, files)
