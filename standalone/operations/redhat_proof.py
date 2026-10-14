"""Bind a saved Red Hat index to its scheduled run and committed native receipts."""

import hashlib
import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.redhat_discovery import INDEX_URL, parse_index
from standalone.evidence_pipeline.parsing.reference_records import normalize_references
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)

from . import store


def saved_index(root, origin, run):
    if origin not in {"synthetic", "public"}:
        raise ValueError("Invalid Red Hat proof origin")
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("Red Hat proof requires an absolute bundle root")
    bundle = root / identifier(run)
    _private_directory(root)
    _private_directory(bundle)
    request = dict(origin=origin, execution_id=run, source_url=INDEX_URL)
    if json.loads(_read(bundle / "request.json", 16384)) != request:
        raise ValueError("Saved Red Hat index has another execution binding")
    payload = _read(bundle / "index.txt")
    digest = hashlib.sha256(payload).hexdigest()
    if json.loads(_read(bundle / "receipt.json", 16384)) != dict(
        request, fingerprint=digest
    ):
        raise ValueError("Saved Red Hat index differs from its receipt")
    return bundle, digest, parse_index(payload)


def imports_committed(cursor, bundle, origin, run, files):
    """Check every exact attempt, source fingerprint, native claim and receipt."""
    for start in range(0, len(files), 128):
        expected = {}
        for entry in files[start : start + 128]:
            connection = stable_id("redhat-discovered-source", origin, entry.url)
            attempt = stable_id("redhat-discovered-attempt", run, connection)
            scope = SourceScope(
                connection,
                "Red Hat",
                "advisories",
                entry.url,
                origin,
                "Red Hat Security Data; CC-BY-4.0; https://access.redhat.com/security/data"
                if origin == "public"
                else "TriageMate generated synthetic Red Hat discovery/advisory fixtures",
            )
            snapshot = prepare(
                scope,
                attempt,
                bundle / attempt,
                vendor_path=entry.path,
                replay_only=True,
            )
            if not snapshot.complete:
                return False
            records = list(normalize_references(snapshot.feed()))
            if len(records) != 1 or records[0].source_record_id != entry.advisory_id:
                return False
            record = records[0]
            revision = stable_id(
                "public-revision",
                connection,
                record.source_record_id,
                record.content_hash,
            )
            receipt = stable_id("public-receipt", revision, attempt)
            expected[attempt] = (
                connection,
                snapshot.input_fingerprint,
                entry.advisory_id,
                record.content_hash,
                receipt,
                entry.url,
                origin,
            )
        cursor.execute(
            "SELECT a.id::text,a.connection_id::text,a.input_fingerprint,o.native_id,"
            "rev.content_hash,r.id::text,c.scope_reference,rev.origin "
            "FROM evidence.collection_attempts a "
            "JOIN evidence.source_connections c ON c.id=a.connection_id "
            "JOIN evidence.observation_receipts r ON r.collection_attempt_id=a.id "
            "JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id "
            "JOIN evidence.public_reference_observations o ON o.receipt_id=r.id "
            "WHERE a.id=ANY(%s::uuid[]) AND a.complete AND a.outcome='success' "
            "AND rev.connection_id=a.connection_id AND c.source_name='Red Hat' "
            "AND c.input_kind='advisories' AND c.tenant_id IS NULL",
            (list(expected),),
        )
        rows = cursor.fetchall()
        if (
            len(rows) != len(expected)
            or {row[0]: tuple(row[1:]) for row in rows} != expected
        ):
            return False
    return True


def event(job, origin, contract, digest):
    return dict(
        kind="redhat_index",
        input_id=identifier(job.input_id),
        run_id=identifier(job.run_id),
        origin=origin,
        worker_contract=contract,
        index_sha256=digest,
    )


def saved_event(cursor, key, run):
    cursor.execute(
        "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
        "AND event->>'kind'='redhat_index' AND event->>'run_id'=%s LIMIT 2",
        (store.service_key(key), identifier(run)),
    )
    rows = cursor.fetchall()
    if len(rows) > 1:
        raise ValueError("Ambiguous Red Hat index declaration")
    return rows[0][0] if rows else None


def seal(key, job, origin, root):
    import sys
    from . import index_proof

    return index_proof.seal(key, job, origin, root, contract=sys.modules[__name__])


def committed(cursor, key, job, origin, root, contract):
    import sys
    from . import index_proof

    return index_proof.committed(
        cursor, key, job, origin, root, contract, contract=sys.modules[__name__]
    )
