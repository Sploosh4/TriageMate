"""Exact saved Cisco RSS membership and committed document receipts."""

import hashlib
from pathlib import Path

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.cisco_collection import source_scope
from standalone.evidence_pipeline.collection.cisco_rss_collection import (
    prepare as prepare_index,
)
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.reference_records import normalize_references
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory
from . import index_proof, store


class CiscoProof:
    def saved_index(self, root, origin, run):
        root = Path(root)
        if not root.is_absolute():
            raise ValueError("Cisco bundle root must be absolute")
        _private_directory(root)
        bundle = root / identifier(run)
        value = prepare_index(bundle, run, origin=origin, replay_only=True)
        if not value.complete:
            raise ValueError("Cisco discovery index is incomplete")
        return bundle, hashlib.sha256(value.payload).hexdigest(), value.items

    def imports_committed(self, cursor, bundle, origin, run, files):
        for entry in files:
            scope = source_scope(origin, entry)
            attempt = stable_id("cisco-discovered-attempt", run, scope.connection_id)
            snapshot = prepare(scope, attempt, bundle / attempt, replay_only=True)
            if not snapshot.complete:
                return False
            records = list(normalize_references(snapshot.feed()))
            if len(records) != 1 or records[0].source_record_id != entry.advisory_id:
                return False
            record = records[0]
            revision = stable_id(
                "public-revision",
                scope.connection_id,
                entry.advisory_id,
                record.content_hash,
            )
            receipt = stable_id("public-receipt", revision, attempt)
            cursor.execute(
                "SELECT a.connection_id::text,a.input_fingerprint,o.native_id,rev.content_hash,"
                "r.id::text,c.scope_reference,rev.origin FROM evidence.collection_attempts a "
                "JOIN evidence.source_connections c ON c.id=a.connection_id "
                "JOIN evidence.observation_receipts r ON r.collection_attempt_id=a.id "
                "JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id "
                "JOIN evidence.public_reference_observations o ON o.receipt_id=r.id "
                "WHERE a.id=%s AND a.complete AND a.outcome='success' "
                "AND rev.connection_id=a.connection_id AND c.source_name='Cisco' "
                "AND c.input_kind='advisories' AND c.tenant_id IS NULL",
                (attempt,),
            )
            if cursor.fetchall() != [
                (
                    scope.connection_id,
                    snapshot.input_fingerprint,
                    entry.advisory_id,
                    record.content_hash,
                    receipt,
                    entry.url,
                    origin,
                )
            ]:
                return False
        return True

    def event(self, job, origin, contract, digest):
        return dict(
            kind="cisco_rss",
            input_id=identifier(job.input_id),
            run_id=identifier(job.run_id),
            origin=origin,
            worker_contract=contract,
            index_sha256=digest,
        )

    def saved_event(self, cursor, key, run):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='cisco_rss' AND event->>'run_id'=%s LIMIT 2",
            (store.service_key(key), identifier(run)),
        )
        rows = cursor.fetchall()
        if len(rows) > 1:
            raise ValueError("Ambiguous Cisco RSS declaration")
        return rows[0][0] if rows else None

    def seal(self, key, job, origin, root):
        return index_proof.seal(key, job, origin, root, contract=self)

    def committed(self, cursor, key, job, origin, root, fingerprint):
        return index_proof.committed(
            cursor, key, job, origin, root, fingerprint, contract=self
        )
