"""Exact Catalog search membership and database receipts for a scheduled KB."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from standalone.evidence_pipeline.parsing.catalog_discovery import search_url
from standalone.evidence_pipeline.collection.catalog_pages import saved_pages
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.reference_records import normalize_references
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from . import index_proof, store


@dataclass(frozen=True)
class CatalogProof:
    kb: str

    def __post_init__(self):
        search_url(self.kb)

    def saved_index(self, root, origin, run):
        if origin not in {"synthetic", "public"}:
            raise ValueError("Invalid Catalog origin")
        root = Path(root)
        if not root.is_absolute():
            raise ValueError("Catalog bundle root must be absolute")
        bundle = root / identifier(run)
        _private_directory(root)
        _private_directory(bundle)
        request = dict(origin=origin, execution_id=run, source_url=search_url(self.kb))
        if json.loads(_read(bundle / "request.json", 16384)) != request:
            raise ValueError("Catalog search belongs to another run or KB")
        payload = _read(bundle / "search.html")
        digest = hashlib.sha256(payload).hexdigest()
        receipt = json.loads(_read(bundle / "receipt.json", 16384))
        collected = receipt.get("collected_at")
        if (
            not isinstance(collected, str)
            or datetime.fromisoformat(collected).utcoffset() is None
        ):
            raise ValueError("Catalog search requires a collection clock")
        if receipt != dict(request, fingerprint=digest, collected_at=collected):
            raise ValueError("Catalog search receipt mismatch")
        result, digest = saved_pages(
            bundle, request=request, kb=self.kb, first_payload=payload
        )
        if not result.complete:
            raise ValueError("Catalog search membership is incomplete")
        return bundle, digest, result.hits

    def imports_committed(self, cursor, bundle, origin, run, files):
        for entry in files:
            scope = catalog_scope(origin, entry.url)
            attempt = stable_id("catalog-discovered-attempt", run, scope.connection_id)
            snapshot = prepare(scope, attempt, bundle / attempt, replay_only=True)
            if not snapshot.complete:
                return False
            records = list(normalize_references(snapshot.feed()))
            if len(records) != 1 or records[0].source_record_id != entry.update_id:
                return False
            record = records[0]
            revision = stable_id(
                "public-revision",
                scope.connection_id,
                entry.update_id,
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
                "AND rev.connection_id=a.connection_id AND c.source_name='Microsoft Update Catalog' "
                "AND c.input_kind='updates' AND c.tenant_id IS NULL",
                (attempt,),
            )
            if cursor.fetchall() != [
                (
                    scope.connection_id,
                    snapshot.input_fingerprint,
                    entry.update_id,
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
            kind="catalog_search",
            input_id=identifier(job.input_id),
            run_id=identifier(job.run_id),
            origin=origin,
            worker_contract=contract,
            index_sha256=digest,
            kb=self.kb,
        )

    def saved_event(self, cursor, key, run):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='catalog_search' AND event->>'run_id'=%s LIMIT 2",
            (store.service_key(key), identifier(run)),
        )
        rows = cursor.fetchall()
        if len(rows) > 1:
            raise ValueError("Ambiguous Catalog search declaration")
        return rows[0][0] if rows else None

    def seal(self, key, job, origin, root):
        return index_proof.seal(key, job, origin, root, contract=self)

    def committed(self, cursor, key, job, origin, root, fingerprint):
        return index_proof.committed(
            cursor, key, job, origin, root, fingerprint, contract=self
        )
