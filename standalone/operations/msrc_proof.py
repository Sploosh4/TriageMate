"""Exact MSRC discovery policy, saved monthly bytes and database receipt proof."""

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.msrc_discovered_collection import (
    source_scope,
)
from standalone.evidence_pipeline.collection.msrc_index_collection import (
    prepare as prepare_index,
)
from standalone.evidence_pipeline.collection.msrc_publication_selection import (
    select_changed,
)
from standalone.evidence_pipeline.collection.osv_query_collection import _read
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory
from . import index_proof, store


@dataclass(frozen=True)
class MsrcProof:
    starting_month: str | None
    retained_ids: frozenset[str]

    def __post_init__(self):
        if not isinstance(self.retained_ids, frozenset):
            raise ValueError("MSRC proof requires immutable retained identities")
        list(
            select_changed(
                (),
                (),
                starting_month=self.starting_month,
                retained_ids=self.retained_ids,
            )
        )

    def saved_index(self, root, origin, run):
        if origin not in {"synthetic", "public"} or not Path(root).is_absolute():
            raise ValueError("Invalid MSRC proof origin or root")
        bundle = Path(root) / identifier(run)
        _private_directory(bundle)
        expected = json.dumps(
            dict(
                origin=origin,
                execution_id=run,
                starting_month=self.starting_month,
                retained_ids=sorted(self.retained_ids),
            ),
            sort_keys=True,
        ).encode()
        if _read(bundle / "selection.json") != expected:
            raise ValueError("MSRC proof policy differs from saved run")
        index = prepare_index(bundle / "index", run, origin=origin, replay_only=True)
        if not index.complete:
            raise ValueError("MSRC proof requires a complete index")
        digest = hashlib.sha256(
            expected + b"\n" + index.payload.fingerprint.encode()
        ).hexdigest()
        return (
            bundle,
            digest,
            select_changed(
                index.items(),
                (),
                starting_month=self.starting_month,
                retained_ids=self.retained_ids,
            ),
        )

    def imports_committed(self, cursor, bundle, origin, run, files):
        with closing(files):
            for item in files:
                scope = source_scope(origin, item)
                attempt = stable_id("msrc-discovered-attempt", run, scope.connection_id)
                snapshot = prepare(
                    scope,
                    attempt,
                    bundle / attempt,
                    month=item.publication_id,
                    replay_only=True,
                )
                if not snapshot.complete:
                    return False
                cursor.execute(
                    "SELECT a.connection_id::text,a.input_fingerprint,c.scope_reference,auth.origin "
                    "FROM evidence.collection_attempts a JOIN evidence.source_connections c ON c.id=a.connection_id "
                    "JOIN evidence_pipeline.authorized_connections auth ON auth.connection_id=c.id "
                    "WHERE a.id=%s AND a.complete AND a.outcome='success' AND c.source_name='MSRC' "
                    "AND c.input_kind='security_updates' AND c.tenant_id IS NULL",
                    (attempt,),
                )
                if cursor.fetchall() != [
                    (scope.connection_id, snapshot.input_fingerprint, item.url, origin)
                ]:
                    return False
                batch, count = [], 0
                with closing(normalize_public(snapshot.feed())) as records:
                    for record in records:
                        revision = stable_id(
                            "public-revision",
                            scope.connection_id,
                            record.source_record_id,
                            record.content_hash,
                        )
                        batch.append(
                            (
                                stable_id("public-receipt", revision, attempt),
                                revision,
                                record.content_hash,
                            )
                        )
                        count += 1
                        if len(batch) == 250:
                            if not self._receipts(
                                cursor, attempt, scope.connection_id, origin, batch
                            ):
                                return False
                            batch = []
                if batch and not self._receipts(
                    cursor, attempt, scope.connection_id, origin, batch
                ):
                    return False
                cursor.execute(
                    "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
                    (attempt,),
                )
                if cursor.fetchone() != (count,):
                    return False
            return True

    @staticmethod
    def _receipts(cursor, attempt, connection, origin, expected):
        cursor.execute(
            "SELECT r.id::text,rev.id::text,rev.content_hash FROM evidence.observation_receipts r "
            "JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id "
            "WHERE r.collection_attempt_id=%s AND rev.connection_id=%s AND rev.origin=%s "
            "AND r.id=ANY(%s::uuid[])",
            (attempt, connection, origin, [row[0] for row in expected]),
        )
        return sorted(cursor.fetchall()) == sorted(expected)

    def event(self, job, origin, contract, digest):
        return dict(
            kind="msrc_index",
            input_id=identifier(job.input_id),
            run_id=identifier(job.run_id),
            origin=origin,
            worker_contract=contract,
            index_sha256=digest,
        )

    def saved_event(self, cursor, key, run):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='msrc_index' AND event->>'run_id'=%s LIMIT 2",
            (store.service_key(key), identifier(run)),
        )
        rows = cursor.fetchall()
        if len(rows) > 1:
            raise ValueError("Ambiguous MSRC discovery declaration")
        return rows[0][0] if rows else None

    def seal(self, key, job, origin, root):
        return index_proof.seal(key, job, origin, root, contract=self)

    def committed(self, cursor, key, job, origin, root, fingerprint):
        return index_proof.committed(
            cursor, key, job, origin, root, fingerprint, contract=self
        )
