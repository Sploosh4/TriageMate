"""Fresh declared enrichment attempts with exact offline completion evidence."""

from contextlib import closing
from pathlib import Path

from standalone.evidence_pipeline.commands import register, ingest_public
from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.enrichment_store import SOURCES
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.parsing.public_inputs import _cve
from standalone.evidence_pipeline.collection.public_pacing import paced
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.collection.public_transport import endpoint
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory


def source_scope(binding, cve):
    cve = _cve(cve)
    kind = SOURCES[binding.source]
    url = endpoint(binding.source, cve, input_kind=kind)
    return SourceScope(
        stable_id(
            "enrichment-refresh-source-v1", binding.source, kind, binding.origin, cve
        ),
        binding.source,
        kind,
        url,
        binding.origin,
        "Explicitly synthetic TriageMate recurring enrichment fixture"
        if binding.origin == "synthetic"
        else "Public recurring CVE enrichment from " + url,
    )


def attempt_id(job, scope):
    return stable_id(
        "enrichment-refresh-attempt-v1", identifier(job.run_id), scope.connection_id
    )


def collect(selection, job, key, root, *, allow_network=False, fixtures=None):
    binding = selection.binding
    if (
        type(allow_network) is not bool
        or binding.origin == "public"
        and (not allow_network or fixtures is not None)
        or binding.origin == "synthetic"
        and (allow_network or not isinstance(fixtures, dict))
    ):
        raise ValueError(
            "Refresh requires explicit public authority or synthetic fixtures"
        )
    if fixtures is not None and (
        len(fixtures) > 100
        or any(
            _cve(cve) != cve or not isinstance(payload, bytes)
            for cve, payload in fixtures.items()
        )
    ):
        raise ValueError("Refresh fixtures require bounded exact CVE wires")
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("Refresh requires an absolute private bundle root")
    _private_directory(root)
    with closing(connect()) as conn, conn, conn.cursor() as cursor:
        binding.active(cursor, key, job)
        cves = selection.saved(cursor, key, job)
    if cves is None:
        raise ValueError("Refresh must be declared before collecting")
    if fixtures is not None and not set(cves) <= set(fixtures):
        raise ValueError("Refresh fixture missing a declared CVE")
    run_root = root / identifier(job.run_id)
    run_root.mkdir(mode=0o700, exist_ok=True)
    _private_directory(run_root)
    for cve in cves:
        scope = source_scope(binding, cve)
        execution = attempt_id(job, scope)
        register(scope)
        with paced(scope.source, origin=scope.origin):
            snapshot = prepare(
                scope,
                execution,
                run_root / execution,
                cve=cve,
                synthetic_payload=None if fixtures is None else fixtures[cve],
            )
            if snapshot.complete:
                with closing(normalize_public(snapshot.feed())) as records:
                    if any(record.source_record_id != cve for record in records):
                        raise ValueError("Refresh response contains an undeclared CVE")
            ingest_public(snapshot)
    return cves


def committed(cursor, selection, job, key, root):
    selection.binding.active(cursor, key, job)
    cves = selection.saved(cursor, key, job)
    if cves is None:
        return False
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("Refresh proof requires an absolute bundle root")
    _private_directory(root)
    for cve in cves:
        scope = source_scope(selection.binding, cve)
        execution = attempt_id(job, scope)
        snapshot = prepare(
            scope, execution, root / job.run_id / execution, cve=cve, replay_only=True
        )
        if not snapshot.complete and snapshot.error_code != "public_not_found":
            return False
        cursor.execute(
            "SELECT a.connection_id::text,a.input_fingerprint,c.scope_reference,auth.origin,"
            "a.started_at,a.finished_at,a.outcome,a.complete,a.error_code "
            "FROM evidence.collection_attempts a "
            "JOIN evidence.source_connections c ON c.id=a.connection_id "
            "JOIN evidence_pipeline.authorized_connections auth ON auth.connection_id=c.id "
            "WHERE a.id=%s AND c.source_name=%s AND c.input_kind=%s AND c.tenant_id IS NULL",
            (execution, scope.source, scope.input_kind),
        )
        if cursor.fetchall() != [
            (
                scope.connection_id,
                snapshot.input_fingerprint,
                scope.scope_reference,
                scope.origin,
                snapshot.started_at,
                snapshot.finished_at,
                snapshot.outcome,
                snapshot.complete,
                snapshot.error_code,
            )
        ]:
            return False
        expected = []
        if snapshot.complete:
            with closing(normalize_public(snapshot.feed())) as records:
                for record in records:
                    if record.source_record_id != cve:
                        return False
                    revision = stable_id(
                        "public-revision", scope.connection_id, cve, record.content_hash
                    )
                    expected.append(
                        (
                            stable_id("public-receipt", revision, execution),
                            revision,
                            record.content_hash,
                            record.claim,
                        )
                    )
        cursor.execute(
            "SELECT r.id::text,v.id::text,v.content_hash,p.claim "
            "FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id "
            "JOIN evidence_pipeline.public_claims p ON p.source_revision_id=v.id "
            "WHERE r.collection_attempt_id=%s AND v.connection_id=%s AND v.origin=%s",
            (execution, scope.connection_id, scope.origin),
        )
        if sorted(cursor.fetchall()) != sorted(expected):
            return False
        cursor.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (execution,),
        )
        if cursor.fetchone() != (len(expected),):
            return False
    return True
