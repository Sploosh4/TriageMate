"""Suffixed publisher IDs remain distinct from canonical CVEs through SQL."""

from backend.database import schema as database_schema

from copy import deepcopy
from dataclasses import replace
import json
import pytest
import psycopg2


from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_store import prepare
from .test_store import db  # noqa: F401


def native_snapshot(connection):
    value = prepare(connection)
    with connection.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    raw = json.loads(value.payload)
    canonical = raw["Vulnerability"][0]
    canonical["CVE"] = "CVE-2099-5001"
    native = deepcopy(canonical)
    native["CVE"] += " mariner - do not use this one"
    raw["Vulnerability"].append(native)
    return replace(value, payload=json.dumps(raw).encode())


def test_native_and_canonical_id_are_distinct_without_inferred_join(db):  # noqa: F811
    value = native_snapshot(db)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT native_id FROM evidence_pipeline.current_msrc_advisory_claims WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("CVE-2099-5001 mariner - do not use this one",)]
        cur.execute(
            "SELECT source_record_id,count(p.id) FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id LEFT JOIN evidence.patch_vulnerabilities p ON p.receipt_id=r.id WHERE r.collection_attempt_id=%s GROUP BY source_record_id ORDER BY source_record_id",
            (value.execution_id,),
        )
        assert cur.fetchall() == [
            ("CVE-2099-5001", 1),
            ("CVE-2099-5001 mariner - do not use this one", 0),
        ]
        cur.execute(
            "SELECT to_jsonb(s),to_jsonb(v),to_jsonb(r),p.claim FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id JOIN evidence.source_connections s ON s.id=v.connection_id JOIN evidence_pipeline.public_claims p ON p.source_revision_id=v.id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        rows = cur.fetchall()
        from standalone.evidence_pipeline.persistence.cvrf_attribution import (
            verify_update_receipt,
        )

        for row in rows:
            verify_update_receipt(cur, *row)


def test_native_cve_injection_rejects_complete_attempt(db, monkeypatch):  # noqa: F811
    from standalone.evidence_pipeline.persistence import public_store
    from .text_bytes import utf8_sha256

    value = native_snapshot(db)
    original = public_store.normalize_public

    def poisoned(feed):
        for record in original(feed):
            if record.source_record_id.endswith(" mariner - do not use this one"):
                claim = json.loads(record.claim)
                claim["record"]["cve_id"] = "CVE-2099-5001"
                encoded = json.dumps(claim, sort_keys=True, separators=(",", ":"))
                record = replace(
                    record, claim=encoded, content_hash=utf8_sha256(encoded)
                )
            yield record

    monkeypatch.setattr(public_store, "normalize_public", poisoned)
    with pytest.raises(psycopg2.Error, match="Invalid CVRF source claim"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_upgrade_idempotence_legacy_entrypoint_and_drift(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)

        from .test_exposure_migration import (
            test_original_schema_verifier_accepts_only_recognized_upgrade,
        )

        test_original_schema_verifier_accepts_only_recognized_upgrade(db)
        cur.execute(
            "REVOKE SELECT ON evidence_pipeline.current_msrc_advisory_claims FROM tm_mock_reader"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
