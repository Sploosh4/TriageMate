"""Native advisory SQL integration uses synthetic data and rolled-back DDL."""

from backend.database import schema as database_schema

from dataclasses import replace
import json

from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_store import prepare
from .test_store import db  # noqa: F401


def advisory(connection):
    value = prepare(connection)
    with connection.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")

        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    raw = json.loads(value.payload)
    raw["Vulnerability"][0]["CVE"] = "ADV160001"
    return replace(value, payload=json.dumps(raw).encode())


def test_native_advisory_sql_preserves_patches_without_cve_identity(db):  # noqa: F811
    value = advisory(db)
    assert persist_public(db, value)["outcome"] == "success"
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id='ADV160001'"
        )
        assert cur.fetchone() == (0,)
        from standalone.evidence_pipeline.persistence.cvrf_attribution import (
            verify_update_receipt,
        )

        cur.execute(
            "SELECT to_jsonb(s),to_jsonb(v),to_jsonb(r),p.claim "
            "FROM evidence.observation_receipts r JOIN evidence.source_revisions v "
            "ON v.id=r.source_revision_id JOIN evidence.source_connections s "
            "ON s.id=v.connection_id JOIN evidence_pipeline.public_claims p "
            "ON p.source_revision_id=v.id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        source, revision, receipt, claim = cur.fetchone()
        verified = verify_update_receipt(cur, source, revision, receipt, claim)
        assert not verified["patch_vulnerabilities"]
        assert len(verified["patch_replacements"]) == 1
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT native_id FROM evidence_pipeline.current_msrc_advisory_claims WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("ADV160001",)]
        cur.execute(
            "SELECT source_patch_id FROM evidence_pipeline.current_msrc_advisory_patch_fixes WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("KB9999991",)]
        cur.execute(
            "SELECT native_id,source_patch_id,superseded_kb FROM evidence_pipeline.current_msrc_advisory_patch_replacements WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("ADV160001", "KB9999991", "KB9999990")]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_msrc_update_claims WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT domain FROM evidence_pipeline.current_native_advisory_facts WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("vendor-advisory",)]
        cur.execute(
            "SELECT count(*),count(*) FILTER(WHERE populated),count(*) FILTER(WHERE applicability='applicable') "
            "FROM evidence_pipeline.current_native_advisory_completeness_cells WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (5, 3, 5)


def test_native_advisory_changed_claim_identity_rolls_back(db, monkeypatch):  # noqa: F811
    import psycopg2
    import pytest
    from standalone.evidence_pipeline.persistence import public_store
    from .text_bytes import utf8_sha256

    value = advisory(db)
    original = public_store.normalize_public

    def changed(feed):
        for record in original(feed):
            document = json.loads(record.claim)
            document["record"]["native_id"] = "ADV160002"
            claim = json.dumps(document, sort_keys=True, separators=(",", ":"))
            yield replace(record, claim=claim, content_hash=utf8_sha256(claim))

    monkeypatch.setattr(public_store, "normalize_public", changed)
    with pytest.raises(psycopg2.Error, match="Invalid CVRF source claim"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_versioned_advisory_upgrade_is_idempotent_and_checks_authority(db):  # noqa: F811
    import pytest

    with db.cursor() as cur:
        cur.execute(
            "SELECT version, artifacts ? 'schema.sql' FROM evidence_pipeline.installation WHERE singleton"
        )
        previous, installed = cur.fetchone()
        assert installed, "The consolidated baseline artifact must be registered"
        database_schema.verify(cur)
        if installed:
            cur.execute(
                "SELECT version FROM evidence_pipeline.installation WHERE singleton"
            )
            assert cur.fetchone() == (previous,)

        database_schema.verify(cur)
        cur.execute(
            "REVOKE SELECT ON evidence_pipeline.current_msrc_advisory_claims FROM tm_mock_reader"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_registration_path_accepts_current_additive_installation():
    from .commands import register
    from .test_cvrf_updates import source
    from .test_commands import cleanup

    scope = source()
    try:
        assert register(scope)
        assert not register(scope)
    finally:
        cleanup(scope)
