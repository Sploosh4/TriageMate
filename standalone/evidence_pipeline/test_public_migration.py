"""Explicit migration verification in rollback-only database transactions."""

from backend.database import schema as database_schema

from backend.database.schema import verify_supported as verify_schema


import pytest


from .test_store import db  # noqa: F401


def test_upgrade_repeat_and_legacy_schema_verification(db):  # noqa: F811
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        verify_schema(cursor)


def test_public_authority_drift_rejected(db):  # noqa: F811
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT DELETE ON evidence_pipeline.public_claims TO tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize("source", ["FIRST", "CISA", "NVD"])
def test_retained_public_data_is_verified_and_tampering_rejected(db, source):  # noqa: F811
    from .test_public_snapshot import attempt
    from .test_public_inputs import scope, wire, kev, nvd
    from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from .test_attribution import verify as verify_data

    value = attempt()
    if source != "FIRST":
        value = PublicSnapshot(
            scope(source),
            value.execution_id,
            value.started_at,
            value.finished_at,
            "success",
            True,
            wire(kev() if source == "CISA" else nvd()).replace(
                b"02:00:00.000", b"02:00:00.123"
            ),
        )
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
    persist_public(db, value)
    with db.cursor() as cursor:
        verify_data(cursor)
        cursor.execute("UPDATE evidence_pipeline.public_claims SET claim=claim || ' ' ")
        with pytest.raises(AssertionError, match="content hash"):
            verify_data(cursor)


def test_public_view_definition_drift_is_rejected(db):  # noqa: F811
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "CREATE OR REPLACE VIEW evidence_pipeline.current_public_kev_observations AS SELECT e.*, c.connection_id,c.source_name,c.input_kind,c.scope_reference,c.selected_attempt_id,c.selected_finished_at,c.latest_outcome,c.latest_finished_at,revision.origin,revision.source_url,revision.licence_or_provenance,revision.content_hash FROM evidence_pipeline.collection_status c JOIN evidence.observation_receipts receipt ON receipt.collection_attempt_id=c.selected_attempt_id JOIN evidence.source_revisions revision ON revision.id=receipt.source_revision_id JOIN evidence_pipeline.public_claims claim ON claim.source_revision_id=revision.id JOIN evidence.kev_observations e ON e.receipt_id=receipt.id WHERE false"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_exact_public_numeric_tampering_is_rejected(db):  # noqa: F811
    from .test_public_snapshot import attempt
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from .test_attribution import verify as verify_data

    value = attempt()
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
    persist_public(db, value)
    with db.cursor() as cursor:
        cursor.execute(
            "UPDATE evidence.epss_observations SET probability=probability + 0.00000000000000000000000000001 WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (value.execution_id,),
        )
        with pytest.raises(AssertionError, match="projection changed"):
            verify_data(cursor)


@pytest.mark.parametrize("damage", ["missing", "extra", "unexpected-field"])
def test_indexed_verifier_rejects_projection_damage(db, damage):  # noqa: F811
    from .test_public_snapshot import attempt
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from .test_attribution import verify as verify_data
    from uuid import uuid4

    value = attempt()
    with db.cursor() as cursor:
        authorize_connection(cursor, value)
    persist_public(db, value)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT e.id,e.cve_id,e.receipt_id FROM evidence.epss_observations e JOIN evidence.observation_receipts r ON r.id=e.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        identity, cve, receipt = cursor.fetchone()
        if damage == "missing":
            cursor.execute(
                "DELETE FROM evidence.epss_observations WHERE id=%s", (identity,)
            )
        elif damage == "extra":
            cursor.execute(
                "INSERT INTO evidence.epss_observations(id,cve_id,receipt_id,probability) VALUES(%s,%s,%s,0.1)",
                (str(uuid4()), cve, receipt),
            )
        else:
            cursor.execute(
                "UPDATE evidence.epss_observations SET model_version='tampered' WHERE id=%s",
                (identity,),
            )
        with pytest.raises(AssertionError, match="projection|observation"):
            verify_data(cursor)
