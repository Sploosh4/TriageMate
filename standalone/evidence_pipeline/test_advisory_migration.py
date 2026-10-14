"""Advisory upgrade, selection semantics and original evidence preservation."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
import json
import pytest
from .test_store import db as database_fixture
from .test_csaf_store import snapshot


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.public_store import persist_public

db = database_fixture


def test_upgrade_repeat_and_authority_drift(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("GRANT DELETE ON evidence.advisories TO tm_pipeline_writer")
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_current_advisories_retain_failure_and_clear_complete_empty(db):
    value = snapshot()
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(db, value)
    failure = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        complete=False,
        outcome="failure",
        payload=b"bad",
        error_code="invalid_public_payload",
    )
    persist_public(db, failure)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT source_patch_id,latest_outcome FROM evidence_pipeline.current_public_patches WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchall() == [("KB5012345", "failure")]
    raw = json.loads(value.payload)
    raw["vulnerabilities"] = []
    empty = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=2),
        payload=json.dumps(raw).encode(),
    )
    persist_public(db, empty)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence_pipeline.current_public_patches WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT count(*) FROM evidence.patches p JOIN evidence.observation_receipts r ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cursor.fetchone() == (1,)


def test_original_and_new_advisory_data_verify_together(db):
    from .test_attribution import verify as verify_data
    from .test_public_migration import (
        test_upgrade_repeat_and_legacy_schema_verification,
    )

    value = snapshot()
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
    persist_public(db, value)
    with db.cursor() as cursor:
        verify_data(cursor)
    test_upgrade_repeat_and_legacy_schema_verification(db)
