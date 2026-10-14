"""Explicit activation and retained classification verification, all rolled back."""

from backend.database import schema as database_schema

import pytest


from .test_classification_store import (
    classified as classified_fixture,
    snapshot as snapshot_fixture,
    db as db_fixture,
    call,
)
from .test_attribution import verify as verify_data
from uuid import uuid4

classified = classified_fixture
snapshot = snapshot_fixture
db = db_fixture


def test_classification_upgrade_and_history_verifier(classified):
    db, device = classified
    call(db, str(uuid4()), device)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        database_schema.verify(cur)
        verify_data(cur)
        cur.execute(
            "UPDATE evidence.classification_decisions SET actor_reference='forged' WHERE provider_device_id=%s",
            (device,),
        )
        with pytest.raises(AssertionError, match="actor changed"):
            verify_data(cur)


def test_classification_function_privilege_drift_rejected(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.record_classification(uuid,uuid,text,text,uuid) TO tm_mock_reader"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
