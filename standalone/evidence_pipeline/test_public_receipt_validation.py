"""Public receipt inserts avoid unrelated scans; edits still validate exposure."""

from backend.database import schema as database_schema

from dataclasses import replace
import json

from .test_store import db as database_fixture
from .test_cvrf_store import snapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.authority import authorize_connection


db = database_fixture


def test_public_batch_does_not_scan_exposure_once_per_receipt(db):
    value = snapshot()
    document = json.loads(value.payload)
    original = document["Vulnerability"][0]
    document["Vulnerability"] = [
        dict(original, CVE=f"CVE-2026-{90000 + i}") for i in range(30)
    ]
    value = replace(value, payload=json.dumps(document).encode())
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("CREATE TEMP TABLE exposure_validation_calls (marker boolean)")
        cur.execute(
            "SELECT pg_get_functiondef('evidence_pipeline.validate_exposure()'::regprocedure)"
        )
        definition = cur.fetchone()[0]
        # Instrument, without removing, the real validator. This entire test,
        # including the function change, is rolled back by the fixture.
        definition = definition.replace(
            "BEGIN",
            "BEGIN\n INSERT INTO pg_temp.exposure_validation_calls VALUES(true);",
            1,
        )
        cur.execute(definition)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM exposure_validation_calls")
        calls = cur.fetchone()[0]
        assert calls < 5
        cur.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (30,)
        cur.execute(
            "UPDATE evidence.observation_receipts SET source_revision_id=source_revision_id WHERE id=(SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s LIMIT 1)",
            (value.execution_id,),
        )
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SELECT count(*) FROM exposure_validation_calls")
        assert cur.fetchone()[0] >= calls + 1
