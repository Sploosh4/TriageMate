"""Remove redundant receipt scans without changing child or parent integrity."""

from dataclasses import replace
import json
from pathlib import Path
from uuid import uuid4
import psycopg2
import pytest
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from .test_exposure_store import bound, db, snapshot  # noqa: F401

BEFORE = (
    Path(__file__).resolve().parents[2]
    / "backend/tests/fixtures/validation/check_exposure_before_scan_reduction.sql"
).read_text()


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_receipt_scan_reduction_preserves_children_and_parent_edits(db, bound):  # noqa: F811
    device, child = bound
    records = [
        {
            "id": f"synthetic-receipt-scan-{n}",
            "machineId": device.records()[0]["id"],
            "cveId": "CVE-2099-99999",
            "productName": "Synthetic receipt scan",
            "productVersion": str(n),
        }
        for n in range(20)
    ]
    child = replace(child, payload=json.dumps(records).encode())
    measures = []
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("CREATE TEMP TABLE exposure_scan_calls (marker boolean)")
        cur.execute(
            "SELECT pg_get_functiondef('evidence_pipeline.validate_exposure()'::regprocedure)"
        )
        definition = cur.fetchone()[0].replace(
            "BEGIN", "BEGIN\n INSERT INTO pg_temp.exposure_scan_calls VALUES(true);", 1
        )
        cur.execute(definition)
        cur.execute(
            "SELECT pg_get_functiondef('evidence_pipeline.check_exposure()'::regprocedure)"
        )
        installed = cur.fetchone()[0]
        for optimized in (False, True):
            cur.execute("SAVEPOINT experiment")
            cur.execute(installed if optimized else BEFORE)
            cur.execute("SET CONSTRAINTS ALL DEFERRED")
            assert persist_exposure(db, child, device.execution_id)["records"] == 20
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
            cur.execute("SELECT count(*) FROM exposure_scan_calls")
            calls = cur.fetchone()[0]
            measures.append(calls)
            assert persist_exposure(db, child, device.execution_id)["replayed"]
            # A parent receipt edit must still run the complete exposure check.
            cur.execute(
                "UPDATE evidence.observation_receipts SET source_revision_id=source_revision_id WHERE id=(SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s LIMIT 1)",
                (child.execution_id,),
            )
            cur.execute("SELECT count(*) FROM exposure_scan_calls")
            assert cur.fetchone()[0] >= calls + 1
            # Database-side duplicate finding identity must still reject writes,
            # independently of the Python parser's checks.
            cur.execute("SAVEPOINT invalid_child")
            with pytest.raises(psycopg2.Error, match="Duplicate source finding"):
                cur.execute(
                    "UPDATE evidence.vulnerability_findings SET source_finding_id='same-synthetic-id' WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
                    (child.execution_id,),
                )
            cur.execute("ROLLBACK TO SAVEPOINT invalid_child")
            cur.execute("SAVEPOINT invalid_insert")
            with pytest.raises(psycopg2.Error, match="Duplicate source finding"):
                cur.execute(
                    "INSERT INTO evidence.vulnerability_findings "
                    "SELECT (jsonb_populate_record(NULL::evidence.vulnerability_findings, "
                    "to_jsonb(f)||jsonb_build_object('id',%s::text,'receipt_id', "
                    "(SELECT other.id::text FROM evidence.observation_receipts other "
                    "WHERE other.collection_attempt_id=r.collection_attempt_id "
                    "AND other.id<>r.id LIMIT 1)))).* "
                    "FROM evidence.vulnerability_findings f "
                    "JOIN evidence.observation_receipts r ON r.id=f.receipt_id "
                    "WHERE r.collection_attempt_id=%s LIMIT 1",
                    (str(uuid4()), child.execution_id),
                )
            cur.execute("ROLLBACK TO SAVEPOINT invalid_insert")
            cur.execute("ROLLBACK TO SAVEPOINT experiment")
        assert measures[0] - measures[1] == 40
