"""Pending advisory authority and persistence, isolated in rolled-back transactions."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4
import json
import pytest

from .test_store import db as database_fixture
from .test_csaf import fixture, scope
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .test_authority import reject

db = database_fixture
TABLES = (
    "advisories",
    "advisory_cves",
    "recommendations",
    "recommendation_cves",
    "patches",
    "patch_vulnerabilities",
    "recommendation_patches",
)


def snapshot():
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    return PublicSnapshot(
        scope(), str(uuid4()), now, now, "success", True, json.dumps(fixture()).encode()
    )


@pytest.fixture
def ready(db):
    value = snapshot()
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, value)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return value


def test_restricted_advisory_roundtrip_and_replay(db, ready):
    assert not persist_public(db, ready)["replayed"]
    assert persist_public(db, ready)["replayed"]
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT p.source_patch_id,r.category,r.product_name,p.product_names FROM evidence.recommendation_patches link JOIN evidence.patches p ON p.id=link.patch_id JOIN evidence.recommendations r ON r.id=link.recommendation_id JOIN evidence.observation_receipts receipt ON receipt.id=link.receipt_id WHERE receipt.collection_attempt_id=%s",
            (ready.execution_id,),
        )
        assert cursor.fetchall() == [
            ("KB5012345", "vendor_fix", "Synthetic Windows", ["Synthetic Windows"])
        ]
        cursor.execute(
            "SELECT count(*) FROM evidence.advisory_cves a JOIN evidence.observation_receipts r ON r.id=a.receipt_id WHERE r.collection_attempt_id=%s",
            (ready.execution_id,),
        )
        assert cursor.fetchone() == (1,)
    for table in TABLES:
        reject(db, "DELETE FROM evidence." + table)
        reject(db, "TRUNCATE evidence." + table)


def test_cross_receipt_and_wrong_cve_links_rejected(db, ready):
    persist_public(db, ready)
    other = replace(ready, execution_id=str(uuid4()))
    persist_public(db, other)
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT p.id,p.receipt_id FROM evidence.patches p JOIN evidence.observation_receipts r ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
            (ready.execution_id,),
        )
        patch, receipt = cursor.fetchone()
        cursor.execute(
            "SELECT p.id,p.receipt_id FROM evidence.recommendations p JOIN evidence.observation_receipts r ON r.id=p.receipt_id WHERE r.collection_attempt_id=%s",
            (other.execution_id,),
        )
        recommendation, other_receipt = cursor.fetchone()
    reject(
        db,
        "INSERT INTO evidence.recommendation_patches VALUES(%s,%s,%s)",
        (recommendation, patch, other_receipt),
    )
    reject(
        db,
        "INSERT INTO evidence.patch_vulnerabilities VALUES(%s,%s,%s,%s)",
        (str(uuid4()), patch, "CVE-2099-8888888", receipt),
    )


def test_reader_has_no_advisory_write_authority(db, ready):
    persist_public(db, ready)
    with db.cursor() as cursor:
        cursor.execute("RESET SESSION AUTHORIZATION")
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
    for table in TABLES:
        reject(db, "DELETE FROM evidence." + table)
        reject(db, "INSERT INTO evidence." + table + " DEFAULT VALUES")


def test_failed_advisory_has_no_projections(db, ready):
    failed = replace(
        ready,
        payload=b"invalid",
        complete=False,
        outcome="failure",
        error_code="invalid_public_payload",
    )
    assert persist_public(db, failed)["outcome"] == "failure"
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (failed.execution_id,),
        )
        assert cursor.fetchone() == (0,)
