"""Draft CVE storage tested with restricted roles in rolled-back transactions."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record
from standalone.evidence_pipeline.parsing.public_snapshot import (
    PARSERS,
    PublicSnapshot,
)
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cve_program import document, scope
from .test_store import db  # noqa: F401


def prepare(db, monkeypatch):  # noqa: F811
    monkeypatch.setitem(PARSERS, ("CVE", "records"), parse_cve_record)
    now = datetime.now(timezone.utc)
    value = PublicSnapshot(
        scope(),
        str(uuid4()),
        now,
        now,
        "success",
        True,
        json.dumps(document()).encode(),
    )
    with db.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    return value


def test_writer_roundtrip_replay_failure_and_rejection(db, monkeypatch):  # noqa: F811
    value = prepare(db, monkeypatch)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT record_state,contributor_kind FROM evidence_pipeline.current_cve_contributions WHERE connection_id=%s ORDER BY contributor_kind",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("PUBLISHED", "adp"), ("PUBLISHED", "cna")]
    failure = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="public_transport_failed",
    )
    assert persist_public(db, failure)["outcome"] == "failure"
    with db.cursor() as cur:
        cur.execute(
            "SELECT record_state FROM evidence_pipeline.current_cve_records WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == ("PUBLISHED",)
    raw = json.loads(value.payload)
    raw["cveMetadata"]["state"] = "REJECTED"
    raw["containers"] = {
        "cna": {
            "providerMetadata": raw["containers"]["cna"]["providerMetadata"],
            "rejectedReasons": [{"lang": "en", "value": "Synthetic rejection"}],
        }
    }
    rejected = replace(
        value,
        execution_id=str(uuid4()),
        finished_at=value.finished_at + timedelta(seconds=2),
        payload=json.dumps(raw).encode(),
    )
    persist_public(db, rejected)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT record_state,source_fields->'rejectedReasons'->0->>'value' FROM evidence_pipeline.current_cve_contributions WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchall() == [("REJECTED", "Synthetic rejection")]
        cur.execute(
            "SELECT count(*) FROM evidence.cve_record_observations WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (value.execution_id,),
        )
        assert cur.fetchone() == (1,)


@pytest.mark.parametrize("damage", ["omit", "field", "cve", "duplicate"])
def test_tampered_projection_rolls_back_attempt(db, monkeypatch, damage):  # noqa: F811
    from standalone.evidence_pipeline.parsing.public_records import PublicRecord

    value = prepare(db, monkeypatch)
    original = PublicRecord.evidence_rows

    def changed(self, receipt):
        for table, row in original(self, receipt):
            if table == "cve_contributions":
                if damage == "omit":
                    continue
                if damage == "field":
                    row["provider_name"] = "Invented publisher"
                if damage == "cve":
                    row["cve_id"] = "CVE-2099-54321"
                if damage == "duplicate":
                    yield table, {**row, "id": str(uuid4())}
            yield table, row

    monkeypatch.setattr(PublicRecord, "evidence_rows", changed)
    with pytest.raises(Exception, match="CVE|row-level security|duplicate key"):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


def test_writer_cannot_append_invented_contributor_or_modify_history(db, monkeypatch):  # noqa: F811
    from .test_authority import reject
    from standalone.evidence_pipeline.persistence.store import atomic
    import psycopg2

    value = prepare(db, monkeypatch)
    persist_public(db, value)
    with (
        db.cursor() as cur,
        pytest.raises(
            psycopg2.errors.InsufficientPrivilege, match="row-level security"
        ),
        atomic(cur),
    ):
        cur.execute(
            "INSERT INTO evidence.cve_contributions SELECT %s,receipt_id,cve_id,'adp',99,organization_id,provider_name,source_fields FROM evidence.cve_contributions LIMIT 1",
            (str(uuid4()),),
        )
    for table in ("cve_contributions", "cve_record_observations"):
        reject(db, "DELETE FROM evidence." + table)
        reject(db, "UPDATE evidence." + table + " SET cve_id='CVE-2099-54321'")
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
    reject(db, "INSERT INTO evidence.cve_contributions DEFAULT VALUES")


def test_cve_import_passes_full_baseline_attribution(db, monkeypatch):  # noqa: F811
    from .test_attribution import verify

    value = prepare(db, monkeypatch)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)


def test_attribution_preserves_precision_and_detects_changes(db, monkeypatch):  # noqa: F811
    from decimal import Decimal
    from standalone.evidence_pipeline.persistence.cve_attribution import (
        verify_cve_receipt,
    )
    from standalone.evidence_pipeline.source_json import encode_source_records

    value = prepare(db, monkeypatch)
    raw = json.loads(value.payload)
    raw["containers"]["adp"][0]["metrics"][0]["other"]["content"][
        "synthetic_number"
    ] = Decimal("0.12345678901234567890123456789")
    value = replace(value, payload=encode_source_records(raw))
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT to_jsonb(c),to_jsonb(rev),to_jsonb(r),p.claim FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id JOIN evidence.source_connections c ON c.id=rev.connection_id JOIN evidence_pipeline.public_claims p ON p.source_revision_id=rev.id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        source, revision, receipt, claim = cur.fetchone()
        result = verify_cve_receipt(cur, source, revision, receipt, claim)
        assert len(result["cve_contributions"]) == 2
        cur.execute(
            "SELECT source_fields->'metrics'->0->'other'->'content'->>'synthetic_number' FROM evidence.cve_contributions WHERE receipt_id=%s AND contributor_kind='adp'",
            (receipt["id"],),
        )
        assert cur.fetchone() == ("0.12345678901234567890123456789",)
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "UPDATE evidence.cve_contributions SET provider_name='Synthetic tampering' WHERE receipt_id=%s AND contributor_kind='adp'",
            (receipt["id"],),
        )
        with pytest.raises(AssertionError, match="CVE projection changed"):
            verify_cve_receipt(cur, source, revision, receipt, claim)
