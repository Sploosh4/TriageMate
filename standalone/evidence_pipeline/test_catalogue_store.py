"""Rollback-only catalogue integration in the existing local PostgreSQL database."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
import importlib.util
from pathlib import Path
from uuid import uuid4

import psycopg2
import pytest


from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.catalogue_store import persist_catalogue
from .test_store import db  # noqa: F401
from .test_vulnerability_catalogue import snapshot


def test_catalogue_receipts_replay_failure_and_empty_success(db):  # noqa: F811
    source = snapshot([{"id": "CVE-2026-10001", "cvssV3": 4.2, "publicExploit": False}])
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, source)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    assert persist_catalogue(db, source)["records"] == 1
    assert persist_catalogue(db, source)["replayed"] is True
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        path = (
            Path(__file__).resolve().parents[2] / "ui-engine/postgres/epss/baseline.py"
        )
        spec = importlib.util.spec_from_file_location("catalogue_baseline", path)
        baseline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(baseline)
        baseline.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    failed = replace(
        source,
        execution_id=str(uuid4()),
        finished_at=source.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        error_code="synthetic_failure",
        payload=b"",
    )
    assert persist_catalogue(db, failed)["outcome"] == "failure"
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT cve_id,cvss_v3,claim->'publicExploit',origin FROM evidence_pipeline.current_vulnerability_catalogue WHERE connection_id=%s",
            (source.scope.connection_id,),
        )
        assert cur.fetchone() == (
            "CVE-2026-10001",
            Decimal("4.2"),
            False,
            "synthetic",
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    empty = replace(
        source,
        execution_id=str(uuid4()),
        finished_at=source.finished_at + timedelta(seconds=2),
        payload=b"[]",
    )
    persist_catalogue(db, empty)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_vulnerability_catalogue WHERE connection_id=%s",
            (source.scope.connection_id,),
        )
        assert cur.fetchone() == (0,)
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM evidence_pipeline.catalogue_observations")


@pytest.mark.parametrize(
    "change",
    [
        "DROP POLICY catalogue_insert ON evidence_pipeline.catalogue_observations",
        "ALTER TABLE evidence_pipeline.catalogue_observations DISABLE TRIGGER catalogue_provenance",
        "GRANT UPDATE ON evidence_pipeline.catalogue_observations TO tm_pipeline_writer",
    ],
)
def test_catalogue_migration_rejects_authority_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
