"""Snapshot publication gates and immutable replay use synthetic saved references."""

import json
from uuid import uuid4
import pytest
from standalone.evidence_pipeline.collection.github_discovery_collection import prepare
from .test_github_advisories import COMMIT


class Cursor:
    def __init__(self):
        self.row = None
        self.calls = []

    def execute(self, sql, args):
        self.calls.append(sql)
        if sql.startswith("INSERT") and self.row is None:
            _, origin, commit, observed, payload, members = args
            self.row = (
                origin,
                commit,
                observed,
                json.loads(payload),
                json.loads(members),
            )

    def fetchone(self):
        return self.row


def saved_reference(tmp_path):
    prepare(
        "ref",
        "heads/main",
        tmp_path / "head",
        origin="synthetic",
        synthetic_payload=json.dumps(
            {"ref": "refs/heads/main", "object": {"type": "commit", "sha": COMMIT}}
        ).encode(),
    )


def test_current_schema_rejects_missing_reference_and_preserves_newest():
    """Exercise the installed publication policy/view behavior in a rollback."""
    from datetime import datetime, timezone
    from backend.database import schema as database_schema
    from .runtime import local_database

    conn = local_database().connect()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(731904216)")
            cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
            database_schema.verify(cursor)
            cursor.execute(
                "DELETE FROM evidence_pipeline.github_repository_snapshots WHERE origin='synthetic'"
            )
            cursor.execute("SET LOCAL ROLE tm_pipeline_writer")
            reference = json.dumps(
                {"ref": "refs/heads/main", "object": {"type": "commit", "sha": COMMIT}}
            )
            sql = (
                "INSERT INTO evidence_pipeline.github_repository_snapshots "
                "VALUES (%s,'synthetic',%s,%s,%s::jsonb,'[]'::jsonb)"
            )
            newer = str(uuid4())
            cursor.execute(
                sql,
                (newer, COMMIT, datetime(2026, 9, 14, tzinfo=timezone.utc), reference),
            )
            cursor.execute(
                sql,
                (
                    str(uuid4()),
                    COMMIT,
                    datetime(2026, 9, 13, tzinfo=timezone.utc),
                    reference,
                ),
            )
            cursor.execute(
                "SELECT run_id::text FROM evidence_pipeline.current_github_repository_snapshot"
            )
            assert cursor.fetchone() == (newer,)
            cursor.execute("SAVEPOINT invalid_reference")
            import psycopg2

            with pytest.raises(psycopg2.errors.CheckViolation):
                cursor.execute(
                    sql, (str(uuid4()), COMMIT, datetime.now(timezone.utc), "{}")
                )
            cursor.execute("ROLLBACK TO SAVEPOINT invalid_reference")
            cursor.execute("SET LOCAL ROLE tm_mock_reader")
            cursor.execute(
                "SELECT count(*) FROM evidence_pipeline.current_github_advisories"
            )
            assert cursor.fetchone() == (0,)
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cursor.execute(
                    sql, (str(uuid4()), COMMIT, datetime.now(timezone.utc), reference)
                )
    finally:
        conn.rollback()
        conn.close()
