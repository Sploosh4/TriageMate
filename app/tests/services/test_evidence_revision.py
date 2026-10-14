"""Cached reader watermarks change only with committed input/publication metadata.

Run the actual-reader check after other database-writing suites finish: it
intentionally observes all successful imports, including another test process.
"""

import json
import unittest
from types import SimpleNamespace

from app.services.evidence_revision import EvidenceRevision
from app.services.postgres_query import QueryError


class RevisionTests(unittest.TestCase):
    def test_empty_ubuntu_publication_changes_only_after_commit(self):
        from datetime import datetime, timezone
        from uuid import uuid4
        from app.services.postgres_query import PostgreSQLQueries
        from standalone.evidence_pipeline.runtime import local_database, connect

        run = str(uuid4())
        commit = uuid4().hex + "a" * 8
        reference = dict(ref="refs/heads/main", object=dict(type="commit", sha=commit))
        revision = EvidenceRevision(PostgreSQLQueries())

        def read():
            revision.checked = float("-inf")
            return revision.read()

        conn = connect()
        try:
            initial = read()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO evidence_pipeline.ubuntu_repository_snapshots VALUES ('Ubuntu',%s,'synthetic',%s,%s,%s::jsonb,'[]'::jsonb)",
                    (run, commit, datetime.now(timezone.utc), json.dumps(reference)),
                )
            self.assertEqual(read(), initial)
            conn.commit()
            published = read()
            self.assertNotEqual(published, initial)
            self.assertEqual(read(), published)
        finally:
            conn.close()
            with local_database().connect() as owner, owner.cursor() as cur:
                cur.execute(
                    "DELETE FROM evidence_pipeline.ubuntu_repository_snapshots WHERE run_id=%s",
                    (run,),
                )

    def test_cache_coalesces_readers_and_failure_does_not_replace_watermark(self):
        calls = []
        rows = [
            ["attempts", "1", "first"],
            ["components", "0", None],
            ["cve", "0", None],
            ["github", "0", None],
            ["ubuntu", "0", None],
        ]
        now = [0]

        def execute(body):
            calls.append(body)
            return json.dumps({"rows": rows, "truncated": False}).encode()

        queries = SimpleNamespace(execute=execute)
        revision = EvidenceRevision(queries, clock=lambda: now[0])
        first = revision.read()
        self.assertEqual(revision.read(), first)
        self.assertEqual(len(calls), 1)
        now[0] = 5
        rows[0][1] = "2"
        second = revision.read()
        self.assertNotEqual(first, second)
        now[0] = 10
        rows.clear()
        with self.assertRaises(QueryError):
            revision.read()
        self.assertEqual(revision.value, second["revision"])
        self.assertEqual(revision.checked, 5)

    def test_busy_poll_cannot_start_another_database_query(self):
        queries = SimpleNamespace(execute=lambda body: self.fail("Concurrent query"))
        revision = EvidenceRevision(queries)
        with revision.lock:
            with self.assertRaises(QueryError):
                revision.read()

    def test_actual_reader_sees_commit_and_historical_import_but_not_replay(self):
        from datetime import datetime, timedelta, timezone
        from dataclasses import replace
        from uuid import uuid4
        from app.services.postgres_query import PostgreSQLQueries
        from standalone.evidence_pipeline.commands import register, ingest
        from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
        from standalone.evidence_pipeline.test_commands import cleanup

        scope = SourceScope(
            str(uuid4()),
            "Entra",
            "devices",
            "synthetic-refresh",
            "synthetic",
            "Explicitly synthetic refresh acceptance",
            str(uuid4()),
        )
        now = datetime.now(timezone.utc)
        snapshot = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
        revision = EvidenceRevision(PostgreSQLQueries())

        def read():
            revision.checked = float("-inf")
            return revision.read()

        try:
            initial = read()
            register(scope)
            self.assertEqual(read(), initial)
            from contextlib import closing
            from standalone.evidence_pipeline.runtime import connect
            from standalone.evidence_pipeline.persistence.store import persist_devices

            with closing(connect()) as conn:
                persist_devices(conn, snapshot)
                self.assertEqual(read(), initial)
                conn.rollback()
            self.assertEqual(read(), initial)
            ingest(snapshot)
            committed = read()
            self.assertNotEqual(committed, initial)
            ingest(snapshot)
            self.assertEqual(read(), committed)
            ingest(
                replace(
                    snapshot,
                    execution_id=str(uuid4()),
                    started_at=now - timedelta(days=1),
                    finished_at=now - timedelta(days=1),
                )
            )
            self.assertNotEqual(read(), committed)
        finally:
            cleanup(scope)
