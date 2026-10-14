"""Database-offline cleanup must not exhaust slots after a workstation restart."""

import unittest
import uuid
import threading
from unittest.mock import Mock, patch

import psycopg2
from app.services.postgres_query import PostgreSQLQueries, QueryError


class CleanupTests(unittest.TestCase):
    def test_shutdown_cancels_running_query_and_waits_for_cleanup(self):
        queries = PostgreSQLQueries()
        entered, release = threading.Event(), threading.Event()
        errors = []

        def validate(_sql):
            entered.set()
            self.assertTrue(release.wait(2))

        def execute():
            try:
                queries.execute({"requestId": str(uuid.uuid4()), "sql": "SELECT 1"})
            except QueryError as error:
                errors.append(error.code)

        with (
            patch("app.services.postgres_query.validate", side_effect=validate),
            patch("app.services.postgres_query.psycopg2.connect") as connect,
        ):
            worker = threading.Thread(target=execute)
            worker.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertFalse(queries.close(timeout=0))
                with self.assertRaises(QueryError) as caught:
                    queries.execute({"requestId": str(uuid.uuid4()), "sql": "SELECT 2"})
                self.assertEqual(caught.exception.code, "shutting_down")
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertTrue(queries.close(timeout=1))
            self.assertEqual(errors, ["cancelled"])
            connect.assert_not_called()
            self.assertEqual(queries.slots._value, 3)

    def test_idle_shutdown_is_idempotent_and_validates_wait(self):
        queries = PostgreSQLQueries()
        for timeout in (True, -1, 61, float("nan"), float("inf"), "1"):
            with self.assertRaises(ValueError):
                queries.close(timeout)
        self.assertFalse(queries.closed)
        self.assertTrue(queries.close(0))
        self.assertTrue(queries.close(0))

    def test_failed_async_connection_cancellation_releases_every_slot(self):
        queries = PostgreSQLQueries()
        capacity = queries.slots._value
        for close_fails in (False, True):
            self.check_repeated_cleanup(queries, capacity, close_fails)

    def check_repeated_cleanup(self, queries, capacity, close_fails):
        for _ in range(capacity * 2):
            connection = Mock()
            connection.isexecuting.return_value = True
            if close_fails:
                connection.close.side_effect = psycopg2.OperationalError("close failed")
            connection.cancel.side_effect = psycopg2.OperationalError(
                "asynchronous connection attempt underway"
            )
            with (
                patch("app.services.postgres_query.validate", return_value=None),
                patch(
                    "backend.database.connections.read_credentials",
                    return_value={
                        "owner": "synthetic-owner" * 3,
                        "reader": "synthetic-reader" * 3,
                    },
                ),
                patch(
                    "app.services.postgres_query.psycopg2.connect",
                    return_value=connection,
                ) as connect,
                patch(
                    "app.services.postgres_query.Job.poll",
                    side_effect=psycopg2.OperationalError("offline"),
                ),
            ):
                with self.assertRaises(QueryError) as caught:
                    queries.execute({"requestId": str(uuid.uuid4()), "sql": "SELECT 1"})
            self.assertEqual(caught.exception.code, "unavailable")
            options = connect.call_args.kwargs["options"].split()
            self.assertIn("work_mem=32MB", options)
            self.assertIn("statement_timeout=20000", options)
            self.assertIn("lock_timeout=20000", options)
            connection.close.assert_called_once()
            self.assertEqual(queries.slots._value, capacity)
            self.assertFalse(queries.jobs)
