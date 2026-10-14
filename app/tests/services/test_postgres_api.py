"""Real HTTP + actual tm_mock_reader integration tests; synthetic data only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid
import sys

from fastapi.testclient import TestClient
from app.api import create_app
from app.services.postgres_query import PostgreSQLQueries, Job, QueryError, MAX_RESULT

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "ui-engine/postgres"))
import manage


class PostgreSQLAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os

        cls.temp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temp.name)

        class Operations:
            def __init__(self, *_args):
                pass

            def read(self):
                return {"state": "off"}

            def close(self):
                return True

        with patch.dict(os.environ, {"TRIAGEMATE_STATE_DIR": str(cls.path)}):
            cls.application = create_app(operations_factory=Operations)
            cls.client = TestClient(
                cls.application,
                base_url="http://127.0.0.1:5190",
                raise_server_exceptions=False,
            )
            cls.client.__enter__()
        cls.queries = cls.application.state.queries
        cls.token = cls.client.get("/api/session").json()["token"]

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.temp.cleanup()

    def post(self, path, body, headers=None):
        result = self.client.post(
            path, json=body, headers={"X-Lab-Token": self.token, **(headers or {})}
        )
        return result.status_code, result.content

    def query(self, sql, identifier=None):
        return self.post(
            "/api/query", {"sql": sql, "requestId": identifier or str(uuid.uuid4())}
        )

    def test_catalogue_uses_actual_reader_metadata(self):
        status, raw = self.post(
            "/api/catalogue",
            {"requestId": str(uuid.uuid4()), "sql": "DELETE FROM computers"},
        )
        self.assertEqual(status, 200)
        rows = json.loads(raw)["rows"]
        self.assertEqual(
            {row[3] for row in rows if row[:2] == ["evidence", "provider_devices"]},
            {"Queryable evidence. Inspect source receipts for origin and provenance."},
        )
        relations = {(row[0], row[1]) for row in rows}
        base_relations = {
            relation for relation in relations if relation[0] != "evidence_pipeline"
        }
        self.assertEqual(
            len(base_relations), 66
        )  # Original 60 plus six CVE/OSV/reference tables
        exposure_installed = ("evidence_pipeline", "current_findings") in relations
        antivirus_installed = any(
            row[0:2] == ["evidence", "antivirus_observations"]
            and row[4] == "signature_status"
            for row in rows
        )
        self.assertEqual(
            len(rows),
            len({(row[0], row[1], row[4]) for row in rows}),
            "Catalogue must return each relation column once",
        )
        for table in (
            "cve_record_observations",
            "cve_contributions",
            "osv_advisory_observations",
            "osv_aliases",
            "osv_affected_packages",
            "public_reference_observations",
        ):
            self.assertIn(("evidence", table), relations)
            self.assertIn(
                "receipt_id", {row[4] for row in rows if row[:2] == ["evidence", table]}
            )
        if exposure_installed:
            self.assertEqual(
                [
                    (row[4], row[5])
                    for row in rows
                    if row[0] == "evidence"
                    and row[1] == "microsoft_tenants"
                    and row[4] == "evidence_origin"
                ],
                [("evidence_origin", "text")],
            )
        self.assertIn(("evidence_pipeline", "current_device_status"), relations)
        self.assertNotIn(("evidence_pipeline", "authorized_connections"), relations)
        self.assertNotIn(("evidence_pipeline", "installation"), relations)
        for name in (
            "input_device_scopes",
            "exposure_snapshots",
            "software_inventory",
            "public_claims",
        ):
            self.assertNotIn(("evidence_pipeline", name), relations)
        if exposure_installed:
            self.assertEqual(
                {name for schema, name in relations if schema == "evidence_pipeline"},
                {
                    "current_device_status",
                    "collection_status",
                    "current_software_inventory",
                    "current_software_devices",
                    "current_findings",
                    "current_classifications",
                    "current_computers",
                    "current_computer_links",
                    "completeness_definition",
                    "current_completeness_cells",
                    "current_completeness",
                    "software_completeness_definition",
                    "current_software_completeness_cells",
                    "current_software_completeness",
                    "software_collection_coverage",
                    "vulnerability_completeness_definition",
                    "current_vulnerability_completeness_cells",
                    "current_vulnerability_completeness",
                    "vulnerability_collection_coverage",
                    "current_missing_patches",
                    "current_update_status",
                    "current_public_epss_observations",
                    "current_public_kev_observations",
                    "current_public_cvss_observations",
                    "current_public_vulnerability_details",
                    "current_public_vulnerability_references",
                    "current_public_advisories",
                    "current_public_advisory_cves",
                    "current_public_recommendations",
                    "current_public_recommendation_cves",
                    "current_public_patches",
                    "current_public_patch_vulnerabilities",
                    "current_public_recommendation_patches",
                }
                | ({"current_antivirus"} if antivirus_installed else set())
                | {
                    "current_vulnerability_catalogue",
                    "current_assessment_baseline",
                    "vulnerability_event_history",
                    "assessment_device_references",
                    "current_defender_recommendations",
                    "recommendation_device_references",
                    "current_msrc_patch_fixes",
                    "current_msrc_patch_replacements",
                    "current_msrc_update_claims",
                    "current_cve_records",
                    "current_cve_contributions",
                    "current_osv_advisories",
                    "current_osv_affected_packages",
                    "current_osv_aliases",
                    "current_osv_relationships",
                    "osv_query_history",
                    "enrichment_request_status",
                    "current_public_references",
                    "current_attack_definitions",
                    "current_ctid_mappings",
                    "current_exploit_metadata",
                    "current_vendor_advisories",
                    "current_vendor_products",
                    "current_vendor_relationships",
                    "current_defender_missing_updates",
                    "current_defender_update_advice",
                    "defender_update_advice_history",
                    "current_github_advisories",
                    "current_github_repository_snapshot",
                    "current_cve_repository_snapshot",
                    "current_cve_repository_records",
                    "current_cve_repository_contributions",
                    "current_ubuntu_repository_snapshot",
                    "current_ubuntu_repository_advisories",
                    "current_ubuntu_repository_packages",
                    "current_ubuntu_repository_relationships",
                    "current_os_classes",
                    "current_device_patch_candidates",
                    "current_device_patch_replacements",
                    "current_inventory_product_evaluations",
                    "current_inventory_identities",
                    "current_windows_cna_evaluations",
                    "current_windows_nvd_evaluations",
                    "current_vmware_tools_cna_evaluations",
                    "product_completeness_definition",
                    "historical_event_completeness_definition",
                    "historical_event_completeness_cells",
                    "current_windows_runtime_releases",
                    "current_windows_inventory",
                    "current_windows_inventory_runs",
                    "windows_inventory_completeness_definition",
                    "current_windows_inventory_completeness_cells",
                    "current_native_inventory_identities",
                    "current_native_inventory_product_evaluations",
                    "current_native_inventory_accounting",
                    "current_public_completeness_cells",
                    "current_product_completeness_cells",
                    "current_native_advisory_facts",
                    "current_native_advisory_completeness_cells",
                    "product_collection_coverage",
                    "product_completeness_coverage",
                    "current_catalog_updates",
                    "current_catalog_replacement_claims",
                    "current_public_epss_observations",
                    "current_public_kev_observations",
                    "current_public_cvss_observations",
                    "current_public_vulnerability_details",
                    "current_public_vulnerability_references",
                },
            )
        pipeline_columns = {row[4] for row in rows if row[0] == "evidence_pipeline"}
        self.assertTrue(
            {"source_present", "reporting_at", "latest_outcome", "selected_attempt_id"}
            <= pipeline_columns
        )
        deferred = {row[1] for row in rows if (row[3] or "").startswith("Deferred")}
        self.assertEqual(len(deferred), 3)
        self.assertNotIn("classification_decisions", deferred)
        self.assertNotIn("notification_details", deferred)
        self.assertTrue(
            all(row[3] for row in rows if row[0] == "evidence" and row[2] == "v")
        )
        self.assertIn(("mock_support", "findings"), relations)
        self.assertIn(("evidence", "current_vulnerabilities"), relations)
        self.assertNotIn(("pg_catalog", "pg_authid"), relations)
        self.assertTrue(
            any(
                row[1] == "computers" and row[4] == "id" and row[5] == "uuid"
                for row in rows
            )
        )
        status, _ = self.post(
            "/api/catalogue",
            {"requestId": str(uuid.uuid4())},
            {"X-Lab-Token": "invalid"},
        )
        self.assertEqual(status, 403)
        status, raw = self.post(
            "/api/catalogue",
            {"requestId": str(uuid.uuid4())},
            {"Origin": "https://example.invalid"},
        )
        self.assertEqual(status, 403)
        with patch("app.services.postgres_query.CONFIG", self.path / "missing"):
            status, raw = self.post("/api/catalogue", {"requestId": str(uuid.uuid4())})
        self.assertEqual(status, 503)
        self.assertNotIn("rows", json.loads(raw))

    def test_reader_boundary_through_actual_api(self):
        statements = [
            "DELETE FROM computers",
            "WITH x AS (DELETE FROM computers RETURNING *) SELECT * FROM x",
            "SELECT 1; DELETE FROM computers",
            "SELECT 1; SET ROLE tm_mock_owner",
            "SET default_transaction_read_only=off",
            "SELECT * INTO forbidden FROM computers",
            "SELECT * FROM computers FOR UPDATE",
            "COPY computers TO PROGRAM 'false'",
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT pg_write_file('/tmp/no','x',false)",
            "SELECT pg_notify('no','no')",
            "SELECT pg_advisory_lock(1)",
            "SELECT pg_sleep(1)",
            "SELECT set_config('search_path','public',false)",
            "CREATE EXTENSION postgres_fdw",
            "SELECT * FROM pg_authid",
            "SELECT pg_terminate_backend(pg_backend_pid())",
        ]
        for statement in statements:
            with self.subTest(statement=statement):
                status, raw = self.query(statement)
                self.assertIn(status, (400, 403))
                self.assertNotIn("rows", json.loads(raw))
        status, raw = self.query("SELECT ';' AS semi /* ; DELETE */;")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["rows"], [[";"]])
        status, raw = self.query("SELECT count(*) FROM computers")
        self.assertEqual(json.loads(raw)["rows"], [[4]])
        self.assertEqual(
            self.post(
                "/api/query",
                {"sql": "SELECT 1", "requestId": str(uuid.uuid4())},
                {"Origin": "https://example.invalid"},
            )[0],
            403,
        )
        self.assertEqual(
            self.post(
                "/api/query/cancel",
                {"requestId": str(uuid.uuid4())},
                {"X-Lab-Token": "wrong"},
            )[0],
            403,
        )
        self.assertEqual(self.query("SELECT current_user")[0], 200)
        self.assertEqual(
            json.loads(self.query("SELECT current_user")[1])["rows"],
            [["tm_mock_reader"]],
        )

    def test_values_metadata_and_no_row_cap(self):
        status, raw = self.query("""SELECT NULL AS missing, false AS flag, 0 AS zero,
          9007199254740993::bigint AS large, 1.0000000000000000001::numeric AS exact,
          '2026-09-11T08:00:00+08'::timestamptz AS moment, ARRAY[1,NULL,2] AS array_value,
          '{"n":9007199254740993}'::jsonb AS document, 'NaN'::float8 AS special""")
        self.assertEqual(status, 200, raw)
        result = json.loads(raw)
        row = result["rows"][0]
        self.assertEqual(row[:3], [None, False, 0])
        self.assertEqual(row[3], {"type": "int8", "value": "9007199254740993"})
        self.assertEqual(row[4], {"type": "numeric", "value": "1.0000000000000000001"})
        self.assertEqual(row[5]["value"], "2026-09-11 00:00:00+00")
        self.assertEqual(row[6]["value"], "{1,NULL,2}")
        self.assertIn("9007199254740993", row[7]["value"])
        self.assertEqual(row[8], {"type": "float8", "value": "NaN"})
        self.assertEqual(len(result["columnTypes"]), 9)
        status, raw = self.query("SELECT generate_series(1,501) AS n")
        self.assertEqual(status, 200, raw)
        self.assertEqual(len(json.loads(raw)["rows"]), 501)
        self.assertFalse(json.loads(raw)["truncated"])
        status, raw = self.query("SELECT 1 WHERE false")
        self.assertEqual(json.loads(raw)["rows"], [])

    def test_complete_json_byte_boundaries(self):
        identifier = str(uuid.uuid4())
        status, raw = self.query("SELECT ''::text AS payload", identifier)
        overhead = len(raw)
        self.assertEqual(status, 200)
        for target in (MAX_RESULT - 1, MAX_RESULT, MAX_RESULT + 1):
            with self.subTest(bytes=target):
                status, raw = self.query(
                    f"SELECT repeat('x',{target - overhead}) AS payload"
                )
                if target <= MAX_RESULT:
                    self.assertEqual(status, 200, raw[:400])
                    self.assertEqual(len(raw), target)
                else:
                    self.assertEqual(status, 413)
                    self.assertEqual(json.loads(raw)["code"], "result_limit")
        # UTF-8 rather than characters; metadata and JSON punctuation count too.
        count = (MAX_RESULT - overhead) // 2 + 1
        status, raw = self.query(f"SELECT repeat('é',{count}) AS payload")
        self.assertEqual(status, 413)

    def hold_computers(self):
        connection = manage.connect()
        connection.cursor().execute(
            "LOCK TABLE evidence.computers IN ACCESS EXCLUSIVE MODE"
        )
        return connection

    def test_cancel_overlap_and_cancel_before_start(self):
        with closing(self.hold_computers()) as blocker, ThreadPoolExecutor() as pool:
            identifier = str(uuid.uuid4())
            future = pool.submit(self.query, "SELECT * FROM computers", identifier)
            time.sleep(0.15)
            status, raw = self.query("SELECT 'newer' AS value")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["rows"], [["newer"]])
            self.assertEqual(
                self.post("/api/query/cancel", {"requestId": identifier})[0], 200
            )
            status, raw = future.result(timeout=2)
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(raw)["code"], "cancelled")
            blocker.rollback()
        identifier = str(uuid.uuid4())
        self.post("/api/query/cancel", {"requestId": identifier})
        self.assertEqual(self.query("SELECT 1", identifier)[0], 409)
        time.sleep(0.05)
        with closing(manage.connect()) as c, c.cursor() as q:
            q.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name='triagemate-ui-query'"
            )
            self.assertEqual(q.fetchone(), (0,))

    def test_application_drain_cancels_database_query_and_preserves_database(self):
        queries = PostgreSQLQueries()
        with closing(manage.connect()) as observer, observer.cursor() as cursor:
            cursor.execute("SELECT pg_postmaster_start_time()")
            started = cursor.fetchone()
            with (
                closing(self.hold_computers()) as blocker,
                ThreadPoolExecutor() as pool,
            ):
                identifier = str(uuid.uuid4())
                future = pool.submit(
                    queries.execute,
                    {"requestId": identifier, "sql": "SELECT * FROM computers"},
                )
                deadline = time.monotonic() + 2
                waiting = False
                while time.monotonic() < deadline:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE application_name='triagemate-ui-query' AND wait_event_type='Lock'"
                    )
                    if cursor.fetchone()[0]:
                        waiting = True
                        break
                    time.sleep(0.01)
                self.assertTrue(
                    waiting,
                    "Expected a real PostgreSQL query waiting on the synthetic table lock",
                )
                self.assertTrue(queries.close(3))
                with self.assertRaises(QueryError) as caught:
                    future.result(timeout=1)
                self.assertEqual(caught.exception.code, "cancelled")
                self.assertFalse(queries.jobs)
                blocker.rollback()
            cursor.execute("SELECT pg_postmaster_start_time()")
            self.assertEqual(cursor.fetchone(), started)
            self.assertEqual(self.query("SELECT 42 AS still_available")[0], 200)

    def test_repeated_failure_cancellation_and_timeout_release_capacity(self):
        capacity = self.queries.slots._value
        self.assertEqual(capacity, 3)
        with closing(self.hold_computers()) as blocker, ThreadPoolExecutor() as pool:
            for _ in range(capacity * 2):
                # Actual PostgreSQL execution error, after acquiring a slot.
                status, _ = self.query("SELECT 1 / 0")
                self.assertEqual(status, 400)
                identifier = str(uuid.uuid4())
                future = pool.submit(self.query, "SELECT * FROM computers", identifier)
                until = time.monotonic() + 2
                while identifier not in self.queries.jobs and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertIn(identifier, self.queries.jobs)
                self.assertEqual(
                    self.post("/api/query/cancel", {"requestId": identifier})[0], 200
                )
                status, raw = future.result(timeout=2)
                self.assertEqual((status, json.loads(raw)["code"]), (409, "cancelled"))
                # Same production deadline, with an aged start to avoid six 20s waits.
                with self.assertRaises(QueryError) as caught:
                    self.queries.execute(
                        {
                            "requestId": str(uuid.uuid4()),
                            "sql": "SELECT * FROM computers",
                        },
                        time.monotonic() - 19.9,
                    )
                self.assertEqual(caught.exception.code, "deadline")
                self.assertEqual(self.queries.slots._value, capacity)
                self.assertFalse(self.queries.jobs)
                self.assertEqual(self.query("SELECT 7 AS recovered")[0], 200)
            # Prove all slots can still serve simultaneous blocked queries.
            identifiers = [str(uuid.uuid4()) for _ in range(capacity)]
            futures = [
                pool.submit(self.query, "SELECT * FROM computers", i)
                for i in identifiers
            ]
            until = time.monotonic() + 2
            while self.queries.slots._value and time.monotonic() < until:
                time.sleep(0.01)
            self.assertEqual(self.queries.slots._value, 0)
            blocker.rollback()
            for future in futures:
                self.assertEqual(future.result(timeout=2)[0], 200)
        self.assertEqual(self.queries.slots._value, capacity)
        self.assertFalse(self.queries.jobs)

    def test_deadline_below_at_above_and_waiting(self):
        # Exact equality uses the same production clock check; wall clocks cannot reliably target an exact instant.
        job = Job(100)
        with patch(
            "app.services.postgres_query.time.monotonic", return_value=119.999999
        ):
            job.check()
        for now in (120, 120.000001):
            with (
                patch("app.services.postgres_query.time.monotonic", return_value=now),
                self.assertRaises(QueryError) as error,
            ):
                job.check()
            self.assertEqual(error.exception.code, "deadline")
        for release_at, expected in [(19.5, 200), (20.2, 408)]:
            with closing(self.hold_computers()) as blocker:
                timer = threading.Timer(release_at, blocker.rollback)
                timer.start()
                started = time.monotonic()
                try:
                    status, raw = self.query("SELECT count(*) FROM computers")
                    self.assertEqual(status, expected, raw)
                    self.assertLess(time.monotonic() - started, 20.6)
                finally:
                    timer.join()
        # Deadline also includes waiting for a connection slot, not just server execution.
        for _ in range(3):
            self.queries.slots.acquire()
        try:
            started = time.monotonic()
            with self.assertRaises(QueryError) as caught:
                self.queries.execute(
                    {"requestId": str(uuid.uuid4()), "sql": "SELECT 1"}, started - 19.9
                )
            self.assertEqual(caught.exception.code, "deadline")
            self.assertLess(time.monotonic() - started, 0.3)
        finally:
            for _ in range(3):
                self.queries.slots.release()

    def test_database_failure_does_not_fallback(self):
        with patch("app.services.postgres_query.CONFIG", self.path / "absent.json"):
            status, raw = self.query("SELECT * FROM findings")
            self.assertEqual(status, 503)
            self.assertIn("SQLite was not used", json.loads(raw)["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
