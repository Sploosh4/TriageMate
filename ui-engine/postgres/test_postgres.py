"""Real PostgreSQL acceptance checks; all mutation cases roll back."""

import csv
import json
import unittest
import uuid
from collections import defaultdict

import psycopg2
from psycopg2 import sql

import manage
from backend.database.fixtures import FIXTURES
from backend.database.metadata import original_tables

DOCS = manage.ROOT / "docs/planning/ui-postgresql"


def uid(alias):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "triagemate-synthetic-v1:" + alias))


def rows(name):
    with (DOCS / name).open() as f:
        return list(csv.DictReader(f))


class PostgreSQLTests(unittest.TestCase):
    database = manage.DB

    def setUp(self):
        self.conn = manage.connect(self.database)
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def query(self, query, args=None):
        self.cur.execute(query, args)
        return self.cur.fetchall()

    def reject(self, statement, args=None):
        self.cur.execute("SAVEPOINT invalid_case")
        try:
            with self.assertRaises(psycopg2.Error) as caught:
                self.cur.execute(statement, args)
                self.cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
            self.assertIn(
                caught.exception.pgcode,
                ["23503", "23505", "23514", "P0001", "42501", "25006"],
            )
        finally:
            self.cur.execute("ROLLBACK TO SAVEPOINT invalid_case")

    def additive_input_tables(self):
        names = {
            "cve_record_observations",
            "cve_contributions",
            "osv_advisory_observations",
            "osv_aliases",
            "osv_affected_packages",
            "public_reference_observations",
        }
        self.cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='evidence' AND table_name=ANY(%s)",
            (list(names),),
        )
        installed = {row[0] for row in self.cur.fetchall()}
        if installed:
            # The migration signature verifies exact added columns/keys/authority.
            # The CSV assertions below continue to check the original schema.
            from backend.database.schema import verify_supported as verify

            verify(self.cur)
        return installed

    def test_47_tables_332_columns_types_keys_and_nullability(self):
        expected = {
            (r["table"], r["column"]): (
                r["postgresql_type"].replace("timestamptz", "timestamp with time zone"),
                r["nullable"] == "NO",
            )
            for r in rows("SchemaColumns.csv")
        }
        actual = self.query("""SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
            WHERE n.nspname IN ('evidence','mock_support') AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped""")
        from backend.database.schema import verify_supported

        verify_supported(self.cur)
        expected[("collection_attempts", "input_fingerprint")] = ("text", False)
        expected[("software_observations", "inventory_id")] = ("uuid", False)
        expected[("vulnerability_findings", "fixing_patch_reference")] = ("text", False)
        expected[("patches", "source_product_id")] = ("text", False)
        expected[("microsoft_tenants", "evidence_origin")] = ("text", True)
        for column in ("signature_status", "engine_status", "platform_status"):
            expected[("antivirus_observations", column)] = ("text", False)
        for column in ("os_architecture", "os_processor"):
            expected[("device_observations", column)] = ("text", False)
        additions = self.additive_input_tables()
        actual = [row for row in actual if row[0] not in additions]
        self.assertEqual(expected, {(t, c): (typ, nn) for t, c, typ, nn in actual})
        self.assertEqual(len(actual), len(expected))
        expected_pk = defaultdict(set)
        for r in rows("SchemaColumns.csv"):
            if "PK" in r["key"]:
                expected_pk[r["table"]].add(r["column"])
        actual_pk = defaultdict(set)
        for (
            t,
            c,
        ) in self.query("""SELECT r.relname,a.attname FROM pg_constraint k JOIN pg_class r ON r.oid=k.conrelid
          JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum=ANY(k.conkey)
          WHERE k.contype='p' AND n.nspname IN ('evidence','mock_support')"""):
            if t not in additions:
                actual_pk[t].add(c)
        self.assertEqual(expected_pk, actual_pk)

    def test_89_foreign_key_contracts(self):
        expected = {
            (r["table"], r["column"], r["target_table"], r["target_column"])
            for r in rows("SchemaRelationships.csv")
        }
        actual = self.query("""SELECT r.relname,a.attname,t.relname,b.attname,k.confdeltype
         FROM pg_constraint k JOIN pg_class r ON r.oid=k.conrelid JOIN pg_class t ON t.oid=k.confrelid
         JOIN pg_namespace n ON n.oid=r.relnamespace
         JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum=k.conkey[1]
         JOIN pg_attribute b ON b.attrelid=t.oid AND b.attnum=k.confkey[1]
         WHERE k.contype='f' AND n.nspname IN ('evidence','mock_support')""")
        expected.add(
            ("software_observations", "inventory_id", "software_inventory", "id")
        )
        additions = self.additive_input_tables()
        actual = [row for row in actual if row[0] not in additions]
        self.assertEqual(len(actual), len(expected))
        self.assertEqual(expected, {r[:4] for r in actual})
        self.assertTrue(all(r[4] == "a" for r in actual))
        # Exercise every FK on a populated source table with a non-existent target.
        tested = 0
        for t, col, target, target_col, _ in actual:
            schema = dict((table, schema) for schema, table in original_tables())[t]
            if not self.query(
                sql.SQL("SELECT 1 FROM {}.{} LIMIT 1").format(
                    sql.Identifier(schema), sql.Identifier(t)
                )
            ):
                continue  # six deferred tables intentionally remain unseeded
            typ = self.query(
                "SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s",
                (schema, t, col),
            )[0][0]
            value = str(uuid.uuid4()) if typ == "uuid" else "CVE-2099-9999999"
            self.reject(
                sql.SQL(
                    "UPDATE {}.{} SET {}=%s WHERE ctid=(SELECT ctid FROM {}.{} LIMIT 1)"
                ).format(
                    sql.Identifier(schema),
                    sql.Identifier(t),
                    sql.Identifier(col),
                    sql.Identifier(schema),
                    sql.Identifier(t),
                ),
                (value,),
            )
            tested += 1
        self.assertGreater(tested, 65)

    def test_277_rows_empty_deferred_and_mock_labels(self):
        from epss.baseline import verify

        verify(self.cur)
        fixture_counts = json.loads(FIXTURES.read_text())["tables"]
        for row in rows("SyntheticFixtureCounts.csv"):
            self.assertEqual(
                len(fixture_counts[row["table"]]), int(row["proposed_rows"])
            )
        self.assertEqual(
            sum(len(v) for v in json.loads(FIXTURES.read_text())["tables"].values()),
            277,
        )
        self.assertEqual(
            self.query(
                "SELECT count(*) FROM pg_tables WHERE schemaname='mock_support'"
            )[0][0],
            4,
        )
        self.assertEqual(
            self.query(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mock_support' AND c.relkind='r' AND obj_description(c.oid) LIKE 'Mock-only%'"
            )[0][0],
            4,
        )

    def test_12_view_column_contracts(self):
        expected = defaultdict(list)
        for r in rows("ViewColumns.csv"):
            expected[r["view"]].append(
                (
                    r["column"],
                    r["postgresql_type"].replace(
                        "timestamptz", "timestamp with time zone"
                    ),
                )
            )
        actual = defaultdict(list)
        for (
            view,
            col,
            typ,
        ) in self.query("""SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod)
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
          WHERE n.nspname='evidence' AND c.relkind='v' AND a.attnum>0 ORDER BY c.relname,a.attnum"""):
            actual[view].append((col, typ))
        self.assertEqual(dict(expected), dict(actual))
        for view in expected:
            self.query(
                sql.SQL("SELECT * FROM evidence.{}").format(sql.Identifier(view))
            )

    def test_example_query_counts(self):
        self.assertEqual(
            self.query(
                "SELECT count(*),count(DISTINCT cve_id),count(DISTINCT computer_id),count(DISTINCT(computer_id,cve_id)) FROM current_vulnerabilities"
            )[0],
            (4, 2, 2, 3),
        )
        self.assertEqual(
            self.query(
                "SELECT count(*),count(DISTINCT finding_id),count(DISTINCT(computer_id,cve_id)),count(DISTINCT cve_id) FROM known_fix_candidates"
            )[0],
            (5, 3, 2, 1),
        )
        for table, count in [
            ("findings_without_known_fix", 1),
            ("current_software", 5),
            ("vulnerability_history", 2),
            ("unresolved_classifications", 1),
        ]:
            self.assertEqual(self.query("SELECT count(*) FROM " + table)[0][0], count)
        self.cur.execute(
            "SELECT to_regclass('evidence_pipeline.notification_episodes')"
        )
        expected_notification_rows = 0
        if self.cur.fetchone()[0] is not None:
            expected_notification_rows = self.query(
                "SELECT coalesce(sum(failure_count),0) FROM evidence_pipeline.notification_episodes"
            )[0][0]
        self.assertEqual(
            self.query("SELECT count(*) FROM notification_details")[0][0],
            expected_notification_rows,
        )
        self.assertEqual(
            self.query(
                "SELECT count(*) FROM computers c WHERE NOT EXISTS(SELECT 1 FROM current_vulnerabilities v WHERE v.computer_id=c.id)"
            )[0][0],
            2,
        )
        self.assertEqual(
            sorted(
                r[0]
                for r in self.query(
                    "SELECT count(DISTINCT finding_id) FROM known_fix_candidates GROUP BY patch_id"
                )
            ),
            [1, 2, 2],
        )
        self.assertEqual(
            self.query(
                "SELECT count(DISTINCT id) FROM computers WHERE display_name='fixture-host'"
            )[0][0],
            2,
        )

    def test_shared_completeness_nine_cases(self):
        fixture = json.loads((DOCS / "CompletenessTestFixtures.json").read_text())
        for case in fixture["computer_cases"]:
            self.assertEqual(
                self.query(
                    "SELECT completeness,completeness_total FROM computer_evidence WHERE computer_id=%s",
                    (uid(case["computer_alias"]),),
                )[0],
                tuple(case["expected"].values()),
            )
        for case in fixture["boundary_cases"] + [fixture["zero_case"]]:
            cells = []
            args = [uid(case["definition"]), case["applicability_state"]]
            for cell in case["cells"]:
                kind = cell["value_kind"].replace("numeric", "number")
                cells.append(
                    "ROW(%s,%s,%s,%s,%s,NULL)::evidence.completeness_cell_input"
                )
                args.extend(
                    [
                        cell["field_key"],
                        kind,
                        cell["value"] if kind == "boolean" else None,
                        cell["value"] if kind == "number" else None,
                        cell["value"] if kind == "text" else None,
                    ]
                )
            actual = self.query(
                "SELECT completeness,completeness_total,100.0*completeness/NULLIF(completeness_total,0) FROM evidence.evaluate_completeness(%s,%s,ARRAY["
                + ",".join(cells)
                + "]::evidence.completeness_cell_input[])",
                args,
            )[0]
            self.assertEqual(
                actual[:2],
                (
                    case["expected"]["completeness"],
                    case["expected"]["completeness_total"],
                ),
            )
            if case["case_alias"] == "Z1":
                self.assertIsNone(actual[2])
        # Mutate source in a rolled-back transaction: views must recompute, not return fixture expectations.
        self.cur.execute(
            "UPDATE device_observations SET last_sync=NULL WHERE provider_device_id=%s",
            (uid("IntuneC1"),),
        )
        self.assertEqual(
            self.query(
                "SELECT completeness,completeness_total FROM computer_evidence WHERE computer_id=%s",
                (uid("C1"),),
            )[0],
            (4, 5),
        )
        self.assertEqual(
            self.query(
                "SELECT count(*) FROM completeness_evidence_cells WHERE populated AND computer_id=%s",
                (uid("C1"),),
            )[0][0],
            4,
        )

    def test_completeness_missing_whitespace_and_invalid_types(self):
        self.assertEqual(
            self.query(
                "SELECT completeness,completeness_total FROM evidence.evaluate_completeness(%s,'resolved',ARRAY[ROW('text_value','text',NULL,NULL,E' \\t\\n',NULL)::evidence.completeness_cell_input])",
                (uid("boundary-v1"),),
            )[0],
            (0, 3),
        )
        self.reject(
            "SELECT * FROM evidence.evaluate_completeness(%s,'resolved',ARRAY[ROW('boolean_flag','boolean',NULL,3,NULL,NULL)::evidence.completeness_cell_input])",
            (uid("boundary-v1"),),
        )
        self.reject(
            "SELECT * FROM evidence.evaluate_completeness(%s,'resolved',ARRAY[]::evidence.completeness_cell_input[])",
            (str(uuid.uuid4()),),
        )

    def test_failed_attempt_preserves_snapshot_and_source_times(self):
        row = self.query(
            "SELECT reporting_at,selected_collected_at,latest_outcome FROM computer_source_status WHERE computer_id=%s AND source_name='Intune'",
            (uid("C1"),),
        )[0]
        self.assertEqual((row[0].hour, row[1].hour, row[2]), (5, 8, "failure"))
        self.assertEqual(
            self.query(
                "SELECT defender_last_seen,intune_last_sync FROM computer_evidence WHERE computer_id=%s",
                (uid("C1"),),
            )[0][0].hour,
            6,
        )
        self.reject(
            "UPDATE mock_snapshot_selections SET collection_attempt_id=%s WHERE connection_id=%s",
            (uid("failure:Intune1"), uid("Intune1")),
        )
        self.reject(
            "UPDATE observation_receipts SET collection_attempt_id=%s WHERE id=(SELECT id FROM observation_receipts LIMIT 1)",
            (uid("success:Intune2"),),
        )
        self.reject(
            "UPDATE device_observations SET provider_device_id=%s WHERE provider_device_id=%s",
            (uid("DefenderC4"), uid("IntuneC1")),
        )

    def test_uniqueness_scores_and_patch_applicability(self):
        self.reject("INSERT INTO computers SELECT * FROM computers LIMIT 1")
        self.reject("UPDATE cvss_observations SET score=11")
        self.reject("UPDATE epss_observations SET probability=-1")
        self.reject(
            "UPDATE mock_fix_matches SET applicability_id=%s WHERE finding_id=%s",
            (uid("app:PB"), uid("F1")),
        )
        self.cur.execute("SAVEPOINT omit_epss")
        self.cur.execute("DELETE FROM epss_observations WHERE cve_id='CVE-2099-10002'")
        self.assertEqual(
            self.query(
                "SELECT c.score,e.probability,k.membership FROM vulnerabilities v LEFT JOIN cvss_observations c USING(cve_id) LEFT JOIN epss_observations e USING(cve_id) LEFT JOIN kev_observations k USING(cve_id) WHERE v.cve_id='CVE-2099-10002'"
            )[0],
            (0, None, False),
        )
        self.cur.execute("ROLLBACK TO SAVEPOINT omit_epss")

    def test_legacy_compatibility_and_patch_cycle(self):
        self.assertEqual(
            self.query("SELECT count(*) FROM mock_support.findings")[0][0], 3
        )
        self.reject(
            "INSERT INTO patch_replacements(id,patch_id,superseded_patch_id,receipt_id) SELECT %s,superseded_patch_id,patch_id,receipt_id FROM patch_replacements LIMIT 1",
            (str(uuid.uuid4()),),
        )
        self.reject(
            "SELECT * FROM evidence.evaluate_completeness(%s,NULL,ARRAY[]::evidence.completeness_cell_input[])",
            (uid("boundary-v1"),),
        )
        self.cur.execute(
            "UPDATE computer_source_links SET computer_id=%s WHERE provider_device_id=%s",
            (uid("C1"), uid("DefenderC2")),
        )
        self.assertEqual(
            self.query(
                "SELECT completeness,completeness_total,applicability_state FROM computer_evidence WHERE computer_id=%s",
                (uid("C1"),),
            )[0],
            (None, None, "unresolved"),
        )

    def test_query_grants_support_identity_aggregate(self):
        # The consolidated baseline owns these grants; queries do not repair them.
        self.cur.execute("SELECT to_regclass('evidence_pipeline.current_computers')")
        has_current_computers = self.cur.fetchone()[0] is not None
        self.cur.execute("SET LOCAL ROLE tm_mock_reader")
        self.assertEqual(
            self.query(
                "SELECT bool_or(value) FROM (VALUES (false),(true),(NULL)) AS facts(value)"
            ),
            [(True,)],
        )
        self.assertEqual(
            self.query(
                "SELECT bool_or(value) FROM (VALUES (false),(NULL)) AS facts(value)"
            ),
            [(False,)],
        )
        self.assertEqual(self.query("SELECT bool_or(NULL::boolean)"), [(None,)])
        if has_current_computers:
            self.cur.execute("SELECT * FROM evidence_pipeline.current_computers")
            self.cur.fetchall()
        self.reject("SELECT pg_read_file('/etc/passwd')")
        self.reject("DELETE FROM computers")

    def test_reader_grants_and_no_mutations(self):
        self.conn.close()
        self.conn = manage.connect(self.database, reader=True)
        self.cur = self.conn.cursor()
        self.assertEqual(self.query("SELECT count(*) FROM computer_evidence")[0][0], 4)
        self.assertEqual(self.query("SHOW statement_timeout")[0][0], "20s")
        for statement in [
            "DELETE FROM computers",
            "CREATE TABLE evidence.forbidden(x int)",
            "CREATE TEMP TABLE forbidden(x int)",
            "SET ROLE tm_mock_owner",
            "SET ROLE tm_mock_fixture",
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT pg_sleep(1)",
            "SELECT pg_notify('test','no')",
            "SELECT set_config('search_path','public',false)",
            "COPY computers TO '/tmp/triagemate-forbidden-export'",
            "CREATE EXTENSION postgres_fdw",
        ]:
            self.reject(statement)
        # Grants still deny writes even if a caller changes the session default.
        self.conn.rollback()
        self.cur.execute("SET default_transaction_read_only=off")
        self.conn.commit()
        self.reject("DELETE FROM computers")
        self.assertEqual(self.query("SELECT count(*) FROM computers")[0][0], 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
