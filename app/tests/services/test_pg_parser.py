"""Parser-boundary regressions, independent of database permission enforcement."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from app.services import pg_parser
from app.services.postgres_query import QueryError, validate


class ParserTests(unittest.TestCase):
    def test_default_library_location_is_preserved(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(pg_parser.library_path(), pg_parser.LIBRARY)
            self.assertEqual(
                pg_parser.LIBRARY,
                Path(__file__).resolve().parents[3]
                / "ui-engine/work/parser/libpg_query.so",
            )

    def test_explicit_retained_library_loads_in_fresh_process(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from app.services import pg_parser; print(pg_parser.parse_sql_json('SELECT 1'))",
            ],
            cwd=Path(__file__).resolve().parents[3],
            env={
                **os.environ,
                "TRIAGEMATE_PG_PARSER_LIBRARY": str(pg_parser.library_path()),
            },
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["version"], 160001)

    def test_invalid_override_never_falls_back_to_default(self):
        for value in (
            "",
            "libpg_query.so",
            "/nonexistent-triagemate-parser/libpg_query.so",
            str(Path(__file__).parent),
        ):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"TRIAGEMATE_PG_PARSER_LIBRARY": value}),
            ):
                with self.assertRaises(OSError):
                    pg_parser.library_path()

    def test_postgresql_16_tree(self):
        tree = json.loads(pg_parser.parse_sql_json("SELECT 1"))
        self.assertEqual(tree["version"], 160001)
        self.assertEqual(set(tree["stmts"][0]["stmt"]), {"SelectStmt"})

    def test_read_queries_and_quoted_delimiters(self):
        for sql in [
            "SELECT '; DELETE FROM computers' AS text",
            "SELECT $$; COMMIT;$$ AS text; -- DELETE FROM computers",
            "/* outer /* nested */ comment */ SELECT 1;",
            'SELECT 1 AS "DELETE;FROM"',
            "WITH x AS (SELECT 1 AS n) SELECT * FROM x",
            "WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<3) SELECT * FROM x",
            "VALUES (1), (2)",
            "SELECT 1 UNION ALL SELECT 2",
            "SELECT U&'d\\0061t' AS unicode_text",
        ]:
            with self.subTest(sql=sql):
                validate(sql)

    def test_rejects_writes_at_any_depth(self):
        for sql in [
            "DELETE FROM computers",
            "SELECT 1; SELECT 2",
            "EXPLAIN SELECT 1",
            "BEGIN READ ONLY",
            "SHOW search_path",
            "WITH x AS (INSERT INTO computers DEFAULT VALUES RETURNING *) SELECT * FROM x",
            "WITH x AS (UPDATE computers SET id=1 RETURNING *) SELECT * FROM x",
            "SELECT * FROM (WITH x AS (DELETE FROM computers RETURNING *) SELECT * FROM x) q",
            "SELECT 1 INTO TEMP nope",
            "SELECT * FROM computers FOR SHARE",
            "SELECT * FROM (SELECT * FROM computers FOR UPDATE) q",
            "WITH x AS (SELECT * FROM computers FOR KEY SHARE) SELECT * FROM x",
        ]:
            with self.subTest(sql=sql), self.assertRaises(QueryError) as raised:
                validate(sql)
            self.assertEqual(raised.exception.code, "readonly")

    def test_invalid_and_nul_input_fail_closed(self):
        for sql in [
            "",
            "-- comment",
            "SELECT (",
            "SELECT 'unterminated",
            "SELECT 1\0; DELETE FROM computers",
            "SELECT '\ud800'",
        ]:
            with self.subTest(sql=repr(sql)), self.assertRaises(QueryError):
                validate(sql)
        validate("SELECT 1")  # Failure cleanup does not poison the next parse.

    def test_missing_library_is_actionable(self):
        with patch.object(pg_parser, "library", side_effect=OSError("missing")):
            with self.assertRaises(QueryError) as raised:
                validate("SELECT 1")
        self.assertEqual(raised.exception.code, "parser_unavailable")
        self.assertIn("build_parser.py", str(raised.exception))

    def test_concurrent_success_and_error_cleanup(self):
        def check(index):
            if index % 2:
                with self.assertRaises(pg_parser.ParseError):
                    pg_parser.parse_sql_json("SELECT (")
            else:
                validate("SELECT $$synthetic ; data$$")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(check, range(200)))
