"""Bounded PostgreSQL SELECT execution. Never provisions or falls back to SQLite."""

import io
import json
import math
import select
import threading
import time
import uuid

import psycopg2
from psycopg2 import extensions
from app.services import pg_parser as parser

from backend.database.target import load_target
from backend.database.connections import connect_query_reader

DEADLINE = 20.0
MAX_RESULT = 45_000_000
TARGET = load_target()
CONFIG = TARGET.credential_directory / "credentials.json"


# Keep name-comparison groups small: the restricted reader does not execute
# PostgreSQL hashname/hashtext functions used for larger constant IN lists.
CATALOGUE_SQL = """
SELECT n.nspname::text AS schema_name, c.relname::text AS relation_name,
       c.relkind::text AS relation_kind,
       CASE WHEN n.nspname='evidence'
            AND d.description='Queryable evidence. Synthetic data only.'
            THEN 'Queryable evidence. Inspect source receipts for origin and provenance.'
            ELSE d.description END AS description,
       a.attname::text AS column_name,
       pg_catalog.format_type(a.atttypid, a.atttypmod) AS column_type,
       a.attnotnull AS not_null
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
LEFT JOIN pg_catalog.pg_description d ON d.objoid=c.oid AND d.objsubid=0
       AND d.classoid='pg_catalog.pg_class'::regclass
WHERE (n.nspname::text IN ('evidence','mock_support')
 OR (n.nspname::text='evidence_pipeline' AND (c.relname IN
 ('current_device_status','collection_status','current_software_inventory','current_software_devices','current_findings','current_classifications','current_computers','current_computer_links')
 OR c.relname::text IN ('completeness_definition','current_completeness_cells','current_completeness')
 OR c.relname::text IN ('software_completeness_definition','current_software_completeness_cells','current_software_completeness','software_collection_coverage',
 'vulnerability_completeness_definition','current_vulnerability_completeness_cells','current_vulnerability_completeness','vulnerability_collection_coverage')
 OR c.relname::text IN ('current_missing_patches','current_update_status','current_antivirus')
 OR c.relname::text IN ('current_public_epss_observations','current_public_kev_observations','current_public_cvss_observations','current_public_vulnerability_details','current_public_vulnerability_references')
 OR c.relname::text IN ('current_public_advisories','current_public_advisory_cves','current_public_recommendations','current_public_recommendation_cves','current_public_patches','current_public_patch_vulnerabilities','current_public_recommendation_patches')
 OR c.relname::text IN ('current_vulnerability_catalogue','current_assessment_baseline','vulnerability_event_history','assessment_device_references','current_defender_recommendations','recommendation_device_references','current_msrc_patch_fixes','current_msrc_patch_replacements')
 OR c.relname::text IN ('current_msrc_update_claims','current_cve_records','current_cve_contributions','current_osv_advisories','current_osv_affected_packages','current_osv_aliases','current_osv_relationships','osv_query_history')
 OR c.relname::text IN ('enrichment_request_status','current_public_references','current_attack_definitions','current_ctid_mappings','current_exploit_metadata','current_vendor_advisories','current_vendor_products','current_vendor_relationships')
 OR c.relname::text IN ('current_defender_missing_updates','current_defender_update_advice','defender_update_advice_history','current_github_advisories','current_github_repository_snapshot','current_cve_repository_snapshot','current_cve_repository_records','current_cve_repository_contributions')

 OR c.relname::text IN ('historical_event_completeness_definition','historical_event_completeness_cells','current_windows_runtime_releases','current_windows_inventory','current_windows_inventory_runs','windows_inventory_completeness_definition','current_windows_inventory_completeness_cells','current_native_inventory_identities','current_native_inventory_product_evaluations','current_native_inventory_accounting')
 OR c.relname::text IN ('current_os_classes','current_device_patch_candidates','current_device_patch_replacements','current_inventory_product_evaluations','current_inventory_identities','current_windows_cna_evaluations','current_windows_nvd_evaluations','current_vmware_tools_cna_evaluations','product_completeness_definition','current_public_completeness_cells','current_product_completeness_cells')
 OR c.relname::text IN ('current_native_advisory_facts','current_native_advisory_completeness_cells','product_collection_coverage','product_completeness_coverage','current_catalog_updates','current_catalog_replacement_claims')
 OR c.relname::text IN ('current_public_epss_observations','current_public_kev_observations','current_public_cvss_observations','current_public_vulnerability_details','current_public_vulnerability_references')
 OR c.relname::text IN ('current_ubuntu_repository_snapshot','current_ubuntu_repository_advisories','current_ubuntu_repository_packages','current_ubuntu_repository_relationships')) AND c.relkind='v'))
  AND c.relkind IN ('r','p','v','m') AND a.attnum>0 AND NOT a.attisdropped
  AND pg_catalog.has_table_privilege(c.oid,'SELECT')
ORDER BY n.nspname,c.relname,a.attnum
"""


class QueryError(Exception):
    def __init__(self, message, status=400, code="query_error"):
        super().__init__(message)
        self.status, self.code = status, code


def encoded(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")


def validate(source):
    if not isinstance(source, str) or not source.strip():
        raise QueryError("Enter a PostgreSQL SELECT query.")
    try:
        statements = json.loads(parser.parse_sql_json(source))["stmts"]
    except OSError as error:
        raise QueryError(
            "SQL parser unavailable. Run ui-engine/scripts/build_parser.py and restart the UI service.",
            503,
            "parser_unavailable",
        ) from error
    except (ValueError, RecursionError) as error:
        raise QueryError("PostgreSQL syntax error: " + str(error)) from error
    if len(statements) != 1 or set(statements[0]["stmt"]) != {"SelectStmt"}:
        raise QueryError(
            "Run one read-only SELECT statement at a time.", 403, "readonly"
        )

    def inspect(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if (key.endswith("Stmt") and key != "SelectStmt") or key in (
                    "intoClause",
                    "lockingClause",
                ):
                    raise QueryError(
                        "Writes, SELECT INTO and row locking are not allowed.",
                        403,
                        "readonly",
                    )
                inspect(value)
        elif isinstance(node, list):
            for value in node:
                inspect(value)

    try:
        inspect(statements)
    except RecursionError as error:
        raise QueryError("Query nesting is too deep. Simplify the SQL.") from error


class Job:
    def __init__(self, started):
        self.end = started + DEADLINE
        self.cancelled = threading.Event()

    def check(self):
        if self.cancelled.is_set():
            raise QueryError(
                "Query cancelled. Your SQL is unchanged.", 409, "cancelled"
            )
        if time.monotonic() >= self.end:
            raise QueryError(
                "Query exceeded 20 seconds. Filter or simplify the SQL and run it again.",
                408,
                "deadline",
            )

    def poll(self, connection):
        while True:
            self.check()
            state = connection.poll()
            if state == extensions.POLL_OK:
                return
            select.select(
                [connection] if state == extensions.POLL_READ else [],
                [connection] if state == extensions.POLL_WRITE else [],
                [],
                max(0, min(0.02, self.end - time.monotonic())),
            )


def cell(value, kind):
    if value is None:
        return None
    if kind in ("int2", "int4", "int8", "oid"):
        number = int(value)
        return (
            number
            if abs(number) <= 9007199254740991
            else {"type": kind, "value": value}
        )
    if kind == "bool":
        return value == "t"
    if kind in ("float4", "float8"):
        number = float(value)
        return number if math.isfinite(number) else {"type": kind, "value": value}
    if kind in ("text", "varchar", "bpchar", "name", "uuid", "unknown"):
        return value
    if kind.startswith("_") or kind in (
        "numeric",
        "json",
        "jsonb",
        "date",
        "time",
        "timetz",
        "timestamp",
        "timestamptz",
        "interval",
        "bytea",
    ):
        return {"type": kind, "value": value}
    raise QueryError(
        f"Unsupported PostgreSQL result type {kind}. Cast that column to text."
    )


class PostgreSQLQueries:
    def __init__(self):
        self.lock = threading.Lock()
        self.drained = threading.Condition(self.lock)
        self.closed = False
        self.jobs = {}
        self.used = {}  # short-lived IDs also close cancel-before-start races
        self.slots = threading.BoundedSemaphore(3)

    def close(self, timeout=5):
        """Reject new queries and wait boundedly for owned query cleanup."""
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 <= timeout <= 60
        ):
            raise ValueError("Query shutdown wait must be between zero and 60 seconds")
        with self.drained:
            self.closed = True
            for job in self.jobs.values():
                job.cancelled.set()
            return self.drained.wait_for(lambda: not self.jobs, timeout)

    @staticmethod
    def identifier(body):
        value = body.get("requestId")
        try:
            if str(uuid.UUID(value)) != value:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise QueryError("A canonical UUID requestId is required.") from None
        return value

    def cancel(self, body):
        identifier = self.identifier(body)
        with self.lock:
            self.prune()
            self.used[identifier] = time.monotonic()
            if identifier in self.jobs:
                self.jobs[identifier].cancelled.set()
        return {"requestId": identifier, "cancelled": True}

    def prune(self):
        now = time.monotonic()
        self.used = {key: stamp for key, stamp in self.used.items() if now - stamp < 60}

    def catalogue(self, body, started=None):
        # Fixed metadata query, with the same role, limits and cancellation registry.
        return self.execute(
            {"requestId": body.get("requestId"), "sql": CATALOGUE_SQL}, started
        )

    def execute(self, body, started=None):
        identifier = self.identifier(body)
        job = Job(time.monotonic() if started is None else started)
        with self.lock:
            if self.closed:
                raise QueryError("Application is shutting down.", 503, "shutting_down")
            self.prune()
            if identifier in self.jobs or identifier in self.used:
                raise QueryError(
                    "Request already used or cancelled. Run again with a new request.",
                    409,
                    "cancelled",
                )
            self.jobs[identifier] = job
        connection = None
        acquired = False
        try:
            if body.get("readonly", True) is not True:
                raise QueryError("SQL is strictly read-only.", 403, "readonly")
            validate(body.get("sql"))
            job.check()
            while not self.slots.acquire(timeout=0.02):
                job.check()
            acquired = True
            job.check()
            try:
                connection = connect_query_reader(TARGET, CONFIG)
                job.poll(connection)
            except (OSError, KeyError, ValueError, psycopg2.OperationalError) as error:
                raise QueryError(
                    "PostgreSQL is unavailable. Start the approved local database and retry; SQLite was not used.",
                    503,
                    "unavailable",
                ) from error
            cursor = connection.cursor()

            def run(sql):
                job.check()
                cursor.execute(sql)
                job.poll(connection)

            run("BEGIN READ ONLY")
            run(
                "SELECT oid,typname FROM pg_catalog.pg_type WHERE typnamespace='pg_catalog'::regnamespace"
            )
            kinds = dict(cursor.fetchall())
            extensions.register_type(
                extensions.new_type(tuple(kinds), "UI_RAW", lambda v, _: v), connection
            )
            # Parser admits exactly one SELECT. The database role and transaction are separate guards.
            run("DECLARE ui_result NO SCROLL CURSOR FOR " + body["sql"])
            run("FETCH FORWARD 0 FROM ui_result")
            columns = [
                {
                    "name": item.name,
                    "type": kinds.get(item.type_code, "unsupported"),
                    "oid": item.type_code,
                }
                for item in cursor.description
            ]
            metadata = {
                "requestId": identifier,
                "engine": "PostgreSQL",
                "columns": [c["name"] for c in columns],
                "columnTypes": columns,
                "truncated": False,
                "changed": 0,
                "editable": False,
            }
            output = io.BytesIO()

            def append(raw):
                job.check()
                if output.tell() + len(raw) > MAX_RESULT:
                    raise QueryError(
                        "Result exceeds 45,000,000 UTF-8 JSON bytes including metadata. Select fewer or smaller values and run again.",
                        413,
                        "result_limit",
                    )
                output.write(raw)

            append(encoded(metadata)[:-1] + b',"rows":[')

            def write_value(value):
                if isinstance(value, str):
                    append(b'"')
                    for offset in range(0, len(value), 8192):
                        append(encoded(value[offset : offset + 8192])[1:-1])
                    append(b'"')
                elif isinstance(value, dict):
                    append(b"{")
                    for index, (key, item) in enumerate(value.items()):
                        if index:
                            append(b",")
                        write_value(key)
                        append(b":")
                        write_value(item)
                    append(b"}")
                else:
                    append(encoded(value))

            first = True
            while True:
                run("FETCH FORWARD 1 FROM ui_result")
                row = cursor.fetchone()
                if row is None:
                    break
                if not first:
                    append(b",")
                append(b"[")
                for index, value in enumerate(row):
                    if index:
                        append(b",")
                    write_value(cell(value, columns[index]["type"]))
                append(b"]")
                first = False
            append(b"]}")
            job.check()
            return output.getvalue()
        except psycopg2.Error as error:
            job.check()
            if error.pgcode in ("57014", "55P03"):
                raise QueryError(
                    "Query exceeded 20 seconds. Filter or simplify the SQL and run again.",
                    408,
                    "deadline",
                ) from error
            message = error.diag.message_primary or "PostgreSQL query failed."
            raise QueryError(
                message + " Check the SQL and run again.",
                403 if error.pgcode in ("42501", "25006") else 400,
            ) from error
        finally:
            try:
                if connection is not None:
                    try:
                        if connection.isexecuting():
                            connection.cancel()
                    except psycopg2.Error:
                        # cancel() can fail while an asynchronous connection is
                        # still starting. Preserve the original request error.
                        pass
                    finally:
                        try:
                            connection.close()
                        except psycopg2.Error:
                            pass
            finally:
                if acquired:
                    self.slots.release()
                with self.lock:
                    self.jobs.pop(identifier, None)
                    self.used[identifier] = time.monotonic()
                    self.drained.notify_all()
