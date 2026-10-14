"""Explicit original synthetic fixture loading for fresh verification databases.

These records are never loaded for an empty/evidence-only installation. The
payload retains its synthetic label and the accepted original fixture identities.
"""

import json
from pathlib import Path

from psycopg2 import sql
from psycopg2.extensions import cursor

FIXTURES = Path(__file__).with_name("baseline") / "fixtures.json"
MOCK_TABLES = frozenset(
    {
        "completeness_definitions",
        "completeness_fields",
        "mock_snapshot_selections",
        "mock_fix_matches",
    }
)


def seed(cur: cursor) -> None:
    """Load only an empty fixture scope, with immediate integrity enforcement.

    The fresh installer owns grants and the surrounding transaction. Any error
    requires rollback; this function never repairs, truncates or reseeds data.
    """
    payload = json.loads(FIXTURES.read_text())
    if (
        payload.get("origin") != "synthetic"
        or payload.get("version") != 1
        or not isinstance(payload.get("tables"), dict)
    ):
        raise ValueError("Expected explicitly synthetic version-one fixtures")
    cur.execute("SELECT current_user,current_setting('role')")
    caller = cur.fetchone()
    if caller is None or caller[0] != "tm_mock_owner":
        raise ValueError("Explicit fixture installation owner required")
    for table in payload["tables"]:
        namespace = "mock_support" if table in MOCK_TABLES else "evidence"
        cur.execute(
            sql.SQL("SELECT EXISTS(SELECT 1 FROM {})").format(
                sql.Identifier(namespace, table)
            )
        )
        if cur.fetchone() != (False,):
            raise ValueError("Synthetic fixture scope already contains records")
    # The historical setup seeds before builtin hardening. The role is NOLOGIN
    # without members and newly created inside this transaction. Retain that
    # seeding ability privately, then restore its exact final function grants.
    cur.execute("""
        SELECT p.oid::regprocedure::text,a.is_grantable
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) a
        WHERE n.nspname IN ('pg_catalog','evidence','mock_support')
          AND a.grantee=(SELECT oid FROM pg_roles WHERE rolname='tm_mock_fixture')
    """)
    original_functions = cur.fetchall()
    cur.execute(
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pg_catalog,evidence,mock_support TO tm_mock_fixture"
    )
    temporary_policies = []
    for table, records in payload["tables"].items():
        if records:
            namespace = "mock_support" if table in MOCK_TABLES else "evidence"
            relation = sql.Identifier(namespace, table)
            cur.execute(
                sql.SQL(
                    "CREATE POLICY triagemate_install_fixture ON {} TO tm_mock_fixture USING (true) WITH CHECK (true)"
                ).format(relation)
            )
            temporary_policies.append((namespace, table))
    cur.execute("SET LOCAL ROLE tm_mock_fixture")
    for table, records in payload["tables"].items():
        namespace = "mock_support" if table in MOCK_TABLES else "evidence"
        for record in records:
            cur.execute(
                sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(namespace, table),
                    sql.SQL(",").join(map(sql.Identifier, record)),
                    sql.SQL(",").join(sql.Placeholder() for _ in record),
                ),
                list(record.values()),
            )
    cur.execute("SELECT set_config('role',%s,true)", (caller[1],))
    # Later deferred triggers inspect protected pipeline provenance. Validate
    # them as the installation owner without granting those tables to fixtures.
    cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
    for namespace, table in temporary_policies:
        cur.execute(
            sql.SQL("DROP POLICY triagemate_install_fixture ON {}").format(
                sql.Identifier(namespace, table)
            )
        )
    cur.execute(
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pg_catalog,evidence,mock_support FROM tm_mock_fixture"
    )
    for function, grantable in original_functions:
        cur.execute(
            sql.SQL("GRANT EXECUTE ON FUNCTION {} TO tm_mock_fixture{}").format(
                sql.SQL(function), sql.SQL(" WITH GRANT OPTION" if grantable else "")
            )
        )
    cur.execute(
        "INSERT INTO evidence.source_connections(id,source_name,input_kind,collector_reference,scope_reference) VALUES('086b7bfe-d067-4213-9681-97b7ebf2b5c7','Synthetic EPSS','epss','triagemate-synthetic-epss-v1','offline-synthetic-epss-v1')"
    )
