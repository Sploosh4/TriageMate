"""Legacy import remains restricted after adding public-source validation helpers."""

from backend.database import schema as database_schema

import json
from pathlib import Path
from uuid import uuid4

import pytest


from .test_store import db as db


def test_explicit_upgrade_restores_import_without_table_writes(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        for role in ("tm_epss_importer", "tm_epss_function"):
            cur.execute(
                "SELECT has_table_privilege(%s,'evidence.public_reference_observations','INSERT')",
                (role,),
            )
            assert cur.fetchone() == (False,)
        raw = json.loads(
            (
                Path(__file__).resolve().parents[1] / "fixtures/synthetic_epss_v1.json"
            ).read_bytes()
        )
        for item in raw["data"]:
            item["cve"] = "CVE-2099-" + str(uuid4().int)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_epss_importer")
        cur.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)",
            (str(uuid4()), json.dumps(raw).encode()),
        )
        result = cur.fetchone()[0]
        assert result["outcome"] == "success", result


@pytest.mark.parametrize(
    "function",
    [
        "pg_catalog.substring(text,text)",
        "evidence_pipeline.wasoc_source_allowed(text,text)",
    ],
)
def test_dependency_authority_drift_is_rejected(db, function):
    from psycopg2 import sql

    with db.cursor() as cur:
        database_schema.verify(cur)
        # Fixed test-owned function signatures, never operator-provided SQL.
        cur.execute(
            sql.SQL("REVOKE EXECUTE ON FUNCTION {} FROM tm_epss_function").format(
                sql.SQL(function)
            )
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
