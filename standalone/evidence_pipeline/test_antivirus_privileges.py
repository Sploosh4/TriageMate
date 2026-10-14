"""Explicit v11 repair, predecessor checks and legacy importer compatibility."""

from backend.database import schema as database_schema

from pathlib import Path
from uuid import uuid4

import pytest


from .test_store import db, snapshot  # noqa: F401
from .test_antivirus_store import antivirus_bound  # noqa: F401


def test_baseline_epss_has_no_antivirus_table_write_grants(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT has_table_privilege('tm_epss_importer','evidence.antivirus_observations','INSERT')"
        )
        assert cur.fetchone() == (False,)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_epss_importer")
        raw = (
            Path(__file__).resolve().parents[2]
            / "standalone/fixtures/synthetic_epss_v1.json"
        ).read_bytes()
        cur.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)", (str(uuid4()), raw)
        )
        assert cur.fetchone()[0]["outcome"] == "success"


@pytest.mark.parametrize(
    "change",
    [
        "GRANT EXECUTE ON FUNCTION pg_catalog.btrim(text) TO tm_epss_importer",
        "GRANT EXECUTE ON FUNCTION pg_catalog.btrim(text) TO tm_mock_reader WITH GRANT OPTION",
        "ALTER FUNCTION pg_catalog.btrim(text) OWNER TO tm_epss_importer",
        "ALTER TABLE evidence.antivirus_observations DISABLE TRIGGER exposure_provenance",
    ],
)
def test_baseline_refuses_unexpected_authority_drift(db, change):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_epss_import_with_generated_antivirus_evidence(db, antivirus_bound):  # noqa: F811
    from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure

    device, health = antivirus_bound
    persist_exposure(db, health, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_epss_importer")
        raw = (
            Path(__file__).resolve().parents[2]
            / "standalone/fixtures/synthetic_epss_v1.json"
        ).read_bytes()
        cur.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)", (str(uuid4()), raw)
        )
        assert cur.fetchone()[0]["outcome"] == "success"
