from backend.database import schema as database_schema
from backend.database.schema import verify_supported as verify_schema
import pytest


from standalone.evidence_pipeline.test_store import db as database_fixture

db = database_fixture


def test_upgrade_is_explicit_and_repeatable_without_changing_manifest(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        before = cur.fetchone()
        database_schema.verify(cur)
        cur.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        assert cur.fetchone() == before


@pytest.mark.parametrize(
    "change",
    [
        "ALTER TABLE evidence_pipeline.input_device_scopes ADD COLUMN unexpected text",
        "CREATE POLICY bypass ON evidence.software_observations FOR INSERT TO tm_pipeline_writer WITH CHECK(true)",
        "ALTER TABLE evidence.software_observations DISABLE ROW LEVEL SECURITY",
        "ALTER FUNCTION evidence_pipeline.validate_exposure() SECURITY DEFINER",
    ],
)
def test_upgrade_signature_rejects_schema_and_authority_drift(db, change):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(change)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_retained_epss_importer_remains_usable(db):
    from pathlib import Path
    from uuid import uuid4

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_epss_importer")
        raw = (
            Path(__file__).resolve().parents[2]
            / "standalone/fixtures/synthetic_epss_v1.json"
        ).read_bytes()
        cur.execute(
            "SELECT epss_import.submit(%s::uuid,%s::bytea)", (str(uuid4()), raw)
        )
        assert cur.fetchone()[0]["outcome"] == "success"


def test_original_schema_verifier_accepts_only_recognized_upgrade(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        verify_schema(cur)
        cur.execute("ALTER TABLE evidence.software ADD COLUMN unexpected text")
        with pytest.raises(ValueError, match="schema/authority differs"):
            verify_schema(cur)
