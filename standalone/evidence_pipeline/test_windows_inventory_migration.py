"""Explicit additive upgrade and drift rejection for read-only Windows inventory."""

from backend.database import schema as database_schema

import pytest

from .test_store import db as db


def test_upgrade_is_idempotent_and_all_previous_registration_gates_accept_it(db):

    from standalone.evidence_pipeline.persistence.store import require_input_migration

    with db.cursor() as cur:
        database_schema.verify(cur)
        for kind in ("update-status", "antivirus", "catalogue"):
            require_input_migration(cur, kind)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute("SELECT * FROM evidence_pipeline.current_windows_inventory LIMIT 0")
        assert "facts" in [column.name for column in cur.description]
        cur.execute(
            "SELECT * FROM evidence_pipeline.current_windows_inventory_runs LIMIT 0"
        )
        assert "record_count" in [column.name for column in cur.description]


@pytest.mark.parametrize("drift", ["grant", "trigger", "binding"])
def test_upgrade_rejects_authority_and_integrity_drift(db, drift):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if drift == "grant":
            cur.execute(
                "GRANT UPDATE ON evidence_pipeline.windows_inventory_bindings TO tm_pipeline_writer"
            )
        elif drift == "trigger":
            cur.execute(
                "ALTER TABLE evidence_pipeline.windows_inventory_observations DISABLE TRIGGER windows_inventory_records_insert_check"
            )
        else:
            cur.execute(
                "ALTER TABLE evidence_pipeline.windows_inventory_bindings DROP CONSTRAINT windows_inventory_bindings_device_connection_id_fkey"
            )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
