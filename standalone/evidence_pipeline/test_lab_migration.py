"""Explicit lab upgrade and exact legacy schema projection; all tests roll back."""

from backend.database import schema as database_schema

import pytest

from .test_store import db as database_fixture


db = database_fixture


def test_repeat_upgrade_and_disabled_trigger_drift(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "ALTER TABLE evidence.source_revisions DISABLE TRIGGER pipeline_lab_revision"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


def test_earlier_upgrade_commands_verify_without_reapplying(db):

    with db.cursor() as cursor:
        database_schema.verify(cursor)


def test_original_schema_and_fixture_verifiers_accept_only_explicit_change(db):
    from .test_public_migration import (
        test_upgrade_repeat_and_legacy_schema_verification,
    )
    from .test_attribution import verify as verify_data

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        verify_data(cursor)
    test_upgrade_repeat_and_legacy_schema_verification(db)


def test_lab_and_synthetic_devices_keep_separate_identities_and_replay(db):
    from dataclasses import replace
    from datetime import datetime, timezone
    from uuid import uuid4
    import json
    from .contracts import SourceScope, Snapshot
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.store import persist_devices

    now = datetime.now(timezone.utc)
    tenant = str(uuid4())
    raw = json.dumps(
        [
            {
                "id": str(uuid4()),
                "deviceId": str(uuid4()),
                "displayName": "Explicitly synthetic lab fixture",
            }
        ]
    ).encode()
    synthetic = Snapshot(
        SourceScope(
            str(uuid4()),
            "Entra",
            "devices",
            "synthetic-test",
            "synthetic",
            "Synthetic test",
            tenant,
        ),
        str(uuid4()),
        now,
        now,
        "success",
        True,
        raw,
    )
    lab = replace(
        synthetic,
        execution_id=str(uuid4()),
        scope=replace(synthetic.scope, connection_id=str(uuid4()), origin="lab"),
    )
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, synthetic)
        authorize_connection(cursor, lab)
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_devices(db, synthetic)
    persist_devices(db, lab)
    assert persist_devices(db, lab)["replayed"]
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT count(DISTINCT tenant_id) FROM evidence.source_connections WHERE id IN (%s,%s)",
            (synthetic.scope.connection_id, lab.scope.connection_id),
        )
        assert cursor.fetchone() == (2,)
        cursor.execute(
            "SELECT DISTINCT origin FROM evidence.source_revisions WHERE connection_id=%s",
            (lab.scope.connection_id,),
        )
        assert cursor.fetchall() == [("lab",)]
        cursor.execute("RESET SESSION AUTHORIZATION")
        from .test_attribution import verify as verify_data

        verify_data(cursor)


@pytest.mark.parametrize("source", ("Intune", "Defender"))
def test_lab_exposure_persists_with_bound_device_snapshot(db, source):
    from dataclasses import replace
    from datetime import datetime, timezone
    from uuid import uuid4
    import json
    from .contracts import SourceScope, Snapshot
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.store import persist_devices
    from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
    from .test_exposure_store import inventory

    now = datetime.now(timezone.utc)
    device = Snapshot(
        SourceScope(
            str(uuid4()),
            source,
            "devices",
            "synthetic-test",
            "lab",
            "Synthetic test",
            str(uuid4()),
        ),
        str(uuid4()),
        now,
        now,
        "success",
        True,
        json.dumps([{"id": str(uuid4())}]).encode(),
    )
    child = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="software" if source == "Intune" else "findings",
        ),
    )
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        authorize_connection(cursor, device)
        authorize_connection(cursor, child)
        cursor.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (child.scope.connection_id, device.scope.connection_id),
        )
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_devices(db, device)
    if source == "Intune":
        child, links = inventory((device, child))
    else:
        links = None
        child = replace(
            child,
            payload=json.dumps(
                [
                    {
                        "id": "synthetic-finding",
                        "machineId": device.records()[0]["id"],
                        "cveId": "CVE-2026-999999",
                        "productName": "Synthetic product",
                        "productVersion": "1",
                        "fixingKbId": "KB-SYNTHETIC",
                    }
                ]
            ).encode(),
        )
    result = persist_exposure(db, child, device.execution_id, links)
    assert result["records"] == (2 if source == "Intune" else 1)
    assert persist_exposure(db, child, device.execution_id, links)["replayed"]


def test_original_fixture_tenant_cannot_be_relabelled_as_lab(db):
    import json
    from backend.database.fixtures import FIXTURES
    from .test_attribution import verify as verify_data

    original = json.loads(FIXTURES.read_text())["tables"]["microsoft_tenants"][0]["id"]
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "UPDATE evidence.microsoft_tenants SET evidence_origin='lab' WHERE id=%s",
            (original,),
        )
        with pytest.raises(AssertionError, match="Original tenant origin changed"):
            verify_data(cursor)
