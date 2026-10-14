"""Proposed v2 relationship migration: real constraints, transaction rollback only."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.store import persist_devices, insert
from standalone.evidence_pipeline.test_store import db as database_fixture
from standalone.evidence_pipeline.test_store import snapshot as snapshot_fixture

db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def exposure(db, snapshot):
    device = replace(snapshot, scope=replace(snapshot.scope, source="Intune"))
    app = replace(
        snapshot,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="software"),
        payload=b"[]",
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, device)
        persist_devices(db, device)
        authorize_connection(cur, app)
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        cur.execute(
            "SELECT id::text FROM evidence.provider_devices WHERE connection_id=%s",
            (device.scope.connection_id,),
        )
        provider = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (app.scope.connection_id, device.scope.connection_id),
        )
        insert(
            cur,
            "collection_attempts",
            {
                "id": app.execution_id,
                "connection_id": app.scope.connection_id,
                "started_at": app.started_at,
                "finished_at": app.finished_at,
                "outcome": "success",
                "complete": True,
                "revision": 1,
                "input_fingerprint": app.input_fingerprint,
            },
        )
        cur.execute(
            "INSERT INTO evidence_pipeline.exposure_snapshots(collection_attempt_id,input_connection_id,device_attempt_id) VALUES(%s,%s,%s)",
            (app.execution_id, app.scope.connection_id, device.execution_id),
        )
        revision, receipt, software, inventory = (str(uuid4()) for _ in range(4))
        insert(
            cur,
            "source_revisions",
            {
                "id": revision,
                "connection_id": app.scope.connection_id,
                "source_record_id": "synthetic-app",
                "collected_at": app.finished_at,
                "content_hash": "a" * 64,
                "origin": "synthetic",
                "licence_or_provenance": app.scope.provenance,
            },
        )
        insert(
            cur,
            "observation_receipts",
            {
                "id": receipt,
                "source_revision_id": revision,
                "collection_attempt_id": app.execution_id,
            },
        )
        insert(
            cur, "software", {"id": software, "product_name": "Synthetic application"}
        )
        cur.execute(
            "INSERT INTO evidence_pipeline.software_inventory VALUES(%s,%s,%s,%s,%s,0)",
            (inventory, app.execution_id, receipt, software, "synthetic-app"),
        )
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
    return dict(
        device=device,
        app=app,
        provider=provider,
        receipt=receipt,
        software=software,
        inventory=inventory,
    )


def add_link(cur, exposure):
    cur.execute("SET CONSTRAINTS ALL DEFERRED")
    cur.execute(
        "UPDATE evidence_pipeline.software_inventory SET reported_device_count=1 WHERE id=%s",
        (exposure["inventory"],),
    )
    insert(
        cur,
        "software_observations",
        {
            "id": str(uuid4()),
            "software_id": exposure["software"],
            "provider_device_id": exposure["provider"],
            "receipt_id": exposure["receipt"],
            "source_application_id": "synthetic-app",
            "inventory_id": exposure["inventory"],
        },
    )
    cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_empty_app_and_then_explicit_device_link_use_existing_tables(db, exposure):
    with db.cursor() as cur:
        add_link(cur, exposure)
        cur.execute(
            "SELECT count(*) FROM evidence.software_observations WHERE inventory_id=%s",
            (exposure["inventory"],),
        )
        assert cur.fetchone() == (1,)


def test_reported_count_cannot_disagree_with_links(db, exposure):
    with db.cursor() as cur, pytest.raises(psycopg2.Error, match="association count"):
        cur.execute(
            "UPDATE evidence_pipeline.software_inventory SET reported_device_count=2 WHERE id=%s",
            (exposure["inventory"],),
        )


def test_pinned_device_membership_survives_parent_deletion(db, exposure):
    with db.cursor() as cur:
        add_link(cur, exposure)
        with pytest.raises(psycopg2.Error, match="pinned source snapshot"):
            cur.execute(
                "DELETE FROM evidence.device_observations WHERE provider_device_id=%s",
                (exposure["provider"],),
            )


@pytest.mark.parametrize("change", ["source", "scope", "outcome"])
def test_invalid_parent_changes_are_rejected(db, exposure, change):
    with db.cursor() as cur, pytest.raises(psycopg2.Error):
        if change == "source":
            cur.execute(
                "UPDATE evidence.source_connections SET source_name='Entra' WHERE id=%s",
                (exposure["app"].scope.connection_id,),
            )
        elif change == "scope":
            cur.execute(
                "UPDATE evidence_pipeline.input_device_scopes SET device_connection_id=input_connection_id"
            )
        else:
            cur.execute(
                "UPDATE evidence.collection_attempts SET outcome='failure',complete=false WHERE id=%s",
                (exposure["device"].execution_id,),
            )
