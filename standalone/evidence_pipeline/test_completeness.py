"""Provisional device counts through the actual reader; synthetic changes roll back."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_devices import make
from .test_store import db as database_fixture

db = database_fixture


@pytest.fixture
def projection(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
    return db


def put(conn, snapshot, *, register=True):
    with conn.cursor() as cur:
        cur.execute("RESET ROLE")
        if register:
            authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    return persist_devices(conn, snapshot)


def read(conn, tenant):
    with conn.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT c.completeness,c.completeness_total,c.applicability_unknown_total "
            "FROM evidence_pipeline.current_completeness c JOIN evidence.microsoft_tenants t "
            "ON t.id=c.tenant_id WHERE t.external_tenant_id=%s ORDER BY computer_key",
            (tenant,),
        )
        counts = cur.fetchall()
        cur.execute(
            "SELECT field_key,value_state,value FROM evidence_pipeline.current_completeness_cells c "
            "JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id "
            "WHERE t.external_tenant_id=%s ORDER BY computer_key,field_key",
            (tenant,),
        )
        return counts, cur.fetchall()


def test_false_missing_identity_and_unknown_provider_are_distinct(projection):
    snapshot = make("Entra", [{"id": str(uuid4()), "isManaged": False}])
    put(projection, snapshot)
    counts, cells = read(projection, snapshot.scope.tenant_id)
    assert counts == [(2, 12, 22)]
    facts = {key: (state, value) for key, state, value in cells}
    assert facts["entra.managed_flag"] == ("present", False)
    assert facts["entra.compliant_flag"] == ("missing", None)
    assert facts["microsoft.registration_id"] == ("missing", None)
    assert facts["microsoft.source_device_type"] == ("missing", None)
    assert facts["defender.native_device_id"] == ("applicability_unknown", None)


def test_shared_identity_counts_once_and_zero_build_is_populated(projection):
    tenant, shared = str(uuid4()), str(uuid4())
    for source, fields in (
        ("Entra", {"deviceId": shared, "isManaged": False}),
        ("Intune", {"azureADDeviceId": shared, "deviceName": "   "}),
        ("Defender", {"aadDeviceId": shared, "osBuild": 0}),
    ):
        put(projection, make(source, [{"id": str(uuid4()), **fields}], tenant))
    counts, cells = read(projection, tenant)
    assert counts == [(6, 34, 0)]
    assert len(cells) == len({key for key, _, _ in cells}) == 34
    assert ("defender.os_build", "present", "0") in cells
    assert ("intune.display_name", "missing", None) in cells
    assert sum(key == "microsoft.registration_id" for key, _, _ in cells) == 1


def test_failed_refresh_preserves_counts_and_empty_success_removes_computer(projection):
    original = make("Defender", [{"id": "synthetic-completeness-device", "osBuild": 0}])
    put(projection, original)
    before = read(projection, original.scope.tenant_id)
    assert before[0] == [(2, 12, 22)]
    failed = replace(
        original,
        execution_id=str(uuid4()),
        finished_at=original.finished_at + timedelta(seconds=1),
        outcome="failure",
        complete=False,
        error_code="synthetic_failure",
        payload=b"",
    )
    put(projection, failed, register=False)
    assert read(projection, original.scope.tenant_id) == before
    put(
        projection,
        replace(
            original,
            execution_id=str(uuid4()),
            finished_at=original.finished_at + timedelta(seconds=2),
            payload=b"[]",
        ),
        register=False,
    )
    assert read(projection, original.scope.tenant_id) == ([], [])


def test_replayed_observation_does_not_multiply_cells(projection):
    original = make("Intune", [{"id": str(uuid4()), "operatingSystem": "Synthetic OS"}])
    put(projection, original)
    first = read(projection, original.scope.tenant_id)
    assert put(projection, original, register=False)["replayed"]
    assert read(projection, original.scope.tenant_id) == first
    changed = replace(
        original,
        execution_id=str(uuid4()),
        finished_at=original.finished_at + timedelta(seconds=1),
        payload=json.dumps(
            [
                {
                    "id": original.records()[0]["id"],
                    "operatingSystem": "Synthetic OS",
                    "osVersion": "1",
                }
            ]
        ).encode(),
    )
    put(projection, changed, register=False)
    counts, cells = read(projection, original.scope.tenant_id)
    assert counts == [(3, 14, 20)]
    assert len(cells) == len(first[1])


def test_equal_registration_ids_do_not_combine_different_tenants(projection):
    shared = str(uuid4())
    first = make("Entra", [{"id": str(uuid4()), "deviceId": shared}])
    second = make("Defender", [{"id": str(uuid4()), "aadDeviceId": shared}])
    put(projection, first)
    put(projection, second)
    assert read(projection, first.scope.tenant_id)[0] == [(2, 12, 22)]
    assert read(projection, second.scope.tenant_id)[0] == [(2, 12, 22)]


def test_ambiguous_same_provider_identity_preserves_separate_computers(projection):
    shared = str(uuid4())
    snapshot = make(
        "Entra",
        [{"id": str(uuid4()), "deviceId": shared} for _ in range(2)],
    )
    put(projection, snapshot)
    counts, cells = read(projection, snapshot.scope.tenant_id)
    assert counts == [(2, 12, 22), (2, 12, 22)]
    assert len(cells) == 68


def test_reader_has_only_select_on_completeness_views(projection):
    with projection.cursor() as cur:
        for name in (
            "completeness_definition",
            "current_completeness_cells",
            "current_completeness",
        ):
            cur.execute(
                "SELECT has_table_privilege('tm_mock_reader',%s,'SELECT'), "
                "has_table_privilege('tm_mock_reader',%s,'INSERT,UPDATE,DELETE')",
                ("evidence_pipeline." + name,) * 2,
            )
            assert cur.fetchone() == (True, False)


def test_manual_classification_does_not_invent_source_purpose(projection):
    snapshot = make("Entra", [{"id": str(uuid4()), "trustType": "ServerAd"}])
    put(projection, snapshot)
    before = read(projection, snapshot.scope.tenant_id)
    with projection.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        cur.execute(
            "SELECT id FROM evidence.provider_devices WHERE connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        device = cur.fetchone()[0]
        cur.execute(
            "SELECT evidence_pipeline.record_classification(%s,%s,'Server',%s,NULL)",
            (str(uuid4()), device, "Synthetic local classification acceptance"),
        )
    assert read(projection, snapshot.scope.tenant_id) == before
    assert ("microsoft.source_device_type", "missing", None) in before[1]
