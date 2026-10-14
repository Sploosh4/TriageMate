"""Synthetic resource associations preserve scope/history and ambiguous parents."""

from backend.database import schema as database_schema

import io
import json
from dataclasses import replace
from uuid import uuid4

import pytest

from .test_store import db as db, snapshot as snapshot
from standalone.windows_inventory.test_store import configured as configured
from standalone.windows_inventory.test_contract import sample
from standalone.windows_inventory.staging import stage
from standalone.windows_inventory.snapshot import InventoryAttempt
from standalone.windows_inventory.store import persist, register


def pair():
    parent = sample()["records"][1] | dict(
        version="1.2.3.4",
        is_bundle=False,
        user_states=[dict(sid="S-1-12-1-11-22-33-44", install_state="Installed")],
    )
    resource = parent | dict(
        native_id="synthetic-resource", architecture="Neutral", is_resource_package=True
    )
    return resource, parent


@pytest.fixture
def matches(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")

        def call(resource, parent):
            cur.execute(
                "SELECT evidence_pipeline.resource_package_pair(%s::jsonb,%s::jsonb)",
                (
                    json.dumps(resource | {"source": "Windows inventory"}),
                    json.dumps(parent | {"source": "Windows inventory"}),
                ),
            )
            return cur.fetchone()[0]

        yield call


def test_exact_resource_family_is_not_an_architecture_or_version_guess(matches):
    resource, parent = pair()
    assert matches(resource, parent)
    assert matches(resource | {"architecture": "X64"}, parent)


@pytest.mark.parametrize("side", ["resource", "parent"])
@pytest.mark.parametrize(
    "change",
    [
        {"name": "different"},
        {"publisher": "different"},
        {"family_name": "different"},
        {"version": "1.2.3.5"},
        {"version": None},
        {"version": "1.2"},
        {"native_id": ""},
        {"is_bundle": True},
        {"is_bundle": None},
        {"is_framework": True},
        {"is_resource_package": None},
        {"kind": "registry"},
        {"architecture": "unsupported"},
    ],
)
def test_missing_and_conflicting_identity_never_produces_a_pair(matches, side, change):
    resource, parent = pair()
    if side == "resource":
        resource |= change
    else:
        parent |= change
    assert not matches(resource, parent)


def test_legacy_observation_without_bundle_flag_remains_unknown(matches):
    resource, parent = pair()
    del parent["is_bundle"]
    assert not matches(resource, parent)


def test_non_neutral_resource_cannot_cross_architecture(matches):
    resource, parent = pair()
    assert not matches(resource | {"architecture": "Arm64"}, parent)


def save(db, configured, records, *, later=False, selected=None):
    device, original, binding = configured
    selected = selected or original
    data = sample() | dict(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
        records=records,
        record_count=len(records),
    )
    if later:
        data.update(
            started_at="2026-09-19T00:00:02Z", finished_at="2026-09-19T00:00:03Z"
        )
    with stage(io.BytesIO(json.dumps(data).encode()), binding) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)


def read(db, selected):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT association_state,candidate_count,parent_receipt_ids,shared_installed_user,applicability FROM evidence_pipeline.current_native_resource_packages WHERE connection_id=%s",
            (selected.connection_id,),
        )
        return cur.fetchall()


@pytest.mark.parametrize("duplicate", [False, True])
def test_bundles_excluded_and_multiple_main_packages_remain_ambiguous(
    db, configured, duplicate
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    resource, parent = pair()
    records = [
        resource,
        parent,
        parent | dict(native_id="synthetic-bundle", is_bundle=True),
    ]
    if duplicate:
        records.append(parent | dict(native_id="synthetic-other-main"))
    save(db, configured, records)
    rows = read(db, configured[1])
    assert len(rows) == 1
    state, count, receipts, shared, applicability = rows[0]
    assert state == ("unknown" if duplicate else "associated")
    assert count == len(receipts) == (2 if duplicate else 1)
    assert shared is (None if duplicate else True)
    assert applicability == "unknown"


def test_family_association_is_separate_from_shared_installed_user(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    resource, parent = pair()
    resource["user_states"] = [dict(sid="S-1-12-1-11-22-33-44", install_state="Staged")]
    save(db, configured, [resource, parent])
    row = read(db, configured[1])[0]
    assert row[0] == "associated" and row[3] is False and row[4] == "unknown"


def test_old_collection_parent_cannot_fill_current_snapshot(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    resource, parent = pair()
    save(db, configured, [resource, parent])
    save(db, configured, [resource], later=True)
    row = read(db, configured[1])[0]
    assert row[:3] == ("unknown", 0, [])


def test_other_collection_scope_cannot_supply_parent(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    device, selected, binding = configured
    other = replace(selected, connection_id=str(uuid4()))
    register(db, other, binding, device.scope.connection_id, device.records()[0]["id"])
    resource, parent = pair()
    save(db, configured, [resource])
    save(db, configured, [parent], selected=other)
    assert read(db, selected)[0][:3] == ("unknown", 0, [])


def test_migration_idempotence_and_authority_drift(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.resource_package_pair(jsonb,jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
