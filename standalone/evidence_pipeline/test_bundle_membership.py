"""Membership integrity, scope isolation and unchanged inventory completeness."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4
import json

import psycopg2
import pytest


from .test_store import db as db, snapshot as snapshot
from .test_resource_package_migration import save
from standalone.windows_inventory.test_store import configured as configured
from standalone.windows_inventory.test_bundle_manifest import envelope, member
from standalone.windows_inventory.store import register
from standalone.evidence_pipeline.persistence.store import atomic


def records(**changes):
    m, p = envelope()["records"]
    p["user_states"] = [dict(sid="S-1-5-21-1-2-3-1000", install_state="Installed")]
    app = p | dict(
        native_id="synthetic-main",
        version=m["version"],
        architecture=m["architecture"],
        is_bundle=False,
        resource_id=m["resource_id"],
    )
    del app["bundle_manifest"]
    app.update(changes)
    return [m, p, app]


def read(db, selected):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT association_state,candidate_count,shared_installed_user,applicability FROM evidence_pipeline.current_windows_bundle_members WHERE connection_id=%s",
            (selected.connection_id,),
        )
        return cur.fetchall()


def test_restricted_membership_is_separate_from_inventory_and_completeness(
    db, configured
):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    save(db, configured, records())
    assert read(db, configured[1]) == [("associated", 1, True, "unknown")]
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s",
            (configured[1].connection_id,),
        )
        assert cur.fetchone() == (2,)
        cur.execute(
            "SELECT DISTINCT kind FROM evidence_pipeline.current_windows_inventory_completeness_cells WHERE connection_id=%s",
            (configured[1].connection_id,),
        )
        assert cur.fetchall() == [("appx",)]
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_windows_inventory_evidence WHERE connection_id=%s",
            (configured[1].connection_id,),
        )
        assert cur.fetchone() == (3,)


@pytest.mark.parametrize(
    "change",
    [
        {"version": "9.9.9.9"},
        {"publisher": "Other publisher"},
        {"architecture": "arm64"},
        {"resource_id": "another-resource"},
        {"resource_id": None},
        {"is_bundle": True},
        {"family_name": "Other_family"},
        {"name": "Other.App"},
    ],
)
def test_conflicting_observed_package_never_associates(db, configured, change):
    with db.cursor() as cur:
        database_schema.verify(cur)
    value = records(**change)
    if change.get("resource_id", "") is None:
        del value[2]["resource_id"]
    save(db, configured, value)
    assert read(db, configured[1]) == [("unknown", 0, None, "unknown")]


def test_stub_and_duplicate_package_candidates_remain_unknown(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    value = records()
    value[0] = member(is_stub=True)
    save(db, configured, value)
    assert read(db, configured[1]) == [("unknown", 1, None, "unknown")]
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
    value = records()
    value.append(value[2] | dict(native_id="different-native-id"))
    save(db, configured, value, later=True)
    assert read(db, configured[1]) == [("unknown", 2, None, "unknown")]


def test_other_collection_scope_cannot_supply_missing_member(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    save(db, configured, records())
    device, selected, binding = configured
    other = replace(selected, connection_id=str(uuid4()))
    register(db, other, binding, device.scope.connection_id, device.records()[0]["id"])
    save(db, configured, records()[:2], selected=other)
    assert read(db, other) == [("unknown", 0, None, "unknown")]


@pytest.mark.parametrize(
    "key,value",
    [
        ("manifest_sha256", "b" * 64),
        ("bundle_version", "9.9.9.9"),
        ("member_index", 2),
        ("publisher", "Other publisher"),
        ("bundle_native_id", "other-bundle"),
        ("member_type", "invented"),
        ("is_stub", "false"),
    ],
)
def test_database_rejects_member_mutation_even_bypassing_python(
    db, configured, key, value
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    save(db, configured, records())
    with db.cursor() as cur:
        with pytest.raises(psycopg2.Error), atomic(cur):
            cur.execute(
                "UPDATE evidence_pipeline.windows_inventory_observations SET facts=jsonb_set(facts,%s,%s::jsonb) WHERE kind='appx_bundle_member'",
                ([key], json.dumps(value)),
            )


def test_database_rejects_changed_parent_count_and_missing_summary(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    save(db, configured, records())
    with db.cursor() as cur:
        for sql in (
            "facts-'bundle_manifest'",
            "jsonb_set(facts,'{bundle_manifest,member_count}','0'::jsonb)",
        ):
            with pytest.raises(psycopg2.Error), atomic(cur):
                cur.execute(
                    "UPDATE evidence_pipeline.windows_inventory_observations SET facts="
                    + sql
                    + " WHERE kind='appx' AND facts->'is_bundle'='true'::jsonb"
                )


def test_migration_idempotence_and_reader_cannot_write(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        with pytest.raises(psycopg2.Error), atomic(cur):
            cur.execute("DELETE FROM evidence_pipeline.windows_inventory_observations")


def test_prior_snapshot_cannot_supply_a_current_member(db, configured):
    with db.cursor() as cur:
        database_schema.verify(cur)
    save(db, configured, records())
    save(db, configured, records()[:2], later=True)
    assert read(db, configured[1]) == [("unknown", 0, None, "unknown")]


@pytest.mark.parametrize(
    "change",
    [
        {"version": "65536.0.0.0"},
        {"bundle_version": "1.2.3.65536"},
        {"native_id": "invented"},
        {"member_index": 1.5},
    ],
)
def test_database_member_field_validation_matches_source_contract(db, change):
    value = member() | change
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT evidence_pipeline.valid_bundle_member(%s::jsonb)",
            (json.dumps(value),),
        )
        assert cur.fetchone() == (False,)
