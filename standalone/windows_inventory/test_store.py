"""Actual PostgreSQL authority, pinned-device, replay and rollback checks."""

from contextlib import contextmanager
from dataclasses import replace
import io
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    ReplayConflict,
    atomic,
)
from standalone.evidence_pipeline.test_store import db as db, snapshot as snapshot

from .contract import DeviceBinding
from .snapshot import InventoryAttempt
from .staging import stage
from .store import register, persist
from .test_contract import sample
from .test_snapshot import scope


@pytest.fixture
def configured(db, snapshot, request):
    origin = getattr(request, "param", "synthetic")
    snapshot = replace(snapshot, scope=replace(snapshot.scope, origin=origin))
    with db.cursor() as cur:
        from backend.database.schema import verify

        verify(cur)
        authorize_connection(cur, snapshot)
    persist_devices(db, snapshot)
    binding = DeviceBinding(
        str(uuid4()), snapshot.scope.tenant_id, snapshot.records()[0]["deviceId"]
    )
    selected = replace(
        scope(),
        origin=origin,
        tenant_id=binding.tenant_id,
        scope_reference="entra-device:" + binding.device_id,
    )
    register(
        db, selected, binding, snapshot.scope.connection_id, snapshot.records()[0]["id"]
    )
    return snapshot, selected, binding


@contextmanager
def inventory(selected, binding, *, execution_id=None, empty=False, later=False):
    data = sample()
    data.update(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
    )
    if empty:
        data.update(records=[], record_count=0)
    if later:
        data.update(
            started_at="2026-09-19T00:00:02Z", finished_at="2026-09-19T00:00:03Z"
        )
    with stage(io.BytesIO(json.dumps(data).encode()), binding) as staged:
        attempt = InventoryAttempt.from_staged(
            selected, execution_id or str(uuid4()), staged
        )
        yield attempt, staged


@pytest.mark.parametrize("configured", ["synthetic", "lab"], indirect=True)
def test_restricted_writer_persists_replays_and_reader_retains_source_facts(
    db, configured
):
    device, selected, binding = configured
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    with inventory(selected, binding) as (attempt, staged):
        assert persist(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        ) == dict(replayed=False, records=2, complete=True)
        assert persist(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )["replayed"]
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT source_name,tenant_id,device_attempt_id::text,kind,version,facts FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s ORDER BY kind",
                (selected.connection_id,),
            )
            rows = cur.fetchall()
            assert len(rows) == 2
            assert all(
                row[:3] == ("Windows inventory", binding.tenant_id, device.execution_id)
                for row in rows
            )
            assert rows[0][5]["user_states"][0]["install_state"] == "Staged"
            assert rows[1][5]["system_component"] == 0
            assert all(row[4] == "01.002.0" for row in rows)


def test_wrong_device_snapshot_and_changed_machine_do_not_publish(db, configured):
    device, selected, binding = configured
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    with inventory(selected, binding) as (attempt, staged):
        with pytest.raises(ValueError, match="pinned device"):
            persist(db, attempt, staged=staged, device_attempt_id=str(uuid4()))
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                (attempt.execution_id,),
            )
            assert cur.fetchone()[0] == 0
    with inventory(selected, replace(binding, machine_guid=str(uuid4()))) as (
        attempt,
        staged,
    ):
        with pytest.raises(ValueError, match="machine identity"):
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)


def test_rebinding_rejected_and_complete_empty_replaces_current_records(db, configured):
    device, selected, binding = configured
    with pytest.raises(ReplayConflict, match="binding changed"):
        register(
            db,
            selected,
            replace(binding, machine_guid=str(uuid4())),
            device.scope.connection_id,
            device.records()[0]["id"],
        )
    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    with inventory(selected, binding, empty=True, later=True) as (attempt, staged):
        assert (
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)[
                "records"
            ]
            == 0
        )
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s",
            (selected.connection_id,),
        )
        assert cur.fetchone()[0] == 0

        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT record_count,coverage->>'unloaded_user_hives',coverage->>'portable_applications' FROM evidence_pipeline.current_windows_inventory_runs WHERE connection_id=%s",
            (selected.connection_id,),
        )
        assert cur.fetchone() == (0, "not-read", "not-enumerated")


def test_repeated_collection_retains_receipts_without_merging_source_kinds(
    db, configured
):
    device, selected, binding = configured
    for later in (False, True):
        with inventory(selected, binding, later=later) as (attempt, staged):
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*),count(DISTINCT v.id) FROM evidence.source_revisions v JOIN evidence.observation_receipts r ON r.source_revision_id=v.id WHERE v.connection_id=%s",
            (selected.connection_id,),
        )
        assert cur.fetchone() == (4, 2)
        cur.execute(
            "SELECT count(*),count(DISTINCT kind) FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s",
            (selected.connection_id,),
        )
        assert cur.fetchone() == (2, 2)


def test_failed_attempt_retains_prior_complete_inventory(db, configured):
    device, selected, binding = configured
    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
        failed = replace(
            attempt,
            execution_id=str(uuid4()),
            complete=False,
            outcome="failure",
            error_code="inventory_timeout",
        )
        assert persist(db, failed) == dict(replayed=False, records=0, complete=False)
        assert persist(db, failed)["replayed"]
        with db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT collection_attempt_id::text FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s",
                (selected.connection_id,),
            )
            assert cur.fetchall() == [(attempt.execution_id,)]


def test_cancelled_import_rolls_back_attempt_receipts_and_rows(
    db, configured, monkeypatch
):
    device, selected, binding = configured
    with inventory(selected, binding) as (attempt, staged):
        original = staged.records

        def interrupted():
            for record in original():
                yield record
                raise KeyboardInterrupt

        monkeypatch.setattr(staged, "records", interrupted)
        with pytest.raises(KeyboardInterrupt):
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                (attempt.execution_id,),
            )
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT count(*) FROM evidence.source_revisions WHERE connection_id=%s",
                (selected.connection_id,),
            )
            assert cur.fetchone()[0] == 0


def test_cross_tenant_registration_rolls_back(db, configured):
    device, selected, binding = configured
    unrelated = replace(binding, tenant_id=str(uuid4()))
    other = replace(selected, connection_id=str(uuid4()), tenant_id=unrelated.tenant_id)
    import psycopg2

    with pytest.raises(psycopg2.Error, match="exact registered device binding"):
        register(
            db, other, unrelated, device.scope.connection_id, device.records()[0]["id"]
        )
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.source_connections WHERE id=%s",
            (other.connection_id,),
        )
        assert cur.fetchone()[0] == 0


@pytest.mark.parametrize("configured", ["synthetic", "lab"], indirect=True)
def test_writer_cannot_register_or_rebind_device_authority(db, configured):
    device, selected, binding = configured
    import psycopg2

    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with atomic(cur):
                cur.execute(
                    "UPDATE evidence_pipeline.windows_inventory_bindings SET machine_guid=%s WHERE connection_id=%s",
                    (str(uuid4()), selected.connection_id),
                )
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with atomic(cur):
                cur.execute(
                    "INSERT INTO evidence_pipeline.windows_inventory_bindings SELECT %s,device_connection_id,native_device_id,machine_guid,entra_device_id FROM evidence_pipeline.windows_inventory_bindings WHERE connection_id=%s",
                    (str(uuid4()), selected.connection_id),
                )


def test_inconsistent_counts_and_unrelated_receipt_rejected(db, configured):
    device, selected, binding = configured
    import psycopg2

    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
        with db.cursor() as cur:
            with pytest.raises(psycopg2.Error, match="count differs"):
                with atomic(cur):
                    cur.execute(
                        "UPDATE evidence_pipeline.windows_inventory_runs SET record_count=3 WHERE attempt_id=%s",
                        (attempt.execution_id,),
                    )
            cur.execute(
                "SELECT receipt_id FROM evidence.device_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
                (device.execution_id,),
            )
            wrong_receipt = cur.fetchone()[0]
            with pytest.raises(psycopg2.Error, match="receipt differs"):
                with atomic(cur):
                    cur.execute(
                        "UPDATE evidence_pipeline.windows_inventory_observations SET receipt_id=%s WHERE attempt_id=%s AND kind='appx'",
                        (wrong_receipt, attempt.execution_id),
                    )


def test_replay_cannot_change_pinned_device_execution(db, configured):
    from datetime import timedelta

    device, selected, binding = configured
    repeated_device = replace(
        device,
        execution_id=str(uuid4()),
        finished_at=device.finished_at + timedelta(seconds=1),
    )
    persist_devices(db, repeated_device)
    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
        with pytest.raises(ReplayConflict, match="context changed"):
            persist(
                db,
                attempt,
                staged=staged,
                device_attempt_id=repeated_device.execution_id,
            )


@pytest.mark.parametrize("bundle", [True, False])
def test_loaded_entra_hive_survives_staging_persistence_and_replay(
    db, configured, bundle
):
    from .contract import REGISTRY_SUFFIXES

    device, selected, binding = configured
    value = sample()
    value["records"][1]["is_bundle"] = bundle
    from .test_manifest import metadata, unavailable

    value["records"][1]["manifest"] = (
        unavailable("not_applicable", "bundle_or_resource_package")
        if bundle
        else metadata()
    )
    value["records"][0].update(
        reported_value_names=[
            "DisplayName",
            "DisplayVersion",
            "SystemComponent",
            "DisplayName_Localized",
        ],
        localized_name="@C:\\Synthetic\\synthetic.exe,-123",
    )
    value.update(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
    )
    sid = "S-1-12-1-11-22-33-44"
    value["coverage"]["loaded_user_sids"] = [sid]
    value["coverage"]["registry_roots"] += [
        "Registry::HKEY_USERS\\" + sid + suffix for suffix in REGISTRY_SUFFIXES
    ]
    value["records"][0]["native_id"] = (
        "HKEY_USERS\\" + sid + REGISTRY_SUFFIXES[0] + "\\SyntheticApp"
    )
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    with stage(io.BytesIO(json.dumps(value).encode()), binding) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        result = persist(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        assert result == dict(replayed=False, records=2, complete=True)
        assert persist(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )["replayed"]
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT facts FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s AND kind='registry'",
            (selected.connection_id,),
        )
        assert cur.fetchone()[0] == value["records"][0]
        cur.execute(
            "SELECT coverage FROM evidence_pipeline.current_windows_inventory_runs WHERE connection_id=%s",
            (selected.connection_id,),
        )
        assert cur.fetchone()[0] == value["coverage"]

        cur.execute(
            "SELECT facts->'is_bundle' FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s AND kind='appx'",
            (selected.connection_id,),
        )
        assert cur.fetchone()[0] is bundle

        cur.execute(
            "SELECT facts->'manifest' FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s AND kind='appx'",
            (selected.connection_id,),
        )
        assert cur.fetchone()[0] == value["records"][1]["manifest"]


@contextmanager
def unsupported_version(db, version):
    """A restricted import must reject metadata before changing retained rows."""
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        if version is None:
            cur.execute("DELETE FROM evidence_pipeline.installation")
        else:
            cur.execute(
                "UPDATE evidence_pipeline.installation SET version=%s", (version,)
            )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        tables = (
            "evidence.collection_attempts",
            "evidence_pipeline.windows_inventory_runs",
            "evidence_pipeline.component_check_runs",
            "evidence_pipeline.selected_component_checks",
            "evidence_pipeline.windows_os_reviews",
        )

        def counts():
            result = []
            for table in tables:
                cur.execute("SELECT count(*) FROM " + table)
                result.append(cur.fetchone()[0])
            return result

        before = counts()
        with pytest.raises(
            ValueError, match="consolidated database migration required"
        ):
            yield
        assert counts() == before


@pytest.mark.parametrize(
    "version", ["pipeline-windows-os-native-facts-v113", "unknown", None]
)
def test_inventory_writer_refuses_unsupported_version(db, configured, version):
    device, selected, binding = configured
    with inventory(selected, binding) as (attempt, staged):
        with unsupported_version(db, version):
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
