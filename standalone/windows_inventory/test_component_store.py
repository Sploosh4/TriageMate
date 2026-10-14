"""Transactional synthetic PostgreSQL evidence; every test rolls back."""

from dataclasses import replace
import hashlib
import io
import json
from uuid import uuid4

import psycopg2
import pytest

from backend.database.schema import verify
from standalone.evidence_pipeline.persistence.store import atomic
from standalone.evidence_pipeline.test_store import db as db, snapshot as snapshot

from .component_store import persist
from .staging import stage
from .store import persist as persist_inventory
from .test_store import configured as configured, inventory
from .test_component_check import case, DIGEST, SOURCE


@pytest.fixture
def ready(db, configured):
    with db.cursor() as cur:
        verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    return configured


def count(db, table):
    # Only test-owned literal table names enter this helper.
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence_pipeline." + table)
        return cur.fetchone()[0]


def test_restricted_persistence_replay_sources_and_reader(db, ready):
    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        before = count(db, "windows_inventory_observations")
        result = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        assert not result["replayed"] and result["records"] == 2
        assert persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        ) == dict(result, replayed=True)
        assert count(db, "windows_inventory_observations") == before
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT version,result->>'state',metadata->>'defender_coverage' "
                "FROM evidence_pipeline.current_component_assessments WHERE check_id=%s",
                (result["check_id"],),
            )
            assert cur.fetchall() == [("01.002.0", "unknown", "unverified")] * 2
            cur.execute(
                "SELECT payload FROM evidence_pipeline.component_check_source_chunks "
                "WHERE check_id=%s AND source_sha256=%s ORDER BY chunk_number",
                (result["check_id"], staged.fingerprint),
            )
            source = b"".join(bytes(r[0]) for r in cur.fetchall())
            assert hashlib.sha256(source).hexdigest() == staged.fingerprint
            assert len(json.loads(source)["records"]) == 2


def test_wrong_snapshot_or_device_cannot_attach_evidence(db, ready):
    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        for execution_id, actual_binding in [
            (str(uuid4()), binding),
            (attempt.execution_id, replace(binding, device_id=str(uuid4()))),
        ]:
            with pytest.raises(ValueError):
                persist(
                    db,
                    execution_id,
                    staged,
                    binding=actual_binding,
                    origin=selected.origin,
                )
        assert count(db, "component_check_runs") == 0


def test_failure_and_new_unchecked_snapshot_preserve_history(db, ready):
    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        result = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        failed = replace(
            attempt,
            execution_id=str(uuid4()),
            outcome="failure",
            complete=False,
            error_code="inventory_timeout",
        )
        persist_inventory(db, failed)
        with db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT check_id::text FROM evidence_pipeline.current_component_assessments"
            )
            assert cur.fetchall() == [(result["check_id"],)]
    with inventory(selected, binding, later=True) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        assert count(db, "current_component_assessments") == 0
        assert count(db, "component_assessment_history") == 2


def test_interrupted_source_processing_rolls_back_whole_check(db, ready, monkeypatch):
    from .component_assessment import StagedAssessment

    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        original = StagedAssessment.source_chunks

        def interrupted(self):
            yield next(original(self))
            raise KeyboardInterrupt

        monkeypatch.setattr(StagedAssessment, "source_chunks", interrupted)
        with pytest.raises(KeyboardInterrupt):
            persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )
        assert count(db, "component_check_runs") == 0
        assert count(db, "component_check_source_chunks") == 0
        assert count(db, "component_check_results") == 0
        assert count(db, "windows_inventory_observations") >= 2
        monkeypatch.setattr(StagedAssessment, "source_chunks", original)
        assert (
            persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )["records"]
            == 2
        )


def test_reviewed_synthetic_rule_retains_per_cve_result_and_bytes(db, ready):
    device, selected, binding = ready
    raw, context, rule = case()
    data = json.loads(raw)
    data.update(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
    )
    raw = json.dumps(data).encode()
    context = replace(
        context, binding=binding, inventory_sha256=hashlib.sha256(raw).hexdigest()
    )
    from .snapshot import InventoryAttempt

    with stage(io.BytesIO(raw), binding) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        result = persist(
            db,
            attempt.execution_id,
            staged,
            binding=binding,
            origin=selected.origin,
            context=context,
            rules=[rule],
            retained_sources={DIGEST: SOURCE},
        )
        with db.cursor() as cur:
            cur.execute(
                "SELECT result->'evaluations'->0->>'state',result->>'state' FROM "
                "evidence_pipeline.current_component_assessments WHERE check_id=%s AND kind='appx'",
                (result["check_id"],),
            )
            assert cur.fetchone() == ("update_required", "unknown")
            cur.execute(
                "SELECT payload FROM evidence_pipeline.component_check_source_chunks "
                "WHERE check_id=%s AND source_sha256=%s",
                (result["check_id"], DIGEST),
            )
            assert bytes(cur.fetchone()[0]) == SOURCE


def test_reader_cannot_write_and_writer_cannot_overwrite(db, ready):
    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        result = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        with db.cursor() as cur:
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                with atomic(cur):
                    cur.execute(
                        "DELETE FROM evidence_pipeline.component_check_runs WHERE id=%s",
                        (result["check_id"],),
                    )
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                with atomic(cur):
                    cur.execute(
                        "UPDATE evidence_pipeline.component_check_results SET result='{}'"
                    )


def test_migration_drift_is_not_silently_repaired(db, configured):
    with db.cursor() as cur:
        verify(cur)
        cur.execute("DROP VIEW evidence_pipeline.current_component_assessments")
        with pytest.raises(ValueError, match="schema/authority differs"):
            verify(cur)


def test_sealed_evidence_cannot_receive_additional_bytes(db, ready):
    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        result = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        with db.cursor() as cur:
            with pytest.raises(psycopg2.Error, match="immutable"):
                with atomic(cur):
                    cur.execute(
                        "INSERT INTO evidence_pipeline.component_check_source_chunks VALUES(%s,%s,99,%s)",
                        (result["check_id"], staged.fingerprint, b"extra"),
                    )


def test_changed_rule_retains_old_assessment_without_completeness_credit(db, ready):
    device, selected, binding = ready
    raw, context, rule = case()
    data = json.loads(raw)
    data.update(
        machine_guid=binding.machine_guid,
        tenant_id=binding.tenant_id,
        device_id=binding.device_id,
    )
    raw = json.dumps(data).encode()
    context = replace(
        context, binding=binding, inventory_sha256=hashlib.sha256(raw).hexdigest()
    )
    from .snapshot import InventoryAttempt

    def completeness():
        with db.cursor() as cur:
            cur.execute(
                "SELECT field_name,applicability,populated,value FROM "
                "evidence_pipeline.current_windows_inventory_completeness_cells "
                "WHERE connection_id=%s ORDER BY native_id,field_name",
                (selected.connection_id,),
            )
            return cur.fetchall()

    with stage(io.BytesIO(raw), binding) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        before = completeness()
        first = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        second = persist(
            db,
            attempt.execution_id,
            staged,
            binding=binding,
            origin=selected.origin,
            context=context,
            rules=[rule],
            retained_sources={DIGEST: SOURCE},
        )
        assert first["check_id"] != second["check_id"]
        assert completeness() == before
        with db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT check_id::text FROM evidence_pipeline.current_component_assessments "
                "WHERE connection_id=%s",
                (selected.connection_id,),
            )
            assert cur.fetchall() == [(second["check_id"],)]
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.component_assessment_history WHERE connection_id=%s",
                (selected.connection_id,),
            )
            assert cur.fetchone()[0] == 4


def test_failed_reevaluation_keeps_prior_result(db, ready, monkeypatch):
    from . import component_store
    from .component_assessment import StagedAssessment

    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        result = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        monkeypatch.setattr(component_store, "engine_fingerprint", lambda: "f" * 64)

        def fail(self):
            raise ValueError("synthetic interrupted result processing")
            yield

        monkeypatch.setattr(StagedAssessment, "results", fail)
        with pytest.raises(ValueError, match="interrupted"):
            persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )
        with db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT check_id::text FROM evidence_pipeline.current_component_assessments "
                "WHERE connection_id=%s",
                (selected.connection_id,),
            )
            assert cur.fetchall() == [(result["check_id"],)]


def test_combined_import_rolls_back_inventory_if_check_fails_then_replays(
    db, ready, monkeypatch
):
    from . import component_store

    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        original = component_store.persist

        def fail(*args, **kwargs):
            raise ValueError("synthetic check interrupted")

        monkeypatch.setattr(component_store, "persist", fail)
        with pytest.raises(ValueError, match="interrupted"):
            component_store.persist_inventory(
                db, attempt, staged=staged, device_attempt_id=device.execution_id
            )
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                (attempt.execution_id,),
            )
            assert cur.fetchone()[0] == 0
        monkeypatch.setattr(component_store, "persist", original)
        assert component_store.persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        ) == dict(replayed=False, records=2, complete=True)
        assert component_store.persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        ) == dict(replayed=True, records=2, complete=True)
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.component_check_runs WHERE inventory_attempt_id=%s",
                (attempt.execution_id,),
            )
            assert cur.fetchone()[0] == 1


def test_shipped_page_distinguishes_unchecked_unknown_and_historical_results(db, ready):
    from standalone.evidence_pipeline.test_inventory_status_page import page_queries

    device, selected, binding = ready

    def query(index):
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(page_queries()[index])
            rows = [
                dict(zip([col.name for col in cur.description], row))
                for row in cur.fetchall()
            ]
            cur.execute("SET LOCAL ROLE tm_pipeline_writer")
            return [
                row
                for row in rows
                if str(row["connection_id"]) == selected.connection_id
            ]

    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        unchecked = query(2)
        assert len(unchecked) == 2
        assert all(
            row["component_check"] == "Not checked for this inventory snapshot"
            for row in unchecked
        )
        persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        checked = query(2)
        assert len(checked) == 2
        assert all(
            row["component_check"] == "Checked; overall applicability unknown"
            for row in checked
        )
        assert all(
            row["per_cve_results"] == [] and row["defender_coverage"] == "unverified"
            for row in checked
        )
        assert all(row["source_references"] for row in checked)
    with inventory(selected, binding, later=True) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        assert all(row["check_id"] is None for row in query(2))
        assert len(query(3)) == 2


@pytest.mark.parametrize(
    "version", ["pipeline-windows-os-native-facts-v113", "unknown", None]
)
def test_component_writer_refuses_unsupported_version(db, ready, version):
    from .test_store import unsupported_version

    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        with unsupported_version(db, version):
            persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )


def test_predecessor_engine_replays_without_new_history(db, ready, monkeypatch):
    from . import component_store
    from .test_engine_identity import COMPONENT

    device, selected, binding = ready
    with inventory(selected, binding) as (attempt, staged):
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
        with monkeypatch.context() as patch:
            patch.setattr(component_store, "engine_fingerprint", lambda: COMPONENT)
            before = persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )
        after = persist(
            db, attempt.execution_id, staged, binding=binding, origin=selected.origin
        )
        assert after == dict(before, replayed=True)
        assert count(db, "component_check_runs") == 1
        with monkeypatch.context() as patch:
            patch.setattr(component_store, "engine_fingerprint", lambda: "f" * 64)
            changed = persist(
                db,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=selected.origin,
            )
        assert changed["check_id"] != before["check_id"]
        assert not changed["replayed"]
        assert count(db, "component_check_runs") == 2
