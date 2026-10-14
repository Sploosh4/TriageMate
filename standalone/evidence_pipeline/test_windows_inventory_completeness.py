"""Source-kind completeness preserves source scope, empty results and false facts."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4

import pytest

from standalone.windows_inventory.test_store import (
    db as db,
    snapshot as snapshot,
    configured as configured,
    inventory,
)
from standalone.windows_inventory.store import register, persist


def select(db, sql, args=()):
    with db.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def apply(db):
    with db.cursor() as cur:
        database_schema.verify(cur)


def summary(db, connections):
    return select(
        db,
        "SELECT domain,populated,applicable,unknown_applicability,percentage,assessment FROM evidence_pipeline.completeness_summary(%s::uuid[]) ORDER BY domain",
        (connections,),
    )


def test_source_kinds_false_zero_and_provenance_exclusions(db, configured):
    device, scope, binding = configured
    apply(db)
    with inventory(scope, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
    cells = select(
        db,
        "SELECT kind,field_name,value,populated,definition_id FROM evidence_pipeline.current_windows_inventory_completeness_cells WHERE connection_id=%s ORDER BY kind,field_name",
        (scope.connection_id,),
    )
    assert len(cells) == 18
    fields = {
        (kind, name): (value, populated) for kind, name, value, populated, _ in cells
    }
    assert fields["registry", "system_component"] == (0, True)
    assert fields["appx", "is_framework"] == (False, True)
    assert fields["registry", "publisher"] == (None, False)
    assert fields["appx", "user_states"][0][0]["install_state"] == "Staged"
    assert all(
        name
        not in (
            "receipt_id",
            "family_name",
            "kind",
            "coverage",
            "started_at",
            "finished_at",
            "device_id",
        )
        for _, name, _, _, _ in cells
    )
    result = summary(db, [scope.connection_id])
    assert len(result) == 2
    assert all(row[1:4] == (14, 18, 0) for row in result)
    assert {row[0] for row in result} == {"whole-product", "windows-inventory"}
    assert summary(db, [scope.connection_id, scope.connection_id]) == result
    assert select(
        db,
        "SELECT completeness_domain,eligible_cells,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
        (scope.connection_id,),
    ) == [("windows-inventory", 18, "Provisional definition")]


def test_repeated_observations_count_once_but_selected_source_scopes_remain_distinct(
    db, configured
):
    device, scope, binding = configured
    apply(db)
    for later in (False, True):
        with inventory(scope, binding, later=later) as (attempt, staged):
            persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    assert summary(db, [scope.connection_id])[0][2] == 18
    other = replace(scope, connection_id=str(uuid4()))
    register(db, other, binding, device.scope.connection_id, device.records()[0]["id"])
    with inventory(other, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    assert summary(db, [scope.connection_id, other.connection_id])[0][1:4] == (
        28,
        36,
        0,
    )
    assert select(
        db,
        "SELECT count(DISTINCT receipt_id) FROM evidence_pipeline.current_windows_inventory_completeness_cells WHERE connection_id=ANY(%s::uuid[])",
        ([scope.connection_id, other.connection_id],),
    ) == [(4,)]


def test_complete_empty_inventory_is_not_assessable_not_one_hundred_percent(
    db, configured
):
    device, scope, binding = configured
    apply(db)
    with inventory(scope, binding, empty=True) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    result = summary(db, [scope.connection_id])
    assert result == [("whole-product", 0, 0, 0, None, "Not assessable")]
    assert select(
        db,
        "SELECT collection_state,eligible_cells,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
        (scope.connection_id,),
    ) == [("collected", 0, "Not assessable: no eligible evidence cells")]


def test_failed_collection_keeps_cells_and_reports_last_success(db, configured):
    device, scope, binding = configured
    apply(db)
    with inventory(scope, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
        before = summary(db, [scope.connection_id])
        from datetime import timedelta

        failed = replace(
            attempt,
            execution_id=str(uuid4()),
            started_at=attempt.started_at + timedelta(seconds=10),
            finished_at=attempt.finished_at + timedelta(seconds=10),
            complete=False,
            outcome="failure",
            error_code="inventory_timeout",
        )
        persist(db, failed)
    assert summary(db, [scope.connection_id]) == before
    assert select(
        db,
        "SELECT collection_state FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
        (scope.connection_id,),
    ) == [("last_success_retained",)]


def test_additive_upgrade_keeps_original_schema_and_previous_guards(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT UPDATE ON evidence_pipeline.windows_inventory_observations TO tm_mock_reader"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_blank_text_and_known_empty_state_list_remain_distinct(
    db, configured, monkeypatch
):
    from standalone.windows_inventory import test_store
    from standalone.windows_inventory.test_contract import sample

    device, scope, binding = configured
    apply(db)
    data = sample()
    data["records"][0]["publisher"] = "   "
    data["records"][1]["user_states"] = []
    monkeypatch.setattr(test_store, "sample", lambda: data)
    with inventory(scope, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    assert select(
        db,
        "SELECT kind,field_name,populated FROM evidence_pipeline.current_windows_inventory_completeness_cells WHERE connection_id=%s AND ((kind='registry' AND field_name='publisher') OR field_name='user_states') ORDER BY kind",
        (scope.connection_id,),
    ) == [("appx", "user_states", True), ("registry", "publisher", False)]
