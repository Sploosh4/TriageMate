"""Eligible architecture facts retain receipt/scope grain and unknown providers."""

from backend.database import schema as database_schema

from dataclasses import replace
from uuid import uuid4

import pytest


from .test_store import db as database_fixture
from .test_devices import make
from .test_completeness import put
from .test_exposure_migration import (
    test_original_schema_verifier_accepts_only_recognized_upgrade as check_original,
)

db = database_fixture


@pytest.mark.parametrize(
    "processor,expected", [("x64", True), ("ARM64", True), (None, False)]
)
def test_one_source_architecture_cell_per_selected_scope(db, processor, expected):
    with db.cursor() as cur:
        database_schema.verify(cur)
    first = make(
        "Defender",
        [
            {
                "id": "synthetic-architecture-completeness",
                "osArchitecture": "64-bit",
                "osProcessor": processor,
            }
        ],
    )
    second = replace(
        first,
        execution_id=str(uuid4()),
        scope=replace(first.scope, connection_id=str(uuid4())),
    )
    put(db, first)
    put(db, second)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT field_name,value,populated,receipt_id,scope_connections::text[] FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND field_name IN ('defender.os_processor','defender.os_architecture','defender.derived_architecture') ORDER BY receipt_id",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        rows = cur.fetchall()
        assert len(rows) == 2
        assert all(
            row[:3] == ("defender.os_processor", processor, expected)
            and row[3] is not None
            and len(row[4]) == 1
            for row in rows
        ), rows
        assert {str(row[4][0]) for row in rows} == {
            first.scope.connection_id,
            second.scope.connection_id,
        }
        cur.execute(
            "SELECT count(DISTINCT entity_key) FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND domain='device'",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        assert cur.fetchone() == (1,)
        cur.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
            ([first.scope.connection_id],),
        )
        assert cur.fetchone() == (1 + int(expected), 12)
        cur.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
            ([first.scope.connection_id, second.scope.connection_id],),
        )
        assert cur.fetchone() == (2 + 2 * int(expected), 22)


def test_architecture_definition_preserves_original_schema_and_detects_drift(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
    check_original(db)


def test_definition_drift_rejected(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "REVOKE SELECT ON evidence_pipeline.completeness_definition FROM tm_mock_reader"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
