"""The shipped relationship queries retain uncertainty and scope boundaries."""

from backend.database import schema as database_schema

from dataclasses import replace
from pathlib import Path
import json
from uuid import uuid4

import pytest

from .test_store import db as db, snapshot as snapshot
from .test_bundle_membership import records
from .test_resource_package_migration import pair, save

from standalone.windows_inventory.test_store import configured as configured
from standalone.windows_inventory.store import register

PAGE = (
    Path(__file__).resolve().parents[2]
    / "standalone/evidence_pipeline/fixtures/analysis_queries/package_relationships.json"
)


def query(connection, index, connection_ids):
    statements = json.loads(PAGE.read_text())
    assert len(statements) == 2
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL ROLE tm_mock_reader")
        cursor.execute(
            "SELECT * FROM ("
            + statements[index].rstrip(";\n ")
            + ") inspected WHERE connection_id = ANY(%s::uuid[])",
            (connection_ids,),
        )
        names = [column.name for column in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]


@pytest.mark.parametrize("case", ["associated", "staged", "ambiguous", "missing"])
def test_resource_page_preserves_candidates_and_installation_uncertainty(
    db, configured, case
):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    resource, parent = pair()
    source = [resource, parent]
    if case == "staged":
        resource["user_states"][0]["install_state"] = "Staged"
    elif case == "ambiguous":
        source.append(parent | dict(native_id="synthetic-second-parent"))
    elif case == "missing":
        source = [resource]
    save(db, configured, source)
    rows = query(db, 0, [configured[1].connection_id])
    assert len(rows) == 1
    row = rows[0]
    assert row["origin"] == "synthetic"
    assert str(row["connection_id"]) == configured[1].connection_id
    assert row["association_state"] == (
        "associated" if case in ("associated", "staged") else "unknown"
    )
    assert (
        row["candidate_count"]
        == len(row["parent_receipt_ids"])
        == {"associated": 1, "staged": 1, "ambiguous": 2, "missing": 0}[case]
    )
    assert (
        row["shared_installed_user"]
        is {"associated": True, "staged": False, "ambiguous": None, "missing": None}[
            case
        ]
    )
    assert row["applicability"] == "unknown"


def test_bundle_page_keeps_declarations_and_other_scope_missing_observation_separate(
    db, configured
):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    save(db, configured, records())
    device, selected, binding = configured
    other = replace(selected, connection_id=str(uuid4()))
    register(db, other, binding, device.scope.connection_id, device.records()[0]["id"])
    save(db, configured, records()[:2], selected=other)
    rows = query(db, 1, [selected.connection_id, other.connection_id])
    assert len(rows) == 2
    by_scope = {str(row["connection_id"]): row for row in rows}
    associated, missing = (
        by_scope[selected.connection_id],
        by_scope[other.connection_id],
    )
    assert associated["association_state"] == "associated"
    assert associated["candidate_count"] == len(associated["package_receipt_ids"]) == 1
    assert associated["shared_installed_user"] is True
    assert missing["association_state"] == "unknown"
    assert missing["association_reason"] == "no_matching_observed_package"
    assert missing["candidate_count"] == 0 and missing["package_receipt_ids"] == []
    assert missing["shared_installed_user"] is None
    for row in rows:
        assert row["origin"] == "synthetic" and row["applicability"] == "unknown"
        assert row["declared_stub"] is False
        assert row["declared_member_type"] == "application"
        assert row["bundle_receipt_id"] and row["declaration_receipt_id"]
