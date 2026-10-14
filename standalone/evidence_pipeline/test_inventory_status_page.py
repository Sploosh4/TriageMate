"""Execute the retained inventory-query fixture SQL against labelled synthetic observations."""

import json
from pathlib import Path

from .test_store import db as db
from backend.tests.windows_identity_support import REFERENCES, facts
from backend.database.schema import verify as install

REFERENCE = REFERENCES["cbs"]

PAGE = (
    Path(__file__).resolve().parents[2]
    / "standalone/evidence_pipeline/fixtures/analysis_queries/windows_inventory.json"
)


def page_queries():
    queries = json.loads(PAGE.read_text())
    assert len(queries) == 5
    return queries


def test_source_identity_labels_keep_missing_fields_installation_and_scopes_separate(
    db,
):
    rows = []
    with db.cursor() as cur:
        install(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for key, changes, scope in [
            ("recognized", {}, "synthetic-scope-a"),
            (
                "source-only",
                {
                    "name": "Synthetic.Unmapped",
                    "product": "Synthetic.Unmapped",
                    "manifest": {
                        "state": "read",
                        "display_name": "Synthetic source name",
                    },
                },
                "synthetic-scope-a",
            ),
            (
                "missing-version",
                {
                    "name": "Synthetic.Unmapped",
                    "product": "Synthetic.Unmapped",
                    "version": None,
                    "manifest": {
                        "state": "unavailable",
                        "display_name": "Unverified name",
                    },
                },
                "synthetic-scope-a",
            ),
            (
                "staged",
                {
                    "name": "Synthetic.Unmapped",
                    "product": "Synthetic.Unmapped",
                    "user_states": [{"install_state": "Staged"}],
                },
                "synthetic-scope-a",
            ),
            (
                "other-scope",
                {"name": "Synthetic.Unmapped", "product": "Synthetic.Unmapped"},
                "synthetic-scope-b",
            ),
        ]:
            original = facts(REFERENCE["packages"][0], architecture="X64", **changes)
            cur.execute(
                "SELECT evidence_pipeline.recognize_windows_inventory(%s::jsonb), evidence_pipeline.native_inventory_accounting(%s::jsonb)",
                (json.dumps(original), json.dumps(original)),
            )
            recognition, accounting = cur.fetchone()
            rows.append(
                dict(
                    origin="synthetic",
                    connection_id=scope,
                    scope_reference=scope,
                    product_name=original["name"],
                    publisher=original["publisher"],
                    version=original["version"],
                    recognition=recognition,
                    source_accounting=accounting,
                    facts=original,
                    receipt_id=key,
                    device_receipt_id="synthetic-device",
                    finished_at="2026-09-20T00:00:00Z",
                )
            )
        columns = list(rows[0])
        json_columns = {"recognition", "source_accounting", "facts"}
        placeholders = (
            "("
            + ",".join(
                "%s::jsonb" if name in json_columns else "%s::text" for name in columns
            )
            + ")"
        )
        virtual_source = (
            "FROM (VALUES "
            + ",".join(placeholders for _ in rows)
            + ") AS synthetic_inventory("
            + ",".join(columns)
            + ")"
        )
        parameters = [
            json.dumps(row[name]) if name in json_columns else row[name]
            for row in rows
            for name in columns
        ]
        output = []
        for statement in page_queries()[:2]:
            source = "FROM evidence_pipeline.current_native_inventory_accounting"
            assert statement.count(source) == 1
            cur.execute(statement.replace(source, virtual_source), parameters)
            output.append(
                [
                    dict(zip([column.name for column in cur.description], row))
                    for row in cur.fetchall()
                ]
            )
    summary, detail = output
    assert sum(row["observations"] for row in summary) == 5
    assert {row["connection_id"] for row in summary} == {
        "synthetic-scope-a",
        "synthetic-scope-b",
    }
    assert {row["origin"] for row in detail} == {"synthetic"}
    by_receipt = {row["receipt_id"]: row for row in detail}
    assert by_receipt["recognized"]["identity_status"] == "Recognized product identity"
    for key in ("source-only", "staged", "other-scope"):
        assert (
            by_receipt[key]["identity_status"]
            == "Source identified; advisory mapping unknown"
        )
        assert by_receipt[key]["product_recognition"] == "unknown"
    assert (
        by_receipt["missing-version"]["identity_status"]
        == "Unknown: source identity fields missing"
    )
    assert by_receipt["missing-version"]["missing_identity_fields"] == ["version"]
    assert by_receipt["source-only"]["reported_display_name"] == "Synthetic source name"
    assert by_receipt["source-only"]["manifest_evidence"] == "read"
    assert by_receipt["missing-version"]["reported_display_name"] is None
    assert by_receipt["missing-version"]["manifest_evidence"] == "unavailable"
    assert by_receipt["recognized"]["reported_display_name"] is None
    assert by_receipt["staged"]["installation_evidence"] == "no_reported_installed_user"
    assert (
        by_receipt["source-only"]["installation_evidence"]
        == "reported_installed_for_some_users"
    )
    assert all(row["inventory_only_applicability"] == "unknown" for row in detail)
    assert all(
        row["reported_version"] == "1.2.3.4"
        for row in detail
        if row["receipt_id"] != "missing-version"
    )
