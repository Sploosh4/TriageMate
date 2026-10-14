"""Restricted-reader SQL agrees with the generated inventory evaluator."""

from backend.database import schema as database_schema

from copy import deepcopy
import json
import pytest

from standalone.evidence_pipeline.assessment.inventory_product_match import (
    evaluate_inventory_product,
)
from .test_inventory_product_match import FACTS, STATEMENT
from .test_store import db as db


@pytest.mark.parametrize(
    "change",
    [
        "affected",
        "fixed",
        "old_publisher",
        "unknown_publisher",
        "wrong_platform",
        "conflicting_os",
        "missing_os",
        "unknown_product",
        "missing_cna",
        "wrong_cna",
        "configuration",
        "module",
        "conflict",
        "malformed",
        "platform_selector",
        "missing_version",
        "missing_affected",
        "empty_affected",
        "unrelated_entry",
        "malformed_product",
        "null_publisher",
    ],
)
def test_restricted_sql_and_python_agree(db, change):
    facts, statement = dict(FACTS), deepcopy(STATEMENT)
    provider = facts.pop("provider")
    entry = statement["affected"][0]
    if change == "fixed":
        facts["version"] = "13.0.5.0"
    if change == "old_publisher":
        facts["publisher"] = "VMware, Inc."
    if change == "unknown_publisher":
        facts["publisher"] = "Other vendor"
    if change == "wrong_platform":
        facts["platform"] = "linux"
    if change == "conflicting_os":
        facts["operating_system"] = "Linux"
    if change == "missing_os":
        facts["operating_system"] = None
    if change == "unknown_product":
        facts["product"] = "open-vm-tools"
    if change == "missing_cna":
        statement = None
    if change == "wrong_cna":
        provider = "Other CNA"
    if change == "configuration":
        statement["configurations"] = []
    if change == "module":
        entry["modules"] = ["Synthetic optional module"]
    if change == "platform_selector":
        entry["platforms"] = ["Linux"]
    if change == "missing_version":
        facts["version"] = None
    if change == "missing_affected":
        statement.pop("affected")
    if change == "empty_affected":
        statement["affected"] = []
    if change == "conflict":
        other = deepcopy(entry)
        other["versions"][0]["status"] = "unaffected"
        statement["affected"].append(other)
    if change == "malformed":
        statement["affected"].append(None)
    if change == "unrelated_entry":
        statement["affected"].insert(0, dict(vendor="Other", product="Tools"))
    if change == "malformed_product":
        entry["product"] = []
    if change == "null_publisher":
        facts["publisher"] = None
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.inventory_product_status(%s::jsonb,%s,%s::jsonb)",
            (json.dumps(statement), provider, json.dumps(facts)),
        )
        assert cur.fetchone()[0] == evaluate_inventory_product(
            statement,
            provider=provider,
            **facts,
        )
        cur.execute(
            "SELECT * FROM evidence_pipeline.current_inventory_product_evaluations LIMIT 0"
        )
