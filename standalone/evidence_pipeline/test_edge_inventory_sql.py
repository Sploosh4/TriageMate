"""Rollback-only SQL parity under the restricted reader; generated evidence."""

from backend.database import schema as database_schema

from copy import deepcopy
import json
import pytest

from .test_store import db as db
from .test_edge_inventory_match import FACTS, STATEMENT
from .test_edge_cpe_match import criterion, configuration
from standalone.evidence_pipeline.assessment.edge_inventory_match import evaluate_edge


@pytest.mark.parametrize(
    "change",
    [
        "affected",
        "outside",
        "default",
        "provider",
        "product",
        "publisher",
        "os",
        "version",
        "platform",
        "module",
        "malformed",
        "wrong_type",
        "conflict",
        "product_conflict",
        "cpe_match",
        "cpe_exclude",
        "cpe_unknown",
        "cpe_environment",
        "cpe_and",
        "cpe_or",
        "cpe_negate",
        "cpe_architecture",
        "cpe_default",
        "null_default",
        "inclusive",
        "two_bounds",
        "empty_versions",
        "legacy",
        "channel",
        "store_alias",
    ],
)
def test_reader_sql_matches_python(db, change):
    facts = dict(FACTS)
    source = deepcopy(STATEMENT)
    provider = "microsoft"
    entry = source["affected"][0]
    rule = entry["versions"][0]
    if change == "outside":
        facts["version"] = "200.0.0.0"
    elif change == "default":
        facts["version"] = "200.0.0.0"
        entry["defaultStatus"] = "unaffected"
    elif change == "provider":
        provider = "other"
    elif change == "product":
        facts["product"] = "Other"
    elif change == "publisher":
        facts["publisher"] = "Other"
    elif change == "os":
        facts["operating_system"] = None
    elif change == "version":
        facts["version"] = "199.0.1000"
    elif change == "platform":
        entry["platforms"] = ["Linux"]
    elif change == "module":
        entry["modules"] = ["Synthetic module"]
    elif change == "malformed":
        source["affected"].append(None)
    elif change == "wrong_type":
        rule["versionType"] = "semver"
    elif change == "conflict":
        entry["versions"].append(dict(rule, status="unaffected"))
    elif change == "product_conflict":
        other = deepcopy(entry)
        other["versions"][0]["status"] = "unaffected"
        source["affected"].append(other)
    elif change == "null_default":
        entry["defaultStatus"] = None
    elif change == "inclusive":
        rule["lessThanOrEqual"] = rule.pop("lessThan")
        facts["version"] = "199.0.1000.10"
    elif change == "two_bounds":
        rule["lessThanOrEqual"] = "199.0.1000.10"
    elif change == "empty_versions":
        entry["versions"] = []
    elif change == "legacy":
        facts["version"] = "44.0.0.0"
    elif change == "channel":
        facts["product"] = "Microsoft Edge Beta"
    elif change == "store_alias":
        facts["product"] = "Microsoft.MicrosoftEdge.Stable"
    if change.startswith("cpe_"):
        matched = criterion(versionEndExcluding="199.0.1000.10")
        other = criterion()
        other["criteria"] = other["criteria"].replace(
            "edge_chromium", "unknown_software"
        )
        source["cpeApplicability"] = configuration(matched)
        if change == "cpe_exclude":
            matched["versionEndExcluding"] = "199.0.1000.5"
        elif change == "cpe_unknown":
            source["cpeApplicability"] = configuration(other)
        elif change == "cpe_environment":
            matched["vulnerable"] = False
        elif change in ("cpe_and", "cpe_or"):
            source["cpeApplicability"] = configuration(
                matched, other, operator="AND" if change == "cpe_and" else "OR"
            )
        elif change == "cpe_negate":
            source["cpeApplicability"] = configuration(other, negate=True)
        elif change == "cpe_architecture":
            matched["criteria"] = "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:x64:*"
        elif change == "cpe_default":
            facts["version"] = "200.0.0.0"
            entry["defaultStatus"] = "unaffected"
    expected = evaluate_edge(source, provider=provider, facts=facts)
    with db.cursor() as q:
        database_schema.verify(q)
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT evidence_pipeline.edge_inventory_status(%s::jsonb,%s,%s::jsonb)",
            (json.dumps(source), provider, json.dumps(facts)),
        )
        assert q.fetchone()[0] == expected
