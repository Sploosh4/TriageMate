"""Synthetic Windows application claims never broaden unsupported evidence."""

from backend.database import schema as database_schema

from copy import deepcopy
import json

import pytest

from standalone.evidence_pipeline.assessment.windows_app_match import (
    PROFILES,
    evaluate_windows_app,
)
from .test_store import db as db


@pytest.fixture(params=["python", "sql"])
def evaluator(request):
    if request.param == "python":
        return evaluate_windows_app
    connection = request.getfixturevalue("db")

    with connection.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute("SET LOCAL ROLE tm_mock_reader")

    def evaluate(source_fields, *, provider, facts):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT evidence_pipeline.windows_app_inventory_status(%s::jsonb,%s,%s::jsonb)",
                (json.dumps(source_fields), provider, json.dumps(facts)),
            )
            return cursor.fetchone()[0]

    return evaluate


@pytest.mark.parametrize("identity", list(PROFILES))
@pytest.mark.parametrize(
    "case,state,reason",
    [
        ("inside", "affected", "explicit_application_product_version_statement"),
        ("outside", "unknown", "explicit_application_product_version_statement"),
        ("default", "unaffected", "explicit_application_product_version_statement"),
        ("inclusive", "affected", "explicit_application_product_version_statement"),
        ("unspecified", "unknown", "unsupported_or_conflicting_version_rules"),
        ("mixed_width", "affected", "explicit_application_product_version_statement"),
        ("ambiguous_width", "unknown", "unsupported_or_conflicting_version_rules"),
        ("leading_zero", "affected", "explicit_application_product_version_statement"),
        ("conflict", "unknown", "conflicting_version_statuses"),
        ("entry_conflict", "unknown", "conflicting_product_entries"),
        ("cpe", "unknown", "incomplete_product_or_cpe_evidence"),
        (
            "configuration",
            "unknown",
            "additional_cna_configuration_requires_evaluation",
        ),
        ("module", "unknown", "unsupported_product_selectors"),
        ("platform", "unknown", "missing_or_unsupported_platform_evidence"),
        ("device_platform", "unknown", "missing_or_conflicting_inventory_platform"),
        ("publisher", "unknown", "unsupported_inventory_product_identity"),
        ("provider", "unknown", "missing_published_microsoft_cna_evidence"),
        ("other_platform_product", "unknown", "no_supported_application_entry"),
        ("invalid_identity", "unknown", "unsupported_inventory_product_identity"),
        ("null_default", "unknown", "missing_version_status"),
    ],
)
def test_explicit_application_claims(identity, case, state, reason, evaluator):
    target, profile = PROFILES[identity]
    facts = dict(
        source="Intune",
        product=identity[0],
        publisher=identity[1],
        platform="windows",
        operating_system="Windows11",
        version="2.0.0.0",
    )
    rule = dict(
        version="1.0.0.0", lessThan="3.0.0.0", versionType="custom", status="affected"
    )
    entry = dict(vendor="Microsoft", product=target, versions=[rule])
    source = dict(affected=[entry])
    provider = "microsoft"
    if case in {"outside", "default"}:
        facts["version"] = "3.0.0.0"
        if case == "default":
            entry["defaultStatus"] = "unaffected"
    elif case == "inclusive":
        facts["version"] = "3.0.0.0"
        rule["lessThanOrEqual"] = rule.pop("lessThan")
    elif case == "unspecified":
        rule["version"] = "unspecified"
    elif case == "mixed_width":
        rule["version"] = "1.0.0"
    elif case == "ambiguous_width":
        rule["version"] = "2.0.0"
    elif case == "leading_zero":
        facts["version"] = "02.00.000.0000"
    elif case == "conflict":
        entry["versions"].append(dict(rule, status="unaffected"))
    elif case == "entry_conflict":
        other = deepcopy(entry)
        other["versions"][0]["status"] = "unaffected"
        source["affected"].append(other)
    elif case == "cpe":
        source["cpeApplicability"] = []
    elif case == "configuration":
        source["configurations"] = []
    elif case == "module":
        entry["modules"] = ["synthetic component"]
    elif case == "platform":
        entry["platforms"] = ["Linux"]
    elif case == "device_platform":
        facts["operating_system"] = "Linux"
    elif case == "publisher":
        facts["publisher"] = "Untrusted Publisher"
    elif case == "provider":
        provider = "other"
    elif case == "other_platform_product":
        entry["product"] = "Microsoft Teams for Android"
    elif case == "invalid_identity":
        facts["product"] = []
    elif case == "null_default":
        entry["defaultStatus"] = None
    before = deepcopy((source, facts))
    result = evaluator(source, provider=provider, facts=facts)
    assert (result["state"], result["reason"]) == (state, reason)
    assert result["inventory"] == facts
    assert (source, facts) == before
    assert (
        result["interpretation"]
        == "publisher_product_version_statement_not_full_applicability"
    )


@pytest.mark.parametrize("identity", list(PROFILES))
def test_inventory_dispatch_preserves_original_facts(identity):
    from standalone.evidence_pipeline.assessment.inventory_product_match import (
        evaluate_inventory_product,
    )

    facts = dict(
        source="Intune",
        product=identity[0],
        publisher=identity[1],
        platform="windows",
        operating_system="Windows11",
        version="2.0.0.0",
    )
    statement = {
        "affected": [
            {
                "vendor": "Microsoft",
                "product": PROFILES[identity][0],
                "versions": [{"version": "2.0.0.0", "status": "affected"}],
            }
        ]
    }
    assert evaluate_inventory_product(
        statement, provider="microsoft", **facts
    ) == evaluate_windows_app(statement, provider="microsoft", facts=facts)


def test_application_migration_idempotence_and_authority(db):

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION evidence_pipeline.windows_app_inventory_status(jsonb,text,jsonb) TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize(
    "lower,upper,candidate,expected",
    [
        ("1.0.0", "25122.1415.3698.6812", "24000.1.2.3", True),
        ("1.0.0", "25122.1415.3698.6812", "26225.1.2.3", False),
        ("1.0.0", "3.0.0.0", "1.0.0.0", None),
        ("1.0.0.0", "3.0.0", "3.0.0.0", None),
        ("3.0.0.0", "1.0.0.0", "2.0.0.0", None),
        ("1.0.0.0", "1.0.0.0", "1.0.0.0", None),
        ("01.00.000.0000", "03.00.000.0000", "02.00.000.0000", True),
        ("unspecified", "3.0.0.0", "2.0.0.0", None),
    ],
)
def test_numeric_version_boundaries(lower, upper, candidate, expected):
    from standalone.evidence_pipeline.assessment.windows_app_match import (
        version_match,
        version_key,
    )

    assert (
        version_match(
            dict(
                version=lower, lessThan=upper, status="affected", versionType="custom"
            ),
            version_key(candidate),
        )
        is expected
    )
