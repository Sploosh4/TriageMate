"""Generated Edge evidence only; no lab observations are test fixtures."""

from copy import deepcopy

import pytest

from standalone.evidence_pipeline.assessment.edge_inventory_match import evaluate_edge

FACTS = dict(
    source="Intune",
    product="Microsoft Edge",
    publisher="Microsoft Corporation",
    version="199.0.1000.5",
    platform="windows",
    operating_system="Windows",
)
STATEMENT = dict(
    affected=[
        dict(
            vendor="Microsoft",
            product="Microsoft Edge (Chromium-based)",
            versions=[
                dict(
                    version="199.0.1000.0",
                    lessThan="199.0.1000.10",
                    versionType="custom",
                    status="affected",
                )
            ],
        )
    ]
)


@pytest.mark.parametrize(
    "version,state",
    [
        ("199.0.1000.0", "affected"),
        ("199.0.1000.9", "affected"),
        ("199.0.1000.10", "unknown"),
        ("200.0.0.0", "unknown"),
        ("198.9.9999.9", "unknown"),
        ("76.0.0.0", "unknown"),
        ("199.0.1000", "unknown"),
        ("199.00.1000.5", "unknown"),
        ("199.0.1000.5-beta", "unknown"),
        (None, "unknown"),
        ([], "unknown"),
    ],
)
def test_boundaries_and_no_inferred_default(version, state):
    statement = deepcopy(STATEMENT)
    facts = dict(FACTS, version=version)
    value = evaluate_edge(statement, provider="microsoft", facts=facts)
    assert value["state"] == state
    assert value["inventory"] == facts
    assert statement == STATEMENT
    assert (
        value["interpretation"]
        == "publisher_product_version_statement_not_full_applicability"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "Defender"),
        ("product", "Microsoft.MicrosoftEdge.Stable"),
        ("product", "Microsoft Edge Beta"),
        ("product", "Microsoft Edge WebView2 Runtime"),
        ("product", "Microsoft Edge "),
        ("publisher", "Microsoft"),
        ("platform", "linux"),
        ("operating_system", "Linux"),
        ("operating_system", None),
        ("operating_system", []),
    ],
)
def test_identity_and_platform_must_be_supported(field, value):
    assert (
        evaluate_edge(
            STATEMENT, provider="microsoft", facts=dict(FACTS, **{field: value})
        )["state"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "damage",
    [
        "provider",
        "configuration",
        "module",
        "architecture",
        "platform",
        "malformed",
        "reversed",
        "both_bounds",
        "changes",
        "semver",
        "wildcard",
        "three_components",
        "null_default",
        "conflict",
        "product_conflict",
        "wrong_product",
        "empty_versions",
    ],
)
def test_insufficient_and_conflicting_claims_remain_unknown(damage):
    statement = deepcopy(STATEMENT)
    entry = statement["affected"][0]
    rule = entry["versions"][0]
    provider = "microsoft"
    if damage == "provider":
        provider = "unrelated"
    elif damage == "configuration":
        statement["configurations"] = []
    elif damage == "module":
        entry["modules"] = ["Synthetic optional module"]
    elif damage == "architecture":
        entry["platforms"] = ["x64"]
    elif damage == "platform":
        entry["platforms"] = ["Linux"]
    elif damage == "malformed":
        statement["affected"].append(None)
    elif damage == "reversed":
        rule["lessThan"] = "198.0.0.0"
    elif damage == "both_bounds":
        rule["lessThanOrEqual"] = "199.0.1000.10"
    elif damage == "changes":
        rule["changes"] = []
    elif damage == "semver":
        rule["versionType"] = "semver"
    elif damage == "wildcard":
        rule["version"] = "199.x.x.x"
    elif damage == "three_components":
        rule["version"] = "199.0.0"
    elif damage == "null_default":
        entry["defaultStatus"] = None
    elif damage == "conflict":
        entry["versions"].append(dict(rule, status="unaffected"))
    elif damage == "product_conflict":
        other = deepcopy(entry)
        other["versions"][0]["status"] = "unaffected"
        statement["affected"].append(other)
    elif damage == "wrong_product":
        entry["product"] = "Microsoft Edge"
    elif damage == "empty_versions":
        entry["versions"] = []
    assert (
        evaluate_edge(statement, provider=provider, facts=FACTS)["state"] == "unknown"
    )


def test_explicit_default_and_inclusive_bound_and_original_indexes():
    statement = deepcopy(STATEMENT)
    entry = statement["affected"][0]
    entry["defaultStatus"] = "unaffected"
    entry["platforms"] = ["Windows"]
    rule = entry["versions"][0]
    rule["lessThanOrEqual"] = rule.pop("lessThan")
    statement["affected"].insert(0, dict(vendor="Other", product="Synthetic unrelated"))
    inside = evaluate_edge(
        statement, provider="microsoft", facts=dict(FACTS, version="199.0.1000.10")
    )
    assert inside["state"] == "affected" and inside["entries"][0]["index"] == 1
    outside = evaluate_edge(
        statement, provider="microsoft", facts=dict(FACTS, version="199.0.1000.11")
    )
    assert outside["state"] == "unaffected"


@pytest.mark.parametrize(
    "change", ["supported", "outside", "publisher", "platform", "conflicting"]
)
def test_shared_inventory_entrypoint_preserves_edge_evidence(change):
    from standalone.evidence_pipeline.assessment.inventory_product_match import (
        evaluate_inventory_product,
    )

    facts = dict(FACTS)
    statement = deepcopy(STATEMENT)
    if change == "outside":
        facts["version"] = "200.0.0.0"
    elif change == "publisher":
        facts["publisher"] = "Unverified publisher"
    elif change == "platform":
        facts["platform"] = "linux"
    elif change == "conflicting":
        statement["affected"][0]["versions"].append(
            dict(statement["affected"][0]["versions"][0], status="unaffected")
        )
    expected = evaluate_edge(statement, provider="microsoft", facts=facts)
    assert (
        evaluate_inventory_product(statement, provider="microsoft", **facts) == expected
    )
    assert expected["state"] == ("affected" if change == "supported" else "unknown")
    assert expected["inventory"] == facts
