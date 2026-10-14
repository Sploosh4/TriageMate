"""Generated inventory facts; no actual lab evidence in fixtures."""

from copy import deepcopy
import pytest

from standalone.evidence_pipeline.assessment.inventory_product_match import (
    evaluate_inventory_product,
)

FACTS = dict(
    provider="vmware",
    source="Intune",
    product="VMware Tools",
    publisher="Broadcom Inc.",
    version="13.0.2.0",
    platform="windows",
    operating_system="Windows",
)
STATEMENT = dict(
    affected=[
        dict(
            vendor="VMware",
            product="VMware Tools",
            platforms=["Windows"],
            defaultStatus="unaffected",
            versions=[
                dict(
                    version="13.0.0",
                    lessThan="13.0.5",
                    versionType="custom",
                    status="affected",
                )
            ],
        )
    ]
)


@pytest.mark.parametrize("publisher", ["VMware, Inc.", "Broadcom Inc."])
@pytest.mark.parametrize(
    "version,state",
    [
        ("13.0.2.0", "affected"),
        ("13.0.5", "unaffected"),
        ("13.0.5.1", "unaffected"),
        ("13.0.02.0", "unknown"),
        (None, "unknown"),
        ("13.0.2-beta", "unknown"),
    ],
)
def test_explicit_inventory_identity_and_version_rules(publisher, version, state):
    statement = deepcopy(STATEMENT)
    value = evaluate_inventory_product(
        statement, **dict(FACTS, publisher=publisher, version=version)
    )
    assert value["state"] == state
    assert value["inventory"]["publisher"] == publisher
    assert value["inventory"]["version"] == version
    assert value["inventory"]["operating_system"] == "Windows"
    assert value["mapping_profile"] == "intune-windows-vmware-tools-v1"
    assert (
        value["interpretation"]
        == "publisher_product_version_statement_not_full_applicability"
    )
    assert statement == STATEMENT


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "Defender"),
        ("source", "untrusted"),
        ("product", "open-vm-tools"),
        ("product", "VMware Tools driver"),
        ("product", "tools"),
        ("product", " VMWARE TOOLS "),
        ("publisher", "Broadcom"),
        ("publisher", "Unknown vendor"),
        ("publisher", None),
        ("publisher", []),
        ("platform", "linux"),
        ("platform", None),
        ("operating_system", "Linux"),
        ("operating_system", None),
        ("operating_system", []),
        ("provider", "unrelated-cna"),
    ],
)
def test_unsupported_or_conflicting_facts_stay_unknown(field, value):
    result = evaluate_inventory_product(STATEMENT, **dict(FACTS, **{field: value}))
    assert result["state"] == "unknown"
    if field != "provider":
        assert result["inventory"][field] == value


@pytest.mark.parametrize(
    "change", ["configuration", "platform", "module", "conflict", "malformed"]
)
def test_additional_selectors_and_conflicts_are_not_discarded(change):
    document = deepcopy(STATEMENT)
    entry = document["affected"][0]
    if change == "configuration":
        document["cpeApplicability"] = []
    elif change == "platform":
        entry["platforms"] = ["Linux"]
    elif change == "module":
        entry["modules"] = ["Synthetic optional component"]
    elif change == "conflict":
        other = deepcopy(entry)
        other["versions"][0]["status"] = "unaffected"
        document["affected"].append(other)
    else:
        document["affected"].append(None)
    assert evaluate_inventory_product(document, **FACTS)["state"] == "unknown"


def test_matching_entries_retain_original_indexes():
    statement = deepcopy(STATEMENT)
    statement["affected"].insert(0, dict(vendor="Other", product="Tools"))
    value = evaluate_inventory_product(statement, **FACTS)
    assert value["state"] == "affected" and value["entries"][0]["index"] == 1
