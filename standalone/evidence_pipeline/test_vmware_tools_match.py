"""Synthetic source statements; no installed lab values or credentials."""

from copy import deepcopy
import pytest
from standalone.evidence_pipeline.assessment.vmware_tools_match import evaluate_tools

FACTS = dict(
    provider="vmware",
    product="tools",
    publisher="vmware",
    version="13.0.1.0",
    operating_system="Windows11",
)
ENTRY = dict(
    vendor="VMware",
    product="Tools",
    platforms=["Windows"],
    defaultStatus="unaffected",
    versions=[
        dict(
            version="13.x.x.x",
            lessThan="13.0.5.0",
            versionType="custom",
            status="affected",
        )
    ],
)


@pytest.mark.parametrize(
    "version,state",
    [
        ("13.0.1.0", "affected"),
        ("13.0.1", "affected"),
        ("13.0.5.0", "unaffected"),
        ("13.0.5", "unaffected"),
        ("14.0.1.0", "unaffected"),
        ("13.0.01.0", "unknown"),
        ("13.0.1-beta", "unknown"),
        ("13.0", "unknown"),
    ],
)
def test_version_statement_and_boundary(version, state):
    value = evaluate_tools([ENTRY], **dict(FACTS, version=version))
    assert value["state"] == state
    assert (
        value["interpretation"]
        == "publisher_product_version_statement_not_full_applicability"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "microsoft"),
        ("publisher", "unknown"),
        ("product", "VMware Tools"),
        ("operating_system", "Linux"),
        ("operating_system", None),
    ],
)
def test_ambiguous_identity_or_platform_remains_unknown(field, value):
    assert (
        evaluate_tools([ENTRY], **dict(FACTS, **{field: value}))["state"] == "unknown"
    )


@pytest.mark.parametrize(
    "change",
    [
        "reversed",
        "bounds",
        "changes",
        "nonprefix",
        "unbounded_wildcard",
        "unsupported_selector",
        "platforms",
        "unknown_type",
    ],
)
def test_unsupported_or_conflicting_rules_stay_unknown(change):
    entry = deepcopy(ENTRY)
    rule = entry["versions"][0]
    if change == "reversed":
        rule["lessThan"] = "12.0.0"
    if change == "bounds":
        rule["lessThanOrEqual"] = "13.0.6"
    if change == "changes":
        rule["changes"] = []
    if change == "nonprefix":
        rule["version"] = "13.x.1"
    if change == "unbounded_wildcard":
        rule["version"] = "x.x.x"
    if change == "unsupported_selector":
        entry["modules"] = ["component"]
    if change == "platforms":
        entry["platforms"] = ["Windows", "Linux"]
    if change == "unknown_type":
        rule["versionType"] = "unsupported"
    assert evaluate_tools([entry], **FACTS)["state"] == "unknown"


def test_source_conflicts_preserved_and_input_not_mutated():
    entry = deepcopy(ENTRY)
    original = deepcopy(entry)
    other = deepcopy(entry)
    other["versions"][0]["status"] = "unaffected"
    result = evaluate_tools([entry, other], **FACTS)
    assert result["state"] == "unknown" and len(result["entries"]) == 2
    assert entry == original
    entry["versions"].append(dict(entry["versions"][0], status="unaffected"))
    assert evaluate_tools([entry], **FACTS)["reason"] == "conflicting_version_statuses"


def test_unrelated_product_cannot_establish_tools_status():
    entry = deepcopy(ENTRY)
    entry["product"] = "VMware Aria Operations"
    assert evaluate_tools([entry], **FACTS)["state"] == "unknown"


def test_commercial_source_statement_without_platform_is_not_full_applicability():
    entry = deepcopy(ENTRY)
    entry.pop("platforms")
    entry["product"] = "VMware tools"
    entry["versions"][0]["versionType"] = "commercial"
    result = evaluate_tools([entry], **FACTS)
    assert result["state"] == "affected"
    assert "not_full_applicability" in result["interpretation"]


@pytest.mark.parametrize("value", [[], {}, ["affected"]])
@pytest.mark.parametrize(
    "field", ["defaultStatus", "status", "versionType", "operating_system"]
)
def test_malformed_source_values_remain_unknown(field, value):
    entry = deepcopy(ENTRY)
    facts = dict(FACTS)
    if field == "operating_system":
        facts[field] = value
    elif field == "defaultStatus":
        entry[field] = value
    else:
        entry["versions"][0][field] = value
    assert evaluate_tools([entry], **facts)["state"] == "unknown"
