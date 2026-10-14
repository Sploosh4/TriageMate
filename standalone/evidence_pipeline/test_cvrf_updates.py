"""Synthetic product-specific MSRC update claims; no inferred inventory matching."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates


def source():
    return SourceScope(
        str(uuid4()),
        "MSRC",
        "security_updates",
        "synthetic-month",
        "synthetic",
        "TriageMate generated synthetic CVRF fixture",
    )


def document():
    return {
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "p1", "Value": "Synthetic product release A"},
                {"ProductID": "p2", "Value": "Synthetic product release B"},
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-12345",
                "ProductStatuses": [{"Type": 3, "ProductID": ["p1", "p2"]}],
                "Remediations": [
                    {
                        "Type": 2,
                        "ProductID": ["p1"],
                        "Description": {"Value": "9999991"},
                        "Supercedence": "9999990",
                        "FixedBuild": "1.2.3.4",
                        "Date": "0001-01-01T00:00:00",
                        "DateSpecified": False,
                    },
                    {
                        "Type": 2,
                        "ProductID": ["p2"],
                        "Description": {"Value": "Other fix channel"},
                        "Supercedence": "Unstructured vendor reference",
                    },
                ],
            }
        ],
    }


def parse(value):
    return parse_cvrf_updates(json.dumps(value).encode(), scope=source())


def test_fixes_and_supersedence_stay_with_the_explicit_product():
    feed = parse(document())
    first, second = feed.records
    assert first.product_id == "p1" and first.patch_kb == "KB9999991"
    assert first.superseded_kb == "KB9999990" and first.fixed_build == "1.2.3.4"
    assert first.source_remediation["DateSpecified"] is False
    assert second.product_id == "p2" and second.patch_kb is None
    assert (
        second.superseded_kb is None
        and second.supersedence_reference == "Unstructured vendor reference"
    )
    assert first.source_status_codes == (3,)


def test_unscoped_and_non_fix_advice_does_not_create_product_relations():
    value = document()
    value["Vulnerability"][0]["Remediations"] = [
        {"Type": 2, "Description": {"Value": "9999991"}},
        {"Type": 0, "ProductID": ["p1"], "Description": {"Value": "9999992"}},
    ]
    assert parse(value).records == ()


def test_self_replacement_remains_raw_without_a_replacement_edge():
    value = document()
    value["Vulnerability"][0]["Remediations"][0]["Supercedence"] = "9999991"
    first = parse(value).records[0]
    assert first.superseded_kb is None and first.supersedence_reference == "9999991"


@pytest.mark.parametrize("bad", ("unknown", ""))
def test_unknown_product_is_not_resolved_by_a_similar_label(bad):
    value = document()
    value["Vulnerability"][0]["Remediations"][0]["ProductID"] = [bad]
    with pytest.raises(ValueError):
        parse(value)


def test_customer_or_microsoft_device_scopes_are_not_public_update_sources():
    with pytest.raises(ValueError):
        parse_cvrf_updates(
            json.dumps(document()).encode(),
            scope=replace(source(), tenant_id=str(uuid4())),
        )


def test_differing_claims_are_preserved_and_exact_duplicates_are_not_repeated():
    value = document()
    remediations = value["Vulnerability"][0]["Remediations"]
    remediations.extend(
        [
            dict(remediations[0]),
            {**remediations[0], "URL": "https://example.invalid/synthetic-alternative"},
        ]
    )
    records = parse(value).records
    assert len(records) == 3
    assert len([item for item in records if item.product_id == "p1"]) == 2


def test_duplicate_json_keys_are_not_silently_overwritten():
    with pytest.raises(ValueError):
        parse_cvrf_updates(b'{"ProductTree":{},"ProductTree":{}}', scope=source())


def test_cycle_claims_stay_visible_without_choosing_a_replacement_winner():
    value = document()
    remediations = value["Vulnerability"][0]["Remediations"]
    original = remediations[0]
    remediations.extend(
        [
            {
                **original,
                "Description": {"Value": "9999990"},
                "Supercedence": "9999991",
            },
            {
                **original,
                "Description": {"Value": "9999992"},
                "Supercedence": "9999991",
            },
        ]
    )
    records = parse(value).records
    cyclic = [item for item in records if item.supersedence_status == "cyclic"]
    assert {item.patch_kb for item in cyclic} == {"KB9999990", "KB9999991"}
    assert all(
        item.superseded_kb is None and item.supersedence_reference for item in cyclic
    )
    newest = next(item for item in records if item.patch_kb == "KB9999992")
    assert newest.superseded_kb == "KB9999991"
    assert newest.supersedence_status == "explicit"


def test_repeated_product_references_are_one_edge_with_original_claim_preserved():
    value = document()
    value["Vulnerability"][0]["ProductStatuses"][0]["ProductID"] = ["p1", "p1", "p2"]
    value["Vulnerability"][0]["Remediations"][0]["ProductID"] = ["p1", "p1"]
    first, second = parse(value).records
    assert first.product_id == "p1" and second.product_id == "p2"
    assert first.source_status_codes == (3,)
    assert first.source_remediation["ProductID"] == ["p1", "p1"]


def test_duplicate_product_definitions_remain_ambiguous_and_rejected():
    value = document()
    value["ProductTree"]["FullProductName"].append(
        {"ProductID": "p1", "Value": "Conflicting synthetic product"}
    )
    with pytest.raises(ValueError, match="Duplicate CVRF product identity"):
        parse(value)


@pytest.mark.parametrize(
    "description", ({}, {"Value": None}, {"Value": ""}, {"Value": "  "})
)
def test_unnamed_fix_keeps_raw_advice_without_inventing_patch_identity(description):
    from standalone.evidence_pipeline.parsing.cvrf_records import normalize_cvrf_updates

    value = document()
    raw = value["Vulnerability"][0]["Remediations"][0]
    raw["Description"] = description
    raw["URL"] = "https://example.invalid/synthetic-fix-channel"
    feed = parse(value)
    first = feed.records[0]
    assert first.patch_reference is None and first.patch_kb is None
    assert first.source_remediation["Description"] == description
    assert first.source_remediation["URL"] == raw["URL"]
    (record,) = normalize_cvrf_updates(feed)
    assert record.rows == ()
    assert json.loads(record.claim)["record"]["updates"][0]["patch_reference"] is None


def test_status_without_product_targets_preserves_claim_without_inventing_links():
    from standalone.evidence_pipeline.parsing.cvrf_records import normalize_cvrf_updates

    value = document()
    value["Vulnerability"][0]["ProductStatuses"] = [{"Type": 3}]
    value["Vulnerability"][0]["Remediations"] = []
    feed = parse(value)
    assert feed.records == ()
    records = list(normalize_cvrf_updates(feed))
    assert len(records) == 1
    claim = json.loads(records[0].claim)
    assert claim["source_vulnerability"]["ProductStatuses"] == [{"Type": 3}]
    assert claim["projection"] == []


@pytest.mark.parametrize("targets", [None, "p1", {}, ["unknown-product"]])
def test_explicit_invalid_status_targets_remain_rejected(targets):
    value = document()
    value["Vulnerability"][0]["ProductStatuses"] = [{"Type": 3, "ProductID": targets}]
    with pytest.raises(ValueError):
        parse(value)
