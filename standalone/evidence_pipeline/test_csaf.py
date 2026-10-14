"""Synthetic CSAF facts distinguish vendor fixes from other recommendations."""

import json
from dataclasses import replace
from uuid import uuid4
import pytest
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.csaf import parse_csaf


def fixture():
    return {
        "document": {
            "csaf_version": "2.0",
            "title": "Synthetic advisory",
            "publisher": {"name": "Synthetic Microsoft fixture"},
            "tracking": {
                "id": "synthetic-advisory",
                "initial_release_date": "2026-01-01T00:00:00Z",
                "current_release_date": "2026-01-02T00:00:00Z",
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_name",
                    "name": "Synthetic",
                    "product": {"product_id": "p1", "name": "Synthetic Windows"},
                }
            ],
            "product_groups": [{"group_id": "g1", "product_ids": ["p1"]}],
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2099-9999999",
                "product_status": {"known_affected": ["p1"]},
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Free text: not a typed version",
                        "group_ids": ["g1"],
                        "url": "https://support.microsoft.com/help/5012345",
                    }
                ],
            }
        ],
        "future_field": {"retained": True},
    }


def scope():
    return SourceScope(
        str(uuid4()),
        "MSRC",
        "advisories",
        "https://example.invalid/synthetic",
        "synthetic",
        "Explicitly synthetic CSAF test fixture",
    )


def parse(value):
    return parse_csaf(json.dumps(value).encode(), scope=scope())


def test_fix_targets_and_complete_raw_claim_are_retained():
    value = fixture()
    feed = parse(value)
    remedy = feed.records[0].remediations[0]
    assert remedy.patch_id == "KB5012345"
    assert remedy.product_ids == ("p1",) and remedy.group_ids == ("g1",)
    assert remedy.details == "Free text: not a typed version"
    assert not hasattr(remedy, "fixed_version")
    assert json.loads(feed.raw_payload) == value
    assert len(feed.input_fingerprint) == 64


@pytest.mark.parametrize(
    "category", ["mitigation", "workaround", "none_available", "no_fix_planned"]
)
def test_non_fix_recommendations_never_become_patches(category):
    value = fixture()
    value["vulnerabilities"][0]["remediations"][0]["category"] = category
    assert parse(value).records[0].remediations[0].patch_id is None


@pytest.mark.parametrize(
    "url",
    [
        "https://example.invalid/help/5012345",
        "https://support.microsoft.com.evil.invalid/help/5012345",
        "http://support.microsoft.com/help/5012345",
        "https://support.microsoft.com/topic/something",
        "https://support.microsoft.com/help/not-a-number",
    ],
)
def test_unrecognized_patch_url_remains_a_reference(url):
    value = fixture()
    value["vulnerabilities"][0]["remediations"][0]["url"] = url
    result = parse(value).records[0].remediations[0]
    assert result.patch_id is None and result.url == url


@pytest.mark.parametrize(
    "fault",
    [
        "version",
        "product",
        "group",
        "duplicate-product",
        "duplicate-cve",
        "category",
        "no-target",
        "credentials",
    ],
)
def test_ambiguous_or_invalid_structures_are_rejected(fault):
    value = fixture()
    remedy = value["vulnerabilities"][0]["remediations"][0]
    if fault == "version":
        value["document"]["csaf_version"] = "2.1"
    elif fault == "product":
        value["vulnerabilities"][0]["product_status"]["known_affected"] = ["missing"]
    elif fault == "group":
        remedy["group_ids"] = ["missing"]
    elif fault == "duplicate-product":
        value["product_tree"]["full_product_names"] = [
            {"product_id": "p1", "name": "Other"}
        ]
    elif fault == "duplicate-cve":
        value["vulnerabilities"] *= 2
    elif fault == "category":
        remedy["category"] = "unknown"
    elif fault == "no-target":
        remedy["group_ids"] = []
    else:
        remedy["url"] = "https://user:password@example.invalid/help/5012345"
    with pytest.raises(ValueError):
        parse(value)


def test_wrong_origin_or_source_cannot_be_relabelled():
    for changes in [{"origin": "lab"}, {"source": "NVD"}]:
        with pytest.raises(ValueError):
            parse_csaf(
                json.dumps(fixture()).encode(), scope=replace(scope(), **changes)
            )


def test_duplicate_json_keys_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        parse_csaf(b'{"document":{},"document":{}}', scope=scope())


def test_fix_targets_are_not_filtered_by_known_affected_status():
    value = fixture()
    value["vulnerabilities"][0]["product_status"] = {"fixed": ["p1"]}
    result = parse(value).records[0]
    assert result.product_status == (("fixed", ("p1",)),)
    assert result.remediations[0].product_ids == ("p1",)


def test_product_relationship_names_remain_source_labels_not_machine_links():
    value = fixture()
    value["product_tree"]["relationships"] = [
        {
            "category": "installed_on",
            "product_reference": "p1",
            "relates_to_product_reference": "p1",
            "full_product_name": {
                "product_id": "r1",
                "name": "Synthetic combined product",
            },
        }
    ]
    remedy = value["vulnerabilities"][0]["remediations"][0]
    remedy.pop("group_ids")
    remedy["product_ids"] = ["r1"]
    result = parse(value)
    assert result.records[0].remediations[0].product_ids == ("r1",)
    assert result.products[-1].name == "Synthetic combined product"
