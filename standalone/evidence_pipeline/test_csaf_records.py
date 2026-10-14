"""Source-supported relational projection, without machine applicability guesses."""

from dataclasses import FrozenInstanceError
from uuid import uuid4
import json
import pytest
from standalone.evidence_pipeline.parsing.csaf import parse_csaf
from standalone.evidence_pipeline.parsing.csaf_records import normalize_csaf
from .test_csaf import fixture, scope


def record(value):
    return next(normalize_csaf(parse_csaf(json.dumps(value).encode(), scope=scope())))


def test_receipt_bound_links_and_no_invented_applicability():
    item = record(fixture())
    receipt = str(uuid4())
    rows = list(item.evidence_rows(receipt))
    indexed = {table: values for table, values in rows}
    assert indexed["patches"]["source_patch_id"] == "KB5012345"
    assert indexed["patches"]["product_names"] == ["Synthetic Windows"]
    assert indexed["patch_vulnerabilities"]["patch_id"] == indexed["patches"]["id"]
    assert indexed["advisory_cves"]["advisory_id"] == indexed["advisories"]["id"]
    assert indexed["recommendations"]["advisory_id"] == indexed["advisories"]["id"]
    assert (
        indexed["recommendation_cves"]["recommendation_id"]
        == indexed["recommendations"]["id"]
    )
    assert indexed["recommendation_patches"]["patch_id"] == indexed["patches"]["id"]
    assert all(values["receipt_id"] == receipt for _, values in rows)
    assert (
        not {"patch_applicability", "device_missing_patches", "recommendation_devices"}
        & indexed.keys()
    )
    assert "recommended_version" not in indexed["recommendations"]
    assert list(item.evidence_rows(receipt)) == rows
    assert list(item.evidence_rows(str(uuid4()))) != rows


def test_duplicate_kb_targets_share_patch_but_keep_recommendations():
    value = fixture()
    value["product_tree"]["full_product_names"] = [
        {"product_id": "p2", "name": "Another synthetic product"}
    ]
    remedy = dict(value["vulnerabilities"][0]["remediations"][0])
    remedy.pop("group_ids")
    remedy["product_ids"] = ["p2"]
    value["vulnerabilities"][0]["remediations"].append(remedy)
    rows = list(record(value).evidence_rows(str(uuid4())))
    patches = [v for t, v in rows if t == "patches"]
    recommendations = [v for t, v in rows if t == "recommendations"]
    assert len(patches) == 1 and len(recommendations) == 2
    assert patches[0]["product_names"] == [
        "Another synthetic product",
        "Synthetic Windows",
    ]
    assert len({r["source_recommendation_id"] for r in recommendations}) == 2


def test_workaround_is_queryable_recommendation_without_patch():
    value = fixture()
    value["vulnerabilities"][0]["remediations"][0]["category"] = "workaround"
    rows = list(record(value).evidence_rows(str(uuid4())))
    assert not any(
        t in ("patches", "patch_vulnerabilities", "recommendation_patches")
        for t, _ in rows
    )
    assert (
        next(v for t, v in rows if t == "recommendations")["category"] == "workaround"
    )


def test_disagreeing_patch_dates_and_urls_remain_unknown_not_chosen():
    value = fixture()
    remedy = value["vulnerabilities"][0]["remediations"][0]
    other = dict(remedy, date="2026-01-02T00:00:00Z", url=remedy["url"] + "/")
    value["vulnerabilities"][0]["remediations"].append(other)
    patch = next(
        v for t, v in record(value).evidence_rows(str(uuid4())) if t == "patches"
    )
    assert patch["url"] is None and patch["published_at"] is None


def test_relationship_recipe_is_immutable():
    item = record(fixture())
    reference = dict(item.rows[1][1])["advisory_id"]
    with pytest.raises(FrozenInstanceError):
        reference.index = 99
    assert json.loads(item.claim)["projection"][1][1][0][1] == {"row_reference": 0}
