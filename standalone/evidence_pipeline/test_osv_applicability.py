"""Source version boundaries, identity isolation and unresolved ordering."""

import json
import pytest

from standalone.evidence_pipeline.parsing.osv import parse_osv
from standalone.evidence_pipeline.assessment.osv_applicability import (
    evaluate,
    range_contains,
    semver_key,
)
from .test_osv import document, scope


def record(events=None, **changes):
    raw = document()
    entry = dict(package=dict(name="synthetic", ecosystem="npm"))
    if events is not None:
        entry["ranges"] = [dict(type="SEMVER", events=events)]
    entry.update(changes)
    raw["affected"] = [entry]
    return parse_osv(json.dumps(raw).encode(), scope=scope()).records[0]


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.9.9", "unaffected"),
        ("1.0.0", "affected"),
        ("1.2.0-rc.1", "affected"),
        ("1.2.0", "unaffected"),
        ("1.2.0+build.77", "unaffected"),
        ("2.0.0", "unaffected"),
        ("3.0.0", "affected"),
        ("3.2.5", "unaffected"),
    ],
)
def test_sorted_semver_ranges_and_reintroduction(version, expected):
    value = record(
        [
            {"fixed": "3.2.5"},
            {"introduced": "1.0.0"},
            {"introduced": "3.0.0"},
            {"fixed": "1.2.0"},
        ]
    )
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version=version)["state"]
        == expected
    )


def test_semver_prerelease_precedence_and_metadata():
    values = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    keys = [semver_key(v) for v in values]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)
    assert semver_key("1.0.0+a") == semver_key("1.0.0+b")


@pytest.mark.parametrize(
    "version", ["1", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3\n", "١.2.3"]
)
def test_non_semver_is_unknown(version):
    value = record([{"introduced": "0"}, {"fixed": "2.0.0"}])
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version=version)["state"]
        == "unknown"
    )


def test_last_affected_is_inclusive_and_is_not_a_fixed_version():
    value = record([{"introduced": "0"}, {"last_affected": "1.2.3"}])
    first = evaluate(value, name="synthetic", ecosystem="npm", version="1.2.3")
    assert first["state"] == "affected" and first["fixed_versions"] == []
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version="1.2.4")["state"]
        == "unaffected"
    )


def test_multiple_limits_are_a_union_and_not_fixes():
    value = dict(
        type="SEMVER",
        events=[{"introduced": "0"}, {"limit": "1.0.0"}, {"limit": "2.0.0"}],
    )
    assert range_contains(value, "1.5.0") is True
    assert range_contains(value, "2.0.0") is False
    value["events"].append({"limit": "*"})
    assert range_contains(value, "3.0.0") is True


def test_identity_and_unknown_ranges_do_not_create_cross_product_matches():
    value = record(
        ranges=[
            dict(type="ECOSYSTEM", events=[{"introduced": "0"}, {"fixed": "2:1.0-3"}])
        ]
    )
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")["state"]
        == "unknown"
    )
    assert (
        evaluate(value, name="different", ecosystem="npm", version="1.0.0")["state"]
        == "unaffected"
    )
    assert (
        evaluate(value, name="synthetic", ecosystem="PyPI", version="1.0.0")["state"]
        == "unaffected"
    )
    value.raw["affected"][0]["versions"] = ["1.0.0"]
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")["state"]
        == "affected"
    )


def test_missing_ranges_and_withdrawal_are_unknown():
    value = record()
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")["state"]
        == "unknown"
    )
    from dataclasses import replace

    value = replace(value, withdrawn="2026-09-14T00:00:00Z")
    assert (
        evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")["reason"]
        == "withdrawn_advisory"
    )


def test_conflicting_equal_precedence_boundaries_are_unknown():
    value = dict(
        type="SEMVER", events=[{"introduced": "1.0.0+a"}, {"fixed": "1.0.0+b"}]
    )
    assert range_contains(value, "1.0.0") is None


@pytest.mark.parametrize(
    "other",
    [
        dict(type="SEMVER", events=[{"introduced": "1.5.0"}, {"fixed": "3.0.0"}]),
        dict(type="ECOSYSTEM", events=[{"introduced": "0"}, {"fixed": "3.0.0"}]),
    ],
)
def test_fixed_candidate_must_survive_all_matching_ranges(other):
    value = record(
        ranges=[
            dict(type="SEMVER", events=[{"introduced": "0"}, {"fixed": "2.0.0"}]),
            other,
        ]
    )
    result = evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")
    assert result["state"] == "affected"
    assert result["fixed_versions"] == []


def test_fixed_candidate_cannot_override_explicit_affected_version():
    value = record([{"introduced": "0"}, {"fixed": "2.0.0"}], versions=["2.0.0"])
    result = evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")
    assert result["state"] == "affected" and result["fixed_versions"] == []


def test_overlapping_ranges_retain_only_verified_later_fix():
    value = record(
        ranges=[
            dict(type="SEMVER", events=[{"introduced": "0"}, {"fixed": "2.0.0"}]),
            dict(type="SEMVER", events=[{"introduced": "0"}, {"fixed": "3.0.0"}]),
        ]
    )
    assert evaluate(value, name="synthetic", ecosystem="npm", version="1.0.0")[
        "fixed_versions"
    ] == ["3.0.0"]
