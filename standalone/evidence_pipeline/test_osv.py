"""Synthetic OSV records retain identity, withdrawal and source range semantics."""

from dataclasses import replace
from decimal import Decimal
import json
from uuid import uuid4

import pytest
from standalone.evidence_pipeline.source_json import encode_source_records
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.osv import parse_osv


def scope():
    return SourceScope(
        str(uuid4()),
        "OSV",
        "advisories",
        "synthetic-osv",
        "synthetic",
        "TriageMate generated synthetic OSV fixture",
    )


def document():
    return dict(
        schema_version="1.9.0",
        id="x_synthetic-advisory",
        modified="2026-09-14T01:02:03.123456789Z",
        aliases=["CVE-2099-1234", "CVE-2099-5678"],
        affected=[
            dict(
                package=dict(name="synthetic-package", ecosystem="PyPI"),
                ranges=[
                    dict(
                        type="ECOSYSTEM",
                        events=[dict(introduced="0"), dict(limit="2.0")],
                    )
                ],
            )
        ],
    )


def parse(raw):
    return parse_osv(encode_source_records(raw), scope=scope()).records[0]


def test_native_identity_multiple_aliases_and_ranges_remain_independent():
    raw = document()
    record = parse(raw)
    assert record.advisory_id == "x_synthetic-advisory"
    assert record.cve_ids == ("CVE-2099-1234", "CVE-2099-5678")
    assert record.raw == raw
    assert record.modified.endswith("123456789Z")
    assert record.raw["affected"][0]["ranges"][0]["events"][-1] == {"limit": "2.0"}


@pytest.mark.parametrize("value", [None, []])
def test_no_cve_alias_does_not_drop_advisory(value):
    raw = document()
    raw["aliases"] = value
    raw["withdrawn"] = "2026-09-14T02:00:00Z"
    record = parse(raw)
    assert record.cve_ids == () and record.withdrawn == raw["withdrawn"]
    assert record.raw["aliases"] == value


def test_minimal_record_and_unknown_source_extensions_are_preserved():
    raw = dict(
        id="x_synthetic",
        modified="2026-09-14T00:00:00Z",
        database_specific={"score": Decimal("0.123456789012345678901")},
    )
    assert parse(raw).raw == raw


@pytest.mark.parametrize(
    "damage",
    ["time", "major", "boundary", "introduced", "git", "package", "severity", "id"],
)
def test_malformed_consumed_fields_are_rejected(damage):
    raw = document()
    item = raw["affected"][0]
    if damage == "time":
        raw["modified"] = "2026-02-30T00:00:00Z"
    elif damage == "major":
        raw["schema_version"] = "2.0.0"
    elif damage == "boundary":
        item["ranges"][0]["events"] = [{"introduced": "0", "fixed": "1"}]
    elif damage == "introduced":
        item["ranges"][0]["events"] = [{"fixed": "1"}]
    elif damage == "git":
        item["ranges"][0].update(
            type="GIT", repo="https://example.invalid/synthetic.git"
        )
    elif damage == "package":
        del item["package"]["ecosystem"]
    elif damage == "severity":
        raw["severity"] = [{"type": "Ubuntu", "score": "low"}]
        item["severity"] = [{"type": "Ubuntu", "score": "high"}]
    else:
        raw["id"] = "../other"
    with pytest.raises(ValueError):
        parse(raw)


def test_private_scope_and_duplicate_keys_are_rejected():
    with pytest.raises(ValueError):
        parse_osv(
            json.dumps(document()).encode(),
            scope=replace(scope(), tenant_id=str(uuid4())),
        )
    with pytest.raises(ValueError):
        parse_osv(b'{"id":"x_a","id":"x_b"}', scope=scope())


@pytest.mark.parametrize("width", [40, 64])
def test_git_special_boundaries_and_full_commits_are_preserved(width):
    raw = document()
    raw["affected"][0]["ranges"] = [
        dict(
            type="GIT",
            repo="https://example.invalid/synthetic.git",
            events=[
                {"introduced": "0"},
                {"fixed": "a" * width},
                {"introduced": "b" * width},
                {"limit": "*"},
            ],
        )
    ]
    assert parse(raw).raw == raw


@pytest.mark.parametrize(
    "name,boundary",
    [
        ("fixed", "0"),
        ("last_affected", "0"),
        ("limit", "0"),
        ("introduced", "*"),
        ("fixed", "*"),
        ("last_affected", "*"),
        ("fixed", "abc123"),
    ],
)
def test_git_special_values_cannot_replace_commit_boundaries(name, boundary):
    raw = document()
    raw["affected"][0]["ranges"] = [
        dict(
            type="GIT",
            repo="https://example.invalid/synthetic.git",
            events=[{"introduced": "0"}, {name: boundary}],
        )
    ]
    with pytest.raises(ValueError, match="full commit identities"):
        parse(raw)
