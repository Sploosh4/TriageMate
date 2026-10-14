"""Synthetic Canonical-shaped records preserve upstream and package boundaries."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
    BASE,
    endpoint,
    parse_ubuntu,
)
from .test_osv import document


def scope(identity="UBUNTU-CVE-2099-1234"):
    return SourceScope(
        str(uuid4()),
        "Ubuntu",
        "advisories",
        endpoint(identity),
        "synthetic",
        "TriageMate generated synthetic Ubuntu fixture",
    )


@pytest.mark.parametrize(
    "identity,path",
    [
        ("UBUNTU-CVE-2099-1234", "cve/2099/UBUNTU-CVE-2099-1234.json"),
        ("USN-9999-1", "usn/USN-9999-1.json"),
        ("LSN-9999-1", "lsn/LSN-9999-1.json"),
    ],
)
def test_native_records_keep_upstream_separate(identity, path):
    raw = dict(
        document(),
        id=identity,
        aliases=[],
        upstream=["CVE-2099-1234"],
        related=["USN-9998-1"],
    )
    raw["affected"] = [
        {
            "package": {"name": "synthetic-package", "ecosystem": "Ubuntu:24.04:LTS"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1:2.3-0ubuntu1"}],
                }
            ],
            "ecosystem_specific": {
                "availability": "synthetic",
                "binaries": [
                    {
                        "binary_name": "synthetic-binary",
                        "binary_version": "1:2.3-0ubuntu1",
                    }
                ],
            },
        }
    ]
    feed = parse_ubuntu(json.dumps(raw).encode(), scope=scope(identity))
    assert endpoint(identity) == BASE + path
    assert feed.records[0].raw == raw
    assert feed.records[0].aliases == () and feed.records[0].cve_ids == ()


@pytest.mark.parametrize(
    "identity",
    [
        "CVE-2099-1234",
        "USN-1-1/../x",
        "USN-1-1?url=x",
        "LSN--1",
        "UBUNTU-CVE-2099-12",
        "usn-1-1",
        None,
    ],
)
def test_invalid_native_routes(identity):
    with pytest.raises(ValueError):
        endpoint(identity)


@pytest.mark.parametrize("change", ["publisher", "tenant", "path", "identity"])
def test_wrong_scope_or_response_rejected(change):
    chosen = scope()
    raw = dict(document(), id="UBUNTU-CVE-2099-1234")
    if change == "publisher":
        chosen = replace(chosen, source="OSV")
    elif change == "tenant":
        chosen = replace(chosen, tenant_id=str(uuid4()))
    elif change == "path":
        chosen = replace(
            chosen, scope_reference=chosen.scope_reference.replace("/2099/", "/2000/")
        )
    else:
        raw["id"] = "UBUNTU-CVE-2099-9999"
    with pytest.raises(ValueError):
        parse_ubuntu(json.dumps(raw).encode(), scope=chosen)
