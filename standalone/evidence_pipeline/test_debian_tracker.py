"""Generated Debian-shaped records preserve source packages and release status."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.debian_tracker import URL, parse_debian


def scope():
    return SourceScope(
        str(uuid4()),
        "Debian",
        "tracker",
        URL,
        "synthetic",
        "TriageMate generated synthetic Debian tracker fixture",
    )


def document():
    return {
        "synthetic-package": {
            "CVE-2099-1234": {
                "releases": {
                    "synthetic-stable": {
                        "status": "resolved",
                        "fixed_version": "0",
                        "repositories": {"synthetic-stable-security": "1:2.3-4"},
                    },
                    "synthetic-testing": {
                        "status": "open",
                        "urgency": "low",
                        "nodsa": "Synthetic triage reason",
                        "repositories": {"synthetic-testing": "2:3.4-5"},
                    },
                    "synthetic-future": {
                        "status": "future_status",
                        "repositories": {},
                        "next_point_update": False,
                    },
                }
            },
            "TEMP-synthetic": {"releases": {}},
        },
        "empty-package": {},
    }


def test_preserve_releases_unknowns_and_packages_without_cves():
    raw = document()
    feed = parse_debian(json.dumps(raw).encode(), scope=scope())
    assert {r.source_record_id: r.issues for r in feed.records} == raw
    assert feed.records[0].cve_ids == ("CVE-2099-1234",)
    assert feed.records[1].cve_ids == ()


@pytest.mark.parametrize(
    "damage", ["package", "cve", "releases", "version", "flag", "tenant"]
)
def test_reject_invalid_contract_or_unapproved_public_scope(damage):
    raw = document()
    chosen = scope()
    if damage == "package":
        raw["../unsafe"] = {}
    elif damage == "cve":
        raw["synthetic-package"]["CVE-invalid"] = {"releases": {}}
    elif damage == "releases":
        raw["synthetic-package"]["CVE-2099-1234"]["releases"] = []
    elif damage == "version":
        raw["synthetic-package"]["CVE-2099-1234"]["releases"]["synthetic-stable"][
            "fixed_version"
        ] = 0
    elif damage == "flag":
        raw["synthetic-package"]["CVE-2099-1234"]["releases"]["synthetic-future"][
            "next_point_update"
        ] = "false"
    elif damage == "public":
        chosen = replace(chosen, origin="public")
    else:
        chosen = replace(chosen, tenant_id=str(uuid4()))
    with pytest.raises(ValueError):
        parse_debian(json.dumps(raw).encode(), scope=chosen)


def test_streamed_and_existing_package_contracts_are_equivalent():
    import io
    from standalone.evidence_pipeline.parsing.debian_tracker import iter_debian

    raw = json.dumps(document()).encode()
    chosen = scope()
    assert (
        tuple(iter_debian(io.BytesIO(raw), scope=chosen))
        == parse_debian(raw, scope=chosen).records
    )


def test_streamed_late_failure_does_not_become_a_complete_feed():
    import io
    from standalone.evidence_pipeline.parsing.debian_tracker import iter_debian

    raw = json.dumps(document())[:-1] + ',"invalid-package":{"CVE-invalid":{}}}'
    with pytest.raises(ValueError):
        list(iter_debian(io.BytesIO(raw.encode()), scope=scope()))
