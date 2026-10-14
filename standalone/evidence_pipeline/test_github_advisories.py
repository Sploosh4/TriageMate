"""Generated GitHub-shaped OSV records and synthetic HTTP; no public requests."""

from dataclasses import replace
from decimal import Decimal
from uuid import uuid4

import pytest
from standalone.evidence_pipeline.source_json import encode_source_records
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.github_advisories import (
    endpoint,
    parse_github_advisory,
)
from standalone.evidence_pipeline.parsing.osv_records import normalize_osv
from standalone.evidence_pipeline.collection.public_transport import download
from .test_osv import document
from .test_public_transport import server  # noqa: F401

COMMIT = "a" * 40
IDENTITY = "GHSA-2222-3333-4444"
PATH = f"advisories/github-reviewed/2099/09/{IDENTITY}/{IDENTITY}.json"


def scope(path=PATH):
    return SourceScope(
        str(uuid4()),
        "GitHub",
        "advisories",
        endpoint(COMMIT, path),
        "synthetic",
        "TriageMate generated synthetic GitHub OSV fixture",
    )


def test_github_export_retains_publisher_and_unstable_extension_fields():
    raw = dict(
        document(),
        id=IDENTITY,
        database_specific={
            "github_reviewed": True,
            "synthetic_number": Decimal("0.123456789123456789"),
        },
    )
    raw["affected"][0]["ranges"][0]["database_specific"] = {
        "last_known_affected_version_range": ">= 1.0, < 2.0"
    }
    chosen = scope()
    feed = parse_github_advisory(encode_source_records(raw), scope=chosen)
    assert feed.scope.source == "GitHub" and feed.scope == chosen
    assert feed.records[0].raw == raw
    assert feed.records[0].cve_ids == tuple(raw["aliases"])
    assert list(normalize_osv(feed))[0].source_record_id == IDENTITY


@pytest.mark.parametrize("directory", ["github-reviewed", "unreviewed"])
def test_unaliased_withdrawn_advisory_is_retained(directory):
    path = PATH.replace("github-reviewed", directory)
    raw = dict(document(), id=IDENTITY, aliases=[], withdrawn="2099-09-14T00:00:00Z")
    record = parse_github_advisory(
        encode_source_records(raw), scope=scope(path)
    ).records[0]
    assert record.cve_ids == () and record.withdrawn == raw["withdrawn"]


@pytest.mark.parametrize(
    "commit", [None, "main", "a" * 39, "a" * 41, "0" * 40, "a" * 39 + "/", "A" * 40]
)
def test_only_explicit_commit_identity_is_accepted(commit):
    with pytest.raises(ValueError):
        endpoint(commit, PATH)


@pytest.mark.parametrize(
    "path",
    [
        "../" + PATH,
        PATH + "?x=1",
        PATH + "#other",
        PATH.replace("2099/09", "2099/13"),
        PATH.replace("github-reviewed", "malware"),
        PATH.replace(IDENTITY + ".json", "GHSA-5555-6666-7777.json"),
        PATH.replace("2222", "1111"),
        PATH.replace("advisories", "%61dvisories"),
    ],
)
def test_path_cannot_change_repository_structure_or_identity(path):
    with pytest.raises(ValueError):
        endpoint(COMMIT, path)


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "OSV"},
        {"tenant_id": str(uuid4())},
        {"scope_reference": "https://example.invalid/record"},
        {"scope_reference": endpoint(COMMIT, PATH).replace(COMMIT, "main")},
    ],
)
def test_source_scope_cannot_be_relabelled(changes):
    with pytest.raises(ValueError):
        parse_github_advisory(
            encode_source_records(dict(document(), id=IDENTITY)),
            scope=replace(scope(), **changes),
        )


def test_different_response_identity_rejected():
    with pytest.raises(ValueError, match="different advisory"):
        parse_github_advisory(
            encode_source_records(dict(document(), id="GHSA-5555-6666-7777")),
            scope=scope(),
        )


def test_deferred_repository_transport_never_opens_connection(server):  # noqa: F811
    with pytest.raises(ValueError, match="deferred"):
        download(
            "GitHub",
            input_kind="advisories",
            repository_commit=COMMIT,
            repository_path=PATH,
        )
    assert not server.closed


def test_repository_route_cannot_mix_source_filters_or_follow_redirect(server):  # noqa: F811
    from standalone.evidence_pipeline.collection.public_transport import (
        endpoint as transport_endpoint,
    )

    for overrides in (
        {"cve": "CVE-2099-1234"},
        {"advisory_id": IDENTITY},
        {"month": "2099-Sep"},
    ):
        with pytest.raises(ValueError, match="mix"):
            transport_endpoint(
                "GitHub",
                input_kind="advisories",
                repository_commit=COMMIT,
                repository_path=PATH,
                **overrides,
            )
    server.response.status = 302
    server.response.headers["Location"] = "https://example.invalid/private"
    with pytest.raises(ValueError, match="deferred"):
        download(
            "GitHub",
            input_kind="advisories",
            repository_commit=COMMIT,
            repository_path=PATH,
        )
    assert not server.closed
