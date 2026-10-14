"""Ubuntu discovery-to-bundle continuation and exact-record completion."""

import hashlib
import json

import pytest

from .test_ubuntu_discovery import objects, COMMIT
from .test_osv import document


def fixtures():
    metadata = objects()
    payloads = {}
    for key, wire in list(metadata.items()):
        if key[0] != "trees":
            continue
        tree = json.loads(wire)
        for item in tree["tree"]:
            if item["type"] != "blob":
                continue
            native = item["path"].removesuffix(".json")
            partition = (
                "cve/2099" if native.startswith("UBUNTU-") else native[:3].lower()
            )
            payload = json.dumps(
                dict(
                    document(),
                    id=native,
                    aliases=[],
                    upstream=["UBUNTU-CVE-2099-9999"],
                    related=["USN-9998-1"],
                )
            ).encode()
            payloads["osv/" + partition + "/" + item["path"]] = payload
            item["size"] = len(payload)
            item["sha"] = hashlib.sha1(
                b"blob " + str(len(payload)).encode() + b"\0" + payload
            ).hexdigest()
        metadata[key] = json.dumps(tree).encode()
    return metadata, payloads


@pytest.mark.parametrize(
    "damage", ["host", "revision", "zero", "year", "query", "traversal"]
)
def test_pinned_parser_rejects_mismatched_scope(damage):
    from dataclasses import replace
    from .test_ubuntu_advisories import scope
    from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
        parse_ubuntu,
        repository_endpoint,
    )

    native = "UBUNTU-CVE-2099-1234"
    url = repository_endpoint(COMMIT, "osv/cve/2099/" + native + ".json", native)
    payload = json.dumps(dict(document(), id=native, aliases=[])).encode()
    assert (
        parse_ubuntu(payload, scope=replace(scope(native), scope_reference=url))
        .records[0]
        .advisory_id
        == native
    )
    url = {
        "host": url.replace("raw.githubusercontent.com", "evil.example"),
        "revision": url.replace(COMMIT, "abc"),
        "zero": url.replace(COMMIT, "0" * 40),
        "year": url.replace("/2099/", "/2098/"),
        "query": url + "?raw=true",
        "traversal": url.replace("/osv/", "/osv/../osv/"),
    }[damage]
    with pytest.raises(ValueError):
        parse_ubuntu(payload, scope=replace(scope(native), scope_reference=url))


def test_pinned_transport_rejects_mixed_source_routes():
    from standalone.evidence_pipeline.collection.public_transport import endpoint

    args = dict(
        input_kind="advisories",
        advisory_id="USN-9999-1",
        repository_commit=COMMIT,
        repository_path="osv/usn/USN-9999-1.json",
    )
    assert f"/{COMMIT}/" in endpoint("Ubuntu", **args)
    for key, value in [
        ("cve", "CVE-2099-1234"),
        ("month", "2099-Jan"),
        ("vendor_path", "2099/example.json"),
    ]:
        with pytest.raises(ValueError):
            endpoint("Ubuntu", **dict(args, **{key: value}))
