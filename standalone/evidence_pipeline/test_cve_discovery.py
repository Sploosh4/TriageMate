"""Synthetic repository trees prove bounded discovery without upstream access."""

import hashlib
import json

import pytest

from standalone.evidence_pipeline.parsing import cve_discovery as discovery

COMMIT = "a" * 40
PAYLOAD = b'{"synthetic":true}'


def fixture(source="CVE"):
    names = (["cves"] if source == "CVE" else []) + [
        "2099",
        "1xxx",
        "CVE-2099-1234.json",
    ]
    ids = [f"{i + 1:040x}" for i in range(len(names))]
    blob = hashlib.sha1(
        b"blob " + str(len(PAYLOAD)).encode() + b"\0" + PAYLOAD
    ).hexdigest()
    trees = {}
    for i, name in enumerate(names):
        leaf = i == len(names) - 1
        item = dict(
            path=name,
            mode="100644" if leaf else "040000",
            type="blob" if leaf else "tree",
            sha=blob if leaf else ids[i + 1],
        )
        if leaf:
            item["size"] = len(PAYLOAD)
        trees[ids[i]] = json.dumps(
            dict(sha=ids[i], truncated=False, tree=[item])
        ).encode()
    return json.dumps(dict(sha=COMMIT, tree=dict(sha=ids[0]))).encode(), trees, ids


@pytest.mark.parametrize("source", ["CVE", "CISA"])
def test_index_and_partition_do_not_confuse_metadata_with_downloads(source):
    commit, trees, ids = fixture(source)
    leaf = trees.pop(ids[-1])
    index = discovery.plan(source, COMMIT, commit, trees)
    assert index.complete and index.partitions == ("2099/1xxx",) and index.files == ()
    pending = discovery.plan(
        source, COMMIT, commit, trees, partition=index.partitions[0]
    )
    assert not pending.complete and pending.pending_trees == (ids[-1],)
    trees[ids[-1]] = leaf
    result = discovery.plan(source, COMMIT, commit, trees, partition="2099/1xxx")
    assert result.complete and len(result.files) == 1
    record = result.files[0]
    assert record.cve_id == "CVE-2099-1234"
    assert f"/{COMMIT}/" in record.url and record.url.endswith(record.path)
    record.verify_payload(PAYLOAD)
    with pytest.raises(ValueError, match="size"):
        record.verify_payload(b"short")
    with pytest.raises(ValueError, match="blob"):
        record.verify_payload(b"x" * len(PAYLOAD))


@pytest.mark.parametrize(
    "damage",
    [
        "truncated",
        "sha",
        "duplicate",
        "traversal",
        "symlink",
        "wrong_bucket",
        "wrong_year",
        "bool_size",
        "missing",
    ],
)
def test_invalid_record_inventory_never_becomes_complete(damage):
    commit, trees, ids = fixture()
    leaf = json.loads(trees[ids[-1]])
    item = leaf["tree"][0]
    if damage == "truncated":
        leaf["truncated"] = True
    elif damage == "sha":
        leaf["sha"] = "f" * 40
    elif damage == "duplicate":
        leaf["tree"].append(item.copy())
    elif damage == "traversal":
        item["path"] = "../CVE-2099-1234.json"
    elif damage == "symlink":
        item["mode"] = "120000"
    elif damage == "wrong_bucket":
        item["path"] = "CVE-2099-2234.json"
    elif damage == "wrong_year":
        item["path"] = "CVE-2098-1234.json"
    elif damage == "bool_size":
        item["size"] = True
    elif damage == "missing":
        parent = json.loads(trees[ids[-2]])
        parent["tree"] = []
        trees[ids[-2]] = json.dumps(parent).encode()
    trees[ids[-1]] = json.dumps(leaf).encode()
    with pytest.raises(ValueError):
        discovery.plan("CVE", COMMIT, commit, trees, partition="2099/1xxx")


def test_empty_bucket_is_complete_and_bounds_fail_explicitly(monkeypatch):
    commit, trees, ids = fixture()
    trees[ids[-1]] = json.dumps(dict(sha=ids[-1], truncated=False, tree=[])).encode()
    result = discovery.plan("CVE", COMMIT, commit, trees, partition="2099/1xxx")
    assert result.complete and result.files == ()


def test_selected_bucket_does_not_require_other_bucket_payloads():
    commit, trees, ids = fixture()
    parent = json.loads(trees[ids[-2]])
    parent["tree"].append(dict(path="2xxx", type="tree", mode="040000", sha="e" * 40))
    trees[ids[-2]] = json.dumps(parent).encode()
    result = discovery.plan("CVE", COMMIT, commit, trees, partition="2099/1xxx")
    assert result.complete and len(result.files) == 1
    index = discovery.plan("CVE", COMMIT, commit, trees)
    assert index.partitions == ("2099/1xxx", "2099/2xxx")


@pytest.mark.parametrize(
    "partition", ["2099/../1xxx", "2099/1xxx?x", "2099/", "2099/１xxx", True]
)
def test_partition_cannot_introduce_a_path(partition):
    commit, trees, _ = fixture()
    with pytest.raises(ValueError, match="partition"):
        discovery.plan("CVE", COMMIT, commit, trees, partition=partition)


def test_repeated_ancestor_is_rejected():
    commit, trees, ids = fixture()
    parent = json.loads(trees[ids[0]])
    parent["tree"][0]["sha"] = ids[0]
    trees[ids[0]] = json.dumps(parent).encode()
    with pytest.raises(ValueError, match="Cyclic"):
        discovery.plan("CVE", COMMIT, commit, trees)


@pytest.mark.parametrize("source", ["CVE", "CISA"])
def test_durable_scan_continues_with_shared_budget_and_replays_offline(
    tmp_path, monkeypatch, source
):
    from standalone.evidence_pipeline.collection import (
        github_scan,
        github_discovery_collection,
    )

    monkeypatch.setattr(
        github_discovery_collection,
        "download_github_object",
        lambda *a, **kw: pytest.fail("Unexpected network"),
    )
    commit, trees, _ = fixture(source)
    branch = "heads/main" if source == "CVE" else "heads/develop"
    fixtures = {
        ("commits", COMMIT): commit,
        ("ref", branch): json.dumps(
            dict(ref="refs/" + branch, object=dict(type="commit", sha=COMMIT))
        ).encode(),
    }
    fixtures.update({("trees", key): value for key, value in trees.items()})
    bundle = tmp_path / "scan"
    for _ in range(6):
        result = github_scan.scan_current(
            bundle,
            source=source,
            origin="synthetic",
            synthetic_objects=fixtures,
            limit=1,
            partition="2099/1xxx",
        )
        assert result.collected_objects <= 1
        if result.complete:
            break
    assert result.complete and result.discovery.files[0].cve_id == "CVE-2099-1234"
    replay = github_scan.scan_current(
        bundle,
        source=source,
        origin="synthetic",
        replay_only=True,
        limit=0,
        partition="2099/1xxx",
    )
    assert (
        replay.complete
        and replay.collected_objects == 0
        and replay.discovery == result.discovery
    )
    with pytest.raises(ValueError, match="different object"):
        github_scan.scan_current(
            bundle,
            source="CISA" if source == "CVE" else "CVE",
            origin="synthetic",
            replay_only=True,
        )


@pytest.mark.parametrize("source", ["CVE", "CISA"])
def test_pinned_record_uses_existing_public_bundle_and_replay(
    tmp_path, monkeypatch, source
):
    from dataclasses import replace
    from uuid import uuid4
    from standalone.evidence_pipeline.collection import (
        public_collection,
        public_transport,
    )
    from .test_cve_program import document, scope

    monkeypatch.setattr(
        public_collection,
        "download",
        lambda *a, **kw: pytest.fail("Unexpected network"),
    )
    cve = "CVE-2099-12345"
    path = ("cves/" if source == "CVE" else "") + "2099/12xxx/" + cve + ".json"
    kind = "records" if source == "CVE" else "vulnrichment"
    url = public_transport.endpoint(
        source, cve, input_kind=kind, repository_commit=COMMIT, repository_path=path
    )
    bound = replace(scope(), source=source, input_kind=kind, scope_reference=url)
    options = dict(cve=cve, repository_commit=COMMIT, repository_path=path)
    execution = str(uuid4())
    wire = json.dumps(document()).encode()
    result = public_collection.prepare(
        bound, execution, tmp_path / "record", synthetic_payload=wire, **options
    )
    assert result.complete and result.records()[0].cve_id == cve
    replay = public_collection.prepare(
        bound, execution, tmp_path / "record", replay_only=True, **options
    )
    assert replay == result
    with pytest.raises(ValueError):
        public_transport.endpoint(
            source,
            cve,
            input_kind=kind,
            repository_commit=COMMIT,
            repository_path=path.replace("12xxx", "13xxx"),
        )
    with pytest.raises(ValueError):
        public_transport.endpoint(
            source, cve, input_kind=kind, repository_commit="main", repository_path=path
        )
