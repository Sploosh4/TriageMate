"""Synthetic Git objects prove completeness and discovery integrity boundaries."""

import hashlib
import json

import pytest

from standalone.evidence_pipeline.parsing import github_discovery as discovery
from .test_github_advisories import COMMIT, PATH


def wire(value):
    return json.dumps(value).encode()


def fixture():
    names = PATH.split("/")
    ids = [f"{i + 1:040x}" for i in range(len(names))]
    payload = b"explicitly synthetic advisory bytes"
    blob = hashlib.sha1(
        b"blob " + str(len(payload)).encode() + b"\0" + payload
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
            item["size"] = len(payload)
        trees[ids[i]] = wire(dict(sha=ids[i], truncated=False, tree=[item]))
    parent = json.loads(trees[ids[1]])
    empty_id = "e" * 40
    parent["tree"].append(
        dict(path="unreviewed", type="tree", mode="040000", sha=empty_id)
    )
    trees[ids[1]] = wire(parent)
    trees[empty_id] = wire(dict(sha=empty_id, truncated=False, tree=[]))
    return wire(dict(sha=COMMIT, tree=dict(sha=ids[0]))), trees, ids, payload


def test_month_index_does_not_require_advisory_trees():
    commit, trees, ids, _ = fixture()
    del trees[ids[-1]]
    month = "github-reviewed/2099/09"
    indexed = discovery.plan(COMMIT, commit, trees, partition=month, index_only=True)
    assert indexed.complete and not indexed.files
    assert indexed.partitions == (month + "@000000",)
    chunk = discovery.plan(COMMIT, commit, trees, partition=indexed.partitions[0])
    assert not chunk.complete and chunk.pending_trees == (ids[-1],)
    with pytest.raises(ValueError, match="outside its month"):
        discovery.plan(COMMIT, commit, trees, partition=month + "@000128")
    with pytest.raises(ValueError, match="align"):
        discovery.partition_prefix(month + "@000001")


def test_empty_native_advisory_directory_is_not_complete():
    commit, trees, ids, _ = fixture()
    trees[ids[-1]] = wire(dict(sha=ids[-1], truncated=False, tree=[]))
    with pytest.raises(ValueError, match="missing its native record"):
        discovery.plan(
            COMMIT, commit, trees, partition="github-reviewed/2099/09@000000"
        )


def test_month_index_rejects_unknown_directory_identity():
    commit, trees, ids, _ = fixture()
    month = json.loads(trees[ids[-2]])
    month["tree"][0]["path"] = "unknown-directory"
    trees[ids[-2]] = wire(month)
    with pytest.raises(ValueError, match="Unsupported advisory directory"):
        discovery.plan(
            COMMIT, commit, trees, partition="github-reviewed/2099/09", index_only=True
        )


def test_discovery_resumes_only_when_every_subtree_present():
    commit, trees, ids, payload = fixture()
    partial = discovery.plan(COMMIT, commit, {ids[0]: trees[ids[0]]})
    assert (
        not partial.complete
        and partial.pending_trees == (ids[1],)
        and not partial.files
    )
    complete = discovery.plan(COMMIT, commit, trees)
    assert complete.complete and len(complete.files) == 1
    file = complete.files[0]
    assert file.path == PATH and COMMIT in file.url
    file.verify_payload(payload)
    with pytest.raises(ValueError, match="blob"):
        file.verify_payload(b"x" * len(payload))
    with pytest.raises(ValueError, match="size"):
        file.verify_payload(b"x")


@pytest.mark.parametrize(
    "damage",
    [
        "truncated",
        "wrong_sha",
        "duplicate",
        "recursive",
        "traversal",
        "cycle",
        "symlink",
        "bad_size",
        "wrong_leaf",
        "missing_truncated",
    ],
)
def test_discovery_rejects_invalid_or_incomplete_tree(damage):
    commit, trees, ids, _ = fixture()
    target = ids[-1] if damage in {"symlink", "bad_size", "wrong_leaf"} else ids[0]
    value = json.loads(trees[target])
    item = value["tree"][0]
    if damage == "truncated":
        value["truncated"] = True
    elif damage == "wrong_sha":
        value["sha"] = "f" * 40
    elif damage == "duplicate":
        value["tree"].append(dict(item))
    elif damage == "recursive":
        item["path"] = "advisories/github-reviewed"
    elif damage == "traversal":
        item["path"] = ".."
    elif damage == "cycle":
        item["sha"] = ids[0]
    elif damage == "symlink":
        item["mode"] = "120000"
    elif damage == "bad_size":
        item["size"] = True
    elif damage == "wrong_leaf":
        item["path"] = "wrong.json"
    elif damage == "missing_truncated":
        del value["truncated"]
    trees[target] = wire(value)
    with pytest.raises(ValueError):
        discovery.plan(COMMIT, commit, trees)


def test_discovery_ignores_unrelated_directories_and_never_uses_body_urls():
    commit, trees, ids, _ = fixture()
    root = json.loads(trees[ids[0]])
    root["tree"].append(
        dict(
            path="docs", type="tree", sha="f" * 40, url="https://example.invalid/secret"
        )
    )
    trees[ids[0]] = wire(root)
    assert discovery.plan(COMMIT, commit, trees).complete
    assert discovery.object_url("trees", ids[0]) == discovery.API + "trees/" + ids[0]


@pytest.mark.parametrize(
    "identity", ["main", "0" * 40, "a" * 39, "A" * 40, "../main", None]
)
def test_discovery_rejects_unpinned_routes(identity):
    with pytest.raises(ValueError):
        discovery.object_url("trees", identity)


def test_discovery_binds_commit_and_bounds_total(monkeypatch):
    commit, trees, _, _ = fixture()
    with pytest.raises(ValueError, match="commit"):
        discovery.plan("f" * 40, commit, trees)
    monkeypatch.setattr(discovery, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError):
        discovery.plan(COMMIT, commit, trees)
    monkeypatch.setattr(discovery, "MAX_ENTRIES", 100_000)


def test_missing_advisory_families_cannot_be_a_complete_empty_inventory():
    commit, trees, ids, _ = fixture()
    trees[ids[0]] = wire(dict(sha=ids[0], truncated=False, tree=[]))
    with pytest.raises(ValueError, match="required advisory directory"):
        discovery.plan(COMMIT, commit, trees)


@pytest.mark.parametrize(
    "document",
    [
        dict(ref="refs/heads/other", object=dict(type="commit", sha=COMMIT)),
        dict(ref="refs/heads/main", object=dict(type="tag", sha=COMMIT)),
        dict(ref="refs/heads/main", object=dict(type="commit", sha="main")),
        dict(ref="refs/heads/main", object=None),
    ],
)
def test_current_reference_rejects_wrong_branch_type_or_identity(document):
    with pytest.raises(ValueError):
        discovery.current_commit(wire(document))


def test_current_reference_has_one_fixed_route():
    assert discovery.object_url("ref", "heads/main") == discovery.API + "ref/heads/main"
    with pytest.raises(ValueError):
        discovery.object_url("ref", "heads/other")
