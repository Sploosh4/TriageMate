"""Synthetic complete tree and byte-identity acceptance; no network."""

import hashlib
import json
import pytest
from standalone.evidence_pipeline.parsing.wasoc_discovery import plan, object_url

COMMIT = "a" * 40
TREE = "b" * 40
BODY = b"# Synthetic advisory - 20990101001\n\nSynthetic data.\n"
BLOB = hashlib.sha1(b"blob " + str(len(BODY)).encode() + b"\0" + BODY).hexdigest()
PATH = "docs/advisories/20990101001-Synthetic.md"


def payloads(items=None, **changes):
    entries = [
        dict(path="docs/advisories", type="tree", mode="040000", sha="c" * 40),
        dict(path=PATH, type="blob", mode="100644", size=len(BODY), sha=BLOB),
    ]
    tree = dict(sha=TREE, truncated=False, tree=entries if items is None else items)
    tree.update(changes)
    return json.dumps(dict(sha=COMMIT, tree=dict(sha=TREE))).encode(), json.dumps(
        tree
    ).encode()


def test_complete_tree_binds_blob_and_preserves_duplicate_native_ids():
    commit, tree = payloads()
    doc = json.loads(tree)
    other = dict(doc["tree"][1], path=PATH.replace("Synthetic", "Another-Synthetic"))
    doc["tree"].append(other)
    files = plan(COMMIT, commit, json.dumps(doc).encode())
    assert len(files) == 2 and files[0].advisory_id == files[1].advisory_id
    assert files[0].url != files[1].url
    for file in files:
        file.verify_payload(BODY)
        with pytest.raises(ValueError):
            file.verify_payload(BODY + b"corrupt")


@pytest.mark.parametrize(
    "change",
    [dict(truncated=True), dict(sha="d" * 40), dict(tree=[]), dict(truncated=None)],
)
def test_partial_or_unbound_index_is_not_complete(change):
    with pytest.raises(ValueError):
        plan(COMMIT, *payloads(**change))


@pytest.mark.parametrize(
    "change",
    [
        dict(mode="120000"),
        dict(size=True),
        dict(path="docs/advisories/../escape.md"),
        dict(sha="0" * 40),
        dict(type="commit"),
    ],
)
def test_invalid_advisory_objects(change):
    commit, tree = payloads()
    doc = json.loads(tree)
    doc["tree"][1].update(change)
    with pytest.raises(ValueError):
        plan(COMMIT, commit, json.dumps(doc).encode())


def test_duplicate_paths_are_rejected():
    commit, tree = payloads()
    doc = json.loads(tree)
    doc["tree"].append(doc["tree"][1])
    with pytest.raises(ValueError):
        plan(COMMIT, commit, json.dumps(doc).encode())


def test_fixed_objects_never_take_response_urls():
    assert object_url("trees", TREE).endswith(TREE + "?recursive=1")
    with pytest.raises(ValueError):
        object_url("trees", "main")
    with pytest.raises(ValueError):
        object_url("https://evil", "main")
