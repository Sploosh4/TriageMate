"""Synthetic Canonical metadata, incomplete inventories and immutable blobs."""

import hashlib
import json

import pytest

from standalone.evidence_pipeline.parsing import ubuntu_discovery as discovery

COMMIT = "a" * 40
PAYLOAD = b'{"synthetic":true}'


def fixture():
    ids = [f"{i + 1:040x}" for i in range(6)]
    blob = hashlib.sha1(
        b"blob " + str(len(PAYLOAD)).encode() + b"\0" + PAYLOAD
    ).hexdigest()

    def entry(name, sha, leaf=False):
        return dict(
            path=name,
            sha=sha,
            type="blob" if leaf else "tree",
            mode="100644" if leaf else "040000",
            size=len(PAYLOAD),
        )

    rows = [
        [entry("osv", ids[1])],
        [entry("cve", ids[2]), entry("usn", ids[3]), entry("lsn", ids[4])],
        [entry("2099", ids[5])],
        [entry("USN-9999-1.json", blob, True)],
        [entry("LSN-9999-1.json", blob, True)],
        [entry("UBUNTU-CVE-2099-1234.json", blob, True)],
    ]
    trees = {
        identity: json.dumps(dict(sha=identity, truncated=False, tree=row)).encode()
        for identity, row in zip(ids, rows, strict=True)
    }
    commit = json.dumps(dict(sha=COMMIT, tree=dict(sha=ids[0]))).encode()
    return commit, trees, ids


def test_index_does_not_require_or_claim_downloaded_advisories():
    commit, trees, ids = fixture()
    for identity in ids[3:]:
        del trees[identity]
    index = discovery.plan(COMMIT, commit, trees)
    assert index.complete and not index.files
    assert index.partitions == ("cve/2099", "lsn", "usn")
    for partition, identity in zip(("usn", "lsn", "cve/2099"), ids[3:], strict=True):
        pending = discovery.plan(COMMIT, commit, trees, partition=partition)
        assert not pending.complete and pending.pending_trees == (identity,)


@pytest.mark.parametrize("partition", ["usn", "lsn", "cve/2099"])
def test_partition_identity_and_blob_verification(partition):
    commit, trees, _ = fixture()
    result = discovery.plan(COMMIT, commit, trees, partition=partition)
    assert result.complete and len(result.files) == 1
    record = result.files[0]
    assert f"/{COMMIT}/osv/{partition}/" in record.url
    record.verify_payload(PAYLOAD)
    with pytest.raises(ValueError, match="blob"):
        record.verify_payload(b"x" * len(PAYLOAD))
    with pytest.raises(ValueError, match="size"):
        record.verify_payload(b"")


@pytest.mark.parametrize(
    "damage",
    [
        "truncated",
        "sha",
        "duplicate",
        "traversal",
        "symlink",
        "wrong_year",
        "bool_size",
        "missing",
    ],
)
def test_bad_inventory_cannot_be_complete(damage):
    commit, trees, ids = fixture()
    tree = json.loads(trees[ids[5]])
    item = tree["tree"][0]
    if damage == "truncated":
        tree["truncated"] = True
    elif damage == "sha":
        tree["sha"] = "f" * 40
    elif damage == "duplicate":
        tree["tree"].append(item.copy())
    elif damage == "traversal":
        item["path"] = "../escape.json"
    elif damage == "symlink":
        item["mode"] = "120000"
    elif damage == "wrong_year":
        item["path"] = "UBUNTU-CVE-2098-1234.json"
    elif damage == "bool_size":
        item["size"] = True
    elif damage == "missing":
        parent = json.loads(trees[ids[2]])
        parent["tree"] = []
        trees[ids[2]] = json.dumps(parent).encode()
    trees[ids[5]] = json.dumps(tree).encode()
    with pytest.raises(ValueError):
        discovery.plan(COMMIT, commit, trees, partition="cve/2099")


def test_budget_and_untrusted_destinations(monkeypatch):
    commit, trees, _ = fixture()
    with pytest.raises(ValueError):
        discovery.object_url("trees", "https://example.org/evil")
    with pytest.raises(ValueError):
        discovery.plan(COMMIT, commit, trees, partition="../usn")
    monkeypatch.setattr(discovery, "MAX_ENTRIES", 2)
    with pytest.raises(ValueError, match="cache"):
        discovery.plan(COMMIT, commit, trees)
    monkeypatch.setattr(discovery, "MAX_ENTRIES", 100_000)


def test_empty_selected_partition_and_missing_root_are_distinct():
    commit, trees, ids = fixture()
    tree = json.loads(trees[ids[3]])
    tree["tree"] = []
    trees[ids[3]] = json.dumps(tree).encode()
    empty = discovery.plan(COMMIT, commit, trees, partition="usn")
    assert empty.complete and not empty.files
    del trees[ids[0]]
    assert not discovery.plan(COMMIT, commit, trees, partition="usn").complete


def objects():
    commit, trees, _ = fixture()
    return {
        ("ref", "heads/main"): json.dumps(
            dict(ref="refs/heads/main", object=dict(type="commit", sha=COMMIT))
        ).encode(),
        ("commits", COMMIT): commit,
        **{("trees", identity): wire for identity, wire in trees.items()},
    }


def test_deferred_scan_rejects_new_collection_and_replay(tmp_path, monkeypatch):
    from standalone.evidence_pipeline.collection.github_scan import scan_current, scan

    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.github_discovery_collection.download_github_object",
        lambda *a, **k: pytest.fail("Synthetic discovery must not use network"),
    )
    bundle = tmp_path / "ubuntu"
    cache = tmp_path / "cache"
    options = dict(
        source="Ubuntu",
        origin="synthetic",
        synthetic_objects=objects(),
        object_cache=cache,
        limit=2,
    )
    with pytest.raises(ValueError, match="deferred"):
        scan_current(bundle, **options)
    with pytest.raises(ValueError, match="deferred"):
        scan_current(bundle, source="Ubuntu", origin="synthetic", replay_only=True)
    with pytest.raises(ValueError, match="deferred"):
        scan(COMMIT, tmp_path / "usn", partition="usn", **options)
    assert not bundle.exists() and not cache.exists()


def test_scan_cli_reports_explicit_ubuntu_deferral(tmp_path, capsys):
    from standalone.evidence_pipeline.collection.github_scan import main

    manifest = []
    for position, ((kind, identity), wire) in enumerate(objects().items()):
        name = f"synthetic-{position}.json"
        (tmp_path / name).write_bytes(wire)
        manifest.append(dict(kind=kind, identity=identity, file=name))
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(dict(objects=manifest)))
    assert (
        main(
            [
                "--source",
                "Ubuntu",
                "--current",
                "--bundle",
                str(tmp_path / "scan"),
                "--origin",
                "synthetic",
                "--synthetic-manifest",
                str(path),
            ]
        )
        == 1
    )
    result = capsys.readouterr()
    assert "deferred" in result.err and not result.out
    assert not (tmp_path / "scan").exists()


def test_deferred_metadata_transport_never_fetches(monkeypatch):
    from contextlib import nullcontext
    from standalone.evidence_pipeline.collection import public_transport

    calls = []
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.public_pacing.paced",
        lambda key: nullcontext(),
    )
    monkeypatch.setattr(
        public_transport,
        "_download_url",
        lambda url, **kwargs: calls.append((url, kwargs)),
    )
    with pytest.raises(ValueError, match="deferred"):
        public_transport.download_github_object("trees", COMMIT, source="Ubuntu")
    with pytest.raises(ValueError):
        public_transport.download_github_object("trees", "../../other", source="Ubuntu")
    assert calls == []
