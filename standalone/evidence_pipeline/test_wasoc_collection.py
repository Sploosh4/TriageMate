"""WA SOC discovery uses existing immutable receipts and fixed public routes."""

from contextlib import nullcontext
from datetime import datetime, timezone
import json

import pytest

from standalone.evidence_pipeline.collection import (
    github_discovery_collection as collection,
    public_transport,
    public_pacing,
)
from standalone.evidence_pipeline.parsing.github_discovery import current_commit
from standalone.evidence_pipeline.contracts import PublicDownload
from standalone.evidence_pipeline.parsing.wasoc_discovery import object_url, plan
from .test_wasoc_discovery import COMMIT, TREE, BODY, payloads


def test_complete_discovery_and_offline_replay_preserve_each_object(
    tmp_path, monkeypatch
):
    commit, tree = payloads()
    reference = json.dumps(
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": COMMIT}}
    ).encode()
    documents = {
        ("ref", "heads/main"): reference,
        ("commits", COMMIT): commit,
        ("trees", TREE): tree,
    }
    calls = []
    monkeypatch.setattr(public_pacing, "paced", lambda source: nullcontext())

    def download(kind, identity, *, source):
        assert source == "WA SOC"
        calls.append((kind, identity))
        now = datetime.now(timezone.utc)
        body = documents[kind, identity]
        return PublicDownload(object_url(kind, identity), now, now, body, body)

    monkeypatch.setattr(collection, "download_github_object", download)
    saved = {}
    for kind, identity in documents:
        saved[kind] = collection.prepare(
            kind,
            identity,
            tmp_path / kind,
            source="WA SOC",
            origin="public",
            allow_network=True,
        )
        assert saved[kind].complete
    assert current_commit(saved["ref"].payload) == COMMIT
    files = plan(COMMIT, saved["commits"].payload, saved["trees"].payload)
    assert len(files) == 1
    files[0].verify_payload(BODY)
    assert calls == list(documents)
    monkeypatch.setattr(
        collection,
        "download_github_object",
        lambda *a, **kw: pytest.fail("Offline replay contacted network"),
    )
    for kind, identity in documents:
        replay = collection.prepare(
            kind,
            identity,
            tmp_path / kind,
            source="WA SOC",
            origin="public",
            replay_only=True,
        )
        assert replay == saved[kind]
        with pytest.raises(ValueError, match="different object or origin|deferred"):
            collection.prepare(
                kind,
                identity,
                tmp_path / kind,
                source="GitHub",
                origin="public",
                replay_only=True,
            )


@pytest.mark.parametrize(
    "kind,identity", [("ref", "heads/main"), ("commits", COMMIT), ("trees", TREE)]
)
def test_transport_uses_fixed_repository_and_shared_pacing(monkeypatch, kind, identity):
    calls = []
    monkeypatch.setattr(
        public_pacing,
        "paced",
        lambda source: calls.append(("paced", source)) or nullcontext(),
    )
    monkeypatch.setattr(
        public_transport,
        "_download_url",
        lambda url, **kw: calls.append((url, kw)) or "downloaded",
    )
    assert (
        public_transport.download_github_object(kind, identity, source="WA SOC")
        == "downloaded"
    )
    assert calls == [
        ("paced", "GitHub REST"),
        (object_url(kind, identity), {"github_api": True}),
    ]


@pytest.mark.parametrize("change", ["wrong_branch", "tag", "wrong_tree", "truncated"])
def test_invalid_discovery_is_retained_as_failure_without_refetch(
    tmp_path, monkeypatch, change
):
    commit, tree = payloads()
    if change in {"wrong_branch", "tag"}:
        kind, identity = "ref", "heads/main"
        document = {
            "ref": "refs/heads/other"
            if change == "wrong_branch"
            else "refs/heads/main",
            "object": {"type": "tag" if change == "tag" else "commit", "sha": COMMIT},
        }
    else:
        kind, identity = "trees", TREE
        document = json.loads(tree)
        document.update(
            {"sha": "d" * 40} if change == "wrong_tree" else {"truncated": True}
        )
    body = json.dumps(document).encode()
    monkeypatch.setattr(
        collection,
        "download_github_object",
        lambda *a, **kw: pytest.fail("Synthetic/replay path contacted network"),
    )
    saved = collection.prepare(
        kind,
        identity,
        tmp_path / "bad",
        source="WA SOC",
        origin="synthetic",
        synthetic_payload=body,
    )
    assert saved.error_code == "invalid_github_discovery_payload"
    assert not saved.complete
    assert (
        collection.prepare(
            kind,
            identity,
            tmp_path / "bad",
            source="WA SOC",
            origin="synthetic",
            replay_only=True,
        )
        == saved
    )


def test_scanner_resumes_budget_and_separates_new_collection_from_replay(
    tmp_path, monkeypatch
):
    from standalone.evidence_pipeline.collection.github_scan import scan_current, scan

    commit, tree = payloads()
    fixtures = {
        ("ref", "heads/main"): json.dumps(
            {"ref": "refs/heads/main", "object": {"type": "commit", "sha": COMMIT}}
        ).encode(),
        ("commits", COMMIT): commit,
        ("trees", TREE): tree,
    }
    monkeypatch.setattr(
        collection,
        "download_github_object",
        lambda *a, **kw: pytest.fail("Synthetic scan contacted network"),
    )
    root = tmp_path / "current"
    options = dict(source="WA SOC", origin="synthetic", synthetic_objects=fixtures)
    first = scan_current(root, limit=1, **options)
    assert not first.complete and first.collected_objects == 1
    second = scan_current(root, limit=1, **options)
    assert not second.complete and second.collected_objects == 1
    third = scan_current(root, limit=1, **options)
    assert third.complete and third.collected_objects == 1
    assert third.discovery.partitions == ("advisories",)
    assert third.discovery.files == ()
    replay = scan_current(root, replay_only=True, **options)
    assert replay.complete and replay.collected_objects == 0
    assert replay.discovery == third.discovery
    records = scan(
        COMMIT,
        tmp_path / "records",
        partition="advisories",
        object_cache=root / "scan",
        **options,
    )
    assert records.complete and records.collected_objects == 0
    assert len(records.discovery.files) == 1
    records.discovery.files[0].verify_payload(BODY)
    assert (
        scan(
            COMMIT,
            tmp_path / "records",
            partition="advisories",
            object_cache=root / "scan",
            replay_only=True,
            **options,
        ).discovery
        == records.discovery
    )
    with pytest.raises(ValueError):
        scan_current(root, partition="../other", **options)


def test_command_exposes_pinned_advisory_scan_and_offline_replay(tmp_path, capsys):
    from standalone.evidence_pipeline.collection.github_scan import main

    commit, tree = payloads()
    records = []
    for kind, identity, body in (("commits", COMMIT, commit), ("trees", TREE, tree)):
        filename = kind + ".json"
        (tmp_path / filename).write_bytes(body)
        records.append(dict(kind=kind, identity=identity, file=filename))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(dict(objects=records)))
    args = [
        "--source",
        "WA SOC",
        "--commit",
        COMMIT,
        "--bundle",
        str(tmp_path / "scan"),
        "--origin",
        "synthetic",
        "--partition",
        "advisories",
    ]
    assert main(args + ["--synthetic-manifest", str(manifest)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["complete"] and len(first["discovery"]["files"]) == 1
    assert main(args + ["--replay-only"]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["complete"] and replay["collected_objects"] == 0
    assert replay["discovery"] == first["discovery"]


def test_advisory_bundle_replays_exact_claim_and_keeps_publisher_clock_unknown(
    tmp_path, monkeypatch
):
    from uuid import uuid4
    from standalone.evidence_pipeline.collection.public_collection import prepare
    from .test_wasoc_advisories import scope, BODY
    from standalone.evidence_pipeline.parsing.public_records import normalize_public
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        reconstruct_reference,
    )
    from standalone.operations.provider_age import provider_clock

    chosen = scope()
    execution = str(uuid4())
    monkeypatch.setattr(
        public_transport,
        "_download_url",
        lambda *a, **kw: pytest.fail("Synthetic/replay downloaded a document"),
    )
    first = prepare(chosen, execution, tmp_path / "advisory", synthetic_payload=BODY)
    assert first.complete
    replay = prepare(chosen, execution, tmp_path / "advisory", replay_only=True)
    assert replay == first
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory

    feed = parse_advisory(replay.payload, scope=chosen)
    assert provider_clock(feed) == (None, None, None)
    (record,) = normalize_public(feed)
    assert reconstruct_reference(chosen, record.claim) == record
    with pytest.raises(ValueError):
        prepare(
            chosen,
            execution,
            tmp_path / "other",
            synthetic_payload=BODY,
            cve="CVE-2099-12345",
        )
    assert not (tmp_path / "other").exists()
