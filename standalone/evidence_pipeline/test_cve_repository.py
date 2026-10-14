"""Explicitly synthetic repository passes preserve origin, budgets and replay."""

import hashlib
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection import (
    cve_repository,
    github_dispatch,
    github_discovery_collection,
    public_collection,
)
from .test_cve_discovery import COMMIT, fixture
from .test_cve_program import document


def repository(source, cves=("CVE-2099-1234", "CVE-2099-1235")):
    commit, trees, ids = fixture(source)
    bucket = cves[0].split("-")[2][:-3] + "xxx"
    parent = json.loads(trees[ids[-2]])
    parent["tree"][0]["path"] = bucket
    trees[ids[-2]] = json.dumps(parent).encode()
    payloads = {}
    leaf = json.loads(trees[ids[-1]])
    leaf["tree"] = []
    for cve in cves:
        record = document()
        record["cveMetadata"]["cveId"] = cve
        payload = json.dumps(record).encode()
        path = (
            ("cves/" if source == "CVE" else "")
            + "2099/"
            + bucket
            + "/"
            + cve
            + ".json"
        )
        payloads[path] = payload
        blob = hashlib.sha1(
            b"blob " + str(len(payload)).encode() + b"\0" + payload
        ).hexdigest()
        leaf["tree"].append(
            dict(
                path=cve + ".json",
                type="blob",
                mode="100644",
                sha=blob,
                size=len(payload),
            )
        )
    trees[ids[-1]] = json.dumps(leaf).encode()
    branch = "heads/main" if source == "CVE" else "heads/develop"
    objects = {
        ("ref", branch): json.dumps(
            dict(ref="refs/" + branch, object=dict(type="commit", sha=COMMIT))
        ).encode(),
        ("commits", COMMIT): commit,
    }
    objects.update({("trees", key): value for key, value in trees.items()})
    return objects, payloads


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def reject(*a, **kw):
        pytest.fail("Unexpected network or database")

    monkeypatch.setattr(github_discovery_collection, "download_github_object", reject)
    monkeypatch.setattr(public_collection, "download", reject)
    monkeypatch.setattr(github_dispatch, "register", reject)
    monkeypatch.setattr(github_dispatch, "ingest_public", reject)


@pytest.mark.parametrize("source", ["CVE", "CISA"])
def test_multi_pass_collection_and_replay_use_exact_pinned_records(tmp_path, source):
    objects, payloads = repository(source)
    execution = str(uuid4())
    partition, after = None, None
    outcomes = []
    for _ in range(10):
        result = cve_repository.collect(
            source,
            tmp_path / "run",
            origin="synthetic",
            execution_id=execution,
            metadata_limit=2,
            record_limit=1,
            next_partition=partition,
            after=after,
            synthetic_objects=objects,
            synthetic_payloads=payloads,
        )
        assert result.metadata_collected <= 2 and len(result.outcomes) <= 1
        outcomes.extend(result.outcomes)
        if result.enumeration_finished:
            break
        partition, after = result.next_partition, result.next_after
    assert result.enumeration_finished and result.commit == COMMIT
    assert len(outcomes) == 2 and len({r["execution_id"] for r in outcomes}) == 2
    assert all(
        r["outcome"] == "success" and not r["database_imported"] for r in outcomes
    )
    replay = cve_repository.collect(
        source,
        tmp_path / "run",
        origin="synthetic",
        execution_id=execution,
        replay_only=True,
        metadata_limit=0,
    )
    assert replay.enumeration_finished and replay.metadata_collected == 0
    assert list(replay.outcomes) == outcomes


def test_blob_mismatch_never_reaches_import(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from . import runtime

    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchall.return_value = []
    monkeypatch.setattr(runtime, "connect", lambda: connection)
    objects, payloads = repository("CVE")
    first = next(iter(payloads))
    payloads[first] += b" "
    result = cve_repository.collect(
        "CVE",
        tmp_path / "run",
        origin="synthetic",
        execution_id=str(uuid4()),
        synthetic_objects=objects,
        synthetic_payloads={first: payloads[first]},
        import_records=True,
    )
    assert result.enumeration_finished
    assert [item["outcome"] for item in result.outcomes] == [
        "invalid_or_mismatched_advisory_bundle",
        "pending",
    ]
    assert not any(item["database_imported"] for item in result.outcomes)
    assert result.collection_complete is False and result.database_complete is False


def test_failed_record_retains_failure_on_replay(tmp_path):
    objects, payloads = repository("CVE")
    first = next(iter(payloads))
    payloads[first] = b"invalid synthetic JSON"
    execution = str(uuid4())
    result = cve_repository.collect(
        "CVE",
        tmp_path / "run",
        origin="synthetic",
        execution_id=execution,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    assert (
        result.enumeration_finished
        and result.outcomes[0]["outcome"] == "invalid_public_payload"
    )
    replay = cve_repository.collect(
        "CVE",
        tmp_path / "run",
        origin="synthetic",
        execution_id=execution,
        replay_only=True,
        metadata_limit=0,
    )
    assert replay.outcomes == result.outcomes
    assert replay.collection_complete is False


def test_invalid_continuation_and_network_modes(tmp_path):
    with pytest.raises(ValueError, match="mode"):
        cve_repository.collect(
            "CVE",
            tmp_path / "run",
            origin="synthetic",
            execution_id=str(uuid4()),
            allow_network=True,
        )
    with pytest.raises(ValueError, match="partition"):
        cve_repository.collect(
            "CVE",
            tmp_path / "run",
            origin="synthetic",
            execution_id=str(uuid4()),
            after="missing",
        )
    assert not (tmp_path / "run").exists()


def test_cli_reports_saved_synthetic_pass_and_pending_status(tmp_path, capsys):
    objects, payloads = repository("CVE")
    execution = str(uuid4())
    run = tmp_path / "run"
    cve_repository.collect(
        "CVE",
        run,
        origin="synthetic",
        execution_id=execution,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    arguments = [
        "--source",
        "CVE",
        "--bundle",
        str(run),
        "--origin",
        "synthetic",
        "--execution-id",
        execution,
        "--replay-only",
        "--metadata-limit",
        "0",
    ]
    assert cve_repository.main(arguments + ["--record-limit", "1"]) == 2
    partial = json.loads(capsys.readouterr().out)
    assert not partial["enumeration_finished"] and partial["next_after"]
    assert cve_repository.main(arguments) == 0
    complete = json.loads(capsys.readouterr().out)
    assert complete["enumeration_finished"] and len(complete["outcomes"]) == 2


def test_successful_last_pass_does_not_hide_an_earlier_failure(tmp_path):
    objects, payloads = repository("CVE")
    first_path = next(iter(payloads))
    payloads[first_path] = b"synthetic invalid record"
    execution = str(uuid4())
    run = tmp_path / "run"
    first = cve_repository.collect(
        "CVE",
        run,
        origin="synthetic",
        execution_id=execution,
        record_limit=1,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    assert not first.enumeration_finished and first.collection_complete is None
    last = cve_repository.collect(
        "CVE",
        run,
        origin="synthetic",
        execution_id=execution,
        next_partition=first.next_partition,
        after=first.next_after,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    assert last.enumeration_finished and last.outcomes[0]["outcome"] == "success"
    assert last.collection_complete is False and last.database_complete is None
