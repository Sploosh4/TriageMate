"""Repository workers preserve continuation and refuse partial success."""

from dataclasses import replace
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.collection.cve_repository import RepositoryPass
from standalone.evidence_pipeline.collection.github_repository import (
    RepositoryPass as GitHubPass,
)

from . import repository_worker as worker


def batch(**changes):
    return replace(
        RepositoryPass("a" * 40, 0, (), None, None, (), (), True, True, True, True),
        **changes,
    )


def run(tmp_path, source="CVE", **options):
    values = dict(
        origin="synthetic",
        execution_id=str(uuid4()),
        synthetic_objects={},
        synthetic_payloads={},
    )
    return worker.collect_batch(source, tmp_path, **(values | options))


def test_advances_metadata_and_records_without_restarting_run(tmp_path, monkeypatch):
    run_id = str(uuid4())
    outcomes = ({"outcome": "success", "database_imported": True},)
    results = iter(
        [
            batch(metadata_collected=2, enumeration_finished=False),
            batch(
                metadata_collected=1,
                outcomes=outcomes,
                next_partition="2099/1xxx",
                next_after="CVE-2099-1234.json",
                enumeration_finished=False,
            ),
            batch(outcomes=outcomes),
        ]
    )
    calls = []

    def collect(source, bundle, **options):
        calls.append((source, bundle, options))
        return next(results)

    monkeypatch.setattr(worker.cve_repository, "collect", collect)
    result = run(tmp_path, execution_id=run_id, metadata_limit=2, record_limit=1)
    assert result == worker.BatchResult("finished", 3, 3, 2, None, None)
    assert all(
        source == "CVE" and path == tmp_path / run_id for source, path, _ in calls
    )
    assert all(options["import_records"] is True for _, _, options in calls)
    assert all(options["allow_network"] is False for _, _, options in calls)
    assert calls[2][2]["next_partition"] == "2099/1xxx"
    assert calls[2][2]["after"] == "CVE-2099-1234.json"


@pytest.mark.parametrize(
    "response,reason",
    [
        (batch(metadata_failures=(("trees", "a" * 40),)), "collection_failed"),
        (batch(outcomes=({"outcome": "failure"},)), "collection_failed"),
        (
            batch(outcomes=({"outcome": "success", "database_imported": False},)),
            "collection_failed",
        ),
        (batch(collection_complete=False), "incomplete_evidence"),
        (batch(database_complete=False), "incomplete_evidence"),
        (batch(snapshot_published=False), "incomplete_evidence"),
        (batch(enumeration_finished=False), "stalled"),
    ],
)
def test_failure_or_absent_progress_never_retries(
    tmp_path, monkeypatch, response, reason
):
    calls = []

    def collect(*args, **kwargs):
        calls.append(1)
        return response

    monkeypatch.setattr(worker.cve_repository, "collect", collect)
    assert run(tmp_path).reason == reason
    assert len(calls) == 1


def test_budget_stops_even_with_metadata_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(
        worker.cve_repository,
        "collect",
        lambda *args, **kwargs: batch(metadata_collected=1, enumeration_finished=False),
    )
    result = run(tmp_path, pass_limit=2)
    assert result.reason == "budget_exhausted" and result.passes == 2


@pytest.mark.parametrize("source", ["CVE", "CISA", "WA SOC"])
def test_complete_empty_repository_can_finish(tmp_path, monkeypatch, source):
    monkeypatch.setattr(worker.cve_repository, "collect", lambda *a, **k: batch())
    monkeypatch.setattr(
        worker.github_repository,
        "collect_current",
        lambda *a, **k: GitHubPass(0, (), None, None, (), (), True, True, True),
    )
    result = run(tmp_path, source)
    assert result.reason == "finished" and result.records_examined == 0


@pytest.mark.parametrize(
    "options",
    [
        {"allow_network": True},
        {"origin": "public"},
        {"origin": "public", "allow_network": True},
        {"origin": "lab"},
        {"pass_limit": True},
        {"metadata_limit": 0},
        {"record_limit": 101},
        {"pass_limit": 10001},
        {"execution_id": "../escape"},
    ],
)
def test_invalid_authority_or_budget_prevents_collection(
    tmp_path, monkeypatch, options
):
    def reject(*args, **kwargs):
        pytest.fail("Invalid request reached collection")

    monkeypatch.setattr(worker.cve_repository, "collect", reject)
    with pytest.raises(ValueError):
        run(tmp_path, **options)
