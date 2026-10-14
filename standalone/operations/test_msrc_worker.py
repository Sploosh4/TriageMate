"""MSRC worker stop conditions; no network, scheduler activation or DB writes."""

from uuid import uuid4
import pytest
from . import msrc_worker as worker


def arguments(tmp_path):
    return dict(
        root=tmp_path,
        origin="synthetic",
        execution_id=str(uuid4()),
        starting_month="2099-Jan",
        retained_ids=frozenset(),
        synthetic_index=b"synthetic mocked index",
        synthetic_payloads={},
    )


def result(
    *, outcome="success", imported=True, remaining=1, after="2099-Jan", complete=True
):
    return dict(
        index_complete=complete,
        remaining=remaining,
        next_after=after,
        outcomes=[dict(outcome=outcome, database_imported=imported)],
    )


def test_all_batches_keep_one_index_run_and_exact_range(tmp_path, monkeypatch):
    calls = []

    def collect(root, **kwargs):
        calls.append((root, kwargs))
        return result() if len(calls) == 1 else result(remaining=0, after=None)

    monkeypatch.setattr(worker.msrc_discovered_collection, "collect", collect)
    args = arguments(tmp_path)
    outcome = worker.collect_batch(**args)
    assert (
        outcome.reason == "finished"
        and outcome.passes == 2
        and outcome.records_examined == 2
    )
    assert calls[0][0] == calls[1][0] == tmp_path / args["execution_id"]
    assert calls[0][1]["after"] is None and calls[1][1]["after"] == "2099-Jan"
    assert all(
        call[1]["starting_month"] == "2099-Jan" and call[1]["import_records"]
        for call in calls
    )


@pytest.mark.parametrize(
    "change",
    [
        {"outcome": "failure"},
        {"outcome": "pending"},
        {"imported": False},
        {"complete": False},
    ],
)
def test_failure_stops_without_skipping_or_retrying(tmp_path, monkeypatch, change):
    calls = []

    def collect(*args, **kwargs):
        calls.append(True)
        return result(**change)

    monkeypatch.setattr(worker.msrc_discovered_collection, "collect", collect)
    assert worker.collect_batch(**arguments(tmp_path)).reason == "collection_failed"
    assert calls == [True]


def test_pass_budget_does_not_report_completion(tmp_path, monkeypatch):
    monkeypatch.setattr(
        worker.msrc_discovered_collection, "collect", lambda *a, **k: result()
    )
    assert (
        worker.collect_batch(**arguments(tmp_path), pass_limit=1).reason
        == "budget_exhausted"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"origin": "public"},
        {"allow_network": True},
        {"pass_limit": 0},
        {"record_limit": True},
    ],
)
def test_invalid_authority_or_budget_never_collects(tmp_path, monkeypatch, change):
    monkeypatch.setattr(
        worker.msrc_discovered_collection,
        "collect",
        lambda *a, **k: pytest.fail("collection"),
    )
    with pytest.raises(ValueError):
        worker.collect_batch(**{**arguments(tmp_path), **change})
