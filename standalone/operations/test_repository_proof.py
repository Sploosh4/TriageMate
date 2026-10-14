"""A published row must match saved head, membership and committed evidence."""

from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest

from . import repository_proof as proof


@pytest.mark.parametrize("source", ["GitHub", "CVE", "CISA", "Ubuntu", "WA SOC"])
@pytest.mark.parametrize(
    "damage",
    [
        None,
        "origin",
        "commit",
        "time",
        "payload",
        "membership",
        "database",
        "collection",
    ],
)
def test_exact_publication_required(tmp_path, monkeypatch, source, damage):
    run = str(uuid4())
    now = datetime.now(timezone.utc)
    commit = "a" * 40
    branch = "heads/develop" if source == "CISA" else "heads/main"
    payload = {"ref": "refs/" + branch, "object": {"type": "commit", "sha": commit}}
    member = {"path": "synthetic-record.json", "receipt_id": str(uuid4())}
    row = ["synthetic", commit, now, payload, [member]]
    completion = {
        "database_complete": damage != "database",
        "collection_complete": damage != "collection",
        "outcomes": [member],
    }
    if damage == "origin":
        row[0] = "public"
    elif damage == "commit":
        row[1] = "b" * 40
    elif damage == "time":
        row[2] = now.replace(year=2000)
    elif damage == "payload":
        row[3] = {}
    elif damage == "membership":
        row[4] = []
    cursor = Mock()
    cursor.fetchone.return_value = tuple(row)
    prepare = Mock(
        return_value=SimpleNamespace(
            complete=True, finished_at=now, payload=json.dumps(payload).encode()
        )
    )
    inspect = Mock(return_value=completion)
    monkeypatch.setattr(proof, "prepare", prepare)
    monkeypatch.setattr(proof, "inspect_run", inspect)
    assert proof.published_run(
        cursor, source, tmp_path, origin="synthetic", execution_id=run
    ) is (damage is None)
    if damage is None:
        assert prepare.call_args.args == ("ref", branch, tmp_path / run / "head")
        assert prepare.call_args.kwargs["replay_only"] is True
        assert inspect.call_args.kwargs["cursor"] is cursor
        assert inspect.call_args.kwargs["execution_id"] == run
        assert inspect.call_args.kwargs["source"] == source
    assert cursor.execute.call_count == 1


def test_absent_publication_does_not_inspect_partial_bundles(tmp_path, monkeypatch):
    cursor = Mock()
    cursor.fetchone.return_value = None
    monkeypatch.setattr(
        proof, "prepare", lambda *a, **k: pytest.fail("Partial bundle was inspected")
    )
    assert not proof.published_run(
        cursor, "Ubuntu", tmp_path, origin="synthetic", execution_id=str(uuid4())
    )


@pytest.mark.parametrize(
    "damage", [None, "input", "contract", "run", "inactive", "missing"]
)
@pytest.mark.parametrize("source", ["Ubuntu", "MSRC"])
def test_scheduler_binding_requires_exact_persisted_job(
    tmp_path, monkeypatch, damage, source
):
    from dataclasses import replace
    from . import store
    from .dispatch import Definition, Dispatcher
    from .lifecycle import Mode
    from .scheduling import Interval
    from .test_dispatch import at

    input_id = str(uuid4())
    contract = "a" * 64
    state = Dispatcher(
        [Definition(input_id, Interval(10, at(0)), worker_contract=contract)], now=at(0)
    )
    state.request_mode(Mode.RUNNING, at(0))
    job = state.tick(at(10)).start[0]
    binding = proof.ScheduledRepository(
        input_id, contract, source, "synthetic", tmp_path
    )
    if damage == "input":
        job = replace(job, input_id=str(uuid4()))
    elif damage == "contract":
        binding = replace(binding, worker_contract="b" * 64)
    elif damage == "run":
        job = replace(job, run_id=str(uuid4()))
    elif damage == "inactive":
        state.control.active.clear()
    monkeypatch.setattr(
        store, "load", lambda *a: None if damage == "missing" else (1, state)
    )
    publication = Mock(return_value=True)
    if source == "MSRC":
        from .msrc_proof import MsrcProof

        monkeypatch.setattr(MsrcProof, "committed", publication)
    else:
        monkeypatch.setattr(proof, "published_run", publication)
    assert binding.committed(Mock(), "synthetic-service", job) is (damage is None)
    assert publication.call_count == (1 if damage is None else 0)


@pytest.mark.parametrize("published", [True, False])
def test_supervisor_repository_proof_has_no_single_record_fallback(
    tmp_path, monkeypatch, published
):
    from .dispatch import Job
    from .supervisor import PostgresRepository

    input_id, run_id = str(uuid4()), str(uuid4())
    now = datetime.now(timezone.utc)
    binding = proof.ScheduledRepository(
        input_id, "a" * 64, "Ubuntu", "synthetic", tmp_path
    )
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (True, "success")
    verify = Mock(return_value=published)
    monkeypatch.setattr(proof.ScheduledRepository, "committed", verify)
    repository = PostgresRepository(
        "synthetic-service", lambda: connection, repository_proofs=[binding]
    )
    job = Job(run_id, input_id, now, now, ())
    assert repository.committed_snapshot(job) == (run_id if published else None)
    verify.assert_called_once_with(cursor, "synthetic-service", job)
    cursor.fetchone.assert_not_called()
    connection.close.assert_called_once()
