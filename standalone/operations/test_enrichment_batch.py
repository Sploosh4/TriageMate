"""Enrichment batch completion rejects changed identity and partial outcomes."""

from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from .dispatch import Job
from .enrichment_batch import ScheduledEnrichment
from .test_dispatch import at


def binding():
    input_id = str(uuid4())
    return ScheduledEnrichment(input_id, "a" * 64, "NVD", "synthetic"), Job(
        str(uuid4()), input_id, at(1), at(1), ()
    )


@pytest.mark.parametrize(
    "state",
    ["succeeded", "not_found", "queued", "started", "unavailable", "invalid", "failed"],
)
def test_only_confirmed_outcomes_finish_batch(monkeypatch, state):
    batch, job = binding()
    request = str(uuid4())
    monkeypatch.setattr(ScheduledEnrichment, "active", lambda *a: (1, at(1)))
    monkeypatch.setattr(ScheduledEnrichment, "saved", lambda *a: [request])
    cursor = Mock()
    cursor.fetchall.return_value = [(request, "NVD", "synthetic", state)]
    assert batch.committed(cursor, "synthetic", job) is (
        state in {"succeeded", "not_found"}
    )


@pytest.mark.parametrize(
    "damage", ["origin", "source", "request", "missing", "duplicate"]
)
def test_matching_count_is_not_enough(monkeypatch, damage):
    batch, job = binding()
    request = str(uuid4())
    monkeypatch.setattr(ScheduledEnrichment, "active", lambda *a: (1, at(1)))
    monkeypatch.setattr(ScheduledEnrichment, "saved", lambda *a: [request])
    row = [request, "NVD", "synthetic", "succeeded"]
    if damage == "origin":
        row[2] = "public"
    elif damage == "source":
        row[1] = "CVE"
    elif damage == "request":
        row[0] = str(uuid4())
    cursor = Mock()
    cursor.fetchall.return_value = (
        [] if damage == "missing" else [row, row] if damage == "duplicate" else [row]
    )
    assert not batch.committed(cursor, "synthetic", job)


@pytest.mark.parametrize(
    "damage", ["contract", "origin", "source", "run", "input", "duplicate_event"]
)
def test_saved_declaration_cannot_change_binding(damage):
    batch, job = binding()
    event = batch.event(job, [str(uuid4())])
    field = {"contract": "worker_contract", "run": "run_id", "input": "input_id"}.get(
        damage, damage
    )
    if damage != "duplicate_event":
        event[field] = "changed"
    cursor = Mock()
    cursor.fetchall.return_value = [(event,)] * (
        2 if damage == "duplicate_event" else 1
    )
    with pytest.raises(ValueError):
        batch.saved(cursor, "synthetic", job)


def test_duplicate_members_and_autocommit_are_rejected():
    batch, job = binding()
    request = str(uuid4())
    with pytest.raises(ValueError):
        batch.event(job, [request, request])
    with pytest.raises(ValueError):
        replace(batch, limit=True)
    cursor = Mock()
    cursor.connection.autocommit = True
    with pytest.raises(ValueError, match="transaction"):
        batch.declare(cursor, "synthetic", job, synthetic_ids=[])
    cursor.execute.assert_not_called()
