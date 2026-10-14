"""Initial discovery and refresh share capacity without starving either lane."""

from dataclasses import replace
from unittest.mock import Mock
import pytest
from .test_enrichment_batch import binding
from .enrichment_refresh_selection import RefreshSelection
from . import enrichment_refresh_selection as module


@pytest.mark.parametrize(
    "limit,available,previous,expected",
    [
        (1, 0, None, 1),
        (1, 1, None, 1),
        (1, 1, [], 1),
        (1, 1, ["prior"], 0),
        (2, 0, None, 2),
        (2, 1, None, 1),
        (3, 1, None, 2),
        (4, 1, None, 3),
        (4, 2, None, 2),
        (100, 50, None, 50),
    ],
)
def test_shared_capacity_and_single_slot_rotation(
    monkeypatch, limit, available, previous, expected
):
    batch, job = binding()
    batch = replace(batch, limit=limit)
    monkeypatch.setattr(type(batch), "active", lambda *a: (1, None))
    monkeypatch.setattr(type(batch), "saved", lambda *a: None)
    selected = Mock(return_value=[{}] * available)
    monkeypatch.setattr(module, "candidates", selected)
    cur = Mock()
    cur.connection.autocommit = False
    cur.fetchone.return_value = None if previous is None else (previous,)
    assert (
        RefreshSelection(batch).initial_capacity(
            cur, "synthetic", job, synthetic_cves=[]
        )
        == expected
    )
    assert selected.call_args.kwargs["limit"] == max(1, limit // 2)
    if limit == 1 and available:
        assert cur.execute.call_args.args[1] == (
            "synthetic",
            batch.input_id,
            batch.source,
            batch.origin,
            batch.worker_contract,
        )


def test_saved_membership_bypasses_new_selection(monkeypatch):
    batch, job = binding()
    monkeypatch.setattr(type(batch), "active", lambda *a: (1, None))
    monkeypatch.setattr(type(batch), "saved", lambda *a: [])
    selected = Mock(side_effect=AssertionError("Replay cannot reselect"))
    monkeypatch.setattr(module, "candidates", selected)
    cur = Mock()
    cur.connection.autocommit = False
    assert (
        RefreshSelection(batch).initial_capacity(cur, "synthetic", job) == batch.limit
    )
    selected.assert_not_called()


@pytest.mark.parametrize("capacity", [-1, True, 1.5, 101])
def test_invalid_initial_capacity_rejected_before_effects(capacity):
    batch, job = binding()
    cur = Mock()
    cur.connection.autocommit = False
    with pytest.raises(ValueError, match="capacity"):
        batch.declare(cur, "synthetic", job, capacity=capacity)
    cur.execute.assert_not_called()
