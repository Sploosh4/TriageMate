"""Per-run refresh membership is fixed and bound to its exact scheduled input."""

from dataclasses import replace
from unittest.mock import Mock
import pytest

from .enrichment_refresh_selection import RefreshSelection
from .test_enrichment_batch import binding
from .test_dispatch import at


@pytest.mark.parametrize(
    "field", ["kind", "input_id", "run_id", "worker_contract", "source", "origin"]
)
def test_changed_declaration_cannot_be_reused(field):
    batch, job = binding()
    selection = RefreshSelection(batch)
    event = selection.event(job, ["CVE-2099-1234"])
    event[field] = "changed"
    cursor = Mock()
    cursor.fetchall.return_value = [(event,)]
    with pytest.raises(ValueError):
        selection.saved(cursor, "synthetic", job)


@pytest.mark.parametrize(
    "cves",
    [["CVE-2099-1234"] * 2, ["not-a-cve"], ["CVE-2099-1234", "CVE-2099-2345"], ()],
)
def test_membership_is_unique_valid_and_bounded(cves):
    batch, job = binding()
    with pytest.raises(ValueError):
        RefreshSelection(replace(batch, limit=1)).event(job, cves)


def test_existing_selection_does_not_expand_on_restart(monkeypatch):
    batch, job = binding()
    selection = RefreshSelection(batch)
    cursor = Mock()
    cursor.connection.autocommit = False
    cursor.fetchall.return_value = [(selection.event(job, ["CVE-2099-1234"]),)]
    monkeypatch.setattr(type(batch), "active", lambda *args: (1, at(1)))
    discovery = Mock(
        side_effect=AssertionError("A saved declaration must not rediscover")
    )
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_selection.candidates", discovery
    )
    assert selection.declare(
        cursor, "synthetic", job, synthetic_cves=["CVE-2099-2345"]
    ) == ["CVE-2099-1234"]
    discovery.assert_not_called()


def test_new_selection_binds_rotation_to_service_and_input(monkeypatch):
    batch, job = binding()
    selection = RefreshSelection(batch)
    cursor = Mock()
    cursor.connection.autocommit = False
    cursor.fetchall.return_value = []
    monkeypatch.setattr(type(batch), "active", lambda *args: (1, at(1)))
    discovery = Mock(return_value=[dict(cve_id="CVE-2099-1234")])
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_selection.candidates", discovery
    )
    assert selection.declare(
        cursor, "synthetic", job, synthetic_cves=["CVE-2099-1234"]
    ) == ["CVE-2099-1234"]
    assert discovery.call_args.kwargs["history"] == ("synthetic", batch.input_id)
    assert "INSERT INTO" in cursor.execute.call_args.args[0]


def test_autocommit_and_duplicate_events_reject():
    batch, job = binding()
    selection = RefreshSelection(batch)
    cursor = Mock()
    cursor.connection.autocommit = True
    with pytest.raises(ValueError, match="transaction"):
        selection.declare(cursor, "synthetic", job)
    cursor.execute.assert_not_called()
    cursor.fetchall.return_value = [(selection.event(job, []),)] * 2
    with pytest.raises(ValueError, match="Ambiguous"):
        selection.saved(cursor, "synthetic", job)
