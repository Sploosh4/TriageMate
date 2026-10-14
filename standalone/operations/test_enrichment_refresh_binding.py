"""The supervisor must prove both initial and refresh work before success."""

from pathlib import Path
from unittest.mock import Mock
import pytest

from .enrichment_batch import ScheduledEnrichment
from .enrichment_refresh_binding import RefreshingEnrichment
from .test_enrichment_batch import binding
from .configuration import load
from .test_configuration import configuration, save, NOW


@pytest.mark.parametrize(
    "initial,refresh,expected",
    [(False, True, False), (True, False, False), (True, True, True)],
)
def test_both_components_are_required(
    tmp_path, monkeypatch, initial, refresh, expected
):
    base, job = binding()
    proof = RefreshingEnrichment(
        base.input_id,
        base.worker_contract,
        base.source,
        base.origin,
        bundle_root=tmp_path,
    )
    monkeypatch.setattr(ScheduledEnrichment, "committed", lambda *args: initial)
    monkeypatch.setattr(ScheduledEnrichment, "saved", lambda *args: [])
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_selection.RefreshSelection.saved",
        lambda *args: [],
    )
    follow = Mock(return_value=refresh)
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_worker.committed", follow
    )
    assert proof.committed(Mock(), "synthetic", job) is expected
    assert follow.call_count == int(initial)


@pytest.mark.parametrize("error", [ValueError("changed"), FileNotFoundError("missing")])
def test_missing_or_changed_refresh_proof_never_completes(tmp_path, monkeypatch, error):
    base, job = binding()
    proof = RefreshingEnrichment(
        base.input_id,
        base.worker_contract,
        base.source,
        base.origin,
        bundle_root=tmp_path,
    )
    monkeypatch.setattr(ScheduledEnrichment, "committed", lambda *args: True)
    monkeypatch.setattr(ScheduledEnrichment, "saved", lambda *args: [])
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_selection.RefreshSelection.saved",
        lambda *args: [],
    )
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_worker.committed",
        Mock(side_effect=error),
    )
    assert not proof.committed(Mock(), "synthetic", job)


def test_refresh_option_changes_worker_contract_but_keeps_service_off(tmp_path):
    document = configuration(tmp_path)
    item = document["inputs"][0]
    item["scope"].update(
        source="NVD",
        input_kind="enrichment_queue",
        scope_reference="triagemate:enrichment/NVD",
    )
    item["parameters"] = {"limit": 1}
    original = load(save(tmp_path, document), now=NOW)
    item["parameters"]["refresh_completed"] = True
    refreshed = load(save(tmp_path, document), now=NOW)
    recipe = refreshed.recipes[0]
    assert isinstance(recipe.binding(), RefreshingEnrichment)
    assert recipe.binding().bundle_root == Path(item["bundle_root"]) / "refresh"
    assert recipe.worker_contract != original.recipes[0].worker_contract
    assert refreshed.state.control.state == "off"
    item["parameters"]["refresh_completed"] = "yes"
    with pytest.raises(ValueError, match="boolean"):
        load(save(tmp_path, document), now=NOW)


def test_combined_membership_cannot_exceed_configured_limit(tmp_path, monkeypatch):
    base, job = binding()
    proof = RefreshingEnrichment(
        base.input_id,
        base.worker_contract,
        base.source,
        base.origin,
        limit=1,
        bundle_root=tmp_path,
    )
    monkeypatch.setattr(ScheduledEnrichment, "committed", lambda *args: True)
    monkeypatch.setattr(ScheduledEnrichment, "saved", lambda *args: ["initial"])
    monkeypatch.setattr(
        "standalone.operations.enrichment_refresh_selection.RefreshSelection.saved",
        lambda *args: ["CVE-2099-1234"],
    )
    assert not proof.committed(Mock(), "synthetic", job)
