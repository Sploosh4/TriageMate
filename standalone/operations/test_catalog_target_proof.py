"""A target batch cannot acknowledge another dispatch or changed evidence."""

from datetime import datetime, timezone
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
import pytest

from .catalog_target_proof import ScheduledCatalogTargets
from .dispatch import Job
from . import store


@pytest.mark.parametrize(
    "damage",
    [None, "job", "contract", "dependency", "cancelled", "inactive", "missing"],
)
def test_parent_proof_requires_exact_active_dispatch(tmp_path, monkeypatch, damage):
    scope, dep, run, snapshot = (str(uuid4()) for _ in range(4))
    now = datetime.now(timezone.utc)
    job = Job(run, scope, now, now, ((dep, snapshot),))
    proof = ScheduledCatalogTargets(scope, "a" * 64, "synthetic", tmp_path, (dep,))
    definition = SimpleNamespace(worker_contract="a" * 64, dependencies=(dep,))
    state = SimpleNamespace(
        definitions={scope: definition},
        inputs={scope: SimpleNamespace(active=job)},
        control=SimpleNamespace(active={run}, cancel_requested=set()),
        clock=now,
    )
    if damage == "job":
        state.inputs[scope].active = replace(job, run_id=str(uuid4()))
    elif damage == "contract":
        definition.worker_contract = "b" * 64
    elif damage == "dependency":
        definition.dependencies = (str(uuid4()),)
    elif damage == "cancelled":
        state.control.cancel_requested.add(run)
    elif damage == "inactive":
        state.control.active.clear()
    monkeypatch.setattr(
        store, "load", lambda *args: None if damage == "missing" else (1, state)
    )
    if damage:
        with pytest.raises(ValueError):
            proof.active(Mock(), "synthetic-target-proof", job)
    else:
        assert proof.active(Mock(), "synthetic-target-proof", job) == (1, now)
        with pytest.raises(ValueError):
            proof.active(
                Mock(),
                "synthetic-target-proof",
                replace(job, prerequisite_snapshots=()),
            )


@pytest.mark.parametrize("damage", [None, "missing", "changed", "unverified"])
def test_declaration_and_current_evidence_must_agree(tmp_path, monkeypatch, damage):
    proof = ScheduledCatalogTargets(
        str(uuid4()), "a" * 64, "synthetic", tmp_path, (str(uuid4()),)
    )
    event = {"kind": "catalog_targets", "manifest_sha256": "a" * 64}
    monkeypatch.setattr(ScheduledCatalogTargets, "active", lambda *args: None)
    monkeypatch.setattr(
        ScheduledCatalogTargets,
        "saved",
        lambda *args: None if damage == "missing" else event,
    )

    def evidence(*args):
        if damage == "unverified":
            raise ValueError("Catalog target imports are incomplete")
        return dict(event, manifest_sha256="b" * 64) if damage == "changed" else event

    monkeypatch.setattr(ScheduledCatalogTargets, "evidence", evidence)
    if damage == "unverified":
        with pytest.raises(ValueError):
            proof.committed(Mock(), "synthetic-target-proof", Mock())
    else:
        assert proof.committed(Mock(), "synthetic-target-proof", Mock()) is (
            damage is None
        )
