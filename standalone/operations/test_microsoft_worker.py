"""Synthetic scheduling boundaries and exact saved-device replay."""

from dataclasses import asdict, replace
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline import commands
from standalone.evidence_pipeline.collection import snapshot_bundle
from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from .configuration import load
from .dispatch import Job
from .microsoft_worker import MicrosoftRecipe, INDEPENDENT, DEPENDENT
from .test_configuration import save
from .test_dispatch import NOW


def case(tmp_path, source="Intune", kind="software"):
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    fixture = tmp_path / "synthetic.json"
    fixture.write_text("[]")
    fixture.chmod(0o600)
    associations = tmp_path / "associations.json"
    associations.write_text("{}")
    associations.chmod(0o600)
    device = SourceScope(
        str(uuid4()),
        source,
        "devices",
        "synthetic-scheduled-devices",
        "synthetic",
        "Explicitly synthetic scheduling test",
        str(uuid4()),
    )
    scope = replace(device, connection_id=str(uuid4()), input_kind=kind)
    dependent = (source, kind) in DEPENDENT
    recipe = MicrosoftRecipe(
        scope,
        root,
        fixture,
        device if dependent else None,
        root if dependent else None,
        associations if kind in ("software", "recommendations") else None,
    )
    if kind == "vulnerability_events":
        recipe = replace(
            recipe,
            baseline_scope=replace(
                scope, connection_id=str(uuid4()), input_kind="vulnerability_baseline"
            ),
        )
    device_run = str(uuid4())
    job = Job(
        str(uuid4()),
        scope.connection_id,
        NOW,
        NOW,
        ((device.connection_id, device_run),) if dependent else (),
    )
    if kind == "vulnerability_events":
        job = replace(
            job,
            prerequisite_snapshots=job.prerequisite_snapshots
            + ((recipe.baseline_scope.connection_id, str(uuid4())),),
        )
    if dependent:
        snapshot_bundle.prepare(
            device,
            device_run,
            root,
            collect=lambda: Snapshot(
                device, device_run, NOW, NOW, "success", True, b"[]"
            ),
        )
    return recipe, job


@pytest.mark.parametrize("source,kind", sorted(INDEPENDENT | DEPENDENT))
def test_supported_inputs_use_exact_import_and_durable_replay(
    tmp_path, monkeypatch, source, kind
):
    from standalone.evidence_pipeline import (
        assessment_commands,
        recommendation_commands,
    )

    from . import microsoft_worker

    monkeypatch.setattr(
        microsoft_worker, "verify_committed_device", lambda snapshot: None
    )
    recipe, job = case(tmp_path, source, kind)
    monkeypatch.setattr(
        microsoft_worker,
        "delta_checkpoint",
        lambda recipe, job: (job.prerequisite_snapshots[1][1], NOW),
    )
    calls = []

    def imported(*args):
        calls.append(args)
        return {"outcome": "success"}

    monkeypatch.setattr(commands, "ingest", imported)
    monkeypatch.setattr(commands, "ingest_catalogue", imported)
    monkeypatch.setattr(commands, "ingest_exposure", imported)
    monkeypatch.setattr(assessment_commands, "ingest", imported)
    monkeypatch.setattr(recommendation_commands, "ingest", imported)
    assert recipe.collect(job) == {"outcome": "success"}
    assert calls[0][0].execution_id == job.run_id
    assert calls[0][0].scope == recipe.scope
    if job.prerequisite_snapshots:
        assert calls[0][1] == job.prerequisite_snapshots[0][1]
    recipe.synthetic_input.unlink()
    if recipe.association_input:
        recipe.association_input.unlink()
    assert recipe.collect(job) == {"outcome": "success"}
    assert calls[1] == calls[0]


@pytest.mark.parametrize(
    "damage",
    ["missing", "other_run", "other_input", "tenant", "payload", "failed", "private"],
)
def test_prerequisite_never_falls_back_or_refetches(tmp_path, monkeypatch, damage):
    recipe, job = case(tmp_path)
    run = job.prerequisite_snapshots[0][1]
    if damage == "missing":
        (recipe.device_root / run / "receipt.json").unlink()
    elif damage == "other_run":
        job = replace(
            job,
            prerequisite_snapshots=((recipe.device_scope.connection_id, str(uuid4())),),
        )
    elif damage == "other_input":
        job = replace(job, prerequisite_snapshots=((str(uuid4()), run),))
    elif damage == "tenant":
        recipe = replace(
            recipe, device_scope=replace(recipe.device_scope, tenant_id=str(uuid4()))
        )
    elif damage == "payload":
        (recipe.device_root / run / "payload.bin").write_bytes(b"[{}]")
    elif damage == "failed":
        receipt = recipe.device_root / run / "receipt.json"
        value = json.loads(receipt.read_text())
        value.update(outcome="failure", complete=False, error_code="synthetic_failure")
        receipt.write_text(json.dumps(value))
    else:
        recipe = replace(recipe, scope=replace(recipe.scope, origin="lab"))
    monkeypatch.setattr(
        commands,
        "ingest_exposure",
        lambda *args: pytest.fail("Invalid prerequisite imported"),
    )
    with pytest.raises((ValueError, OSError)):
        recipe.collect(job)
    assert not (recipe.bundle_root / job.run_id).exists()


def configuration(tmp_path):
    recipe, job = case(tmp_path)
    common = dict(
        schedule=dict(
            kind="interval", seconds=3600, anchor=NOW.isoformat(), offset_seconds=0
        ),
        bundle_root=str(recipe.bundle_root),
        synthetic_input=str(recipe.synthetic_input),
        allow_network=False,
    )
    device = dict(common, scope=asdict(recipe.device_scope), parameters={})
    child = dict(
        common,
        scope=asdict(recipe.scope),
        parameters={
            "device_input": recipe.device_scope.connection_id,
            "association_input": str(recipe.association_input),
        },
    )
    return dict(version=1, concurrency=1, grace_seconds=60, inputs=[child, device])


def test_configuration_binds_dependencies_independent_of_list_order(tmp_path):
    document = configuration(tmp_path)
    configured = load(save(tmp_path, document), now=NOW)
    child, device = configured.recipes
    assert child.device_scope == device.scope
    assert configured.state.definitions[child.scope.connection_id].dependencies == (
        device.scope.connection_id,
    )


@pytest.mark.parametrize(
    "damage",
    [
        "missing_device",
        "missing_association",
        "wrong_tenant",
        "network",
        "deferred",
        "relative",
        "extra",
    ],
)
def test_configuration_rejects_invalid_microsoft_binding(tmp_path, damage):
    document = configuration(tmp_path)
    child, device = document["inputs"]
    if damage == "missing_device":
        child["parameters"].pop("device_input")
    elif damage == "missing_association":
        child["parameters"].pop("association_input")
    elif damage == "wrong_tenant":
        device["scope"]["tenant_id"] = str(uuid4())
    elif damage == "network":
        child["allow_network"] = True
    elif damage == "deferred":
        device["scope"]["input_kind"] = "users"
    elif damage == "relative":
        child["parameters"]["association_input"] = "relative.json"
    else:
        child["parameters"]["credential"] = "not-permitted"
    with pytest.raises(ValueError):
        load(save(tmp_path, document), now=NOW)


def test_rewritten_bundle_cannot_replace_committed_prerequisite(tmp_path, monkeypatch):
    from . import microsoft_worker

    recipe, job = case(tmp_path)
    calls = []

    def reject(snapshot):
        calls.append(snapshot.execution_id)
        raise ValueError(
            "Saved device bytes do not match committed prerequisite evidence"
        )

    monkeypatch.setattr(microsoft_worker, "verify_committed_device", reject)
    with pytest.raises(ValueError, match="committed prerequisite"):
        recipe.collect(job)
    assert calls == [job.prerequisite_snapshots[0][1]]
    assert not (recipe.bundle_root / job.run_id).exists()


@pytest.mark.parametrize(
    "damage",
    ["absent", "wrong_kind", "wrong_tenant", "missing_run", "wrong_run_source"],
)
def test_delta_requires_exact_baseline_prerequisite(tmp_path, damage):
    recipe, job = case(tmp_path, "Defender", "vulnerability_events")
    if damage == "absent":
        recipe = replace(recipe, baseline_scope=None)
    elif damage == "wrong_kind":
        recipe = replace(
            recipe, baseline_scope=replace(recipe.baseline_scope, input_kind="devices")
        )
    elif damage == "wrong_tenant":
        recipe = replace(
            recipe,
            baseline_scope=replace(recipe.baseline_scope, tenant_id=str(uuid4())),
        )
    elif damage == "missing_run":
        job = replace(job, prerequisite_snapshots=job.prerequisite_snapshots[:1])
    else:
        job = replace(
            job,
            prerequisite_snapshots=(
                job.prerequisite_snapshots[0],
                (str(uuid4()), str(uuid4())),
            ),
        )
    with pytest.raises(ValueError):
        recipe.validate(job)


def test_delta_configuration_rejects_baseline_bound_to_different_devices(tmp_path):
    document = configuration(tmp_path)
    child, device = document["inputs"]
    device["scope"]["source"] = "Defender"
    baseline = {
        **device,
        "scope": {
            **device["scope"],
            "connection_id": str(uuid4()),
            "input_kind": "vulnerability_baseline",
        },
        "parameters": {"device_input": str(uuid4())},
    }
    child["scope"].update(source="Defender", input_kind="vulnerability_events")
    child["parameters"] = {
        "device_input": device["scope"]["connection_id"],
        "baseline_input": baseline["scope"]["connection_id"],
    }
    document["inputs"].append(baseline)
    with pytest.raises(ValueError, match="same configured device"):
        load(save(tmp_path, document), now=NOW)


@pytest.mark.parametrize(
    "kind,damage",
    [("devices", "missing"), ("devices", "shape"), ("software", "associations")],
)
def test_invalid_fixture_records_replayable_failure(
    tmp_path, monkeypatch, kind, damage
):
    from . import microsoft_worker

    recipe, job = case(tmp_path, "Intune", kind)
    monkeypatch.setattr(
        microsoft_worker, "verify_committed_device", lambda snapshot: None
    )
    if damage == "missing":
        recipe.synthetic_input.unlink()
    elif damage == "shape":
        recipe.synthetic_input.write_text('{"invalid":true}')
    else:
        recipe.association_input.write_text("[]")
    captured = []

    def failed(snapshot, *args):
        assert not snapshot.complete
        assert snapshot.error_code == "invalid_synthetic_microsoft_input"
        if kind == "software":
            assert args[1] is None
        captured.append(snapshot)
        return {"outcome": "failure"}

    monkeypatch.setattr(commands, "ingest", failed)
    monkeypatch.setattr(commands, "ingest_exposure", failed)
    assert recipe.collect(job)["outcome"] == "failure"
    recipe.synthetic_input.write_text("[]")
    assert recipe.collect(job)["outcome"] == "failure"
    assert captured[0] == captured[1]


@pytest.mark.parametrize(
    "scoped,extra_association", [(True, False), (True, True), (False, False)]
)
def test_scoped_network_recommendations_use_device_relationship_without_association_config(
    tmp_path, monkeypatch, scoped, extra_association
):
    from . import microsoft_network

    recipe, job = case(tmp_path, "Defender", "recommendations")
    recipe = replace(
        recipe,
        scope=replace(
            recipe.scope,
            origin="lab",
            scope_reference=("native-device-id:" + "a" * 40 if scoped else "inventory"),
        ),
        device_scope=replace(recipe.device_scope, origin="lab"),
        synthetic_input=None,
        association_input=None,
        network_config=tmp_path / "collector.json",
        association_config=tmp_path / "association.json" if extra_association else None,
    )
    checked = []
    # Configuration/permission validation has direct command tests. Here the
    # scheduling gate must reach it only for the supported association shape.
    monkeypatch.setattr(
        microsoft_network, "configurations", lambda value: checked.append(value)
    )
    if scoped and not extra_association:
        recipe.validate(job)
        assert checked == [recipe]
    else:
        with pytest.raises(ValueError, match="association"):
            recipe.validate(job)
        assert checked == []
