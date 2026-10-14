"""Explicit Windows recipe configuration and source/device authority boundaries."""

from dataclasses import asdict, replace
import hashlib
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.windows_inventory.test_contract import BINDING, sample
from standalone.windows_inventory.test_snapshot import scope

from .configuration import load
from .dispatch import Job
from .test_configuration import save
from .test_dispatch import NOW
from .windows_inventory_worker import WindowsInventoryRecipe


def case(tmp_path):
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    fixture = tmp_path / "inventory.json"
    fixture.write_text(json.dumps(sample()))
    fixture.chmod(0o600)
    device = SourceScope(
        str(uuid4()),
        "Entra",
        "devices",
        "synthetic-devices",
        "synthetic",
        "Generated synthetic fixture",
        BINDING.tenant_id,
    )
    recipe = WindowsInventoryRecipe(
        scope(), root, device, root, BINDING, str(uuid4()), fixture
    )
    job = Job(
        str(uuid4()),
        recipe.scope.connection_id,
        NOW,
        NOW,
        ((device.connection_id, str(uuid4())),),
    )
    return recipe, job


def test_synthetic_configuration_has_exact_dependency_and_no_network(tmp_path):
    recipe, job = case(tmp_path)
    recipe.validate(job)
    cadence = dict(
        kind="interval", seconds=3600, anchor=NOW.isoformat(), offset_seconds=0
    )
    parent = dict(
        scope=asdict(recipe.device_scope),
        bundle_root=str(recipe.device_root),
        synthetic_input=str(recipe.synthetic_input),
        allow_network=False,
        parameters={},
        schedule=cadence,
    )
    child = dict(
        scope=asdict(recipe.scope),
        bundle_root=str(recipe.bundle_root),
        synthetic_input=str(recipe.synthetic_input),
        allow_network=False,
        parameters=dict(
            device_input=recipe.device_scope.connection_id,
            binding=asdict(BINDING),
            native_device_id=recipe.native_device_id,
        ),
        schedule=cadence,
    )
    document = dict(version=1, concurrency=1, grace_seconds=30, inputs=[parent, child])
    configured = load(save(tmp_path, document), now=NOW)
    assert isinstance(configured.recipes[1], WindowsInventoryRecipe)
    assert (
        configured.state.definitions[recipe.scope.connection_id].dependencies
        == recipe.dependencies
    )
    assert configured.state.control.state == "off"
    child["allow_network"] = True
    with pytest.raises(ValueError, match="authority differs"):
        load(save(tmp_path, document), now=NOW)


@pytest.mark.parametrize(
    "damage",
    [
        "missing-prerequisite",
        "wrong-prerequisite",
        "tenant",
        "origin",
        "source",
        "timeout",
        "network",
        "scope",
    ],
)
def test_invalid_recipe_rejected_before_collection(tmp_path, damage):
    recipe, job = case(tmp_path)
    if damage == "missing-prerequisite":
        job = replace(job, prerequisite_snapshots=())
    elif damage == "wrong-prerequisite":
        job = replace(job, prerequisite_snapshots=((str(uuid4()), str(uuid4())),))
    elif damage == "tenant":
        recipe = replace(
            recipe, device_scope=replace(recipe.device_scope, tenant_id=str(uuid4()))
        )
    elif damage == "origin":
        recipe = replace(
            recipe, device_scope=replace(recipe.device_scope, origin="lab")
        )
    elif damage == "source":
        recipe = replace(
            recipe, device_scope=replace(recipe.device_scope, source="Unknown")
        )
    elif damage == "timeout":
        recipe = replace(recipe, timeout_seconds=True)
    elif damage == "network":
        recipe = replace(recipe, ssh_host="unexpected-host")
    else:
        job = replace(job, input_id=str(uuid4()))
    with pytest.raises(ValueError):
        recipe.validate(job)


def test_lab_recipe_pins_config_and_excludes_synthetic_input(tmp_path):
    recipe, job = case(tmp_path)
    config = tmp_path / "ssh-config"
    config.write_text("Host synthetic-test-alias\n  HostName 192.0.2.1\n")
    config.chmod(0o600)
    recipe = replace(
        recipe,
        scope=replace(recipe.scope, origin="lab"),
        device_scope=replace(recipe.device_scope, origin="lab"),
        ssh_config=config,
        ssh_host="synthetic-test-alias",
        ssh_config_fingerprint=hashlib.sha256(config.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="without synthetic"):
        recipe.validate(job)
    recipe = replace(recipe, synthetic_input=None)
    recipe.validate(job)  # No socket or process is opened by configuration validation.
    config.write_text(config.read_text() + "  Port 2222\n")
    with pytest.raises(ValueError, match="configuration changed"):
        recipe.validate(job)
