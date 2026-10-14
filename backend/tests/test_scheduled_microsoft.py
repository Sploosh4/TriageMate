"""Scheduled collector dispatch uses synthetic policy fixtures, never credentials."""

from dataclasses import replace
from uuid import uuid4
import json

import pytest

from microsoft_evidence import collector_command as command
from tests.test_microsoft_collector_command import config_file as collector_fixture
from tests.test_microsoft_live_authority import NOW
from standalone.operations.dispatch import Job
from standalone.operations.microsoft_worker import MicrosoftRecipe
from standalone.operations.microsoft_network import fingerprint


config_file = collector_fixture


def operational_configuration(tmp_path, path, body):
    from datetime import datetime, timedelta, timezone

    value = dict(
        version=1,
        concurrency=1,
        grace_seconds=5,
        inputs=[
            dict(
                scope=body["scope"],
                schedule=dict(
                    kind="interval",
                    seconds=3600,
                    anchor=(
                        datetime.now(timezone.utc) + timedelta(seconds=1)
                    ).isoformat(),
                    offset_seconds=0,
                ),
                bundle_root=body["bundle_root"],
                synthetic_input=None,
                allow_network=True,
                parameters={"collector_config": str(path)},
            )
        ],
    )
    target = tmp_path / "operations.json"
    target.write_text(json.dumps(value))
    target.chmod(0o600)
    return target, value


def test_operational_config_freezes_collector_contents(config_file, tmp_path):
    from standalone.operations.configuration import load

    path, body = config_file
    target, _ = operational_configuration(tmp_path, path, body)
    first = load(target, now=NOW)
    original = first.state.definitions[body["scope"]["connection_id"]].worker_contract
    assert first.recipes[0].network_fingerprint == fingerprint(path)
    path.write_text(path.read_text() + "\n")
    changed = load(target, now=NOW)
    assert (
        changed.state.definitions[body["scope"]["connection_id"]].worker_contract
        != original
    )


@pytest.mark.parametrize("damage", ["disabled", "missing", "fixture", "relative"])
def test_operational_network_requires_explicit_configuration(
    config_file, tmp_path, damage
):
    from standalone.operations.configuration import load

    path, body = config_file
    target, value = operational_configuration(tmp_path, path, body)
    item = value["inputs"][0]
    if damage == "disabled":
        item["allow_network"] = False
    elif damage == "missing":
        item["parameters"] = {}
    elif damage == "fixture":
        item["synthetic_input"] = str(path)
    else:
        item["parameters"]["collector_config"] = "relative.json"
    target.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load(target, now=NOW)


def test_application_process_replays_synthetic_bundle_without_credentials(
    config_file, tmp_path, monkeypatch
):
    from datetime import datetime, timezone
    import time
    from standalone.evidence_pipeline.contracts import Snapshot
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
    from standalone.evidence_pipeline.runtime import local_database
    from standalone.evidence_pipeline.test_commands import cleanup

    path, body = config_file
    config = command.load_configuration(path)
    target, _ = operational_configuration(tmp_path, path, body)
    run_uuid = uuid4()
    run = str(run_uuid)
    now = datetime.now(timezone.utc)
    payload = json.dumps(
        [
            dict(
                id=str(uuid4()),
                deviceId=str(uuid4()),
                displayName="Explicitly synthetic scheduled replay",
            )
        ]
    ).encode()
    prepare(
        config.scope,
        run,
        config.bundle_root,
        collect=lambda: Snapshot(config.scope, run, now, now, "success", True, payload),
    )
    assert not config.key_path.exists() and not config.certificate_path.exists()
    monkeypatch.setattr("standalone.operations.dispatch.uuid4", lambda: run_uuid)
    from app.services.operations_api import create_service

    key, service = "synthetic-microsoft-replay-" + str(uuid4()), None
    try:
        service = create_service(tmp_path, target, key)
        service.request_mode("running")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current = service.status()
            if current["inputs"][0]["latest_success"]:
                break
            time.sleep(0.05)
        assert current["inputs"][0]["latest_snapshot"] == run, current
        service.request_mode("off")
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT complete,outcome FROM evidence.collection_attempts WHERE id=%s AND connection_id=%s",
                (run, config.scope.connection_id),
            )
            assert cursor.fetchone() == (True, "success")
    finally:
        if service is not None:
            service.close(timeout=5)
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        cleanup(config.scope)


def test_scheduled_network_adapter_reuses_existing_collector(config_file, monkeypatch):
    config_file, _ = config_file
    config = command.load_configuration(config_file)
    recipe = MicrosoftRecipe(
        config.scope,
        config.bundle_root,
        None,
        network_config=config_file,
        network_fingerprint=fingerprint(config_file),
    )
    job = Job(str(uuid4()), config.scope.connection_id, NOW, NOW, ())
    calls = []

    def run(configured, execution, **options):
        calls.append((configured, execution, options))
        return {"outcome": "success", "replayed": False}

    monkeypatch.setattr(command, "run", run)
    assert recipe.collect(job)["outcome"] == "success"
    assert calls[0][0] == config and calls[0][1] == job.run_id
    assert calls[0][2] == dict(
        allow_network=True,
        device_snapshot=None,
        association_config=None,
        predecessor=None,
        since=None,
    )
    # Changing public configuration content is rejected before collector effects.
    config_file.write_text(config_file.read_text() + "\n")
    with pytest.raises(ValueError, match="changed"):
        recipe.collect(job)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "damage", ["origin", "scope", "bundle", "fixture", "association"]
)
def test_scheduled_authority_cannot_cross_scope(
    config_file, tmp_path, monkeypatch, damage
):
    config_file, _ = config_file
    config = command.load_configuration(config_file)
    recipe = MicrosoftRecipe(
        config.scope,
        config.bundle_root,
        None,
        network_config=config_file,
        network_fingerprint=fingerprint(config_file),
    )
    job = Job(str(uuid4()), config.scope.connection_id, NOW, NOW, ())
    if damage == "origin":
        recipe = replace(recipe, scope=replace(config.scope, origin="synthetic"))
    elif damage == "scope":
        recipe = replace(
            recipe, scope=replace(config.scope, provenance="Changed synthetic policy")
        )
    elif damage == "bundle":
        recipe = replace(recipe, bundle_root=tmp_path)
    elif damage == "fixture":
        recipe = replace(recipe, synthetic_input=config_file)
    else:
        recipe = replace(recipe, association_config=config_file)
    monkeypatch.setattr(
        command,
        "run",
        lambda *a, **k: pytest.fail("Invalid authority reached collector"),
    )
    with pytest.raises(ValueError):
        recipe.collect(job)
