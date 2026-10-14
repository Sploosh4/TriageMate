"""Synthetic dependent Catalog jobs run through the actual scheduler processes."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.evidence_pipeline.test_exposure_commands import remove_exposure
from standalone.evidence_pipeline.test_catalog_discovery import (
    empty_payload,
    payload,
    row,
    ID,
)
from standalone.evidence_pipeline.test_update_catalog import payload as detail
from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
from standalone.evidence_pipeline.parsing.update_catalog import endpoint
from .catalog_target_recipe import REFERENCE


@pytest.fixture
def catalog_database(monkeypatch):
    """Bounded chain behavior must not depend on earlier committed fixture history."""
    from backend.database.installation import setup
    from standalone.evidence_pipeline.test_bootstrap import isolated_database

    with isolated_database(monkeypatch) as database:
        setup(database, profile="empty")
        yield database


@pytest.mark.parametrize(
    "invalid_index,repeat,nonempty",
    [
        (False, False, False),
        (True, False, False),
        ("recover", False, False),
        (False, True, False),
        (False, True, True),
        (False, True, 2),
    ],
)
def test_scheduled_device_missing_patch_catalog_chain(
    tmp_path, invalid_index, repeat, nonempty, monkeypatch, catalog_database
):
    from app.services.operations_api import create_service
    from .notifications import load as notifications

    device = SourceScope(
        str(uuid4()),
        "Defender",
        "devices",
        "synthetic-catalog-devices",
        "synthetic",
        "Generated test",
        str(uuid4()),
    )
    missing = replace(device, connection_id=str(uuid4()), input_kind="missing_patches")
    target = SourceScope(
        str(uuid4()),
        "Microsoft Update Catalog",
        "catalog_targets",
        REFERENCE,
        "synthetic",
        "Generated test",
    )
    native = str(uuid4())
    update = str(uuid4())
    second_update = str(uuid4())
    public_scope = catalog_scope("synthetic", endpoint(update))
    public_scopes = [public_scope]
    if nonempty == 2:
        public_scopes.append(catalog_scope("synthetic", endpoint(second_update)))
    roots = {}
    for scope in (device, missing, target):
        roots[scope.connection_id] = tmp_path / scope.connection_id
        roots[scope.connection_id].mkdir(mode=0o700)

    def fixture(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return str(path)

    device_file = fixture("device.json", [{"id": native}])
    missing_file = fixture("missing.json", [{"machineId": native, "id": "KB9999991"}])
    targets_file = fixture(
        "targets.json",
        {
            "origin": "synthetic",
            "searches": {
                "KB9999991": {
                    "index": "invalid synthetic response"
                    if invalid_index
                    else payload(
                        row(update),
                        "1 - 1 of 2 (page 1 of 2)"
                        if nonempty == 2
                        else "1 - 1 of 1 (page 1 of 1)",
                    ).decode()
                    if nonempty
                    else empty_payload().decode(),
                    "records": {update: detail().decode().replace(ID, update)}
                    if nonempty
                    else {},
                }
            },
        },
    )
    if nonempty == 2:
        document = json.loads(Path(targets_file).read_text())
        entry = document["searches"]["KB9999991"]
        entry["pages"] = {
            "2": payload(row(second_update), "2 - 2 of 2 (page 2 of 2)").decode()
        }
        entry["records"][second_update] = detail().decode().replace(ID, second_update)
        Path(targets_file).write_text(json.dumps(document))
    anchor = datetime.now(timezone.utc) + timedelta(seconds=2)
    inputs = []
    for scope, path, parameters in (
        (device, device_file, {}),
        (missing, missing_file, {"device_input": device.connection_id}),
        (target, targets_file, {"missing_patch_inputs": [missing.connection_id]}),
    ):
        inputs.append(
            dict(
                scope=asdict(scope),
                bundle_root=str(roots[scope.connection_id]),
                synthetic_input=path,
                allow_network=False,
                parameters=parameters,
                schedule=dict(
                    kind="interval",
                    seconds=5 if repeat or invalid_index == "recover" else 60,
                    anchor=anchor.isoformat(),
                    offset_seconds=0,
                ),
            )
        )
    if nonempty:
        inputs[-1]["provider_age_seconds"] = 172800
    config = fixture(
        "operations.json",
        dict(version=1, concurrency=1, grace_seconds=1, inputs=inputs),
    )
    key = "synthetic-catalog-target-" + str(uuid4())
    service = None
    try:
        # Real workers and durable scheduling, but explicit schedule slots: a slow
        # observer must not accidentally request a third cycle while asserting two.
        schedule_clock = [anchor - timedelta(seconds=1)]
        from .service import Service
        from .configuration import load as load_configuration

        monkeypatch.setattr(
            "app.services.operations_api.load",
            lambda path, **kwargs: load_configuration(
                path, now=anchor - timedelta(seconds=1)
            ),
        )

        monkeypatch.setattr(
            "app.services.operations_api.Service",
            lambda *args, **kwargs: Service(
                *args,
                clock=lambda: min(datetime.now(timezone.utc), schedule_clock[0]),
                **kwargs,
            ),
        )
        service = create_service(tmp_path, config, key)
        service.request_mode("running")
        schedule_clock[0] = anchor
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = service.status()
            # The committed completion event is authoritative even when failure
            # occurs before the target's output directory can be created.
            with local_database().connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s AND event->>'kind' IN ('catalog_targets','repository_failure')",
                    (key,),
                )
                completed = cur.fetchone()[0]
                finished = completed >= (2 if repeat else 1)
            if repeat and completed == 1 and not status["active"]:
                schedule_clock[0] = anchor + timedelta(seconds=5)
            if finished and not any(item["active"] for item in status["inputs"]):
                break
            time.sleep(0.05)
        if not finished or any(item["active"] for item in status["inputs"]):
            with local_database().connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s",
                    (key,),
                )
                events = [row[0] for row in cur.fetchall()]
            pytest.fail(
                "Synthetic chain did not complete/drain: "
                + json.dumps(
                    {"status": status, "events": events}, default=str, sort_keys=True
                )
            )
        if nonempty == 2:
            # Reproduce a slow observer crossing another real interval. The
            # bounded scheduler clock must still have requested only two slots.
            time.sleep(5.1)
        notices = notifications(key)
        if invalid_index:
            assert len(notices) == 1 and notices[0]["category"] == "collection-failure"
            assert notices[0]["status"] == "unresolved"
            if invalid_index == "recover":
                # Simulate the source recovering. No scheduler restart, input
                # toggle or manual retry occurs between the failed and good runs.
                recovered = json.loads(Path(targets_file).read_text())
                recovered["searches"]["KB9999991"]["index"] = empty_payload().decode()
                Path(targets_file).write_text(json.dumps(recovered))
                schedule_clock[0] = anchor + timedelta(seconds=5)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    with local_database().connect() as conn, conn.cursor() as cur:
                        cur.execute(
                            "SELECT count(*) FROM evidence_pipeline.operation_events "
                            "WHERE service_key=%s AND event->>'kind'='catalog_targets'",
                            (key,),
                        )
                        recovered_runs = cur.fetchone()[0]
                    status = service.status()
                    if recovered_runs and not status["active"]:
                        break
                    time.sleep(0.05)
                assert recovered_runs >= 1 and not status["active"], status
                notices = notifications(key)
                failures = [n for n in notices if n["category"] == "collection-failure"]
                assert len(failures) == 1 and failures[0]["status"] == "resolved"
                assert all(item["latest_success"] for item in status["inputs"])
        else:
            # Advancing the schedule can surface overdue history. A later
            # success resolves that episode; failures still fail this check.
            assert all(
                notice["category"] == "collection-overdue"
                and notice["status"] == "resolved"
                for notice in notices
            ), notices
            assert all(item["latest_success"] for item in status["inputs"])
        if nonempty:
            for public_scope in public_scopes:
                with local_database().connect() as conn, conn.cursor() as cur:
                    cur.execute("SET LOCAL ROLE tm_mock_reader")
                    cur.execute(
                        "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=%s AND complete AND outcome='success'",
                        (public_scope.connection_id,),
                    )
                    assert cur.fetchone() == (2,)
                    cur.execute(
                        "SELECT count(*) FROM evidence.observation_receipts r JOIN evidence.collection_attempts a ON a.id=r.collection_attempt_id WHERE a.connection_id=%s",
                        (public_scope.connection_id,),
                    )
                    assert cur.fetchone() == (2,)
                    cur.execute(
                        "SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
                        (public_scope.connection_id,),
                    )
                    assert cur.fetchone() == (1,)
                    cur.execute(
                        "SELECT applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
                        ([public_scope.connection_id],),
                    )
                    assert cur.fetchone() == (8,)
            manifests = [
                json.loads(path.read_text())
                for path in roots[target.connection_id].glob("*/targets.json")
            ]
            assert len(manifests) == 2
            assert (
                len(
                    {manifest["selection"]["snapshots"][0][1] for manifest in manifests}
                )
                == 2
            )
        from .catalog_age import read_target_clock

        configured = load_configuration(Path(config), now=anchor)
        recipe = configured.recipes[-1]
        with local_database().connect() as conn, conn.cursor() as cur:
            clock = read_target_clock(cur, key, recipe)
        assert clock["provider_time"] == (
            "2026-09-16T00:00:00+00:00" if nonempty else None
        )
        if nonempty:
            assert len(configured.provider_policies) == 1
            manifest_path = (
                roots[target.connection_id] / clock["attempt_id"] / "targets.json"
            )
            original = manifest_path.read_bytes()
            damaged = json.loads(original)
            damaged["selection"]["snapshots"][0][1] = str(uuid4())
            manifest_path.write_text(json.dumps(damaged))
            with local_database().connect() as conn, conn.cursor() as cur:
                assert read_target_clock(cur, key, recipe)["provider_time"] is None
            manifest_path.write_bytes(original)
            with local_database().connect() as conn, conn.cursor() as cur:
                assert read_target_clock(cur, key, recipe) == clock
        service.request_mode("off")
        service.close(timeout=5)
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
    finally:
        if service is not None:
            service.close(timeout=5)
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        if nonempty:
            for public_scope in public_scopes:
                with local_database().connect() as conn, conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s)",
                        (public_scope.connection_id,),
                    )
                    cur.execute(
                        "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                        (public_scope.connection_id,),
                    )
                cleanup(public_scope)
        remove_exposure(missing)
        cleanup(device)
