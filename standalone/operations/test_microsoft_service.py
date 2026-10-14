"""Configured synthetic device-to-software collection through actual processes and DB."""

from contextlib import closing
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import time
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.runtime import connect, local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.evidence_pipeline.test_exposure_commands import remove_exposure
from .microsoft_worker import verify_committed_device
from standalone.evidence_pipeline.collection.snapshot_bundle import prepare

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def test_scheduled_software_uses_committed_device_and_rejects_rewritten_bundle(
    tmp_path,
):
    from app.services.operations_api import create_service
    from app.services.postgres_query import PostgreSQLQueries

    device = SourceScope(
        str(uuid4()),
        "Intune",
        "devices",
        "synthetic-scheduled-devices",
        "synthetic",
        "Explicitly synthetic scheduled acceptance",
        str(uuid4()),
    )
    child = replace(device, connection_id=str(uuid4()), input_kind="software")
    native = str(uuid4())
    application = "synthetic-scheduled-" + str(uuid4())
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)

    def fixture(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return str(path)

    device_path = fixture(
        "devices.json",
        [{"id": native, "deviceName": "Synthetic scheduled workstation"}],
    )
    software_path = fixture(
        "software.json",
        [{"id": application, "displayName": application, "deviceCount": 1}],
    )
    association_path = fixture("associations.json", {application: [native]})
    anchor = datetime.now(timezone.utc) + timedelta(seconds=2)
    common = dict(
        schedule=dict(
            kind="interval", seconds=60, anchor=anchor.isoformat(), offset_seconds=0
        ),
        bundle_root=str(root),
        allow_network=False,
    )
    config = fixture(
        "operations.json",
        dict(
            version=1,
            concurrency=1,
            grace_seconds=1,
            inputs=[
                dict(
                    common,
                    scope=asdict(child),
                    synthetic_input=software_path,
                    parameters={
                        "device_input": device.connection_id,
                        "association_input": association_path,
                    },
                ),
                dict(
                    common,
                    scope=asdict(device),
                    synthetic_input=device_path,
                    parameters={},
                ),
            ],
        ),
    )
    key = "synthetic-microsoft-service-" + str(uuid4())
    service = None
    try:
        service = create_service(tmp_path, config, key)
        service.request_mode("running")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status = service.status()
            inputs = {item["input_id"]: item for item in status["inputs"]}
            if inputs[child.connection_id]["latest_success"]:
                break
            time.sleep(0.05)
        assert inputs[child.connection_id]["latest_success"], status
        service.request_mode("off")
        assert service.close(timeout=5)
        device_run = inputs[device.connection_id]["latest_snapshot"]
        child_run = inputs[child.connection_id]["latest_snapshot"]
        receipt = json.loads((root / child_run / "receipt.json").read_text())
        assert receipt["binding"]["device_execution_id"] == device_run
        with closing(connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT device_attempt_id::text FROM evidence_pipeline.exposure_snapshots WHERE input_connection_id=%s",
                (child.connection_id,),
            )
            assert cur.fetchone() == (device_run,)
        query = PostgreSQLQueries()
        data = json.loads(
            query.execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT source_application_id,reported_device_count,observed_device_count FROM evidence_pipeline.current_software_inventory WHERE connection_id='"
                    + child.connection_id
                    + "'::uuid",
                }
            )
        )
        assert data["rows"] == [[application, 1, 1]]

        def no_fetch():
            pytest.fail("Saved device tried to fetch")

        saved = prepare(device, device_run, root, collect=no_fetch)
        verify_committed_device(saved)
        with pytest.raises(ValueError, match="committed prerequisite"):
            verify_committed_device(replace(saved, payload=saved.payload + b" "))
    finally:
        if service is not None:
            service.close(timeout=5)
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        remove_exposure(child)
        cleanup(device)


def test_scheduled_delta_advances_from_baseline_then_previous_delta(tmp_path):
    from app.services.operations_api import create_service
    from .microsoft_worker import MicrosoftRecipe
    from .dispatch import Job

    device = SourceScope(
        str(uuid4()),
        "Defender",
        "devices",
        "synthetic-delta-devices",
        "synthetic",
        "Explicitly synthetic scheduled delta acceptance",
        str(uuid4()),
    )
    baseline = replace(
        device, connection_id=str(uuid4()), input_kind="vulnerability_baseline"
    )
    delta = replace(
        device, connection_id=str(uuid4()), input_kind="vulnerability_events"
    )
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    payload = tmp_path / "empty-synthetic.json"
    payload.write_text("[]")
    payload.chmod(0o600)
    anchor = datetime.now(timezone.utc) + timedelta(seconds=2)
    common = dict(
        bundle_root=str(root), synthetic_input=str(payload), allow_network=False
    )

    def item(scope, seconds, parameters):
        return dict(
            common,
            scope=asdict(scope),
            parameters=parameters,
            schedule=dict(
                kind="interval",
                seconds=seconds,
                anchor=anchor.isoformat(),
                offset_seconds=0,
            ),
        )

    config = tmp_path / "delta-operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=1,
                inputs=[
                    item(
                        delta,
                        2,
                        {
                            "device_input": device.connection_id,
                            "baseline_input": baseline.connection_id,
                        },
                    ),
                    item(baseline, 60, {"device_input": device.connection_id}),
                    item(device, 60, {}),
                ],
            )
        )
    )
    config.chmod(0o600)
    key = "synthetic-delta-service-" + str(uuid4())
    service = None
    observed = []
    try:
        service = create_service(tmp_path, config, key)
        service.request_mode("running")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status = service.status()
            inputs = {value["input_id"]: value for value in status["inputs"]}
            current = inputs[delta.connection_id]["latest_snapshot"]
            if current and current not in observed:
                observed.append(current)
            if len(observed) == 2:
                break
            time.sleep(0.05)
        assert len(observed) == 2, status
        service.request_mode("off")
        assert service.close(timeout=5)
        baseline_run = inputs[baseline.connection_id]["latest_snapshot"]
        device_run = inputs[device.connection_id]["latest_snapshot"]
        first = json.loads((root / observed[0] / "receipt.json").read_text())
        second = json.loads((root / observed[1] / "receipt.json").read_text())
        assert first["binding"]["predecessor_attempt_id"] == baseline_run
        assert second["binding"]["predecessor_attempt_id"] == observed[0]
        assert second["binding"]["since_time"] >= first["binding"]["since_time"]
        with closing(connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT attempt_id::text FROM evidence_pipeline.assessment_checkpoints WHERE connection_id=%s",
                (delta.connection_id,),
            )
            assert cur.fetchone() == (observed[1],)
        # Replay the first delta after a later checkpoint exists, without rereading
        # the fixture or substituting the latest predecessor into its old request.
        payload.unlink()
        recipe = MicrosoftRecipe(
            delta, root, payload, device, root, baseline_scope=baseline
        )
        job = Job(
            observed[0],
            delta.connection_id,
            anchor,
            anchor,
            (
                (device.connection_id, device_run),
                (baseline.connection_id, baseline_run),
            ),
        )
        assert recipe.collect(job)["replayed"]
        wrong_baseline = replace(
            job,
            run_id=str(uuid4()),
            prerequisite_snapshots=(
                job.prerequisite_snapshots[0],
                (baseline.connection_id, str(uuid4())),
            ),
        )
        with pytest.raises(ValueError, match="committed checkpoint"):
            recipe.collect(wrong_baseline)
        assert not (root / wrong_baseline.run_id).exists()
        payload.write_text('{"invalid": "synthetic delta fixture"}')
        payload.chmod(0o600)
        failed = recipe.collect(replace(job, run_id=str(uuid4())))
        assert failed["outcome"] == "failure"
        with closing(connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT attempt_id::text FROM evidence_pipeline.assessment_checkpoints WHERE connection_id=%s",
                (delta.connection_id,),
            )
            assert cur.fetchone() == (observed[1],)

    finally:
        if service is not None:
            service.close(timeout=5)
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        for source in (delta, baseline):
            with (
                closing(local_database().connect()) as conn,
                conn,
                conn.cursor() as cur,
            ):
                cur.execute(
                    "DELETE FROM evidence_pipeline.assessment_runs r USING evidence.collection_attempts a WHERE a.id=r.attempt_id AND a.connection_id=%s",
                    (source.connection_id,),
                )
                cur.execute(
                    "DELETE FROM evidence_pipeline.assessment_bindings WHERE connection_id=%s",
                    (source.connection_id,),
                )
            cleanup(source)
        cleanup(device)
