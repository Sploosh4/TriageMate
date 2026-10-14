"""Real worker processes use synthetic public evidence and owned test rows only."""

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import multiprocessing
from pathlib import Path
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.commands import register
from standalone.evidence_pipeline.runtime import connect, local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.evidence_pipeline.test_public_inputs import scope as public_scope, epss
from standalone.evidence_pipeline.collection.public_transport import endpoint


from .dispatch import Definition, Dispatcher, Job
from .lifecycle import Mode
from .process_worker import PublicRecipe, ProcessHandle, PublicWorkers, start_public
from .scheduling import Interval
from .supervisor import PostgresRepository, Supervisor
from .test_supervisor import Repository

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def scope():
    return replace(
        public_scope("FIRST"),
        connection_id=str(uuid4()),
        scope_reference=endpoint("FIRST"),
    )


def payload(cve):
    return epss(f"{cve},0.1,0.2\n")


def synthetic_wait(event):
    event.wait(30)


def test_configured_application_service_collects_and_stops(tmp_path):
    """The same factory used by app startup runs an explicitly synthetic input."""
    from dataclasses import asdict
    import json
    import time

    from app.services.operations_api import create_service

    chosen = scope()
    cve = "CVE-2099-" + str(uuid4().int)[:18]
    data = tmp_path / "synthetic.csv"
    data.write_bytes(payload(cve))
    data.chmod(0o600)
    bundles = tmp_path / "bundles"
    bundles.mkdir(mode=0o700)
    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=0,
                inputs=[
                    dict(
                        scope=asdict(chosen),
                        schedule=dict(
                            kind="interval",
                            seconds=2,
                            anchor=(
                                datetime.now(timezone.utc) + timedelta(seconds=0.2)
                            ).isoformat(),
                            offset_seconds=0,
                        ),
                        bundle_root=str(bundles),
                        synthetic_input=str(data),
                        allow_network=False,
                        parameters={},
                    )
                ],
            )
        )
    )
    config.chmod(0o600)
    key = "synthetic-app-service-" + str(uuid4())
    service = None
    try:
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        assert service.status()["configured_inputs"] == 1
        service.request_mode("running")
        deadline = time.monotonic() + 15
        while (
            time.monotonic() < deadline
            and not service.status()["inputs"][0]["latest_success"]
        ):
            time.sleep(0.02)
        current = service.status()
        assert current["inputs"][0]["latest_success"], current
        service.request_mode("off")
        assert service.close(timeout=5)
        with closing(connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.current_public_epss_observations WHERE connection_id=%s",
                (chosen.connection_id,),
            )
            assert cur.fetchone() == (1,)
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
            cur.execute(
                "DELETE FROM evidence.epss_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)",
                (chosen.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                (chosen.connection_id,),
            )
            # This test owns its generated CVE; removing only observations
            # leaves an unexplained identity that breaks the next retained gate.
            cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
        cleanup(chosen)
        with closing(local_database().connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,)
            )
            assert cur.fetchone() == (0,)


def test_real_worker_commits_synthetic_collection_before_supervisor_success(tmp_path):
    chosen = scope()
    cve = "CVE-2099-" + str(uuid4().int)[:18]
    data = tmp_path / "synthetic.csv"
    data.write_bytes(payload(cve))
    data.chmod(0o600)
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    recipe = PublicRecipe(chosen, root, data)
    now = datetime.now(timezone.utc)
    state = Dispatcher(
        [Definition(chosen.connection_id, Interval(600, now))],
        now=now - timedelta(seconds=1),
    )
    state.request_mode(Mode.RUNNING, now - timedelta(seconds=1))
    key = "synthetic-worker-" + str(uuid4())
    repository = PostgresRepository(key)
    handles = []

    def launch(job):
        # Verify the committed intent through a fresh database connection.
        _, saved = repository.load()
        assert saved.inputs[chosen.connection_id].active == job
        handle = start_public(recipe, job, service_key=key)
        handles.append(handle)
        return handle

    try:
        register(chosen)
        supervisor = Supervisor(repository, state, launch)
        (job,) = supervisor.tick(now).start
        handles[0].process.join(timeout=15)
        assert handles[0].poll() == 0
        # Simulate lost parent handles after collection committed, before its
        # completion checkpoint. Recovery must inspect the lease and database.
        recovered_workers = PublicWorkers(key, [recipe], tmp_path)
        try:
            recovered = Supervisor(repository, state, recovered_workers)
            recovered.tick(now)
        finally:
            recovered_workers.close()
        _, restored = repository.load()
        assert restored.inputs[chosen.connection_id].latest_success
        assert restored.inputs[chosen.connection_id].latest_snapshot == job.run_id
        with closing(connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.current_public_epss_observations WHERE connection_id=%s",
                (chosen.connection_id,),
            )
            assert cur.fetchone() == (1,)
    finally:
        for handle in handles:
            handle.cancel()
            handle.process.join(timeout=5)
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                """DELETE FROM evidence.epss_observations WHERE receipt_id IN
              (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)""",
                (chosen.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                (chosen.connection_id,),
            )
            # This test owns its generated CVE; removing only observations
            # leaves an unexplained identity that breaks the next retained gate.
            cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
        cleanup(chosen)
        with closing(local_database().connect()) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,)
            )
            assert cur.fetchone() == (0,)


def test_off_stops_a_real_process_and_waits_for_terminal_handle():
    from .test_dispatch import dispatcher, at

    context = multiprocessing.get_context("spawn")
    event = context.Event()
    process = context.Process(target=synthetic_wait, args=(event,), daemon=True)
    handles = []

    def launch(job):
        process.start()
        handle = ProcessHandle(process)
        handles.append(handle)
        return handle

    state = dispatcher()
    state.control.grace_seconds = 0
    supervisor = Supervisor(Repository(), state, launch)
    try:
        supervisor.tick(at(600))
        supervisor.request_mode(Mode.OFF, at(601))
        supervisor.tick(at(601))
        assert supervisor.state.control.state == "draining"
        process.join(timeout=5)
        assert process.exitcode is not None
        supervisor.tick(at(602))
        assert supervisor.state.control.state == "off"
    finally:
        event.set()
        if handles:
            handles[0].cancel()
            process.join(timeout=5)


def test_recipe_cannot_turn_synthetic_data_into_network_collection(tmp_path):
    tmp_path.chmod(0o700)
    chosen = scope()
    now = datetime.now(timezone.utc)
    job = Job(str(uuid4()), chosen.connection_id, now, now, ())
    recipe = PublicRecipe(chosen, tmp_path, Path("synthetic.csv"))
    for invalid in [
        replace(recipe, allow_network=True),
        replace(recipe, synthetic_input=None),
        replace(recipe, parameters=(("arbitrary_url", "https://example.invalid"),)),
        replace(recipe, scope=replace(chosen, connection_id=str(uuid4()))),
    ]:
        with pytest.raises(ValueError):
            invalid.validate(job)


@pytest.mark.parametrize("state_change", ["completed", "cancelled"])
def test_delayed_child_cannot_collect_after_recovery_or_cancellation(
    tmp_path, monkeypatch, state_change
):
    from . import process_worker
    from .test_dispatch import NOW, at

    chosen = scope()
    tmp_path.chmod(0o700)
    recipe = PublicRecipe(chosen, tmp_path, tmp_path / "synthetic.csv")
    state = Dispatcher([Definition(chosen.connection_id, Interval(600, NOW))], now=NOW)
    state.request_mode(Mode.RUNNING, NOW)
    (job,) = state.tick(at(600)).start
    if state_change == "completed":
        state.finished(job.run_id, success=False, now=at(601))
    else:
        state.control.cancel_requested.add(job.run_id)
    monkeypatch.setattr(PostgresRepository, "load", lambda self: (1, state))
    invoked = []
    monkeypatch.setattr(
        process_worker, "_collect_under_lease", lambda *args: invoked.append(True)
    )
    with pytest.raises(SystemExit) as result:
        process_worker._collect(recipe, job, "synthetic-service")
    assert result.value.code == 1 and invoked == []
