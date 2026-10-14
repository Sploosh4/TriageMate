"""Real dispatcher, journal, recipe and proof in one rolled-back transaction.

Connections share the transaction so no synthetic evidence is committed. This
checks orchestration in-process; separate-process crash acceptance remains separate.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.test_enrichment_store import db, bound, snapshot  # noqa: F401
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.contracts import SourceScope, Snapshot
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.test_public_inputs import nvd
from standalone.evidence_pipeline import enrichment_commands
from .enrichment_recipe import EnrichmentRecipe
from . import enrichment_recipe, enrichment_refresh_worker
from .configuration import Definition, Interval
from .dispatch import Dispatcher
from .supervisor import Supervisor, PostgresRepository
from .lifecycle import Mode


class SharedTransaction:
    def __init__(self, connection):
        self.connection = connection

    @property
    def autocommit(self):
        return self.connection.autocommit

    def cursor(self, *args, **kwargs):
        return self.connection.cursor(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        pass


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("reload_between_cycles", [False, True])
@pytest.mark.parametrize("interrupt_first_refresh", [False, True])
def test_initial_refresh_and_new_observation_join_without_reconfiguring(
    db,  # noqa: F811
    bound,  # noqa: F811
    tmp_path,
    monkeypatch,
    reload_between_cycles,
    interrupt_first_refresh,
):
    device, child = bound
    now = datetime.now(timezone.utc)
    cves = ["CVE-2099-" + str(uuid4().int)[:10] for _ in range(2)]
    key = "synthetic-refresh-schedule-" + uuid4().hex
    scope = SourceScope(
        str(uuid4()),
        "NVD",
        "enrichment_queue",
        "triagemate:enrichment/NVD",
        "synthetic",
        "Generated scheduler regression fixture",
    )
    wires = {}
    requests = {}
    for cve in cves:
        raw = nvd()
        raw["vulnerabilities"][0]["cve"]["id"] = cve
        wire = json.dumps(raw)
        wires[cve] = wire
        requests[
            stable_id(
                "enrichment-request-v1", "NVD", "vulnerabilities", "synthetic", cve
            )
        ] = wire
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps(dict(origin="synthetic", requests=requests, refresh=wires))
    )
    fixture.chmod(0o600)
    recipe = EnrichmentRecipe(
        scope,
        tmp_path,
        fixture,
        limit=1,
        worker_contract="a" * 64,
        refresh_completed=True,
    )
    shared = SharedTransaction(db)
    for module in (enrichment_recipe, enrichment_refresh_worker, enrichment_commands):
        monkeypatch.setattr(module, "connect", lambda: shared)

    def register(source):
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
            cur.execute(
                "SELECT 1 FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
                (source.connection_id,),
            )
            if cur.fetchone() is None:
                authorize_connection(
                    cur,
                    Snapshot(
                        source,
                        str(uuid4()),
                        now,
                        now,
                        "failure",
                        False,
                        b"",
                        "synthetic_registration",
                    ),
                )
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")

    for module in (enrichment_commands, enrichment_refresh_worker):
        monkeypatch.setattr(module, "register", register)
        monkeypatch.setattr(
            module, "ingest_public", lambda value: persist_public(db, value)
        )

    interrupted = []

    def refresh_import(value):
        if interrupt_first_refresh and not interrupted:
            # Model termination after durable bundle creation but before DB import.
            interrupted.append(value)
            return None
        return persist_public(db, value)

    monkeypatch.setattr(enrichment_refresh_worker, "ingest_public", refresh_import)

    def observe(values):
        records = [
            dict(
                id="synthetic-" + cve,
                machineId=device.records()[0]["id"],
                cveId=cve,
                productName="Synthetic refresh product",
                productVersion="1",
            )
            for cve in values
        ]
        observed = replace(
            child, execution_id=str(uuid4()), payload=json.dumps(records).encode()
        )
        with db.cursor() as cur:
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        result = persist_exposure(db, observed, device.execution_id)
        discovered = enrichment_commands.after_findings_commit(observed, result)
        assert discovered["enrichment"]["state"] == "checked"

    observe(cves[:1])
    definition = Definition(
        scope.connection_id, Interval(60, now), worker_contract=recipe.worker_contract
    )
    state = Dispatcher([definition], now=now)
    repository = PostgresRepository(
        key, connector=lambda: shared, enrichment_proofs=[recipe.binding()]
    )
    launched = []

    class Finished:
        def poll(self):
            return 0

        def cancel(self):
            raise AssertionError("No cancellation expected")

    def launch(job):
        launched.append(job)
        complete = recipe.collect(job, key)
        assert complete is not (interrupt_first_refresh and len(launched) == 2)
        return Finished()

    supervisor = Supervisor(repository, state, launch)
    supervisor.request_mode(Mode.RUNNING, now)
    cycles = 5 if interrupt_first_refresh else 4
    for cycle in range(cycles):
        if cycle and reload_between_cycles:
            supervisor = Supervisor(repository, state, launch)
            assert not supervisor.needs_recovery
        if cycle == 1:
            # A new request is already pending when the refresh turn is due.
            observe(cves)
        tick = now + timedelta(seconds=(cycle + 1) * 60 + 1)
        supervisor.tick(tick)
        supervisor.tick(tick + timedelta(seconds=1))
        failed = interrupt_first_refresh and cycle == 1
        assert supervisor.state.inputs[scope.connection_id].latest_success is not failed
        if not failed:
            assert (
                supervisor.state.inputs[scope.connection_id].latest_snapshot
                == launched[-1].run_id
            )
    assert len(launched) == cycles
    with db.cursor() as cur:
        cur.execute(
            "SELECT event->'cve_ids' FROM evidence_pipeline.operation_events WHERE service_key=%s AND event->>'kind'='enrichment_refresh_batch' ORDER BY id",
            (key,),
        )
        expected = [[], [cves[0]], [], [cves[1]]]
        if interrupt_first_refresh:
            expected.append([cves[0]])
        assert [row[0] for row in cur.fetchall()] == expected
        if interrupt_first_refresh:
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                (interrupted[0].execution_id,),
            )
            assert cur.fetchone() == (0,)
            assert interrupted[0].execution_id != enrichment_refresh_worker.attempt_id(
                launched[4], interrupted[0].scope
            )
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[])",
            (
                [
                    enrichment_refresh_worker.source_scope(
                        recipe.binding(), cve
                    ).connection_id
                    for cve in cves
                ],
            ),
        )
        assert cur.fetchone() == (2,)
    supervisor.request_mode(Mode.OFF, now + timedelta(seconds=cycles * 60 + 3))
    assert not supervisor.state.control.active
