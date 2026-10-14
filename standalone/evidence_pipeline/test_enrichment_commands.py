"""Committed synthetic enrichment, real worker connections and source-scoped cleanup."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json
from uuid import uuid4

import pytest
from psycopg2 import sql

from . import enrichment_commands as worker
from standalone.evidence_pipeline.persistence.enrichment_store import request_scope
from .runtime import local_database
from .test_commands import cleanup
from .test_exposure_commands import remove_exposure
from .test_public_inputs import nvd
from .test_enrichment_store import (
    queued_input as queued_fixture,
    db as database_fixture,
    bound as bound_fixture,
    snapshot as snapshot_fixture,
)

db = database_fixture
bound = bound_fixture
snapshot = snapshot_fixture
queued_input = queued_fixture


@pytest.fixture
def committed_input(db, queued_input, monkeypatch):
    from standalone.evidence_pipeline.collection import public_collection

    def no_network(*args, **kwargs):
        pytest.fail("Committed synthetic enrichment attempted network collection")

    monkeypatch.setattr(public_collection, "download", no_network)
    device, child, cves = queued_input
    db.commit()
    try:
        yield child, cves
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id::text FROM evidence_pipeline.enrichment_requests WHERE cause_receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s))",
                (child.scope.connection_id,),
            )
            ids = [row[0] for row in cur.fetchall()]
            scopes = [request_scope(cur, key)[0] for key in ids]
            cur.execute(
                "DELETE FROM evidence_pipeline.enrichment_runs WHERE request_id=ANY(%s::uuid[])",
                (ids,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.enrichment_requests WHERE id=ANY(%s::uuid[])",
                (ids,),
            )
            for table in (
                "cvss_observations",
                "vulnerability_details",
                "vulnerability_references",
                "cve_contributions",
                "cve_record_observations",
                "recommendation_patches",
                "recommendation_cves",
                "patch_vulnerabilities",
                "recommendations",
                "patches",
                "advisory_cves",
                "advisories",
            ):
                cur.execute(
                    sql.SQL(
                        "DELETE FROM evidence.{} WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=ANY(%s::uuid[]))"
                    ).format(sql.Identifier(table)),
                    (ids,),
                )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=ANY(%s::uuid[]))",
                (ids,),
            )
            cur.execute(
                "DELETE FROM evidence.vulnerability_findings WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)) RETURNING software_id",
                (child.scope.connection_id,),
            )
            software = [row[0] for row in cur.fetchall()]
            cur.execute(
                "DELETE FROM evidence.software s WHERE s.id=ANY(%s::uuid[]) AND NOT EXISTS(SELECT 1 FROM evidence.vulnerability_findings f WHERE f.software_id=s.id) AND NOT EXISTS(SELECT 1 FROM evidence.software_observations o WHERE o.software_id=s.id) AND NOT EXISTS(SELECT 1 FROM evidence_pipeline.software_inventory i WHERE i.software_id=s.id)",
                (software,),
            )
            cur.execute(
                "DELETE FROM evidence.vulnerabilities WHERE cve_id=ANY(%s)", (cves,)
            )
        for chosen in scopes:
            cleanup(chosen)
        remove_exposure(child.scope)
        cleanup(device.scope)


def fixtures_for(ids):
    fixtures = {}
    with local_database().connect() as conn, conn.cursor() as cur:
        for request in ids:
            scope, cve = request_scope(cur, request)
            if scope.source in ("CVE", "CISA"):
                from .test_cve_program import document

                raw = document()
                raw["cveMetadata"]["cveId"] = cve
            elif scope.source == "MSRC":
                from .test_csaf import fixture

                raw = fixture()
                raw["vulnerabilities"][0]["cve"] = cve
            else:
                raw = nvd()
                raw["vulnerabilities"][0]["cve"]["id"] = cve
            fixtures[request] = json.dumps(raw).encode()
    return fixtures


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("empty", [False, True])
def test_scheduled_batch_commits_exact_membership_before_processing(
    tmp_path, committed_input, empty
):
    from contextlib import closing
    from standalone.operations import store
    from standalone.operations.dispatch import Definition, Dispatcher
    from standalone.operations.enrichment_batch import ScheduledEnrichment
    from standalone.operations.lifecycle import Mode
    from standalone.operations.notifications import load as notices
    from standalone.operations.scheduling import Interval
    from standalone.operations.test_dispatch import at
    from .runtime import connect

    child, _ = committed_input
    requests = worker.discover_attempt(child.execution_id, sources=["NVD"])
    fixtures = fixtures_for(requests)
    key, input_id = "synthetic-enrichment-batch-" + str(uuid4()), str(uuid4())
    contract = "a" * 64
    state = Dispatcher(
        [Definition(input_id, Interval(10, at(0)), worker_contract=contract)], now=at(0)
    )
    state.request_mode(Mode.RUNNING, at(0))
    job = state.tick(at(10)).start[0]
    batch = ScheduledEnrichment(input_id, contract, "NVD", "synthetic", limit=1)
    try:
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            store.save(cursor, key, 0, state)
            assert not batch.committed(cursor, key, job)
            selected = batch.declare(
                cursor, key, job, synthetic_ids=[] if empty else requests
            )
        assert len(selected) == (0 if empty else 1)
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            assert batch.declare(cursor, key, job, synthetic_ids=requests) == selected
            assert batch.committed(cursor, key, job) is empty
        assert notices(key) == []
        results = worker.process_pending(
            tmp_path / "bundles",
            limit=1,
            sources=["NVD"],
            synthetic_inputs=fixtures,
            request_ids=selected,
        )
        assert len(results) == len(selected)
        with closing(connect()) as conn, conn, conn.cursor() as cursor:
            assert batch.committed(cursor, key, job)
            assert batch.saved(cursor, key, job) == selected
        assert all(
            worker.status(request)["state"] == "queued"
            for request in requests
            if request not in selected
        )
    finally:
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("invalid", [False, True])
def test_application_schedules_exact_enrichment_batch(
    tmp_path, committed_input, invalid
):
    from datetime import datetime, timedelta, timezone
    import time

    child, _ = committed_input
    requests = worker.discover_attempt(child.execution_id, sources=["NVD"])
    payloads = fixtures_for(requests)
    fixture = tmp_path / "synthetic-enrichment.json"
    fixture.write_text(
        json.dumps(
            dict(
                origin="synthetic",
                requests={
                    key: "{}" if invalid else payload.decode()
                    for key, payload in payloads.items()
                },
            )
        )
    )
    fixture.chmod(0o600)
    bundles = tmp_path / "bundles"
    bundles.mkdir(mode=0o700)
    key, input_id = "synthetic-enrichment-service-" + str(uuid4()), str(uuid4())
    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=5,
                inputs=[
                    dict(
                        scope=dict(
                            connection_id=input_id,
                            source="NVD",
                            input_kind="enrichment_queue",
                            scope_reference="triagemate:enrichment/NVD",
                            origin="synthetic",
                            provenance="Explicitly synthetic scheduled enrichment acceptance",
                        ),
                        schedule=dict(
                            kind="interval",
                            seconds=3600,
                            anchor=(
                                datetime.now(timezone.utc) + timedelta(seconds=1)
                            ).isoformat(),
                            offset_seconds=0,
                        ),
                        bundle_root=str(bundles),
                        synthetic_input=str(fixture),
                        allow_network=False,
                        parameters=dict(limit=1),
                    )
                ],
            )
        )
    )
    config.chmod(0o600)
    from app.services.operations_api import create_service
    from standalone.operations.notifications import load as notices

    service = None
    try:
        service = create_service(tmp_path, config, key)
        service.request_mode("running")
        deadline = time.monotonic() + 30
        batch = None
        while time.monotonic() < deadline:
            current = service.status()
            with local_database().connect() as conn, conn.cursor() as cursor:
                cursor.execute(
                    "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s AND event->>'kind'='enrichment_batch'",
                    (key,),
                )
                row = cursor.fetchone()
                batch = None if row is None else row[0]
            if (
                batch is not None
                and not current["inputs"][0]["active"]
                and not current["recovery_required"]
            ):
                break
            time.sleep(0.1)
        assert batch is not None and not current["inputs"][0]["active"], current
        assert current["inputs"][0]["latest_success"] is (not invalid), current
        assert len(batch["request_ids"]) == 1
        selected = batch["request_ids"][0]
        assert worker.status(selected)["state"] == (
            "invalid" if invalid else "succeeded"
        )
        assert all(
            worker.status(request)["state"] == "queued"
            for request in requests
            if request != selected
        )
        observed_notices = notices(key)
        if invalid:
            assert len(observed_notices) == 1
            notice = observed_notices[0]
            assert notice["category"] == "collection-failure"
            assert notice["status"] == "unresolved"
            assert notice["urgency"] == "critical"
            assert notice["parameters"]["api"] == "NVD"
        else:
            assert observed_notices == []
        service.request_mode("off")
        service.close(timeout=5)
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        assert service.status()["inputs"][0]["latest_success"] is (not invalid)
        assert notices(key) == observed_notices
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


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("provider", ["NVD", "MSRC", "CVE", "CISA"])
def test_bounded_processor_commits_queryable_evidence_and_replays(
    tmp_path, committed_input, provider
):
    child, cves = committed_input
    ids = worker.discover_attempt(child.execution_id, sources=[provider])
    assert len(ids) == 2
    fixtures = fixtures_for(ids)
    root = tmp_path / "bundles"
    assert (
        worker.process_pending(
            root,
            synthetic_inputs=fixtures,
            sources=["CVE" if provider != "CVE" else "NVD"],
        )
        == []
    )
    assert all(worker.status(key)["state"] == "queued" for key in ids)
    first = worker.process_pending(
        root, limit=1, synthetic_inputs=fixtures, request_ids=[ids[1]]
    )
    assert len(first) == 1 and first[0]["state"] == "succeeded"
    assert first[0]["request_id"] == ids[1]
    assert worker.status(ids[0])["state"] == "queued"
    assert worker.process_pending(root, synthetic_inputs=fixtures, request_ids=[]) == []
    second = worker.process_pending(root, limit=1, synthetic_inputs=fixtures)
    assert len(second) == 1 and second[0]["state"] == "succeeded"
    assert worker.process_pending(root, synthetic_inputs=fixtures) == []
    assert worker.discover_attempt(child.execution_id, sources=[provider]) == []
    for request in ids:
        assert worker.replay_request(root, request)["state"] == "succeeded"
    from app.services.postgres_query import PostgreSQLQueries

    query = (
        "SELECT cve_id,state,origin FROM evidence_pipeline.enrichment_request_status WHERE id IN ("
        + ",".join("'" + key + "'::uuid" for key in ids)
        + ") ORDER BY cve_id"
    )
    result = json.loads(
        PostgreSQLQueries().execute({"requestId": str(uuid4()), "sql": query})
    )
    assert result["rows"] == [[cve, "succeeded", "synthetic"] for cve in sorted(cves)]
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[])",
            (ids,),
        )
        assert cur.fetchone() == (2,)
        cur.execute(
            "SELECT c.source_name,rev.source_record_id,rev.origin FROM evidence.observation_receipts r "
            "JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id "
            "JOIN evidence.source_connections c ON c.id=rev.connection_id "
            "WHERE c.id=ANY(%s::uuid[]) ORDER BY rev.source_record_id",
            (ids,),
        )
        assert cur.fetchall() == [(provider, cve, "synthetic") for cve in sorted(cves)]


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_concurrent_discovery_and_processing_share_one_execution(
    tmp_path, committed_input, monkeypatch
):
    from standalone.evidence_pipeline.persistence import enrichment_store

    child, _ = committed_input
    barrier = Barrier(2)
    original = enrichment_store.execute_values

    def synchronized_insert(*args, **kwargs):
        barrier.wait(timeout=10)
        return original(*args, **kwargs)

    monkeypatch.setattr(enrichment_store, "execute_values", synchronized_insert)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda _: worker.discover_attempt(child.execution_id, sources=["NVD"]),
                range(2),
            )
        )
    ids = [key for result in outcomes for key in result]
    assert len(ids) == len(set(ids)) == 2
    fixtures = fixtures_for(ids)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda _: worker.process_pending(
                    tmp_path / "bundles", synthetic_inputs=fixtures
                ),
                range(2),
            )
        )
    assert all(
        row["state"] != "unconfirmed" for result in outcomes for row in result
    ), outcomes
    assert all(worker.status(key)["state"] == "succeeded" for key in ids)
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[])",
            (ids,),
        )
        assert cur.fetchone() == (2,)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_failed_response_stays_visible_without_automatic_retry(
    tmp_path, committed_input
):
    child, _ = committed_input
    ids = worker.discover_attempt(child.execution_id, sources=["NVD"])
    fixtures = fixtures_for(ids)
    fixtures[ids[0]] = b"Explicitly synthetic malformed JSON"
    root = tmp_path / "bundles"
    results = worker.process_pending(root, synthetic_inputs=fixtures)
    assert {row["state"] for row in results} == {"invalid", "succeeded"}
    assert worker.status(ids[0])["error_code"] == "invalid_public_payload"
    assert worker.process_pending(root, synthetic_inputs=fixtures) == []
    assert worker.replay_request(root, ids[0])["state"] == "invalid"
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[])",
            (ids,),
        )
        assert cur.fetchone() == (2,)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("committed", [False, True])
def test_interrupted_import_replays_the_same_attempt(
    tmp_path, committed_input, monkeypatch, committed
):
    child, _ = committed_input
    ids = worker.discover_attempt(child.execution_id, sources=["NVD"])
    original = worker.ingest_public
    calls = []

    def lost_ack(value):
        calls.append(value.execution_id)
        if len(calls) == 1:
            if committed:
                original(value)
            raise OSError("Synthetic interruption around commit")
        return original(value)

    monkeypatch.setattr(worker, "ingest_public", lost_ack)
    root = tmp_path / "bundles"
    results = worker.process_pending(root, synthetic_inputs=fixtures_for(ids))
    assert {row["state"] for row in results} == {"unconfirmed", "succeeded"}
    assert {worker.status(key)["state"] for key in ids} == (
        {"succeeded"} if committed else {"started", "succeeded"}
    )
    monkeypatch.setattr(worker, "ingest_public", original)
    for key in ids:
        assert worker.replay_request(root, key)["state"] == "succeeded"
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[])",
            (ids,),
        )
        assert cur.fetchone() == (2,)


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"limit": 0, "allow_network": True},
        {"limit": True, "allow_network": True},
        {"allow_network": "yes"},
        {"allow_network": True, "synthetic_inputs": {"bad": b"x"}},
        {"synthetic_inputs": {"bad": b"x"}},
        {"allow_network": True, "sources": []},
        {"allow_network": True, "sources": [["NVD"]]},
        {"allow_network": True, "sources": ["NVD", "NVD"]},
    ],
)
def test_invalid_execution_options_have_no_side_effects(tmp_path, options):
    root = tmp_path / "must-not-exist"
    with pytest.raises(ValueError):
        worker.process_pending(root, **options)
    assert not root.exists()


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("discovery_outage", [False, True])
def test_finding_import_queues_only_after_commit_and_preserves_success(
    tmp_path, committed_input, monkeypatch, discovery_outage
):
    from dataclasses import replace
    from datetime import timedelta
    from .commands import ingest_exposure

    child, _ = committed_input
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT device_attempt_id::text FROM evidence_pipeline.exposure_snapshots WHERE collection_attempt_id=%s",
            (child.execution_id,),
        )
        device_attempt = cur.fetchone()[0]
    failure = replace(
        child,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="synthetic_failure",
    )
    assert ingest_exposure(failure, device_attempt)["outcome"] == "failure"
    original = worker.discover_attempt
    if discovery_outage:

        def unavailable(*args, **kwargs):
            raise OSError("Synthetic queue connection failure")

        monkeypatch.setattr(worker, "discover_attempt", unavailable)
    new = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(seconds=1),
    )
    result = ingest_exposure(new, device_attempt)
    assert result["outcome"] == "success" and not result["replayed"]
    assert result["enrichment"]["state"] == (
        "unconfirmed" if discovery_outage else "checked"
    )
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.enrichment_causes WHERE collection_attempt_id=%s",
            (failure.execution_id,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerability_findings f JOIN evidence.observation_receipts r ON r.id=f.receipt_id WHERE r.collection_attempt_id=%s",
            (new.execution_id,),
        )
        assert cur.fetchone() == (3,)
    monkeypatch.setattr(worker, "discover_attempt", original)
    again = ingest_exposure(new, device_attempt)
    assert again["replayed"]
    assert again["enrichment"]["queued"] == (8 if discovery_outage else 0)
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.enrichment_requests WHERE cause_receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (new.execution_id,),
        )
        assert cur.fetchone() == (8,)
        cur.execute(
            "SELECT id::text FROM evidence_pipeline.enrichment_requests WHERE source_name='NVD' AND cause_receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (new.execution_id,),
        )
        ids = [row[0] for row in cur.fetchall()]
    completed = worker.process_pending(
        tmp_path / "automatic", synthetic_inputs=fixtures_for(ids)
    )
    assert len(completed) == 2 and all(row["state"] == "succeeded" for row in completed)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_busy_source_slot_leaves_requests_unclaimed(
    tmp_path, committed_input, monkeypatch
):
    child, _ = committed_input
    ids = worker.discover_attempt(child.execution_id, sources=["NVD"])
    fixtures = fixtures_for(ids)
    original = worker.paced

    def occupied(*args, **kwargs):
        raise worker.PublicSourceBusy("Synthetic occupied request slot")

    monkeypatch.setattr(worker, "paced", occupied)
    root = tmp_path / "bundles"
    results = worker.process_pending(root, synthetic_inputs=fixtures)
    assert len(results) == 2 and all(row["state"] == "deferred" for row in results)
    assert all(worker.status(key)["state"] == "queued" for key in ids)
    assert list(root.iterdir()) == []
    monkeypatch.setattr(worker, "paced", original)
    results = worker.process_pending(root, synthetic_inputs=fixtures)
    assert all(row["state"] == "succeeded" for row in results)
