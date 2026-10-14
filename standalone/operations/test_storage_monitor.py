"""Configured storage measurements, deduplicated notices and failure visibility."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.test_store import db as database_fixture
from .storage_monitor import StoragePolicy, StorageMonitor, measure
from .storage_usage import Usage
from .notifications import load, project
from .test_dispatch import NOW
from .test_configuration import configuration, save
from .configuration import load as load_configuration

db = database_fixture


@pytest.mark.parametrize(
    "damage", [None, "relative", "root", "duplicate", "zero", "boolean", "extra"]
)
def test_storage_configuration_requires_explicit_bounded_policy(tmp_path, damage):
    document = configuration(tmp_path)
    value = dict(directories=[str(tmp_path)], maximum_bytes=1024)
    if damage == "relative":
        value["directories"] = ["relative"]
    if damage == "root":
        value["directories"] = ["/"]
    if damage == "duplicate":
        value["directories"] *= 2
    if damage == "zero":
        value["maximum_bytes"] = 0
    if damage == "boolean":
        value["maximum_bytes"] = True
    if damage == "extra":
        value["delete"] = True
    document["storage"] = value
    if damage:
        with pytest.raises(ValueError):
            load_configuration(save(tmp_path, document), now=NOW)
    else:
        policy = load_configuration(save(tmp_path, document), now=NOW).storage_policy
        assert policy == StoragePolicy((tmp_path,), 1024)


def test_database_failure_is_unknown_and_does_not_abort_transaction(db, tmp_path):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        result = measure(
            cur, StoragePolicy((tmp_path,), 1024), sampler=lambda _: Usage(1, 1, ())
        )
        assert result["condition"] == "unknown"
        assert result["database_bytes"] is None
        assert result["incomplete_reasons"] == ["database_unavailable"]
        cur.execute("SELECT 1")
        assert cur.fetchone() == (1,)


def test_partial_known_usage_can_still_exceed_allowance(db, tmp_path):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        result = measure(
            cur,
            StoragePolicy((tmp_path,), 1),
            sampler=lambda _: Usage(10, 1, ("entry_budget",)),
        )
        assert result["condition"] == "over_limit"
        assert result["known_bytes"] >= 10 and result["database_bytes"] > 0


def test_monitor_persists_one_episode_and_resolves_under_new_allowance(tmp_path):
    from .dispatch import Dispatcher
    from .supervisor import PostgresRepository

    key = "synthetic-storage-test-" + str(uuid4())
    ticks = [0]
    policy = StoragePolicy((tmp_path,), 1)
    monitor = StorageMonitor(key, policy, clock=lambda: ticks[0])
    try:
        PostgresRepository(key).commit(0, Dispatcher([], now=NOW))
        monitor.check(NOW)
        first = load(key)
        assert len(first) == 1 and first[0]["category"] == "storage-pressure"
        assert first[0]["status"] == "unresolved"
        ticks[0] += 61
        monitor.check(NOW + timedelta(seconds=61))
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            event = cur.fetchone()[0]
        bad = dict(event, known_bytes=event["known_bytes"] + 1)
        with pytest.raises(ValueError):
            project(key, bad, None, None, None, None)
        monitor.policy = replace(policy, maximum_bytes=2**63 - 1)
        ticks[0] += 61
        monitor.check(NOW + timedelta(seconds=122))
        result = load(key)
        assert len(result) == 1 and result[0]["id"] == first[0]["id"]
        assert result[0]["status"] == "resolved"
        assert "Nothing was deleted" in result[0]["details"]["interpretation"]
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )


def test_disabled_monitor_does_not_access_database():
    def unexpected():
        pytest.fail("Disabled storage monitoring opened the database")

    StorageMonitor("synthetic-disabled", None, connector=unexpected).check(NOW)


def test_application_hosts_storage_monitor_only_while_running(tmp_path):
    from .lifecycle import Mode

    from app.services.operations_api import create_service

    key = "synthetic-storage-app-" + str(uuid4())
    document = dict(
        version=1,
        concurrency=1,
        grace_seconds=0,
        inputs=[],
        storage=dict(directories=[str(tmp_path)], maximum_bytes=1),
    )
    service = None
    try:
        service = create_service(tmp_path, save(tmp_path, document), key)
        service.tick()
        assert load(key) == []
        service.request_mode(Mode.RUNNING)
        service.tick()
        assert load(key)[0]["category"] == "storage-pressure"
        service.request_mode(Mode.OFF)
        service.storage_monitor.checked = float("-inf")
        service.storage_monitor.sampler = lambda _: pytest.fail(
            "Off service sampled storage"
        )
        service.tick()
        assert not service.fault
    finally:
        if service is not None:
            service.close()
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
