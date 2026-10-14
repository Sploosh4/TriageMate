"""Repository failure episodes commit atomically, deduplicate and retain history."""

from contextlib import closing
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import local_database
from .dispatch import Definition, Dispatcher
from .lifecycle import Mode
from .notifications import load
from .repository_proof import ScheduledRepository
from .repository_recipe import SOURCE_URLS
from .scheduling import Interval
from .supervisor import PostgresRepository
from .test_dispatch import at
from .enrichment_batch import ScheduledEnrichment
from standalone.evidence_pipeline.persistence.enrichment_store import (
    SOURCES as ENRICHMENT_SOURCES,
)


@pytest.mark.parametrize(
    "source,enrichment",
    [(source, False) for source in SOURCE_URLS]
    + [(source, True) for source in ENRICHMENT_SOURCES],
)
def test_failed_repeated_and_recovered_runs_preserve_one_episode(
    tmp_path, source, enrichment
):
    input_id, key = str(uuid4()), "synthetic-failure-" + str(uuid4())
    binding = (
        ScheduledEnrichment(input_id, "a" * 64, source, "synthetic")
        if enrichment
        else ScheduledRepository(
            input_id,
            "a" * 64,
            source,
            "synthetic",
            tmp_path,
            "KB9999991" if source == "Microsoft Update Catalog" else None,
        )
    )
    repository = PostgresRepository(
        key, **{("enrichment_proofs" if enrichment else "repository_proofs"): [binding]}
    )
    state = Dispatcher(
        [Definition(input_id, Interval(60, at(0)), worker_contract="a" * 64)], now=at(0)
    )
    revision = repository.commit(0, state)
    state.request_mode(Mode.RUNNING, at(0))
    revision = repository.commit(revision, state)
    try:
        notice_id = None
        runs = []
        for index, success in enumerate([False, False, True], 1):
            job = state.tick(at(index * 60)).start[0]
            runs.append(job.run_id)
            revision = repository.commit(revision, state)
            state.finished(
                job.run_id,
                success=success,
                snapshot_id=job.run_id if success else None,
                now=at(index * 60 + 1),
            )
            revision = repository.commit(revision, state)
            notices = load(key)
            assert len(notices) == 1
            record = notices[0]
            assert record["urgency"] == "critical" and record["synthetic"]
            assert record["category"] == "collection-failure"
            if source == "Microsoft Update Catalog":
                assert record["details"]["kb"] == "KB9999991"
            if source == "Cisco":
                assert record["message"] == "Cisco RSS collection failed"
                assert record["details"]["source"] == "Cisco"
            if enrichment:
                assert record["message"] == source + " enrichment collection failed"
                assert (
                    record["parameters"]["organisation"]
                    == "triagemate:enrichment/" + source
                )
            assert record["status"] == ("resolved" if success else "unresolved")
            assert record["details"]["failure_count"] == min(index, 2)
            if notice_id is not None:
                assert record["id"] == notice_id
            notice_id = record["id"]
            revision = repository.commit(revision, state)
            assert load(key) == notices  # Repeated checkpoint is not another failure.
        with closing(local_database().connect()) as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s ORDER BY id",
                (key,),
            )
            history = [row[0] for row in cursor.fetchall()]
        assert [row["status"] for row in history] == [
            "unresolved",
            "unresolved",
            "resolved",
        ]
        assert history[0]["failed_run_id"] == runs[0]
        assert history[-1]["failed_run_id"] == runs[1]
        assert history[-1]["recovery_run_id"] == runs[2]
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


@pytest.mark.parametrize("enrichment", [False, True])
def test_planned_shutdown_does_not_open_failure(tmp_path, enrichment):
    from unittest.mock import Mock
    from copy import deepcopy
    from .repository_failures import record

    input_id = str(uuid4())
    before = Dispatcher(
        [Definition(input_id, Interval(60, at(0)), worker_contract="a" * 64)], now=at(0)
    )
    before.request_mode(Mode.RUNNING, at(0))
    job = before.tick(at(60)).start[0]
    before.request_mode(Mode.MAINTENANCE, at(61))
    after = deepcopy(before)
    after.finished(job.run_id, success=False, now=at(62))
    cursor = Mock()
    record(
        cursor,
        "synthetic",
        3,
        before,
        after,
        {input_id: dict(source="CVE" if enrichment else "Red Hat", origin="synthetic")},
        enrichment=enrichment,
    )
    cursor.execute.assert_not_called()


def test_failure_notice_rolls_back_with_completion_checkpoint(tmp_path):
    from . import store

    input_id, key = str(uuid4()), "synthetic-failure-rollback-" + str(uuid4())
    binding = ScheduledRepository(input_id, "a" * 64, "Red Hat", "synthetic", tmp_path)
    repository = PostgresRepository(key, repository_proofs=[binding])
    state = Dispatcher(
        [Definition(input_id, Interval(60, at(0)), worker_contract="a" * 64)], now=at(0)
    )
    state.request_mode(Mode.RUNNING, at(0))
    job = state.tick(at(60)).start[0]
    revision = repository.commit(0, state)
    try:
        state.finished(job.run_id, success=False, now=at(61))
        with closing(local_database().connect()) as conn, conn.cursor() as cursor:
            store.save(
                cursor,
                key,
                revision,
                state,
                repository_sources={
                    input_id: dict(source="Red Hat", origin="synthetic")
                },
            )
            cursor.execute(
                "SELECT count(*) FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            assert cursor.fetchone() == (1,)
            assert load(key) == []  # Another connection cannot see uncommitted failure.
            conn.rollback()
        assert load(key) == []
        assert repository.load()[1].inputs[input_id].active == job
        repository.commit(revision, state)
        assert load(key)[0]["urgency"] == "critical"
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
