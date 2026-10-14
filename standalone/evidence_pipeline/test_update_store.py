"""Actual source-status persistence with replay, empty snapshots and rollback."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from .test_store import db, snapshot  # noqa: F401
from .test_update_schema import update_bound  # noqa: F401
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.store import ReplayConflict


def count_current(cur, child):
    view = (
        "current_missing_patches"
        if child.scope.source == "Defender"
        else "current_update_status"
    )
    cur.execute(
        f"SELECT count(*) FROM evidence_pipeline.{view} WHERE connection_id=%s",
        (child.scope.connection_id,),
    )
    return cur.fetchone()[0]


def test_update_ingestion_replay_failure_and_complete_empty(db, update_bound):  # noqa: F811
    device, child, _, _ = update_bound
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    first = persist_exposure(db, child, device.execution_id)
    assert first["records"] == 1 and not first["replayed"]
    assert persist_exposure(db, child, device.execution_id)["replayed"]
    with db.cursor() as cur:
        assert count_current(cur, child) == 1
    later = replace(
        child,
        execution_id=str(uuid4()),
        started_at=child.finished_at + timedelta(seconds=1),
        finished_at=child.finished_at + timedelta(seconds=2),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="synthetic_failure",
    )
    persist_exposure(db, later)
    with db.cursor() as cur:
        assert count_current(cur, child) == 1
    empty = replace(
        later,
        execution_id=str(uuid4()),
        outcome="success",
        complete=True,
        payload=b"[]",
        error_code=None,
        finished_at=later.finished_at + timedelta(seconds=1),
    )
    persist_exposure(db, empty, device.execution_id)
    with db.cursor() as cur:
        assert count_current(cur, child) == 0
        cur.execute(
            "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (child.execution_id,),
        )
        assert cur.fetchone()[0] == 1
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_update_unknown_device_attempt_does_not_leave_partial_rows(db, update_bound):  # noqa: F811
    _, child, _, _ = update_bound
    with pytest.raises(ValueError, match="complete snapshot"):
        persist_exposure(db, child, str(uuid4()))
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (child.execution_id,),
        )
        assert cur.fetchone()[0] == 0


def test_changed_execution_payload_is_a_conflict(db, update_bound):  # noqa: F811
    device, child, _, _ = update_bound
    persist_exposure(db, child, device.execution_id)
    with pytest.raises(ReplayConflict):
        persist_exposure(db, replace(child, payload=b"[]"), device.execution_id)
    with db.cursor() as cur:
        assert count_current(cur, child) == 1
