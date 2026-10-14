"""Configured timeliness alerts preserve maintenance and committed-success boundaries."""

from contextlib import closing
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import local_database
from .checkpoint import encode, decode
from .configuration import load as configure
from .dispatch import Definition, Dispatcher
from .lifecycle import Mode
from .notifications import load
from .scheduling import Interval
from .supervisor import PostgresRepository
from .test_configuration import configuration, save
from .test_dispatch import NOW, at


def monitored():
    state = Dispatcher(
        [Definition("synthetic-input", Interval(10, NOW), overdue_after_seconds=25)],
        now=NOW,
    )
    state.request_mode(Mode.RUNNING, NOW)
    return state


def overdue(actions):
    return [notice for notice in actions.notices if notice.kind.startswith("overdue_")]


def test_never_successful_input_opens_once_and_failure_cannot_resolve():
    state = monitored()
    (job,) = state.tick(at(10)).start
    assert overdue(state.tick(at(24))) == []
    (opened,) = overdue(state.tick(at(25)))
    assert opened.kind == "overdue_opened" and opened.reference_at == NOW
    assert overdue(state.tick(at(40))) == []
    state.finished(job.run_id, success=False, now=at(41))
    assert overdue(state.tick(at(41))) == []
    (next_job,) = state.tick(at(50)).start
    state.finished(
        next_job.run_id, success=True, snapshot_id="synthetic-success", now=at(51)
    )
    (resolved,) = overdue(state.tick(at(51)))
    assert (
        resolved.kind == "overdue_resolved" and resolved.episode_id == opened.episode_id
    )
    assert resolved.reference_at == opened.reference_at
    assert state.inputs["synthetic-input"].last_success_at == at(51)


def test_planned_pause_suppresses_new_alerts_and_resume_gets_full_window():
    state = monitored()
    state.request_mode(Mode.MAINTENANCE, at(20))
    assert overdue(state.tick(at(5000))) == []
    state.request_mode(Mode.RUNNING, at(5000))
    assert overdue(state.tick(at(5024))) == []
    (notice,) = overdue(state.tick(at(5025)))
    assert notice.reference_at == at(5000)
    # Repeating Running cannot keep extending the deadline.
    state.request_mode(Mode.RUNNING, at(5026))
    assert state.inputs["synthetic-input"].monitor_since == at(5000)


def test_pending_episode_and_reference_survive_checkpoint_and_maintenance():
    state = monitored()
    state.tick(at(10))
    state.tick(at(25))
    encoded = encode(state)
    state = decode(encoded)
    assert encode(state) == encoded
    original = state.inputs["synthetic-input"].overdue_episode
    state.request_mode(Mode.OFF, at(26))
    state.request_mode(Mode.RUNNING, at(100))
    state = decode(encode(state))
    assert state.inputs["synthetic-input"].overdue_episode == original
    assert state.inputs["synthetic-input"].overdue_reference_at == NOW


def test_confirmation_after_deadline_records_open_and_resolved_together():
    state = monitored()
    (job,) = state.tick(at(10)).start
    state.finished(job.run_id, success=True, snapshot_id="synthetic-late", now=at(30))
    events = overdue(state.tick(at(30)))
    assert [value.kind for value in events] == ["overdue_opened", "overdue_resolved"]
    assert events[0].episode_id == events[1].episode_id


def test_configured_default_follows_interval_and_explicit_override(tmp_path):
    document = configuration(tmp_path)
    configured = configure(save(tmp_path, document), now=NOW)
    assert (
        next(iter(configured.state.definitions.values())).overdue_after_seconds == 7260
    )
    document["inputs"][0]["overdue_after_seconds"] = 120
    configured = configure(save(tmp_path, document), now=NOW)
    assert (
        next(iter(configured.state.definitions.values())).overdue_after_seconds == 120
    )


@pytest.mark.parametrize("value", [None, True, 0, -1, "30"])
def test_bad_configured_threshold_is_rejected(tmp_path, value):
    document = configuration(tmp_path)
    document["inputs"][0]["overdue_after_seconds"] = value
    with pytest.raises(ValueError):
        configure(save(tmp_path, document), now=NOW)


@pytest.mark.xdist_group("retained_evidence_schema")
def test_committed_overdue_episode_reaches_notification_channel_and_resolves():
    key = "synthetic-overdue-" + str(uuid4())
    state = monitored()
    repository = PostgresRepository(key)
    try:
        (job,) = state.tick(at(10)).start
        revision = repository.commit(0, state)
        actions = state.tick(at(25))
        assert load(key) == []
        revision = repository.commit(revision, state, actions.notices)
        records = [
            value for value in load(key) if value["category"] == "collection-overdue"
        ]
        assert len(records) == 1 and records[0]["status"] == "unresolved"
        assert "publisher's data age" in records[0]["details"]["interpretation"]
        restored = repository.load()[1]
        restored.finished(
            job.run_id, success=True, snapshot_id="synthetic-complete", now=at(26)
        )
        actions = restored.tick(at(26))
        repository.commit(revision, restored, actions.notices)
        [resolved] = [
            value for value in load(key) if value["category"] == "collection-overdue"
        ]
        assert resolved["id"] == records[0]["id"] and resolved["status"] == "resolved"
    finally:
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )


def test_policy_edit_does_not_rewrite_existing_episode_threshold():
    from dataclasses import replace

    state = monitored()
    (job,) = state.tick(at(10)).start
    (opened,) = overdue(state.tick(at(25)))
    state.request_mode(Mode.OFF, at(26))
    state.finished(job.run_id, success=False, now=at(27))
    state.definitions["synthetic-input"] = replace(
        state.definitions["synthetic-input"], overdue_after_seconds=100
    )
    state.request_mode(Mode.RUNNING, at(30))
    (job,) = state.tick(at(40)).start
    state.finished(
        job.run_id, success=True, snapshot_id="synthetic-recovery", now=at(41)
    )
    (resolved,) = overdue(state.tick(at(41)))
    assert resolved.episode_id == opened.episode_id
    assert resolved.reference_at == NOW and resolved.threshold_seconds == 25
