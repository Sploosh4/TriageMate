"""Dispatch acceptance covers overlap, dependency failure and maintenance timing."""

from datetime import datetime, timedelta, timezone

import pytest

from .dispatch import Definition, Dispatcher
from .lifecycle import Mode
from .scheduling import Interval

NOW = datetime(2099, 9, 23, tzinfo=timezone.utc)


def at(seconds):
    return NOW + timedelta(seconds=seconds)


def dispatcher(*definitions, concurrency=1):
    result = Dispatcher(
        definitions or [Definition("input", Interval(600, NOW))],
        now=NOW,
        concurrency=concurrency,
    )
    result.request_mode(Mode.RUNNING, NOW)
    return result


def test_overlap_opens_at_two_configured_skips_and_resolves_only_after_later_success():
    worker = dispatcher()
    (original,) = worker.tick(at(600)).start
    assert worker.tick(at(1200)).notices == ()
    actions = worker.tick(at(1800))
    assert not actions.start
    (opened,) = actions.notices
    assert (opened.kind, opened.skipped_count, opened.original_run_id) == (
        "overlap_opened",
        2,
        original.run_id,
    )
    assert worker.tick(at(1800)).notices == ()
    (updated,) = worker.tick(at(2400)).notices
    assert (updated.kind, updated.skipped_count) == ("overlap_updated", 3)
    worker.finished(
        original.run_id, success=True, snapshot_id="committed-original", now=at(2401)
    )
    assert worker.tick(at(2401)).notices == ()
    (later,) = worker.tick(at(3000)).start
    worker.finished(later.run_id, success=False, now=at(3001))
    assert worker.tick(at(3001)).notices == ()
    (recovery,) = worker.tick(at(3600)).start
    worker.finished(
        recovery.run_id, success=True, snapshot_id="committed-recovery", now=at(3601)
    )
    (resolved,) = worker.tick(at(3601)).notices
    assert (resolved.kind, resolved.skipped_count) == ("overlap_resolved", 3)


def test_completion_between_ticks_still_accounts_for_overlaps():
    worker = dispatcher()
    (original,) = worker.tick(at(600)).start
    worker.finished(
        original.run_id, success=True, snapshot_id="committed", now=at(1801)
    )
    (notice,) = worker.tick(at(1801)).notices
    assert notice.kind == "overlap_opened" and notice.skipped_count == 2


def test_capacity_backlog_is_bounded_and_is_not_mislabelled_overlap():
    worker = dispatcher(
        Definition("a", Interval(60, NOW)), Definition("b", Interval(60, NOW))
    )
    (first,) = worker.tick(at(60)).start
    assert first.input_id == "a"
    assert not worker.tick(at(120)).start
    assert worker.inputs["b"].missed_count == 1
    worker.finished(first.run_id, success=True, snapshot_id="a-snapshot", now=at(121))
    (second,) = worker.tick(at(121)).start
    assert second.input_id == "b" and second.scheduled_at == at(120)
    assert worker.inputs["b"].overlap_run is None


def test_failed_prerequisite_waits_without_falling_back_to_previous_snapshot():
    worker = dispatcher(
        Definition("devices", Interval(60, NOW)),
        Definition("software", Interval(60, NOW), ("devices",)),
        concurrency=2,
    )
    (parent,) = worker.tick(at(60)).start
    worker.finished(
        parent.run_id, success=True, snapshot_id="devices-first", now=at(61)
    )
    (child,) = worker.tick(at(61)).start
    assert child.prerequisite_snapshots == (("devices", "devices-first"),)
    worker.finished(
        child.run_id, success=True, snapshot_id="software-first", now=at(62)
    )
    (parent,) = worker.tick(at(120)).start
    worker.finished(parent.run_id, success=False, now=at(121))
    assert worker.tick(at(121)).start == ()
    assert worker.inputs["software"].pending == at(120)
    (parent,) = worker.tick(at(180)).start
    worker.finished(parent.run_id, success=True, snapshot_id="devices-new", now=at(181))
    (child,) = worker.tick(at(181)).start
    assert child.prerequisite_snapshots == (("devices", "devices-new"),)


def test_maintenance_drops_queued_work_suppresses_expected_skips_and_keeps_stagger():
    worker = dispatcher(
        Definition("a", Interval(60, NOW, 5)), Definition("b", Interval(60, NOW, 15))
    )
    (first,) = worker.tick(at(5)).start
    worker.request_mode(Mode.MAINTENANCE, at(10))
    assert worker.tick(at(69)).cancel == ()
    assert worker.tick(at(70)).cancel == (first.run_id,)
    assert worker.control.state == "draining"
    worker.finished(first.run_id, success=False, now=at(71))
    assert worker.control.state == "maintenance"
    assert worker.tick(at(300)).notices == ()
    worker.request_mode(Mode.RUNNING, at(300))
    assert worker.tick(at(300)).start == ()
    (next_job,) = worker.tick(at(305)).start
    assert next_job.input_id == "a"
    assert worker.inputs["b"].pending is None


@pytest.mark.parametrize(
    "definitions",
    [
        [Definition("a", Interval(60, NOW), ("missing",))],
        [
            Definition("a", Interval(60, NOW), ("b",)),
            Definition("b", Interval(60, NOW), ("a",)),
        ],
        [Definition("a", Interval(60, NOW)), Definition("a", Interval(60, NOW))],
    ],
)
def test_invalid_dependency_configuration_fails_before_dispatch(definitions):
    with pytest.raises(ValueError):
        dispatcher(*definitions)


def test_completion_requires_known_worker_and_committed_snapshot_identity():
    worker = dispatcher()
    (job,) = worker.tick(at(600)).start
    for run_id, success, snapshot in [
        ("unknown", True, "snapshot"),
        (job.run_id, True, None),
        (job.run_id, False, "not-a-committed-snapshot"),
    ]:
        with pytest.raises(ValueError):
            worker.finished(run_id, success=success, snapshot_id=snapshot, now=at(601))
    assert worker.inputs["input"].active == job
