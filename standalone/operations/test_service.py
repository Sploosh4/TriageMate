"""Service controls and fault recovery preserve committed intent and live workers."""

from threading import Event

import pytest

from .service import Service
from .lifecycle import Mode
from .test_dispatch import dispatcher, at
from .test_supervisor import Repository, Handle


class Workers:
    def __init__(self, repository):
        self.repository = repository
        self.handles = {}
        self.closed = False
        self.started = Event()

    def __call__(self, job):
        assert job.run_id in self.repository.saved["control"]["active"]
        handle = Handle()
        self.handles[job.run_id] = handle
        self.started.set()
        return handle

    def recover(self, job):
        # A known live process remains live after a checkpoint fault.
        return self.handles[job.run_id]

    def close(self):
        self.closed = True


def setup():
    repository = Repository()
    workers = Workers(repository)
    clock = [at(0)]
    service = Service(
        repository, dispatcher(), workers, clock=lambda: clock[0], poll_seconds=0.01
    )
    return repository, workers, clock, service


def test_provider_monitor_only_runs_while_collecting():
    from unittest.mock import Mock

    _, _, _, service = setup()
    monitor = Mock()
    service.provider_monitor = monitor
    service.tick()
    assert monitor.check.call_count == 1
    service.request_mode(Mode.MAINTENANCE)
    service.tick()
    assert monitor.check.call_count == 1
    service.request_mode(Mode.OFF)
    service.tick()
    assert monitor.check.call_count == 1


def test_off_keeps_controls_available_and_drain_waits_for_worker_exit():
    repository, workers, clock, service = setup()
    clock[0] = at(600)
    service.tick()
    ((run, handle),) = workers.handles.items()
    assert service.status()["active"] == 1
    assert service.request_mode(Mode.OFF)["state"] == "draining"
    clock[0] = at(661)
    service.tick()
    assert handle.cancelled and service.status()["state"] == "draining"
    handle.exit_code = 1
    service.tick()
    assert service.status()["state"] == "off"
    assert service.status()["available"]
    assert service.request_mode(Mode.RUNNING)["state"] == "running"
    assert service.close() and workers.closed


def test_checkpoint_failure_recovers_live_handle_without_duplicate_launch():
    repository, workers, clock, service = setup()
    clock[0] = at(600)
    service.tick()
    assert len(workers.handles) == 1
    repository.fail = True
    with pytest.raises(ConnectionError):
        service.request_mode(Mode.MAINTENANCE)
    assert service.status()["state"] == "recovering"
    with pytest.raises(ValueError, match="recovering"):
        service.request_mode(Mode.OFF)
    repository.fail = False
    service.tick()
    assert not service.status()["recovery_required"]
    assert service.status()["state"] == "running" and len(workers.handles) == 1
    assert not service.close(timeout=0) and not workers.closed
    next(iter(workers.handles.values())).exit_code = 1
    assert service.close() and workers.closed


def test_backward_wall_clock_does_not_fault_or_repeat_slots():
    _, workers, clock, service = setup()
    clock[0] = at(600)
    service.tick()
    clock[0] = at(500)
    service.tick()
    assert not service.status()["recovery_required"] and len(workers.handles) == 1


def test_background_loop_runs_and_shutdown_is_idempotent():
    _, workers, clock, service = setup()
    clock[0] = at(600)
    service.start()
    service.start()
    try:
        assert workers.started.wait(2)
        next(iter(workers.handles.values())).exit_code = 1
        assert service.close(timeout=2)
        assert service.close(timeout=0)
        assert not service.status()["available"]
        with pytest.raises(ValueError, match="shutting down"):
            service.request_mode(Mode.RUNNING)
    finally:
        for handle in workers.handles.values():
            handle.exit_code = 1
        service.close(timeout=2)


def test_changed_configuration_cannot_replace_saved_schedule():
    repository, workers, _, service = setup()
    different = dispatcher()
    different.definitions = {}
    with pytest.raises(ValueError, match="Stop collection"):
        Service(repository, different, workers, clock=lambda: at(0))
    assert service.close()
    replacement = Service(repository, different, workers, clock=lambda: at(0))
    assert replacement.status()["configured_inputs"] == 0
    assert replacement.status()["state"] == "off"


@pytest.mark.parametrize(
    "cadence,next_due", [("minute", 1020), ("three_minutes", 1080), ("daily", 1020)]
)
def test_stopped_cadence_change_preserves_evidence_and_uses_new_due_time(
    cadence, next_due
):
    from .dispatch import Definition
    from .scheduling import Daily, Interval

    repository, workers, clock, service = setup()
    clock[0] = at(600)
    service.tick()
    ((run, handle),) = workers.handles.items()
    repository.snapshots[run] = "synthetic-committed-before-change"
    handle.exit_code = 0
    clock[0] = at(601)
    service.tick()
    assert service.close()

    schedule = {
        "minute": Interval(60, at(0)),
        "three_minutes": Interval(180, at(0)),
        "daily": Daily(8, 17),
    }[cadence]
    clock[0] = at(1000)
    new_workers = Workers(repository)
    replacement = Service(
        repository,
        dispatcher(Definition("input", schedule)),
        new_workers,
        clock=lambda: clock[0],
    )
    try:
        assert replacement.status()["state"] == "off"
        assert (
            replacement.status()["inputs"][0]["latest_snapshot"]
            == repository.snapshots[run]
        )
        replacement.tick()
        assert not new_workers.handles
        replacement.request_mode(Mode.RUNNING)
        clock[0] = at(next_due - 1)
        replacement.tick()
        assert not new_workers.handles
        clock[0] = at(next_due)
        replacement.tick()
        assert len(new_workers.handles) == 1
        job = replacement.supervisor.state.inputs["input"].active
        assert job.scheduled_at == at(next_due)
        replacement.tick()
        assert len(new_workers.handles) == 1
    finally:
        for handle in new_workers.handles.values():
            handle.exit_code = 1
        replacement.close(timeout=2)


def test_status_remains_available_during_database_wait(monkeypatch):
    _, _, _, service = setup()
    entered, release = Event(), Event()

    def stalled(now):
        entered.set()
        assert release.wait(2)

    monkeypatch.setattr(service.supervisor, "tick", stalled)
    service.start()
    try:
        assert entered.wait(1)
        assert service.status()["available"]
        with pytest.raises(ValueError, match="busy"):
            service.request_mode(Mode.OFF)
    finally:
        release.set()
        service.close(timeout=2)
