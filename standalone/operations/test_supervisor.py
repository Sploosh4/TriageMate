"""Worker effects must follow committed intent, including on failure paths."""

import pytest

from .checkpoint import decode, encode
from .lifecycle import Mode
from .store import CheckpointConflict
from .supervisor import Supervisor
from .test_dispatch import dispatcher, at


class Repository:
    def __init__(self):
        self.saved = None
        self.revision = 0
        self.commits = 0
        self.fail = False
        self.snapshots = {}

    def load(self):
        return None if self.saved is None else (self.revision, decode(self.saved))

    def commit(self, expected, state, notices=()):
        if self.fail:
            raise ConnectionError("Synthetic commit acknowledgement failure")
        if expected != self.revision:
            raise CheckpointConflict("Synthetic concurrent update")
        self.saved = encode(state)
        self.revision += 1
        self.commits += 1
        return self.revision

    def committed_snapshot(self, job):
        return self.snapshots.get(job.run_id)


class Handle:
    def __init__(self):
        self.exit_code = None
        self.cancelled = False

    def poll(self):
        return self.exit_code

    def cancel(self):
        self.cancelled = True


def setup():
    repository = Repository()
    started = []

    def launch(job):
        assert job.run_id in repository.saved["control"]["active"]
        handle = Handle()
        started.append((job, handle))
        return handle

    supervisor = Supervisor(repository, dispatcher(), launch)
    return repository, supervisor, started


def test_start_follows_committed_intent_and_exit_code_does_not_prove_success():
    repository, supervisor, started = setup()
    supervisor.tick(at(600))
    job, handle = started[0]
    handle.exit_code = 0  # A successful process exit alone is insufficient.
    supervisor.tick(at(601))
    assert not supervisor.state.inputs["input"].latest_success
    assert supervisor.state.inputs["input"].latest_snapshot is None
    assert job.run_id not in supervisor.state.control.active
    supervisor.tick(at(1200))
    job, handle = started[1]
    repository.snapshots[job.run_id] = job.run_id
    handle.exit_code = 1  # A post-commit process error cannot erase committed evidence.
    supervisor.tick(at(1201))
    assert supervisor.state.inputs["input"].latest_success
    assert supervisor.state.inputs["input"].latest_snapshot == job.run_id


@pytest.mark.parametrize("failure", ["connection", "conflict"])
def test_uncertain_or_conflicting_commit_never_starts_worker(failure):
    repository, supervisor, started = setup()
    if failure == "connection":
        repository.fail = True
    else:
        repository.revision += 1
    with pytest.raises((ConnectionError, CheckpointConflict)):
        supervisor.tick(at(600))
    assert started == []
    assert supervisor.needs_recovery
    with pytest.raises(ValueError, match="recovery"):
        supervisor.tick(at(601))


def test_failed_launch_preserves_durable_intent_without_retrying():
    repository, supervisor, _ = setup()
    attempts = []

    def failing(job):
        attempts.append(job)
        raise OSError("Synthetic launch failure")

    supervisor.start_worker = failing
    with pytest.raises(OSError):
        supervisor.tick(at(600))
    assert len(attempts) == 1
    assert attempts[0].run_id in repository.saved["control"]["active"]
    with pytest.raises(ValueError, match="recovery"):
        supervisor.tick(at(601))
    assert len(attempts) == 1


def test_pause_cancellation_is_persisted_and_waits_for_exit():
    repository, supervisor, started = setup()
    supervisor.tick(at(600))
    job, handle = started[0]

    def cancel():
        assert job.run_id in repository.saved["control"]["cancel_requested"]
        handle.cancelled = True

    handle.cancel = cancel
    supervisor.request_mode(Mode.OFF, at(601))
    supervisor.tick(at(660))
    assert not handle.cancelled
    supervisor.tick(at(661))
    assert handle.cancelled and supervisor.state.control.state == "draining"
    handle.exit_code = -15
    supervisor.tick(at(662))
    assert supervisor.state.control.state == "off"


def test_restart_does_not_assume_a_persisted_active_worker_is_dead():
    repository, first, started = setup()
    first.tick(at(600))
    relaunched = []
    restored = Supervisor(repository, dispatcher(), lambda job: relaunched.append(job))
    assert restored.needs_recovery
    with pytest.raises(ValueError, match="recovery"):
        restored.tick(at(1200))
    assert relaunched == []
    assert len(started) == 1


def test_idle_polls_do_not_rewrite_the_checkpoint_document():
    repository, supervisor, started = setup()
    initial = repository.commits
    for second in range(1, 100):
        supervisor.tick(at(second))
    assert repository.commits == initial and not started
    supervisor.tick(at(600))
    assert repository.commits == initial + 1 and len(started) == 1
