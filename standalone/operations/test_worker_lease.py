"""Real OS locks distinguish busy workers and fence delayed starts during recovery."""

import multiprocessing
from uuid import uuid4

import pytest

from .worker_lease import Lease, RecoveredHandle, paths, watch_cancellation
from .process_worker import PublicWorkers
from .supervisor import Supervisor
from .test_dispatch import dispatcher, at
from .test_supervisor import Repository


def leased_wait(root, run_id, ready):
    lease_path, _ = paths(root, run_id)
    with Lease(lease_path):
        stop, thread = watch_cancellation(root, run_id)
        ready.set()
        try:
            stop.wait(30)
        finally:
            stop.set()
            thread.join()


def test_live_worker_can_be_cancelled_without_guessing_a_pid(tmp_path):
    tmp_path.chmod(0o700)
    run_id = str(uuid4())
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    process = context.Process(target=leased_wait, args=(tmp_path, run_id, ready))
    handle = RecoveredHandle(tmp_path, run_id)
    process.start()
    try:
        assert ready.wait(5)
        assert handle.poll() is None
        handle.cancel()
        process.join(timeout=5)
        assert process.exitcode == 125
        assert handle.poll() == 0
        late = Lease(paths(tmp_path, run_id)[0])
        assert not late.acquire()  # Recovery holds its fence through checkpoint commit.
        handle.close()
        assert late.acquire()
        late.close()
    finally:
        handle.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)


def test_recovery_commits_before_releasing_worker_fence(tmp_path):
    tmp_path.chmod(0o700)
    state = dispatcher()
    (job,) = state.tick(at(600)).start
    repository = Repository()
    repository.commit(0, state)
    handle = RecoveredHandle(tmp_path, job.run_id)

    class Factory:
        def recover(self, old):
            assert old == job
            return handle

        def __call__(self, new):
            raise AssertionError("Interrupted run was relaunched")

    original_commit = repository.commit

    def commit(expected, candidate, notices=()):
        competing = Lease(paths(tmp_path, job.run_id)[0])
        assert not competing.acquire()
        return original_commit(expected, candidate, notices)

    repository.commit = commit
    supervisor = Supervisor(repository, dispatcher(), Factory())
    supervisor.tick(at(601))
    assert not supervisor.state.control.active
    assert not supervisor.state.inputs["input"].latest_success
    lease = Lease(paths(tmp_path, job.run_id)[0])
    assert lease.acquire()
    lease.close()


def test_only_one_supervisor_owns_a_service(tmp_path):
    tmp_path.chmod(0o700)
    first = PublicWorkers("synthetic-service", [], tmp_path)
    try:
        with pytest.raises(ValueError, match="already has"):
            PublicWorkers("synthetic-service", [], tmp_path)
    finally:
        first.close()
    replacement = PublicWorkers("synthetic-service", [], tmp_path)
    replacement.close()


def test_lease_rejects_symlinks_and_publicly_readable_files(tmp_path):
    tmp_path.chmod(0o700)
    target = tmp_path / "target"
    target.write_text("synthetic")
    with pytest.raises(ValueError, match="owner-only"):
        Lease(target).acquire()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        Lease(link).acquire()
