"""Host the durable supervisor while keeping collection controls available.

Database/worker faults suspend dispatch. A later poll reconciles the committed
checkpoint and authoritative worker leases before allowing another decision.
"""

from datetime import datetime, timezone
from copy import deepcopy
from threading import Event, RLock, Thread

from .lifecycle import Mode
from .dispatch import Dispatcher
from .scheduling import utc
from .supervisor import Supervisor


class Service:
    def __init__(
        self,
        repository,
        initial_state,
        workers,
        *,
        clock=None,
        poll_seconds=1,
        certificate_monitor=None,
        provider_monitor=None,
        storage_monitor=None,
    ):
        if (
            isinstance(poll_seconds, bool)
            or not isinstance(poll_seconds, (int, float))
            or not 0.01 <= poll_seconds <= 60
        ):
            raise ValueError("Operational polling must be between 0.01 and 60 seconds")
        self.repository, self.initial_state, self.workers = (
            repository,
            initial_state,
            workers,
        )
        self.certificate_monitor = certificate_monitor
        self.provider_monitor = provider_monitor
        self.storage_monitor = storage_monitor
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.poll_seconds = poll_seconds
        self.lock = RLock()
        self.wake = Event()
        self.thread = None
        self.closing = False
        self.closed = False
        self.fault = False
        self.supervisor = self._restore()
        self._status = self._snapshot()

    def _restore(self):
        restored = Supervisor(self.repository, self.initial_state, self.workers)
        changed = (
            restored.state.definitions != self.initial_state.definitions
            or restored.state.concurrency != self.initial_state.concurrency
            or restored.state.control.grace_seconds
            != self.initial_state.control.grace_seconds
        )
        if changed:
            if (
                restored.state.control.active
                or restored.state.control.desired == Mode.RUNNING
            ):
                raise ValueError(
                    "Stop collection before changing operational configuration"
                )
            candidate = Dispatcher(
                self.initial_state.definitions.values(),
                now=max(utc(self.clock()), restored.state.clock),
                concurrency=self.initial_state.concurrency,
                grace_seconds=self.initial_state.control.grace_seconds,
            )
            candidate.control.desired = restored.state.control.desired
            for key, definition in candidate.definitions.items():
                previous = restored.state.definitions.get(key)
                if (
                    previous is not None
                    and previous.worker_contract == definition.worker_contract
                ):
                    candidate.inputs[key] = deepcopy(restored.state.inputs[key])
            restored._publish(candidate)
        return restored

    def _now(self):
        # A backwards wall-clock adjustment must not replay schedule slots.
        return max(utc(self.clock()), self.supervisor.state.clock)

    def status(self):
        # Reads stay available while the supervisor waits on a database timeout.
        # This is the last verified state, copied so callers cannot mutate it.
        return deepcopy(self._status)

    def _snapshot(self):
        with self.lock, self.supervisor.lock:
            state = self.supervisor.state
            return dict(
                available=not self.closed,
                state="recovering" if self.fault else state.control.state,
                desired=state.control.desired.value,
                active=len(state.control.active),
                configured_inputs=len(state.inputs),
                revision=self.supervisor.revision,
                recovery_required=self.fault or self.supervisor.needs_recovery,
                inputs=[
                    dict(
                        input_id=key,
                        active=value.active is not None,
                        latest_success=value.latest_success,
                        latest_snapshot=value.latest_snapshot,
                        missed_count=value.missed_count,
                    )
                    for key, value in state.inputs.items()
                ],
            )

    def request_mode(self, mode):
        mode = Mode(mode)
        if not self.lock.acquire(timeout=0.1):
            raise ValueError("Operational service is busy; retry shortly")
        try:
            if self.closed or self.closing:
                raise ValueError("Operational service is shutting down")
            if self.fault or self.supervisor.needs_recovery:
                raise ValueError("Operational state is recovering; retry shortly")
            try:
                self.supervisor.request_mode(mode, self._now())
            except Exception:
                self.fault = True
                self._status = self._snapshot()
                self.wake.set()
                raise
            self.wake.set()
            self._status = self._snapshot()
            return self.status()
        finally:
            self.lock.release()

    def tick(self):
        with self.lock:
            if self.closed:
                return
            try:
                if self.fault or self.supervisor.needs_recovery:
                    if not hasattr(self.workers, "recover"):
                        raise ValueError("Worker recovery handles are unavailable")
                    previous = self.supervisor
                    replacement = self._restore()
                    # New recovery handles acquire leases when polled. Release
                    # any old completed-worker fencing leases only after restore.
                    for handle in previous.handles.values():
                        if hasattr(handle, "close"):
                            handle.close()
                    self.supervisor = replacement
                    self.fault = False
                if self.closing:
                    self.supervisor.request_mode(Mode.OFF, self._now())
                self.supervisor.tick(self._now())
                if (
                    self.certificate_monitor is not None
                    and self.supervisor.state.control.accepts_work
                    and not self.closing
                ):
                    self.certificate_monitor.check(self._now())
                if (
                    self.provider_monitor is not None
                    and self.supervisor.state.control.accepts_work
                    and not self.closing
                ):
                    self.provider_monitor.check(self._now())
                if (
                    self.storage_monitor is not None
                    and self.supervisor.state.control.accepts_work
                    and not self.closing
                ):
                    self.storage_monitor.check(self._now())
                if self.closing and not self.supervisor.state.control.active:
                    self._release()
            except Exception:
                # Raw exceptions can contain source details. Status exposes the
                # recovery state; no empty checkpoint or speculative restart.
                self.fault = True
            finally:
                self._status = self._snapshot()

    def start(self):
        with self.lock:
            if self.closed or self.closing:
                raise ValueError("Operational service is shutting down")
            if self.thread is not None:
                return
            self.thread = Thread(
                target=self._run, name="triagemate-operations", daemon=True
            )
            self.thread.start()

    def _run(self):
        while not self.closed:
            self.wake.clear()
            self.tick()
            if not self.closed:
                self.wake.wait(self.poll_seconds)

    def _release(self):
        if hasattr(self.workers, "close"):
            self.workers.close()
        self.closed = True

    def close(self, timeout=5):
        """Request graceful off; a timed-out drain retains ownership and continues.

        The host may call again. It must not declare active workers stopped or
        release the singleton lease while this service still supervises them.
        """
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 <= timeout <= 60
        ):
            raise ValueError("Shutdown wait must be between zero and 60 seconds")
        with self.lock:
            if self.closed:
                return True
            self.closing = True
            self.wake.set()
        if self.thread is None:
            self.tick()
        else:
            self.thread.join(timeout)
        return self.closed
