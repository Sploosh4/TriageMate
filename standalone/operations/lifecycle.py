"""Local collection controls keep restart available while workers drain.

The hosting service serializes calls and delivers cancellation requests to its
workers. A cancellation request is not treated as proof that a worker stopped.
"""

from datetime import datetime, timedelta
from enum import Enum

from .scheduling import utc


class Mode(str, Enum):
    RUNNING = "running"
    OFF = "off"
    MAINTENANCE = "maintenance"


class Lifecycle:
    def __init__(self, *, grace_seconds: int = 60, mode: Mode = Mode.OFF):
        if type(grace_seconds) is not int or grace_seconds < 0:
            raise ValueError("Shutdown grace must be a nonnegative number of seconds")
        self.grace_seconds = grace_seconds
        self.desired = Mode(mode)
        self.deadline = None
        self.active: set[str] = set()
        self.cancel_requested: set[str] = set()

    @property
    def state(self) -> str:
        if self.desired != Mode.RUNNING and self.active:
            return "draining"
        return self.desired.value

    @property
    def accepts_work(self) -> bool:
        return self.desired == Mode.RUNNING

    @property
    def suppress_outage_notifications(self) -> bool:
        return self.desired != Mode.RUNNING

    def request(self, mode: Mode, now: datetime):
        now, mode = utc(now), Mode(mode)
        if mode == self.desired:
            return
        self.desired = mode
        if mode == Mode.RUNNING:
            self.deadline = None
        elif self.active and self.deadline is None:
            self.deadline = now + timedelta(seconds=self.grace_seconds)

    def started(self, job_id: str):
        if not isinstance(job_id, str) or not job_id or len(job_id) > 256:
            raise ValueError("Worker identity must be a bounded nonempty string")
        if not self.accepts_work:
            raise ValueError("Collection is paused")
        if job_id in self.active:
            raise ValueError("Worker is already active")
        self.active.add(job_id)

    def finished(self, job_id: str):
        if job_id not in self.active:
            raise ValueError("Unknown active worker")
        self.active.remove(job_id)
        self.cancel_requested.discard(job_id)
        if not self.active:
            self.deadline = None

    def cancellations_due(self, now: datetime) -> tuple[str, ...]:
        now = utc(now)
        if self.deadline is None or now < self.deadline:
            return ()
        newly_due = self.active - self.cancel_requested
        self.cancel_requested.update(newly_due)
        return tuple(sorted(newly_due))
