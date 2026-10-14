"""Serialized dispatch decisions for one local collector supervisor.

The supervisor persists decisions before launching workers. This module does not
run threads, infer that a worker stopped, or retry a failed collection attempt.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from .lifecycle import Lifecycle, Mode
from .scheduling import Daily, Interval, utc


@dataclass(frozen=True)
class Definition:
    input_id: str
    schedule: Daily | Interval
    dependencies: tuple[str, ...] = ()
    worker_contract: str | None = None
    overdue_after_seconds: int | None = None


@dataclass(frozen=True)
class Job:
    run_id: str
    input_id: str
    scheduled_at: datetime
    started_at: datetime
    prerequisite_snapshots: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Notice:
    kind: str
    input_id: str
    original_run_id: str
    skipped_count: int
    at: datetime


@dataclass(frozen=True)
class OverdueNotice:
    kind: str
    input_id: str
    episode_id: str
    reference_at: datetime
    threshold_seconds: int
    at: datetime


@dataclass(frozen=True)
class Actions:
    start: tuple[Job, ...]
    cancel: tuple[str, ...]
    notices: tuple[Notice | OverdueNotice, ...]


@dataclass
class InputState:
    cursor: datetime
    pending: datetime | None = None
    active: Job | None = None
    active_skips: int = 0
    latest_success: bool = False
    latest_snapshot: str | None = None
    overlap_run: str | None = None
    overlap_count: int = 0
    # These are missed opportunities, not failed source collections.
    missed_count: int = 0
    monitor_since: datetime | None = None
    last_success_at: datetime | None = None
    overdue_episode: str | None = None
    overdue_reference_at: datetime | None = None
    overdue_threshold_seconds: int | None = None


def identity(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("Operational identity must be a bounded nonempty string")
    return value


class Dispatcher:
    def __init__(
        self,
        definitions,
        *,
        now: datetime,
        concurrency: int = 1,
        grace_seconds: int = 60,
    ):
        now = utc(now)
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("Collector concurrency must be between 1 and 32")
        self.definitions = {}
        for definition in definitions:
            if not isinstance(definition, Definition) or not isinstance(
                definition.schedule, (Daily, Interval)
            ):
                raise ValueError("Validated collection schedule required")
            if not isinstance(definition.dependencies, tuple) or len(
                set(definition.dependencies)
            ) != len(definition.dependencies):
                raise ValueError(
                    "Prerequisites must be unique immutable input identities"
                )
            identity(definition.input_id)
            if definition.worker_contract is not None:
                identity(definition.worker_contract)
            if definition.overdue_after_seconds is not None and (
                type(definition.overdue_after_seconds) is not int
                or definition.overdue_after_seconds < 1
            ):
                raise ValueError(
                    "Overdue collection threshold must be a positive integer"
                )
            if definition.input_id in self.definitions:
                raise ValueError("Only one schedule is allowed per input")
            self.definitions[definition.input_id] = definition
            if len(self.definitions) > 256:
                raise ValueError("Operational schedule limit exceeded")
        visiting, done = set(), set()

        def visit(key):
            if key not in self.definitions:
                raise ValueError("Unknown prerequisite input")
            if key in visiting:
                raise ValueError("Collection prerequisites contain a cycle")
            if key in done:
                return
            visiting.add(key)
            for parent in self.definitions[key].dependencies:
                visit(identity(parent))
            visiting.remove(key)
            done.add(key)

        for key in self.definitions:
            visit(key)
        self.inputs = {key: InputState(now) for key in self.definitions}
        self.control = Lifecycle(grace_seconds=grace_seconds)
        self.concurrency = concurrency
        self.clock = now
        self._notices = []

    def request_mode(self, mode: Mode, now: datetime):
        now, mode = utc(now), Mode(mode)
        self._accrue(now)
        was_running = self.control.accepts_work
        self.control.request(mode, now)
        if self.control.accepts_work and not was_running:
            for state in self.inputs.values():
                state.monitor_since = now
        if not self.control.accepts_work:
            for state in self.inputs.values():
                state.pending = None

    def _accrue(self, now: datetime):
        now = utc(now)
        if now < self.clock:
            raise ValueError("Operational clock cannot move backwards")
        self.clock = now
        for key, definition in self.definitions.items():
            state = self.inputs[key]
            due = definition.schedule.due(state.cursor, now)
            state.cursor = now
            if not self.control.accepts_work or due is None:
                continue
            if state.active is not None:
                state.active_skips += due.count
                if state.overlap_run is not None:
                    state.overlap_count += due.count
                    self._notice("overlap_updated", key, state, now)
                elif state.active_skips >= 2:
                    state.overlap_run = state.active.run_id
                    state.overlap_count = state.active_skips
                    self._notice("overlap_opened", key, state, now)
            else:
                state.missed_count += due.count - 1 + (state.pending is not None)
                state.pending = due.latest

    def _overdue(self, now):
        if not self.control.accepts_work:
            return
        for key, definition in self.definitions.items():
            threshold = definition.overdue_after_seconds
            state = self.inputs[key]
            if threshold is None:
                continue
            if state.monitor_since is None:
                state.monitor_since = now
            reference = max(
                state.monitor_since, state.last_success_at or state.monitor_since
            )
            if (
                state.overdue_episode is None
                and (now - reference).total_seconds() >= threshold
            ):
                state.overdue_episode = str(uuid4())
                state.overdue_reference_at = reference
                state.overdue_threshold_seconds = threshold
                self._notices.append(
                    OverdueNotice(
                        "overdue_opened",
                        key,
                        state.overdue_episode,
                        reference,
                        threshold,
                        now,
                    )
                )

    def tick(self, now: datetime) -> Actions:
        now = utc(now)
        self._accrue(now)
        self._overdue(now)
        started = []
        if self.control.accepts_work:
            candidates = sorted(
                (state.pending, key)
                for key, state in self.inputs.items()
                if state.pending is not None and state.active is None
            )
            for scheduled, key in candidates:
                if len(self.control.active) >= self.concurrency:
                    break
                parents = self.definitions[key].dependencies
                if any(
                    self.inputs[parent].active is not None
                    or self.inputs[parent].pending is not None
                    or not self.inputs[parent].latest_success
                    for parent in parents
                ):
                    continue
                bindings = tuple(
                    (parent, self.inputs[parent].latest_snapshot) for parent in parents
                )
                state = self.inputs[key]
                job = Job(str(uuid4()), key, scheduled, now, bindings)
                self.control.started(job.run_id)
                state.active, state.pending, state.active_skips = job, None, 0
                started.append(job)
        actions = Actions(
            tuple(started), self.control.cancellations_due(now), tuple(self._notices)
        )
        self._notices.clear()
        return actions

    def finished(
        self,
        run_id: str,
        *,
        success: bool,
        now: datetime,
        snapshot_id: str | None = None,
    ):
        now = utc(now)
        if now < self.clock or type(success) is not bool:
            raise ValueError("Invalid worker completion clock or outcome")
        if success:
            identity(snapshot_id)
        elif snapshot_id is not None:
            raise ValueError("Failed collection cannot publish a snapshot")
        matches = [
            (key, state)
            for key, state in self.inputs.items()
            if state.active is not None and state.active.run_id == run_id
        ]
        if len(matches) != 1:
            raise ValueError("Unknown active collection run")
        key, state = matches[0]
        if now < state.active.started_at:
            raise ValueError("Collection finished before it started")
        self._accrue(now)
        self._overdue(now)
        self.control.finished(run_id)
        state.active = None
        state.latest_success = success
        state.latest_snapshot = snapshot_id
        if success:
            if state.overdue_episode is not None:
                reference = state.overdue_reference_at
                self._notices.append(
                    OverdueNotice(
                        "overdue_resolved",
                        key,
                        state.overdue_episode,
                        reference,
                        state.overdue_threshold_seconds,
                        now,
                    )
                )
                state.overdue_episode = None
                state.overdue_reference_at = None
                state.overdue_threshold_seconds = None
            state.last_success_at = now
        if success and state.overlap_run is not None and state.overlap_run != run_id:
            self._notice("overlap_resolved", key, state, now)
            state.overlap_run, state.overlap_count = None, 0
        self.clock = now

    def _notice(self, kind, key, state, now):
        self._notices.append(
            Notice(kind, key, state.overlap_run, state.overlap_count, now)
        )
