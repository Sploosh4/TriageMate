"""Deterministic collection-failure episodes; no connectivity checks or device actions."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
from uuid import UUID

from .contracts import identifier, utc


def notification_id(connection, first_failure):
    raw = "triagemate-collection-notification-v1:" + connection + ":" + first_failure
    return str(UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))


@dataclass(frozen=True)
class CollectionAttempt:
    id: str
    connection_id: str
    started_at: datetime
    finished_at: datetime
    complete: bool
    outcome: str

    def __post_init__(self):
        object.__setattr__(self, "id", identifier(self.id))
        object.__setattr__(self, "connection_id", identifier(self.connection_id))
        object.__setattr__(self, "started_at", utc(self.started_at))
        object.__setattr__(self, "finished_at", utc(self.finished_at))
        if self.finished_at < self.started_at or type(self.complete) is not bool:
            raise ValueError("Invalid collection attempt")
        if self.outcome not in ("success", "failure") or self.complete != (
            self.outcome == "success"
        ):
            raise ValueError(
                "Only complete successes and recorded failures are supported"
            )


@dataclass(frozen=True)
class CollectionNotification:
    id: str
    connection_id: str
    first_failure_id: str
    latest_failure_id: str
    failure_ids: tuple[str, ...]
    episode_started_at: datetime
    status: str
    recovery_attempt_id: str | None
    resolved_at: datetime | None
    urgency: str = "critical"

    @property
    def page(self):
        # Preserve the established folder spelling and existing links.
        return "System/TriageMate/Notifiations/collection-" + self.id


def collection_notifications(attempts):
    """Consecutive failures on one connection form an episode.

    Only a later complete success on that same registered input resolves it.
    Source collection order matches the current-snapshot selector. Late-arriving
    history is recomputed; earlier failed attempts are never relabelled success.
    """
    seen = set()
    grouped = {}
    for attempt in attempts:
        if not isinstance(attempt, CollectionAttempt) or attempt.id in seen:
            raise ValueError("Unique validated collection attempts are required")
        seen.add(attempt.id)
        grouped.setdefault(attempt.connection_id, []).append(attempt)
    result = []
    for connection, values in grouped.items():
        pending = []

        def episode(recovery=None):
            first, last = pending[0], pending[-1]
            return CollectionNotification(
                notification_id(connection, first.id),
                connection,
                first.id,
                last.id,
                tuple(item.id for item in pending),
                first.finished_at,
                "resolved" if recovery else "unresolved",
                recovery.id if recovery else None,
                recovery.finished_at if recovery else None,
            )

        for attempt in sorted(
            values, key=lambda item: (item.finished_at, item.started_at, item.id)
        ):
            if attempt.outcome == "failure":
                pending.append(attempt)
            elif pending:
                result.append(episode(attempt))
                pending = []
        if pending:
            result.append(episode())
    return tuple(
        sorted(
            result, key=lambda item: (item.episode_started_at, item.id), reverse=True
        )
    )
