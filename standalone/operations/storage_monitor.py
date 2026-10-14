"""Sample configured persistent storage and journal pressure without deleting data."""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

from standalone.evidence_pipeline.contracts import utc
from standalone.evidence_pipeline.runtime import connect
from .storage_usage import sample
from .store import service_key


@dataclass(frozen=True)
class StoragePolicy:
    directories: tuple[Path, ...]
    maximum_bytes: int

    def __post_init__(self):
        if (
            type(self.maximum_bytes) is not int
            or not 1 <= self.maximum_bytes <= 2**63 - 1
            or not 1 <= len(self.directories) <= 32
            or any(
                not isinstance(path, Path)
                or not path.is_absolute()
                or ".." in path.parts
                or len(path.parts) > 128
                or path == Path("/")
                for path in self.directories
            )
            or len(set(self.directories)) != len(self.directories)
        ):
            raise ValueError(
                "Storage requires explicit product directories and a positive byte allowance"
            )

    @property
    def fingerprint(self):
        return hashlib.sha256(
            json.dumps(
                [sorted(str(path) for path in self.directories), self.maximum_bytes],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()


def measure(cursor, policy, *, sampler=sample):
    files = sampler(policy.directories)
    reasons = list(files.incomplete_reasons)
    database = None
    cursor.execute("SAVEPOINT storage_measurement")
    try:
        cursor.execute("SELECT evidence_pipeline.product_database_bytes()")
        value = cursor.fetchone()[0]
        if type(value) is not int or value < 0:
            raise ValueError("Invalid database size")
        database = value
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT storage_measurement")
        reasons.append("database_unavailable")
    finally:
        cursor.execute("RELEASE SAVEPOINT storage_measurement")
    known = files.allocated_bytes + (database or 0)
    condition = (
        "over_limit"
        if known >= policy.maximum_bytes
        else "unknown"
        if reasons
        else "below_limit"
    )
    return dict(
        condition=condition,
        database_bytes=database,
        filesystem_bytes=files.allocated_bytes,
        known_bytes=known,
        incomplete_reasons=sorted(set(reasons)),
        maximum_bytes=policy.maximum_bytes,
        directories_count=len(policy.directories),
        policy_fingerprint=policy.fingerprint,
    )


def record(cursor, key, observed, now, revision):
    cursor.execute(
        "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
        "AND event->>'kind' LIKE 'storage_%%' ORDER BY id DESC LIMIT 1",
        (key,),
    )
    row = cursor.fetchone()
    previous = row[0] if row else None
    active = previous is not None and previous["kind"] != "storage_resolved"
    healthy = observed["condition"] == "below_limit"
    if healthy and not active:
        return False
    # Do not append an event for every byte change during the same condition.
    if previous and all(
        previous.get(field) == observed[field]
        for field in (
            "condition",
            "incomplete_reasons",
            "policy_fingerprint",
        )
    ):
        return False
    event = dict(
        kind="storage_resolved"
        if healthy
        else "storage_updated"
        if active
        else "storage_opened",
        input_id="storage",
        episode_id=previous["episode_id"] if active else str(uuid4()),
        at=utc(now).isoformat(),
        **observed,
    )
    cursor.execute(
        "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
        "VALUES(%s,%s,%s,%s::jsonb)",
        (key, revision, now, json.dumps(event)),
    )
    return True


class StorageMonitor:
    def __init__(
        self, key, policy, *, connector=connect, clock=time.monotonic, sampler=sample
    ):
        self.key, self.policy = service_key(key), policy
        self.connector, self.clock, self.sampler = connector, clock, sampler
        self.checked = float("-inf")

    def check(self, now=None):
        if self.policy is None or self.clock() - self.checked < 60:
            return
        now = utc(now or datetime.now(timezone.utc))
        with closing(self.connector()) as conn, conn, conn.cursor() as cursor:
            observed = measure(cursor, self.policy, sampler=self.sampler)
            cursor.execute(
                "SELECT revision FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s FOR UPDATE",
                (self.key,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(
                    "Storage monitoring requires an operational checkpoint"
                )
            record(cursor, self.key, observed, now, row[0])
        self.checked = self.clock()
