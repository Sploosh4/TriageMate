"""Immutable per-run refresh membership in the existing operation journal."""

from dataclasses import dataclass
import json

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.public_inputs import _cve
from .checkpoint import keys
from .enrichment_batch import ScheduledEnrichment
from .enrichment_refresh import candidates
from . import store


@dataclass(frozen=True)
class RefreshSelection:
    binding: ScheduledEnrichment

    def initial_capacity(self, cursor, key, job, *, synthetic_cves=None):
        """Share each batch; alternate at size one using the durable journal."""
        if cursor.connection.autocommit:
            raise ValueError("Batch allocation requires an explicit transaction")
        key = store.service_key(key)
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        self.binding.active(cursor, key, job)
        if self.binding.saved(cursor, key, job) is not None:
            return self.binding.limit  # Replay retains the already declared membership.
        available = candidates(
            cursor,
            source=self.binding.source,
            origin=self.binding.origin,
            limit=max(1, self.binding.limit // 2),
            synthetic_cves=synthetic_cves,
        )
        if not available:
            return self.binding.limit
        if self.binding.limit > 1:
            return self.binding.limit - len(available)
        cursor.execute(
            "SELECT event->'request_ids' FROM evidence_pipeline.operation_events "
            "WHERE service_key=%s AND event->>'kind'='enrichment_batch' "
            "AND event->>'input_id'=%s AND event->>'source'=%s "
            "AND event->>'origin'=%s AND event->>'worker_contract'=%s "
            "ORDER BY id DESC LIMIT 1",
            (
                key,
                self.binding.input_id,
                self.binding.source,
                self.binding.origin,
                self.binding.worker_contract,
            ),
        )
        previous = cursor.fetchone()
        return 0 if previous is not None and previous[0] else 1

    def __post_init__(self):
        if not isinstance(self.binding, ScheduledEnrichment):
            raise ValueError("Refresh selection requires a scheduled binding")

    def event(self, job, cves):
        if (
            not isinstance(cves, list)
            or len(cves) > self.binding.limit
            or any(_cve(value) != value for value in cves)
            or len(set(cves)) != len(cves)
            or identifier(job.input_id) != self.binding.input_id
        ):
            raise ValueError("Invalid scheduled refresh membership")
        return dict(
            kind="enrichment_refresh_batch",
            input_id=self.binding.input_id,
            run_id=identifier(job.run_id),
            worker_contract=self.binding.worker_contract,
            source=self.binding.source,
            origin=self.binding.origin,
            cve_ids=cves,
        )

    def saved(self, cursor, key, job):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='enrichment_refresh_batch' AND event->>'run_id'=%s LIMIT 2",
            (store.service_key(key), identifier(job.run_id)),
        )
        rows = cursor.fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("Ambiguous refresh batch declaration")
        event = rows[0][0]
        keys(
            event,
            [
                "kind",
                "input_id",
                "run_id",
                "worker_contract",
                "source",
                "origin",
                "cve_ids",
            ],
        )
        if event != self.event(job, event["cve_ids"]):
            raise ValueError("Refresh batch declaration changed binding")
        return event["cve_ids"]

    def declare(self, cursor, key, job, *, synthetic_cves=None, capacity=None):
        if cursor.connection.autocommit:
            raise ValueError("Refresh declaration requires an explicit transaction")
        capacity = self.binding.limit if capacity is None else capacity
        if type(capacity) is not int or not 0 <= capacity <= self.binding.limit:
            raise ValueError("Refresh capacity exceeds the shared batch limit")
        key = store.service_key(key)
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        revision, now = self.binding.active(cursor, key, job)
        saved = self.saved(cursor, key, job)
        if saved is not None:
            return saved
        selected = (
            candidates(
                cursor,
                source=self.binding.source,
                origin=self.binding.origin,
                limit=capacity,
                synthetic_cves=synthetic_cves,
                history=(key, self.binding.input_id),
            )
            if capacity
            else []
        )
        cves = [row["cve_id"] for row in selected]
        event = self.event(job, cves)
        cursor.execute(
            "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
            "VALUES(%s,%s,%s,%s::jsonb)",
            (key, revision, now, json.dumps(event)),
        )
        return cves
