"""Durable bounded enrichment selection in the existing operational event journal."""

from dataclasses import dataclass
import json
import re

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.persistence.enrichment_store import SOURCES

from . import store
from .checkpoint import keys


@dataclass(frozen=True)
class ScheduledEnrichment:
    input_id: str
    worker_contract: str
    source: str
    origin: str
    limit: int = 100

    def __post_init__(self):
        if (
            self.input_id != identifier(self.input_id)
            or not isinstance(self.worker_contract, str)
            or not re.fullmatch(r"[a-f0-9]{64}", self.worker_contract)
            or self.source not in SOURCES
            or self.origin not in {"synthetic", "public"}
            or type(self.limit) is not int
            or not 1 <= self.limit <= 100
        ):
            raise ValueError("Invalid scheduled enrichment binding")

    def active(self, cursor, key, job):
        if job.input_id != self.input_id or job.prerequisite_snapshots:
            raise ValueError("Enrichment batch differs from scheduled input")
        saved = store.load(cursor, key)
        if saved is None:
            raise ValueError("Enrichment requires persisted dispatch")
        revision, state = saved
        definition = state.definitions.get(self.input_id)
        current = state.inputs.get(self.input_id)
        if (
            definition is None
            or definition.worker_contract != self.worker_contract
            or current is None
            or current.active != job
            or job.run_id not in state.control.active
        ):
            raise ValueError("Enrichment batch requires the exact active job")
        return revision, state.clock

    def saved(self, cursor, key, job):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='enrichment_batch' AND event->>'run_id'=%s LIMIT 2",
            (key, identifier(job.run_id)),
        )
        rows = cursor.fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("Ambiguous enrichment batch declaration")
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
                "request_ids",
            ],
        )
        expected = self.event(job, event["request_ids"])
        if event != expected:
            raise ValueError("Enrichment batch declaration changed binding")
        return event["request_ids"]

    def event(self, job, requests):
        if (
            not isinstance(requests, list)
            or len(requests) > self.limit
            or any(identifier(value) != value for value in requests)
            or len(set(requests)) != len(requests)
        ):
            raise ValueError("Invalid enrichment batch membership")
        return dict(
            kind="enrichment_batch",
            input_id=self.input_id,
            run_id=identifier(job.run_id),
            worker_contract=self.worker_contract,
            source=self.source,
            origin=self.origin,
            request_ids=requests,
        )

    def declare(self, cursor, key, job, *, synthetic_ids=None, capacity=None):
        """Caller commits before processing; an existing declaration never expands."""
        if cursor.connection.autocommit:
            raise ValueError("Enrichment declaration requires an explicit transaction")
        capacity = self.limit if capacity is None else capacity
        if type(capacity) is not int or not 0 <= capacity <= self.limit:
            raise ValueError(
                "Initial enrichment capacity exceeds the shared batch limit"
            )
        key = store.service_key(key)
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        revision, now = self.active(cursor, key, job)
        saved = self.saved(cursor, key, job)
        if saved is not None:
            return saved
        if self.origin == "synthetic":
            if not isinstance(synthetic_ids, (list, tuple)) or len(synthetic_ids) > 100:
                raise ValueError(
                    "Synthetic enrichment needs explicit request identities"
                )
            selected = [identifier(value) for value in synthetic_ids]
            if len(set(selected)) != len(selected):
                raise ValueError("Duplicate synthetic enrichment identity")
        else:
            if synthetic_ids is not None:
                raise ValueError("Public enrichment cannot select synthetic fixtures")
            selected = []
        cursor.execute(
            "SELECT id::text FROM evidence_pipeline.enrichment_request_status "
            "WHERE source_name=%s AND origin=%s AND state='queued' "
            "AND (%s OR id=ANY(%s::uuid[])) ORDER BY requested_at,id LIMIT %s",
            (self.source, self.origin, self.origin == "public", selected, capacity),
        )
        requests = [row[0] for row in cursor.fetchall()]
        cursor.execute(
            "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
            "VALUES(%s,%s,%s,%s::jsonb)",
            (key, revision, now, json.dumps(self.event(job, requests))),
        )
        return requests

    def committed(self, cursor, key, job):
        self.active(cursor, key, job)
        requests = self.saved(cursor, key, job)
        if requests is None:
            return False
        cursor.execute(
            "SELECT id::text,source_name,origin,state FROM evidence_pipeline.enrichment_request_status "
            "WHERE id=ANY(%s::uuid[])",
            (requests,),
        )
        rows = cursor.fetchall()
        return (
            {row[0] for row in rows} == set(requests)
            and len(rows) == len(requests)
            and all(
                source == self.source
                and origin == self.origin
                and status in {"succeeded", "not_found"}
                for _, source, origin, status in rows
            )
        )
