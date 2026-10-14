"""Scheduler completion proof for exact prerequisite-derived Catalog searches."""

from dataclasses import dataclass, asdict
import hashlib
import json
from pathlib import Path
import re

from standalone.evidence_pipeline.collection.catalog_targets import select_targets
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
)
from .catalog_proof import CatalogProof
from . import store


@dataclass(frozen=True)
class ScheduledCatalogTargets:
    input_id: str
    worker_contract: str
    origin: str
    bundle_root: Path
    dependencies: tuple[str, ...]
    target_limit: int = 100
    record_limit: int = 10
    pass_limit: int = 10

    def __post_init__(self):
        identifier(self.input_id)
        if (
            not isinstance(self.worker_contract, str)
            or not re.fullmatch(r"[a-f0-9]{64}", self.worker_contract)
            or self.origin not in {"synthetic", "lab"}
            or not isinstance(self.bundle_root, Path)
            or not self.bundle_root.is_absolute()
            or not isinstance(self.dependencies, tuple)
            or not 1 <= len(self.dependencies) <= 100
            or len(set(self.dependencies)) != len(self.dependencies)
        ):
            raise ValueError("Invalid scheduled Catalog target binding")
        for dependency in self.dependencies:
            identifier(dependency)
        for value, maximum in (
            (self.target_limit, 1000),
            (self.record_limit, 100),
            (self.pass_limit, 100),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("Invalid Catalog target budget")

    def active(self, cursor, key, job):
        identifier(job.run_id)
        bindings = job.prerequisite_snapshots
        if (
            job.input_id != self.input_id
            or len(bindings) != len(self.dependencies)
            or {scope for scope, _ in bindings} != set(self.dependencies)
        ):
            raise ValueError("Catalog target prerequisites differ from configuration")
        for _, run in bindings:
            identifier(run)
        saved = store.load(cursor, store.service_key(key))
        if saved is None:
            raise ValueError("Catalog targets require persisted dispatch")
        revision, state = saved
        definition = state.definitions.get(self.input_id)
        current = state.inputs.get(self.input_id)
        if (
            definition is None
            or current is None
            or definition.worker_contract != self.worker_contract
            or set(definition.dependencies) != set(self.dependencies)
            or current.active != job
            or job.run_id not in state.control.active
            or job.run_id in state.control.cancel_requested
        ):
            raise ValueError("Catalog targets require the exact uncancelled active job")
        return revision, state.clock

    def evidence(self, cursor, job):
        _private_directory(self.bundle_root)
        bundle = self.bundle_root / identifier(job.run_id)
        _private_directory(bundle)
        raw = _read(bundle / "targets.json")
        selected = select_targets(
            cursor,
            dict(job.prerequisite_snapshots),
            origin=self.origin,
            maximum=self.target_limit,
        )
        expected = json.loads(
            json.dumps(
                dict(
                    run_id=job.run_id,
                    origin=self.origin,
                    selection=asdict(selected),
                    target_limit=self.target_limit,
                    record_limit=self.record_limit,
                    pass_limit=self.pass_limit,
                )
            )
        )
        if not selected.complete or json.loads(raw) != expected:
            raise ValueError(
                "Saved Catalog selection differs from prerequisite evidence"
            )
        searches = bundle / "searches"
        _private_directory(searches)
        origin = "synthetic" if self.origin == "synthetic" else "public"
        indexes = []
        for kb in selected.kbs:
            run = stable_id("catalog-target-search", job.run_id, kb)
            proof = CatalogProof(kb)
            child, digest, entries = proof.saved_index(searches, origin, run)
            if not proof.imports_committed(cursor, child, origin, run, entries):
                raise ValueError("Catalog target imports are incomplete")
            indexes.append(dict(kb=kb, run_id=run, index_sha256=digest))
        return dict(
            kind="catalog_targets",
            input_id=self.input_id,
            run_id=job.run_id,
            worker_contract=self.worker_contract,
            origin=self.origin,
            manifest_sha256=hashlib.sha256(raw).hexdigest(),
            indexes=indexes,
        )

    def saved(self, cursor, key, job):
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'='catalog_targets' AND event->>'run_id'=%s LIMIT 2",
            (key, job.run_id),
        )
        rows = cursor.fetchall()
        if len(rows) > 1:
            raise ValueError("Ambiguous Catalog target declaration")
        return rows[0][0] if rows else None

    def seal(self, cursor, key, job):
        if cursor.connection.autocommit:
            raise ValueError("Catalog declaration requires a transaction")
        key = store.service_key(key)
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        revision, now = self.active(cursor, key, job)
        event = self.evidence(cursor, job)
        previous = self.saved(cursor, key, job)
        if previous is not None and previous != event:
            raise ValueError("Catalog target declaration changed")
        if previous is None:
            cursor.execute(
                "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) VALUES(%s,%s,%s,%s::jsonb)",
                (key, revision, now, json.dumps(event)),
            )

    def committed(self, cursor, key, job):
        self.active(cursor, key, job)
        previous = self.saved(cursor, key, job)
        return previous is not None and previous == self.evidence(cursor, job)
