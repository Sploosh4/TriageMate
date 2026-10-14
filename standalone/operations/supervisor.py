"""Commit dispatch intent before worker effects; validate results against PostgreSQL.

A worker handle must implement poll() (None while alive) and idempotent cancel().
Restored active runs require their authoritative handles before dispatch resumes.
"""

from contextlib import closing
from threading import RLock

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.runtime import connect

from . import store
from .checkpoint import encode, decode


class PostgresRepository:
    def __init__(
        self,
        key="local",
        connector=connect,
        *,
        repository_proofs=(),
        enrichment_proofs=(),
        catalog_target_proofs=(),
    ):
        from .repository_proof import ScheduledRepository
        from .enrichment_batch import ScheduledEnrichment

        self.key = store.service_key(key)
        self.connector = connector
        self.repository_proofs = {}
        for proof in repository_proofs:
            if (
                not isinstance(proof, ScheduledRepository)
                or proof.input_id in self.repository_proofs
            ):
                raise ValueError("Unique scheduled repository proof required")
            self.repository_proofs[proof.input_id] = proof
        self.enrichment_proofs = {}
        for proof in enrichment_proofs:
            if (
                not isinstance(proof, ScheduledEnrichment)
                or proof.input_id in self.enrichment_proofs
                or proof.input_id in self.repository_proofs
            ):
                raise ValueError("Unique scheduled enrichment proof required")
            self.enrichment_proofs[proof.input_id] = proof

        from .catalog_target_proof import ScheduledCatalogTargets

        self.catalog_target_proofs = {}
        for proof in catalog_target_proofs:
            if (
                not isinstance(proof, ScheduledCatalogTargets)
                or proof.input_id in self.catalog_target_proofs
                or proof.input_id in self.repository_proofs
                or proof.input_id in self.enrichment_proofs
            ):
                raise ValueError("Unique scheduled Catalog target proof required")
            self.catalog_target_proofs[proof.input_id] = proof

    def load(self):
        with closing(self.connector()) as conn, conn, conn.cursor() as cur:
            return store.load(cur, self.key)

    def commit(self, expected_revision, state, notices=()):
        with closing(self.connector()) as conn, conn, conn.cursor() as cur:
            revision = store.save(
                cur,
                self.key,
                expected_revision,
                state,
                notices=notices,
                repository_sources={
                    **{
                        key: {
                            "source": proof.source,
                            "origin": proof.origin,
                            **({"kb": proof.kb} if proof.kb is not None else {}),
                        }
                        for key, proof in self.repository_proofs.items()
                    },
                    **{
                        key: {
                            "source": "Microsoft Update Catalog",
                            "origin": "synthetic"
                            if proof.origin == "synthetic"
                            else "public",
                            "mode": "targets",
                        }
                        for key, proof in self.catalog_target_proofs.items()
                    },
                },
                enrichment_sources={
                    key: {"source": proof.source, "origin": proof.origin}
                    for key, proof in self.enrichment_proofs.items()
                },
            )
        return revision  # The transaction has committed before acknowledgement.

    def committed_snapshot(self, job):
        run, source = identifier(job.run_id), identifier(job.input_id)
        with closing(self.connector()) as conn, conn, conn.cursor() as cur:
            # A terminated client can leave its COMMIT finishing in PostgreSQL.
            # Wait for the writer transaction before deciding that evidence is absent.
            cur.execute("SELECT pg_advisory_xact_lock(731904217)")
            if source in self.catalog_target_proofs:
                proof = self.catalog_target_proofs[source]
                return run if proof.committed(cur, self.key, job) else None
            if source in self.repository_proofs:
                proof = self.repository_proofs[source]
                return run if proof.committed(cur, self.key, job) else None
            if source in self.enrichment_proofs:
                proof = self.enrichment_proofs[source]
                return run if proof.committed(cur, self.key, job) else None
            cur.execute(
                """SELECT complete,outcome FROM evidence.collection_attempts
              WHERE id=%s AND connection_id=%s""",
                (run, source),
            )
            row = cur.fetchone()
        return run if row == (True, "success") else None


def decision_state(state):
    document = encode(state)
    del document["clock"]
    for value in document["inputs"].values():
        del value["cursor"]
    return document


class Supervisor:
    def __init__(self, repository, initial_state, start_worker):
        self.repository, self.start_worker = repository, start_worker
        loaded = repository.load()
        if loaded is None:
            self.revision = repository.commit(0, initial_state)
            self.state = decode(encode(initial_state))
        else:
            self.revision, self.state = loaded
        self.handles = {}
        if hasattr(start_worker, "recover"):
            for state in self.state.inputs.values():
                if state.active is not None:
                    self.handles[state.active.run_id] = start_worker.recover(
                        state.active
                    )
        self.faulted = False
        self.lock = RLock()

    @property
    def needs_recovery(self):
        return self.faulted or bool(self.state.control.active - self.handles.keys())

    def _publish(self, candidate, notices=()):
        try:
            revision = self.repository.commit(self.revision, candidate, notices)
        except Exception:
            # A failed acknowledgement may conceal a committed write. Retain the
            # old state but forbid further effects until authoritative recovery.
            self.faulted = True
            raise
        self.state, self.revision = candidate, revision

    def request_mode(self, mode, now):
        with self.lock:
            if self.faulted:
                raise ValueError("Operational state requires recovery")
            candidate = decode(encode(self.state))
            candidate.request_mode(mode, now)
            self._publish(candidate)

    def tick(self, now):
        with self.lock:
            if self.needs_recovery:
                raise ValueError(
                    "Active worker or checkpoint outcome requires recovery"
                )
            # Inspect authoritative process handles before deciding new starts.
            for run_id, handle in list(self.handles.items()):
                if handle.poll() is None:
                    continue
                job = next(
                    state.active
                    for state in self.state.inputs.values()
                    if state.active is not None and state.active.run_id == run_id
                )
                snapshot = self.repository.committed_snapshot(job)
                candidate = decode(encode(self.state))
                candidate.finished(
                    run_id, success=snapshot is not None, snapshot_id=snapshot, now=now
                )
                self._publish(candidate)
                if hasattr(handle, "close"):
                    handle.close()
                del self.handles[run_id]
            candidate = decode(encode(self.state))
            actions = candidate.tick(now)
            if actions.notices or decision_state(candidate) != decision_state(
                self.state
            ):
                self._publish(candidate, actions.notices)
            else:
                # Idle polls need no full JSON checkpoint write. No external
                # effect depends on these in-memory clock/cursor advances.
                self.state = candidate
            try:
                for job in actions.start:
                    self.handles[job.run_id] = self.start_worker(job)
                for run_id in self.state.control.cancel_requested:
                    self.handles[run_id].cancel()
            except Exception:
                self.faulted = True
                raise
            return actions
