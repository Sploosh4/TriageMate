"""Transactional component checks recomputed from validated inventory evidence."""

import csv
import hashlib
from pathlib import Path
from tempfile import TemporaryFile
from uuid import UUID, uuid5

from backend.database.schema import require_current_version
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.persistence.store import atomic, ReplayConflict

from .component_assessment import canonical, prepare
from .engine_identity import canonical_fingerprint


def engine_fingerprint():
    """Version the executable interpretation separately from source evidence."""
    here = Path(__file__).parent
    fingerprint = hashlib.sha256()
    for name in (
        "component_check.py",
        "component_assessment.py",
        "component_store.py",
        "contract.py",
        "staging.py",
    ):
        fingerprint.update(name.encode() + b"\0")
        fingerprint.update((here / name).read_bytes())
    return canonical_fingerprint("component", fingerprint.hexdigest())


def persist_inventory(connection, attempt, *, staged=None, device_attempt_id=None):
    """Publish inventory and its default unknown-preserving check in one unit.

    Reviewed rule evidence can subsequently be evaluated against this exact
    retained snapshot using ``persist``. No synthetic rule or external fetch is
    introduced into normal inventory collection or replay.
    """
    from .contract import DeviceBinding
    from .store import persist as store_inventory

    if connection.autocommit:
        raise ValueError("Inventory and component checks require one transaction")
    with connection.cursor() as cur, atomic(cur):
        result = store_inventory(
            connection, attempt, staged=staged, device_attempt_id=device_attempt_id
        )
        if attempt.complete:
            metadata = staged.metadata
            binding = DeviceBinding(
                *(metadata[key] for key in ("machine_guid", "tenant_id", "device_id"))
            )
            persist(
                connection,
                attempt.execution_id,
                staged,
                binding=binding,
                origin=attempt.scope.origin,
            )
        return result


def persist(
    connection,
    inventory_attempt_id,
    inventory,
    *,
    binding,
    origin,
    context=None,
    rules=(),
    retained_sources=None,
):
    """Persist a complete derived result set atomically, without changing inventory.

    The caller commits before announcing success. Repeating the same snapshot,
    rule/context/source evidence and evaluator is idempotent. Changed evidence or
    evaluator creates another historical assessment, never overwriting a verdict.
    """
    if connection.autocommit:
        raise ValueError("Component persistence requires an explicit transaction")
    inventory_attempt_id = identifier(inventory_attempt_id)
    with prepare(
        inventory,
        binding=binding,
        origin=origin,
        context=context,
        rules=rules,
        retained_sources=retained_sources,
    ) as checked:
        metadata = checked.metadata
        encoded = canonical(metadata)
        evidence = hashlib.sha256(encoded.encode()).hexdigest()
        engine = engine_fingerprint()
        check_id = str(uuid5(UUID(inventory_attempt_id), evidence + engine))
        with connection.cursor() as cur, atomic(cur):
            cur.execute("SELECT pg_advisory_xact_lock(731904217)")
            require_current_version(cur)
            cur.execute(
                "SELECT a.input_fingerprint,a.started_at,a.finished_at,w.record_count "
                "FROM evidence.collection_attempts a JOIN evidence_pipeline.windows_inventory_runs w "
                "ON w.attempt_id=a.id WHERE a.id=%s AND a.complete AND a.outcome='success'",
                (inventory_attempt_id,),
            )
            pinned = cur.fetchone()
            if (
                pinned is None
                or pinned[0] != inventory.fingerprint
                or pinned[3] != metadata["result_count"]
            ):
                raise ValueError(
                    "Component check requires its exact complete inventory snapshot"
                )
            cur.execute(
                "SELECT inventory_attempt_id::text,evidence_fingerprint,engine_fingerprint,metadata "
                "FROM evidence_pipeline.component_check_runs WHERE id=%s",
                (check_id,),
            )
            previous = cur.fetchone()
            replayed = previous is not None
            if replayed and previous != (
                inventory_attempt_id,
                evidence,
                engine,
                metadata,
            ):
                raise ReplayConflict(
                    "Component assessment replay differs from retained evidence"
                )
            if not replayed:
                cur.execute(
                    "INSERT INTO evidence_pipeline.component_check_runs"
                    "(id,inventory_attempt_id,evidence_fingerprint,engine_fingerprint,metadata) "
                    "VALUES(%s,%s,%s,%s,%s::jsonb)",
                    (check_id, inventory_attempt_id, evidence, engine, encoded),
                )
            # Recheck source integrity even on replay. Both temporary spools are
            # disk-backed and source chunks never exceed 64 KiB.
            with TemporaryFile(mode="w+", encoding="utf-8", newline="") as spool:
                writer = csv.writer(spool)
                current, digest, seen = None, None, set()
                for source_hash, number, chunk in checked.source_chunks():
                    if source_hash != current:
                        if current is not None and digest.hexdigest() != current:
                            raise ValueError(
                                "Component source digest differs from retained bytes"
                            )
                        if source_hash in seen:
                            raise ValueError(
                                "Component source chunks are not contiguous"
                            )
                        seen.add(source_hash)
                        current, digest = source_hash, hashlib.sha256()
                    digest.update(chunk)
                    if not replayed:
                        writer.writerow(
                            (check_id, source_hash, number, "\\x" + chunk.hex())
                        )
                if current is None or digest.hexdigest() != current:
                    raise ValueError(
                        "Component source digest differs from retained bytes"
                    )
                if seen != {s["sha256"] for s in metadata["sources"]}:
                    raise ValueError("Component source set differs from assessment")
                if not replayed:
                    spool.seek(0)
                    cur.copy_expert(
                        "COPY evidence_pipeline.component_check_source_chunks"
                        "(check_id,source_sha256,chunk_number,payload) FROM STDIN WITH (FORMAT CSV)",
                        spool,
                    )
            with TemporaryFile(mode="w+", encoding="utf-8", newline="") as spool:
                writer = csv.writer(spool)
                digest, count = hashlib.sha256(), 0
                for row in checked.results():
                    cur.execute(
                        "SELECT receipt_id::text,facts FROM evidence_pipeline.windows_inventory_observations "
                        "WHERE attempt_id=%s AND kind=%s AND native_id=%s",
                        (inventory_attempt_id, row["kind"], row["native_id"]),
                    )
                    source = cur.fetchone()
                    if (
                        source is None
                        or hashlib.sha256(canonical(source[1]).encode()).hexdigest()
                        != row["facts_sha256"]
                    ):
                        raise ValueError(
                            "Component result differs from exact persisted inventory facts"
                        )
                    result = canonical(row)
                    digest.update(result.encode() + b"\n")
                    count += 1
                    if not replayed:
                        writer.writerow((check_id, source[0], result))
                if (
                    count != metadata["result_count"]
                    or digest.hexdigest() != metadata["results_sha256"]
                ):
                    raise ValueError("Component result stream changed after evaluation")
                if not replayed:
                    spool.seek(0)
                    cur.copy_expert(
                        "COPY evidence_pipeline.component_check_results(check_id,receipt_id,result) "
                        "FROM STDIN WITH (FORMAT CSV)",
                        spool,
                    )
            if not replayed:
                cur.execute(
                    "INSERT INTO evidence_pipeline.component_check_seals(check_id) VALUES(%s)",
                    (check_id,),
                )
            return dict(check_id=check_id, replayed=replayed, records=count)
