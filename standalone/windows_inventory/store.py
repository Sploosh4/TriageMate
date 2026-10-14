"""Transactional Windows inventory receipts with exact pinned device evidence."""

import csv
from datetime import datetime, timezone
import json
from tempfile import TemporaryFile
from uuid import uuid4

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from backend.database.schema import require_current_version
from standalone.evidence_pipeline.contracts import Snapshot, identifier
from standalone.evidence_pipeline.persistence.exposure_store import receipt
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    source_connection,
    stage_attempt,
    ReplayConflict,
)

from .contract import DeviceBinding, observation_key
from .snapshot import InventoryAttempt, verify_binding


def register(
    connection, scope, binding: DeviceBinding, device_connection_id, native_device_id
):
    """Owner-only registration; this never grants a runtime writer new authority."""
    if connection.autocommit:
        raise ValueError("Inventory registration requires an explicit transaction")
    verify_binding(scope, binding)
    device_connection_id = identifier(device_connection_id)
    if (
        not isinstance(native_device_id, str)
        or not native_device_id.strip()
        or len(native_device_id) > 4096
    ):
        raise ValueError("An exact provider-native device ID is required")
    now = datetime.now(timezone.utc)
    envelope = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
    expected = (
        device_connection_id,
        native_device_id,
        binding.machine_guid,
        binding.device_id,
    )
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        from backend.database.schema import verify

        verify(cur)
        source_connection(cur, envelope)
        cur.execute(
            "SELECT origin FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
            (scope.connection_id,),
        )
        existing = cur.fetchone()
        if existing is None:
            authorize_connection(cur, envelope)
        elif existing != (scope.origin,):
            raise ReplayConflict("Inventory authority origin changed")
        cur.execute(
            "SELECT device_connection_id::text,native_device_id,machine_guid::text,entra_device_id::text FROM evidence_pipeline.windows_inventory_bindings WHERE connection_id=%s",
            (scope.connection_id,),
        )
        previous = cur.fetchone()
        if previous is None:
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_inventory_bindings VALUES(%s,%s,%s,%s,%s)",
                (scope.connection_id, *expected),
            )
        elif previous != expected:
            raise ReplayConflict("Inventory registered device binding changed")


def persist(
    connection, attempt: InventoryAttempt, *, staged=None, device_attempt_id=None
):
    """Insert all rows atomically; force integrity checks before acknowledging.

    Observations are copied in one statement after their immutable receipts are
    prepared. The temporary CSV is disk-backed, avoiding a retained row list and
    allowing statement-level total-count validation once per complete input.
    Caller must commit before reporting operational success.
    """
    if connection.autocommit or not isinstance(attempt, InventoryAttempt):
        raise ValueError(
            "Inventory persistence requires an explicit validated transaction"
        )
    if attempt.complete:
        if (
            InventoryAttempt.from_staged(attempt.scope, attempt.execution_id, staged)
            != attempt
        ):
            raise ValueError("Inventory staged evidence differs from its attempt")
        device_attempt_id = identifier(device_attempt_id)
    elif staged is not None or device_attempt_id is not None:
        raise ValueError(
            "Failed inventory must not publish observations or device context"
        )
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        require_current_version(cur)
        cur.execute(
            "SELECT device_connection_id::text,native_device_id,machine_guid::text,entra_device_id::text FROM evidence_pipeline.windows_inventory_bindings WHERE connection_id=%s",
            (attempt.scope.connection_id,),
        )
        bound = cur.fetchone()
        if bound is None:
            raise ValueError("Inventory requires explicit device-source registration")
        binding = DeviceBinding(bound[2], attempt.scope.tenant_id, bound[3])
        verify_binding(attempt.scope, binding)
        provider = None
        if attempt.complete:
            actual = DeviceBinding(
                *(
                    staged.metadata[key]
                    for key in ("machine_guid", "tenant_id", "device_id")
                )
            )
            if actual != binding:
                raise ValueError(
                    "Inventory machine identity differs from registered authority"
                )
            cur.execute(
                "SELECT DISTINCT p.id::text FROM evidence.provider_devices p "
                "JOIN evidence.device_observations o ON o.provider_device_id=p.id "
                "JOIN evidence.observation_receipts r ON r.id=o.receipt_id "
                "JOIN evidence.collection_attempts a ON a.id=r.collection_attempt_id "
                "WHERE p.connection_id=%s AND p.native_device_id=%s AND p.microsoft_registration_id=%s "
                "AND a.id=%s AND a.connection_id=p.connection_id AND a.complete AND a.outcome='success'",
                (bound[0], bound[1], bound[3], device_attempt_id),
            )
            providers = cur.fetchall()
            if len(providers) != 1:
                raise ValueError(
                    "Inventory requires its exact complete pinned device observation"
                )
            provider = providers[0][0]
        replayed = stage_attempt(cur, attempt)
        count = 0
        if attempt.complete:
            context = (
                device_attempt_id,
                provider,
                staged.metadata["coverage"],
                staged.metadata["record_count"],
            )
            if replayed:
                cur.execute(
                    "SELECT device_attempt_id::text,provider_device_id::text,coverage,record_count FROM evidence_pipeline.windows_inventory_runs WHERE attempt_id=%s",
                    (attempt.execution_id,),
                )
                if cur.fetchone() != context:
                    raise ReplayConflict("Inventory execution device context changed")
                count = context[3]
            else:
                cur.execute(
                    "INSERT INTO evidence_pipeline.windows_inventory_runs VALUES(%s,%s,%s,%s::jsonb,%s)",
                    (
                        attempt.execution_id,
                        context[0],
                        context[1],
                        json.dumps(context[2]),
                        context[3],
                    ),
                )
                with TemporaryFile(mode="w+", encoding="utf-8", newline="") as spool:
                    writer = csv.writer(spool)
                    for record in staged.records():
                        received = receipt(
                            cur, attempt, observation_key(binding, record), record
                        )
                        writer.writerow(
                            (
                                received,
                                attempt.execution_id,
                                record["kind"],
                                record["native_id"],
                                json.dumps(record, ensure_ascii=False),
                            )
                        )
                        count += 1
                    if count != context[3]:
                        raise ValueError("Inventory staged record count changed")
                    spool.seek(0)
                    cur.copy_expert(
                        "COPY evidence_pipeline.windows_inventory_observations(receipt_id,attempt_id,kind,native_id,facts) FROM STDIN WITH (FORMAT CSV)",
                        spool,
                    )
        return dict(replayed=replayed, records=count, complete=attempt.complete)
