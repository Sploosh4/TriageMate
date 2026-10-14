"""Transactional device persistence into the accepted evidence tables.

The caller supplies an authorized connection and commits the transaction. No
credentials, database creation, migrations, network access or startup imports.
Runtime importer-role provisioning is a separate required integration step.
"""

from contextlib import contextmanager
import hashlib

from psycopg2 import sql

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.devices import normalize_devices, stable_id


class ReplayConflict(ValueError):
    """An immutable scope or execution identifier was reused inconsistently."""


def require_input_migration(cursor, feature):
    """Use shared current-version bookkeeping without expanding writer authority."""
    if feature not in {"update-status", "antivirus", "catalogue"}:
        raise ValueError("Unsupported restricted input feature")
    from backend.database.schema import require_current_version

    require_current_version(cursor)


@contextmanager
def atomic(cursor):
    cursor.execute("SAVEPOINT evidence_pipeline_write")
    try:
        cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        yield
        # Force deferred source/receipt constraints before acknowledging success.
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute("RELEASE SAVEPOINT evidence_pipeline_write")
    except BaseException:
        # Interrupts must not leave a partially staged import in a connection
        # whose caller may catch cancellation and continue using it.
        cursor.execute("ROLLBACK TO SAVEPOINT evidence_pipeline_write")
        cursor.execute("RELEASE SAVEPOINT evidence_pipeline_write")
        raise


def insert(cursor, table, values):
    columns = list(values)
    cursor.execute(
        sql.SQL("INSERT INTO evidence.{} ({}) VALUES ({})").format(
            sql.Identifier(table),
            sql.SQL(",").join(map(sql.Identifier, columns)),
            sql.SQL(",").join(sql.Placeholder() for _ in columns),
        ),
        [values[key] for key in columns],
    )


def require_lab_schema(cursor, scope):
    if scope.origin != "lab":
        return
    cursor.execute(
        "SELECT 1 FROM pg_attribute WHERE attrelid='evidence.microsoft_tenants'::regclass AND attname='evidence_origin' AND NOT attisdropped"
    )
    if cursor.fetchone() is None:
        raise ValueError(
            "Lab persistence requires the explicit provenance-schema migration"
        )


def source_connection(cursor, snapshot):
    scope = snapshot.scope
    require_lab_schema(cursor, scope)
    tenant = (
        stable_id("tenant", scope.origin, scope.tenant_id)
        if scope.tenant_id is not None
        else None
    )
    marker = (
        "evidence-pipeline-v1:"
        + scope.origin
        + ":"
        + hashlib.sha256(scope.provenance.encode()).hexdigest()
    )
    expected = (scope.source, scope.input_kind, tenant, marker, scope.scope_reference)
    cursor.execute(
        "SELECT source_name,input_kind,tenant_id::text,collector_reference,scope_reference FROM evidence.source_connections WHERE id=%s",
        (scope.connection_id,),
    )
    existing = cursor.fetchone()
    if existing is not None:
        if existing != expected:
            raise ReplayConflict("Connection scope or provenance changed")
        return
    if tenant is not None:
        cursor.execute(
            "SELECT external_tenant_id,cloud_label FROM evidence.microsoft_tenants WHERE id=%s",
            (tenant,),
        )
        existing_tenant = cursor.fetchone()
        if existing_tenant is not None and existing_tenant != (
            scope.tenant_id,
            "Microsoft",
        ):
            raise ReplayConflict("Tenant identity collision")
        if existing_tenant is None:
            insert(
                cursor,
                "microsoft_tenants",
                {
                    "id": tenant,
                    "external_tenant_id": scope.tenant_id,
                    "cloud_label": "Microsoft",
                    **({"evidence_origin": "lab"} if scope.origin == "lab" else {}),
                },
            )
    insert(
        cursor,
        "source_connections",
        {
            "id": scope.connection_id,
            "source_name": scope.source,
            "input_kind": scope.input_kind,
            "tenant_id": tenant,
            "collector_reference": marker,
            "scope_reference": scope.scope_reference,
        },
    )


def stage_attempt(cursor, snapshot):
    """Stage one immutable attempt; return True when its exact replay exists."""
    outcome = "success" if snapshot.complete else "failure"
    error = snapshot.error_code or (
        "partial_input" if snapshot.outcome == "partial" else None
    )
    detail = (
        "Partial snapshot; previous complete evidence retained"
        if snapshot.outcome == "partial"
        else None
    )
    expected_attempt = (
        snapshot.scope.connection_id,
        snapshot.started_at,
        snapshot.finished_at,
        outcome,
        snapshot.complete,
        error,
        detail,
        snapshot.input_fingerprint,
    )
    source_connection(cursor, snapshot)
    cursor.execute(
        "SELECT connection_id::text,started_at,finished_at,outcome,complete,error_code,safe_error_detail,input_fingerprint FROM evidence.collection_attempts WHERE id=%s",
        (snapshot.execution_id,),
    )
    existing = cursor.fetchone()
    if existing is not None:
        if existing != expected_attempt:
            raise ReplayConflict("Execution identifier was reused with different input")
        return True
    insert(
        cursor,
        "collection_attempts",
        {
            "id": snapshot.execution_id,
            "connection_id": snapshot.scope.connection_id,
            "started_at": snapshot.started_at,
            "finished_at": snapshot.finished_at,
            "outcome": outcome,
            "complete": snapshot.complete,
            "error_code": error,
            "safe_error_detail": detail,
            "revision": 1,
            "input_fingerprint": snapshot.input_fingerprint,
        },
    )
    return False


def persist_devices(connection, snapshot: Snapshot) -> dict:
    """All evidence from a complete device snapshot, or no evidence from it.

    Caller must commit before reporting durable success. On a lost commit
    acknowledgement replay the same execution, never generate a replacement ID.
    Failure/partial attempts are retained without replacing device observations.
    Provider registration changes are rejected pending explicit conflict handling.
    """
    if connection.autocommit:
        raise ValueError("Device persistence requires an explicit transaction")
    if (
        snapshot.scope.source not in ("Entra", "Intune", "Defender")
        or snapshot.scope.input_kind != "devices"
    ):
        raise ValueError("Only Microsoft device snapshots are supported")
    devices = normalize_devices(snapshot) if snapshot.complete else ()
    outcome = "success" if snapshot.complete else "failure"
    with connection.cursor() as cursor, atomic(cursor):
        require_lab_schema(cursor, snapshot.scope)
        # One ordered lock protects shared tenant creation and receipt identity.
        # Draft ingestion is serialised; no database-wide external lock service.
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        if stage_attempt(cursor, snapshot):
            return {
                "execution_id": snapshot.execution_id,
                "outcome": outcome,
                "devices": len(devices),
                "replayed": True,
            }
        for device in devices:
            cursor.execute(
                "SELECT connection_id::text,native_device_id,microsoft_registration_id FROM evidence.provider_devices WHERE id=%s",
                (device.provider_id,),
            )
            provider = cursor.fetchone()
            expected_provider = (
                snapshot.scope.connection_id,
                device.native_id,
                device.registration_id,
            )
            if provider is not None and provider != expected_provider:
                raise ReplayConflict(
                    "Provider identity changed; preserve earlier evidence and investigate"
                )
            if provider is None:
                insert(
                    cursor,
                    "provider_devices",
                    {
                        "id": device.provider_id,
                        "connection_id": snapshot.scope.connection_id,
                        "native_device_id": device.native_id,
                        "microsoft_registration_id": device.registration_id,
                    },
                )
            revision = stable_id(
                "device-revision",
                snapshot.scope.connection_id,
                device.native_id,
                device.content_hash,
            )
            cursor.execute(
                "SELECT connection_id::text,source_record_id,content_hash,origin,licence_or_provenance FROM evidence.source_revisions WHERE id=%s",
                (revision,),
            )
            old_revision = cursor.fetchone()
            expected_revision = (
                snapshot.scope.connection_id,
                device.native_id,
                device.content_hash,
                snapshot.scope.origin,
                snapshot.scope.provenance,
            )
            if old_revision is not None and old_revision != expected_revision:
                raise ReplayConflict("Source revision collision")
            if old_revision is None:
                insert(
                    cursor,
                    "source_revisions",
                    {
                        "id": revision,
                        "connection_id": snapshot.scope.connection_id,
                        "source_record_id": device.native_id,
                        "source_updated_at": None,
                        "collected_at": snapshot.finished_at,
                        "content_hash": device.content_hash,
                        "origin": snapshot.scope.origin,
                        "source_url": None,
                        "licence_or_provenance": snapshot.scope.provenance,
                    },
                )
            receipt = stable_id("device-receipt", revision, snapshot.execution_id)
            insert(
                cursor,
                "observation_receipts",
                {
                    "id": receipt,
                    "source_revision_id": revision,
                    "collection_attempt_id": snapshot.execution_id,
                },
            )
            insert(
                cursor,
                "device_observations",
                {
                    "id": stable_id("device-observation", receipt, device.provider_id),
                    "provider_device_id": device.provider_id,
                    "receipt_id": receipt,
                    "observed_at": None,
                    **device.observation(),
                },
            )
        return {
            "execution_id": snapshot.execution_id,
            "outcome": outcome,
            "devices": len(devices),
            "replayed": False,
        }
