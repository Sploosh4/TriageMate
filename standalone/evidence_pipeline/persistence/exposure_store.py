"""Transactional software/finding persistence using explicitly bound device inputs."""

from dataclasses import asdict
import hashlib
import json

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.exposure import (
    associations,
    normalize_findings,
    normalize_software,
)
from standalone.evidence_pipeline.parsing.update_status import (
    normalize_missing_patches,
    normalize_update_status,
)
from standalone.evidence_pipeline.parsing import update_records, antivirus_records
from standalone.evidence_pipeline.parsing.antivirus import normalize_antivirus
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    insert,
    stage_attempt,
    ReplayConflict,
)


def catalog_software(cursor, item):
    expected = (item.publisher, item.product_name, item.version, item.platform)
    cursor.execute(
        "SELECT publisher,product_name,version,platform FROM evidence.software WHERE id=%s",
        (item.id,),
    )
    existing = cursor.fetchone()
    if existing is None:
        insert(cursor, "software", asdict(item))
    elif existing != expected:
        raise ReplayConflict("Software identity collision")


def receipt(cursor, snapshot, source_id, content):
    content_hash = hashlib.sha256(
        json.dumps(
            content, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()
    revision = stable_id(
        "exposure-revision", snapshot.scope.connection_id, source_id, content_hash
    )
    expected = (
        snapshot.scope.connection_id,
        source_id,
        content_hash,
        snapshot.scope.origin,
        snapshot.scope.provenance,
    )
    cursor.execute(
        "SELECT connection_id::text,source_record_id,content_hash,origin,licence_or_provenance FROM evidence.source_revisions WHERE id=%s",
        (revision,),
    )
    existing = cursor.fetchone()
    if existing is None:
        insert(
            cursor,
            "source_revisions",
            {
                "id": revision,
                "connection_id": snapshot.scope.connection_id,
                "source_record_id": source_id,
                "collected_at": snapshot.finished_at,
                "content_hash": content_hash,
                "origin": snapshot.scope.origin,
                "licence_or_provenance": snapshot.scope.provenance,
            },
        )
    elif existing != expected:
        raise ReplayConflict("Exposure revision collision")
    key = stable_id("exposure-receipt", revision, snapshot.execution_id)
    insert(
        cursor,
        "observation_receipts",
        {
            "id": key,
            "source_revision_id": revision,
            "collection_attempt_id": snapshot.execution_id,
        },
    )
    return key


def persist_exposure(
    connection, snapshot, device_attempt_id=None, association_payload=None
):
    """Stage an entire scoped snapshot; caller must commit before reporting success.

    Software association wire bytes have a separate exact fingerprint. Reusing
    an execution with changed associations or a different pinned device attempt
    is a conflict even when the app-list response is unchanged.
    """
    if connection.autocommit:
        raise ValueError("Exposure persistence requires an explicit transaction")
    kind = snapshot.scope.input_kind
    if (snapshot.scope.source, kind) not in (
        ("Intune", "software"),
        ("Defender", "findings"),
        ("Defender", "missing_patches"),
        ("Defender", "antivirus"),
        ("Intune", "update_status"),
    ):
        raise ValueError("Unsupported exposure source")
    if snapshot.scope.origin not in ("synthetic", "lab"):
        raise ValueError("Microsoft exposure requires synthetic or lab origin")
    relation_hash = None
    mapped = None
    if snapshot.complete:
        device_attempt_id = identifier(device_attempt_id)
        if kind == "software":
            mapped = associations(association_payload)
            relation_hash = hashlib.sha256(association_payload).hexdigest()
        elif association_payload is not None:
            raise ValueError("This input does not use an association payload")
    from standalone.evidence_pipeline.persistence.store import (
        require_lab_schema,
        require_input_migration,
    )

    with connection.cursor() as cursor, atomic(cursor):
        require_lab_schema(cursor, snapshot.scope)
        if kind in ("missing_patches", "update_status"):
            require_input_migration(cursor, "update-status")
        if kind == "antivirus":
            require_input_migration(cursor, "antivirus")
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        cursor.execute(
            "SELECT device_connection_id::text FROM evidence_pipeline.input_device_scopes WHERE input_connection_id=%s",
            (snapshot.scope.connection_id,),
        )
        binding = cursor.fetchone()
        if binding is None:
            raise ValueError(
                "Exposure input requires explicit device-source registration"
            )
        records = ()
        providers = {}
        if snapshot.complete:
            cursor.execute(
                "SELECT connection_id::text,complete,outcome FROM evidence.collection_attempts WHERE id=%s",
                (device_attempt_id,),
            )
            if cursor.fetchone() != (binding[0], True, "success"):
                raise ValueError(
                    "A complete snapshot of the bound device source is required"
                )
            cursor.execute(
                "SELECT DISTINCT p.native_device_id,p.id::text FROM evidence.provider_devices p "
                "JOIN evidence.device_observations d ON d.provider_device_id=p.id "
                "JOIN evidence.observation_receipts r ON r.id=d.receipt_id "
                "WHERE r.collection_attempt_id=%s AND p.connection_id=%s",
                (device_attempt_id, binding[0]),
            )
            providers = dict(cursor.fetchall())
            if kind == "software":
                records = normalize_software(snapshot, mapped, set(providers))
            else:
                adapter = {
                    "findings": normalize_findings,
                    "antivirus": normalize_antivirus,
                    "missing_patches": normalize_missing_patches,
                    "update_status": normalize_update_status,
                }[kind]
                records = adapter(snapshot, set(providers))
        replayed = stage_attempt(cursor, snapshot)
        context = (snapshot.scope.connection_id, device_attempt_id, relation_hash)
        if snapshot.complete:
            if replayed:
                cursor.execute(
                    "SELECT input_connection_id::text,device_attempt_id::text,relationship_fingerprint "
                    "FROM evidence_pipeline.exposure_snapshots WHERE collection_attempt_id=%s",
                    (snapshot.execution_id,),
                )
                if cursor.fetchone() != context:
                    raise ReplayConflict(
                        "Execution association or device context changed"
                    )
            else:
                cursor.execute(
                    "INSERT INTO evidence_pipeline.exposure_snapshots VALUES(%s,%s,%s,%s)",
                    (snapshot.execution_id, *context),
                )
                for record_number, item in enumerate(records, start=1):
                    if kind in ("missing_patches", "update_status", "antivirus"):
                        recipe = (
                            antivirus_records if kind == "antivirus" else update_records
                        )
                        received = receipt(
                            cursor,
                            snapshot,
                            recipe.source_record_id(item),
                            recipe.content(item),
                        )
                        for table, values in recipe.rows(
                            item,
                            received,
                            providers[item.native_device_id],
                            snapshot.finished_at,
                        ):
                            insert(cursor, table, values)
                        continue
                    catalog_software(cursor, item.software)
                    source_id = (
                        item.source_application_id
                        if kind == "software"
                        else item.source_finding_id
                    )
                    received = receipt(cursor, snapshot, source_id, asdict(item))
                    if kind == "software":
                        inventory = stable_id("software-inventory", received)
                        cursor.execute(
                            "INSERT INTO evidence_pipeline.software_inventory VALUES(%s,%s,%s,%s,%s,%s)",
                            (
                                inventory,
                                snapshot.execution_id,
                                received,
                                item.software.id,
                                item.source_application_id,
                                item.reported_device_count,
                            ),
                        )
                        for native in item.native_device_ids:
                            insert(
                                cursor,
                                "software_observations",
                                {
                                    "id": stable_id(
                                        "software-observation",
                                        inventory,
                                        providers[native],
                                    ),
                                    "software_id": item.software.id,
                                    "provider_device_id": providers[native],
                                    "receipt_id": received,
                                    "source_application_id": source_id,
                                    "inventory_id": inventory,
                                },
                            )
                    else:
                        cursor.execute(
                            "SELECT 1 FROM evidence.vulnerabilities WHERE cve_id=%s",
                            (item.cve_id,),
                        )
                        if cursor.fetchone() is None:
                            insert(cursor, "vulnerabilities", {"cve_id": item.cve_id})
                        insert(
                            cursor,
                            "vulnerability_findings",
                            {
                                "id": stable_id("vulnerability-finding", received),
                                "provider_device_id": providers[item.native_device_id],
                                "software_id": item.software.id,
                                "cve_id": item.cve_id,
                                "receipt_id": received,
                                "source_finding_id": source_id,
                                "source_severity_label": item.source_severity_label,
                                "fixing_patch_reference": item.fixing_patch_reference,
                            },
                        )
                        if record_number % 50 == 0:
                            # Drain deferred checks before the entire snapshot's
                            # work accumulates in one timed statement. This is
                            # still the same transaction/savepoint: a later
                            # failure rolls back every earlier validated batch.
                            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                            cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        return {
            "execution_id": snapshot.execution_id,
            "outcome": "success" if snapshot.complete else "failure",
            "records": len(records),
            "replayed": replayed,
        }
