"""Retain selected capture evidence without rewriting its inventory/time context."""

import base64
from dataclasses import asdict
import hashlib
from pathlib import Path
from uuid import UUID, uuid5

from backend.database.schema import require_current_version
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.persistence.store import atomic, ReplayConflict

from .component_assessment import canonical
from .component_check import check_selected_components
from .component_snapshot import validate_selected
from .component_store import engine_fingerprint as component_engine_fingerprint
from .engine_identity import canonical_fingerprint


def engine_fingerprint():
    here = Path(__file__).parent
    fingerprint = hashlib.sha256(
        (
            component_engine_fingerprint()
            + "".join(
                hashlib.sha256((here / name).read_bytes()).hexdigest()
                for name in (
                    "selected_component_store.py",
                    "component_snapshot.py",
                    "servicing_manifest.py",
                )
            )
        ).encode()
    ).hexdigest()
    return canonical_fingerprint("selected", fingerprint)


def persist(
    connection,
    inventory_attempt_id,
    raw,
    *,
    binding,
    origin,
    rules=(),
    retained_sources=None,
):
    """Recompute, then insert complete capture/results/proof in one transaction.

    The inventory is an explicit association anchor only. Each capture keeps its
    own source bytes, observation time, installed version and conflicting facts.
    No selected observation is added to inventory counts or completeness cells.
    """
    if connection.autocommit:
        raise ValueError("Selected component persistence requires a transaction")
    inventory_attempt_id = identifier(inventory_attempt_id)
    sources = dict(retained_sources or {})
    snapshot = validate_selected(raw, binding)
    report = check_selected_components(
        raw, binding=binding, origin=origin, rules=rules, retained_sources=sources
    )
    report["binding"] = asdict(binding)
    report["inventory_association_limit"] = (
        "Exact identity/version association only; separate capture time does not establish unchanged state between observations."
    )
    originals = {record["native_id"]: record for record in snapshot["records"]}
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        require_current_version(cur)
        cur.execute(
            "SELECT b.machine_guid::text,t.external_tenant_id,b.entra_device_id::text,auth.origin "
            "FROM evidence.collection_attempts a JOIN evidence_pipeline.windows_inventory_runs w ON w.attempt_id=a.id "
            "JOIN evidence_pipeline.windows_inventory_bindings b ON b.connection_id=a.connection_id "
            "JOIN evidence.source_connections c ON c.id=a.connection_id "
            "JOIN evidence.microsoft_tenants t ON t.id=c.tenant_id "
            "JOIN evidence_pipeline.authorized_connections auth ON auth.connection_id=c.id "
            "WHERE a.id=%s AND a.complete AND a.outcome='success'",
            (inventory_attempt_id,),
        )
        if cur.fetchone() != (
            binding.machine_guid,
            binding.tenant_id,
            binding.device_id,
            origin,
        ):
            raise ValueError(
                "Selected capture differs from registered inventory device or origin"
            )
        for row in report["rows"]:
            record = originals[row["native_id"]]
            identity = {
                key: record[key]
                for key in ("name", "family_name", "publisher", "architecture")
            }
            row["observed_identity"] = identity
            row["manifest_evidence"] = record.get("manifest")
            cur.execute(
                "SELECT receipt_id::text,facts FROM evidence_pipeline.windows_inventory_observations "
                "WHERE attempt_id=%s AND kind='appx' AND native_id=%s",
                (inventory_attempt_id, row["native_id"]),
            )
            candidate = cur.fetchone()
            matched = candidate is not None and all(
                candidate[1].get(k) == v
                for k, v in dict(identity, version=row["version"]).items()
            )
            row["inventory_receipt_id"] = candidate[0] if matched else None
            row["inventory_association"] = (
                "exact_identity_and_version_only"
                if matched
                else "inventory_identity_or_version_unverified"
            )
        # Native XML/compressed bytes are already retained inside the capture.
        # Retain only referenced additional public source bytes, never unrelated data.
        extra = {
            a["sha256"]: base64.b64encode(sources[a["sha256"]]).decode()
            for a in report["sources"]
            if a["sha256"] in sources
        }
        encoded = canonical(report)
        evidence = hashlib.sha256(
            canonical(dict(report=report, supporting_sources=extra)).encode()
        ).hexdigest()
        engine = engine_fingerprint()
        check_id = str(uuid5(UUID(inventory_attempt_id), evidence + engine))
        cur.execute(
            "SELECT evidence_fingerprint,engine_fingerprint,capture_sha256,report,supporting_sources "
            "FROM evidence_pipeline.selected_component_checks WHERE id=%s",
            (check_id,),
        )
        previous = cur.fetchone()
        expected = (evidence, engine, hashlib.sha256(raw).hexdigest(), report, extra)
        if previous is not None:
            if previous != expected:
                raise ReplayConflict(
                    "Selected component replay differs from retained evidence"
                )
        else:
            cur.execute(
                "INSERT INTO evidence_pipeline.selected_component_checks "
                "(id,inventory_attempt_id,evidence_fingerprint,engine_fingerprint,capture_sha256,capture,report,supporting_sources) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                (
                    check_id,
                    inventory_attempt_id,
                    evidence,
                    engine,
                    expected[2],
                    raw,
                    encoded,
                    canonical(extra),
                ),
            )
        return dict(
            check_id=check_id,
            replayed=previous is not None,
            records=len(report["rows"]),
            associated=sum(
                row["inventory_receipt_id"] is not None for row in report["rows"]
            ),
        )
