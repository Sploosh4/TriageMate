"""Device-scoped Defender responses for the retained PostgreSQL workspace."""

from datetime import datetime, timezone
import json
from urllib.parse import quote

from standalone.evidence_pipeline.contracts import (
    MAX_RECORDS,
    Snapshot,
)
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.parsing.update_status import normalize_missing_patches

from .defender_vulnerability_fields import MISSING_KB_PROVIDER_FIELDS
from .pipeline import connection_scope, device_binding
from .source_registry import SOURCE_INPUTS


def collect_missing_patches(
    *,
    scope,
    execution_id,
    device_snapshot,
    authority_for_device,
    transport,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    """Collect every pinned device; a failed request cannot publish partial state.

    The authority callback supplies an independently verified lease and prepared
    context for each concrete route. No credentials are acquired here. Provider
    counts do not create CVE relationships.
    """
    device_binding(scope, device_snapshot, source="Defender")
    if scope.input_kind != "missing_patches" or scope.origin != "lab":
        raise ValueError("Missing-patch collection requires its dedicated lab scope")
    devices = normalize_devices(device_snapshot)
    source = next(s for s in SOURCE_INPUTS if s.input_id == "ms-defender-missing-kb-v1")
    started = now()
    encoded = []
    for device in devices:
        if cancelled():
            raise ValueError("Missing-patch collection cancelled")
        prepared, token = authority_for_device(device.native_id)
        if prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud):
            raise ValueError("Missing-patch authority does not match connection scope")
        expected = f"/api/machines/{quote(device.native_id, safe='')}/getmissingkbs"
        if prepared.endpoint.path_template != expected:
            raise ValueError("Missing-patch endpoint does not match pinned device")
        result = transport.collect(
            prepared=prepared,
            token=token,
            source_input_id=source.input_id,
            query={},
            allowed_record_fields=frozenset(MISSING_KB_PROVIDER_FIELDS),
            required_record_fields=frozenset({"id"}),
            cancelled=cancelled,
        )
        if (
            result.input_id != source.input_id
            or result.source_contract_id != source.source_contract_id
            or not result.pages
        ):
            raise ValueError("Missing-patch response has no matching complete contract")
        for page in result.pages:
            for record in page.records:
                if set(record) - set(MISSING_KB_PROVIDER_FIELDS):
                    raise ValueError("Unexpected missing-patch response fields")
                raw = json.dumps(
                    {**record, "machineId": device.native_id},
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
                if len(encoded) >= MAX_RECORDS:
                    raise ValueError("Missing-patch snapshot exceeds retained bounds")
                encoded.append(raw)
    snapshot = Snapshot(
        scope,
        execution_id,
        started,
        now(),
        "success",
        True,
        b"[" + b",".join(encoded) + b"]",
    )
    normalize_missing_patches(snapshot, {d.native_id for d in devices})
    return snapshot


def collect_and_ingest_missing_patches(
    *,
    scope,
    execution_id,
    device_snapshot,
    root,
    authority_for_device,
    transport,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    """Persist a replayable bundle before importing any missing-patch evidence."""
    from standalone.evidence_pipeline.commands import ingest_exposure
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
    from .live_authority import MicrosoftLiveAuthorityError
    from .transport import MicrosoftTransportError

    binding = device_binding(scope, device_snapshot, source="Defender")

    def collect():
        started = now()
        try:
            return collect_missing_patches(
                scope=scope,
                execution_id=execution_id,
                device_snapshot=device_snapshot,
                authority_for_device=authority_for_device,
                transport=transport,
                now=now,
                cancelled=cancelled,
            )
        except (MicrosoftLiveAuthorityError, MicrosoftTransportError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_missing_patches"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        )

    snapshot = prepare(scope, execution_id, root, collect=collect, binding=binding)
    return ingest_exposure(snapshot, device_snapshot.execution_id)
