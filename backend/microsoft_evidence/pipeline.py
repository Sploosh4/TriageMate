"""Bridge verified Microsoft device collection into PostgreSQL snapshot inputs.

No database writes, agency assignment or credential acquisition occurs here.
Callers must supply separately prepared server-owned authority and a verified
lease. Network-collected evidence is always lab-labelled in this draft.
"""

from datetime import datetime, timezone
import json
import re
from typing import Callable

from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.device_binding import device_binding

from .cloud import MicrosoftConnectionScope, PreparedCollectionContext
from .live_authority import MicrosoftAccessTokenLease
from .resource_authority import MicrosoftResourceToken
from .source_registry import SOURCE_INPUTS
from .transport import MicrosoftHttpTransport

DEVICE_INPUTS = {
    "Entra": ("entra", "ms-entra-directory-device-v1", "/v1.0/devices"),
    "Intune": (
        "intune",
        "ms-intune-managed-device-v1",
        "/v1.0/deviceManagement/managedDevices",
    ),
    "Defender": ("defender", "ms-defender-machine-v1", "/api/machines"),
}


def selected_device_id(scope: SourceScope) -> str | None:
    """Recognise an authority-bound, single Microsoft device selection.

    This is a narrower connection than the legacy inventory scopes. Never turn
    an invalid selection into an unfiltered inventory request.
    """
    prefix = "native-device-id:"
    if not scope.scope_reference.startswith("native-device-id"):
        return None
    native_id = scope.scope_reference[len(prefix) :]
    if (
        not scope.scope_reference.startswith(prefix)
        or scope.source not in DEVICE_INPUTS
        or (
            scope.input_kind != "devices"
            and (scope.source, scope.input_kind)
            not in (
                ("Defender", "findings"),
                ("Defender", "antivirus"),
                ("Defender", "recommendations"),
            )
        )
        or re.fullmatch(
            r"[0-9a-f]{40}"
            if scope.source == "Defender"
            else r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
            native_id,
        )
        is None
    ):
        raise ValueError("Invalid single-device collection scope")
    return native_id


def selected_device_allowlist(scope: SourceScope) -> frozenset[str] | None:
    """Authority-bound Defender inventory guard, including restored registrations."""
    prefix = "allowed-native-device-ids:"
    if not scope.scope_reference.startswith("allowed-native-device-ids"):
        return None
    values = scope.scope_reference[len(prefix) :].split(",")
    if (
        not scope.scope_reference.startswith(prefix)
        or scope.source != "Defender"
        or scope.input_kind != "devices"
        or scope.origin != "lab"
        or not 1 <= len(values) <= 8
        or values != sorted(set(values))
        or any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in values)
    ):
        raise ValueError("Invalid explicit device allowlist")
    return frozenset(values)


def connection_scope(scope: SourceScope, *, cloud="global") -> MicrosoftConnectionScope:
    """Bind every pipeline scope field into the existing authority fingerprint."""
    if scope.source not in DEVICE_INPUTS:
        raise ValueError("Microsoft connection scope requires a Microsoft source")
    return MicrosoftConnectionScope(
        connection_id=scope.connection_id,
        tenant_id=scope.tenant_id,
        cloud=cloud,
        product=DEVICE_INPUTS[scope.source][0],
        input_kind=scope.input_kind,
        origin=scope.origin,
        scope_reference=scope.scope_reference,
        provenance=scope.provenance,
    )


def collect_devices(
    *,
    scope: SourceScope,
    execution_id: str,
    prepared: PreparedCollectionContext,
    token: MicrosoftAccessTokenLease | MicrosoftResourceToken,
    transport: MicrosoftHttpTransport,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    cancelled: Callable[[], bool] = lambda: False,
) -> Snapshot:
    """Return only a complete, validated device snapshot; failures raise safely.

    This does not activate lab persistence or decide which tenant is authorized.
    That authority remains in the server-owned manifest and connection register.
    The caller records failure attempts separately without materializing devices.
    """
    if scope.origin != "lab" or scope.input_kind != "devices":
        raise ValueError("Network device collection requires a lab device scope")
    expected = connection_scope(scope, cloud=prepared.scope.cloud)
    if prepared.scope != expected:
        raise ValueError("Prepared authority does not match the pipeline connection")
    _, input_id, path = DEVICE_INPUTS[scope.source]
    selected_id = selected_device_id(scope)
    allowed_ids = selected_device_allowlist(scope)
    if scope.source == "Intune" and selected_id is not None:
        path += "/" + selected_id
    if prepared.endpoint.path_template != path:
        raise ValueError("Device collection requires the device inventory endpoint")
    source = next(item for item in SOURCE_INPUTS if item.input_id == input_id)
    fields = frozenset(source.retained_fields)
    query = (
        {"$select": ",".join(source.retained_fields)}
        if scope.source != "Defender"
        else {}
    )
    if selected_id is not None and scope.source != "Intune":
        query["$filter"] = f"id eq '{selected_id}'"
    started = now()
    result = transport.collect(
        prepared=prepared,
        token=token,
        query=query,
        allowed_record_fields=fields,
        required_record_fields=frozenset({"id"}),
        cancelled=cancelled,
        allow_continuation=selected_id is None,
    )
    if (
        result.input_id != input_id
        or result.source_contract_id != source.source_contract_id
    ):
        raise ValueError("Collected source contract does not match the device input")
    records = [record for page in result.pages for record in page.records]
    if selected_id is not None and (
        len(records) > 1 or any(record.get("id") != selected_id for record in records)
    ):
        raise ValueError("Response exceeds the single-device collection scope")
    if allowed_ids is not None and any(
        record.get("id") not in allowed_ids for record in records
    ):
        raise ValueError("Response exceeds the explicit device allowlist")
    payload = json.dumps(
        records,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_devices(snapshot)
    return snapshot


def prepare_device_collection(
    *,
    scope,
    execution_id,
    root,
    prepared,
    token,
    transport,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    """Persist the device attempt before a caller tries restricted DB ingestion."""
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
    from .live_authority import MicrosoftLiveAuthorityError
    from .transport import MicrosoftTransportCancelled, MicrosoftTransportError

    def collect():
        started = now()
        try:
            return collect_devices(
                scope=scope,
                execution_id=execution_id,
                prepared=prepared,
                token=token,
                transport=transport,
                now=now,
                cancelled=cancelled,
            )
        except MicrosoftTransportCancelled:
            error = "microsoft_collection_cancelled"
        except (MicrosoftTransportError, MicrosoftLiveAuthorityError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_collection"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        )

    return prepare(scope, execution_id, root, collect=collect)


def collect_and_ingest_devices(**collection):
    """Collect or replay a durable bundle, then commit through the restricted writer.

    The connection must already be owner-registered. An ingestion exception must
    be retried using the same bundle root, scope and execution ID; it does not
    trigger another Microsoft request or overwrite the stored outcome.
    """
    from standalone.evidence_pipeline.commands import ingest

    snapshot = prepare_device_collection(**collection)
    return ingest(snapshot)


def collect_findings(
    *,
    scope,
    execution_id,
    device_snapshot,
    prepared,
    token,
    transport,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    """Collect Defender CVE instances against an explicit complete device snapshot.

    A full terminal page is rejected rather than silently treating a potentially
    truncated response as complete. Source KB text stays a reference, not proof
    of installation, applicability or remediation.
    """
    from standalone.evidence_pipeline.parsing.exposure import normalize_findings

    if (
        scope.source != "Defender"
        or scope.input_kind != "findings"
        or scope.origin != "lab"
        or device_snapshot.scope.source != "Defender"
        or device_snapshot.scope.input_kind != "devices"
        or not device_snapshot.complete
        or device_snapshot.scope.origin != scope.origin
        or device_snapshot.scope.tenant_id != scope.tenant_id
    ):
        raise ValueError(
            "Findings require complete Defender devices from the same tenant and origin"
        )
    devices = normalize_devices(device_snapshot)
    selected_id = selected_device_id(scope)
    if selected_id is not None and (
        len(devices) != 1 or devices[0].native_id != selected_id
    ):
        raise ValueError(
            "Single-device findings require the exact selected device snapshot"
        )
    if prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud):
        raise ValueError("Prepared authority does not match finding scope")
    if (
        prepared.endpoint.path_template
        != "/api/vulnerabilities/machinesVulnerabilities"
    ):
        raise ValueError("Finding collection requires the fixed vulnerability endpoint")
    source = next(
        item for item in SOURCE_INPUTS if item.input_id == "ms-defender-machine-cve-v1"
    )
    started = now()
    result = transport.collect(
        prepared=prepared,
        token=token,
        source_input_id=source.input_id,
        query={
            "$top": "10000",
            **(
                {"$filter": f"machineId eq '{selected_id}'"}
                if selected_id is not None
                else {}
            ),
        },
        allowed_record_fields=frozenset(source.retained_fields),
        required_record_fields=frozenset({"id", "machineId", "cveId", "productName"}),
        cancelled=cancelled,
        allow_continuation=selected_id is None,
    )
    if (
        result.input_id != source.input_id
        or result.source_contract_id != source.source_contract_id
    ):
        raise ValueError("Collected source contract differs from finding input")
    if len(result.pages[-1].records) >= 10000:
        raise ValueError(
            "Full terminal finding page cannot establish snapshot completeness"
        )
    payload = json.dumps(
        [record for page in result.pages for record in page.records],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_findings(snapshot, {device.native_id for device in devices})
    return snapshot


def collect_and_ingest_findings(
    *,
    scope,
    execution_id,
    device_snapshot,
    root,
    prepared,
    token,
    transport,
    now=lambda: datetime.now(timezone.utc),
):
    """Durably bind a finding attempt to its exact device snapshot before import."""
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
    from standalone.evidence_pipeline.commands import ingest_exposure
    from .live_authority import MicrosoftLiveAuthorityError
    from .transport import MicrosoftTransportError

    binding = finding_binding(scope, device_snapshot)

    def collect():
        started = now()
        try:
            return collect_findings(
                scope=scope,
                execution_id=execution_id,
                device_snapshot=device_snapshot,
                prepared=prepared,
                token=token,
                transport=transport,
                now=now,
            )
        except (MicrosoftLiveAuthorityError, MicrosoftTransportError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_findings"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        )

    snapshot = prepare(scope, execution_id, root, collect=collect, binding=binding)
    return ingest_exposure(snapshot, device_snapshot.execution_id)


def finding_binding(scope, device_snapshot):
    """Canonical binding shared by callable and command finding imports."""
    return device_binding(scope, device_snapshot, source="Defender")


def collect_and_ingest_software(
    *,
    scope,
    execution_id,
    root,
    device_snapshot,
    collect,
    now=lambda: datetime.now(timezone.utc),
):
    """Save application and relationship inputs together before restricted import.

    The supplied collector finishes both paginated inputs and returns a Snapshot
    plus exact association bytes. Replay never calls it again, including after an
    uncertain database acknowledgement. No device/application link is inferred.
    """
    from standalone.evidence_pipeline.commands import ingest_exposure
    from standalone.evidence_pipeline.collection.snapshot_bundle import (
        prepare_with_associations,
    )
    from standalone.evidence_pipeline.parsing.exposure import associations
    from standalone.evidence_pipeline.parsing.exposure import normalize_software
    from .live_authority import MicrosoftLiveAuthorityError
    from .transport import MicrosoftTransportError

    if scope.input_kind != "software" or scope.origin != "lab":
        raise ValueError("Software collection requires a lab software scope")
    binding = device_binding(scope, device_snapshot, source="Intune")
    known = {device.native_id for device in normalize_devices(device_snapshot)}

    def validated_collection():
        started = now()
        try:
            snapshot, links = collect()
            if snapshot.scope != scope or snapshot.execution_id != execution_id:
                raise ValueError("Software collector returned a different execution")
            normalize_software(snapshot, associations(links), known)
            return snapshot, links
        except (MicrosoftTransportError, MicrosoftLiveAuthorityError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_collection"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        ), None

    snapshot, links = prepare_with_associations(
        scope, execution_id, root, collect=validated_collection, binding=binding
    )
    return ingest_exposure(snapshot, device_snapshot.execution_id, links)
