"""Collect complete Intune application and device-link inputs for the pipeline."""

from datetime import datetime, timezone
import json
import re

from standalone.evidence_pipeline.contracts import (
    MAX_RECORDS,
    Snapshot,
)
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.parsing.exposure import (
    normalize_software,
    selected_software_device_id,
)

from .pipeline import connection_scope, device_binding
from .source_registry import SOURCE_INPUTS


def device_software_path(native):
    return f"/beta/deviceManagement/managedDevices/{native}/detectedApps"


def _encode(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def collect_software(
    *,
    scope,
    execution_id,
    device_snapshot,
    prepared,
    token,
    transport,
    application_device_authority,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    """Fetch every app and its explicit device links using separately bound routes.

    The authority callback returns (prepared context, token) for one exact app
    route. The caller owns credentials; this adapter cannot broaden authority.
    Pagination and response bounds are enforced by the existing transport.
    Aggregate retained record counts are bounded across all application results.
    """
    if scope.origin != "lab" or scope.input_kind != "software":
        raise ValueError("Network software collection requires a lab software scope")
    device_binding(scope, device_snapshot, source="Intune")
    known = {device.native_id for device in normalize_devices(device_snapshot)}
    selected = selected_software_device_id(scope)
    if selected is not None and known != {selected}:
        raise ValueError("Software scope requires its exact selected device snapshot")
    expected = connection_scope(scope, cloud=prepared.scope.cloud)
    started = now()

    def fetch(authority, lease, path, input_id, fields):
        if authority.scope != expected or authority.endpoint.path_template != path:
            raise ValueError(
                "Software authority does not match its exact connection and route"
            )
        source = next(item for item in SOURCE_INPUTS if item.input_id == input_id)
        result = transport.collect(
            prepared=authority,
            token=lease,
            source_input_id=input_id,
            query={"$select": ",".join(fields)},
            allowed_record_fields=frozenset(fields),
            required_record_fields=frozenset({"id"}),
            cancelled=cancelled,
        )
        if (
            result.input_id != input_id
            or result.source_contract_id != source.source_contract_id
        ):
            raise ValueError("Software response has a different source contract")
        return [record for page in result.pages for record in page.records]

    source = next(
        item for item in SOURCE_INPUTS if item.input_id == "ms-intune-detected-app-v1"
    )
    applications = fetch(
        prepared,
        token,
        device_software_path(selected)
        if selected is not None
        else "/v1.0/deviceManagement/detectedApps",
        source.input_id,
        source.retained_fields,
    )
    payload = _encode(applications)
    if len(applications) > MAX_RECORDS:
        raise ValueError("Software collection exceeds aggregate bounds")
    app_ids = []
    for app in applications:
        app_id = app.get("id")
        if (
            app_id in (".", "..")
            or not isinstance(app_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._~-]{1,512}", app_id)
        ):
            raise ValueError("Unsupported application identifier in device-link route")
        app_ids.append(app_id)
    if len(set(app_ids)) != len(app_ids):
        raise ValueError("Duplicate application identity")
    links = {}
    records = len(applications)
    for app_id in app_ids:
        if selected is not None:
            # The device-specific navigation relationship supplies this association.
            links[app_id] = [selected]
            continue
        authority, lease = application_device_authority(app_id)
        path = f"/v1.0/deviceManagement/detectedApps/{app_id}/managedDevices"
        devices = fetch(
            authority, lease, path, "ms-intune-detected-app-device-edge-v1", ("id",)
        )
        records += len(devices)
        links[app_id] = [device["id"] for device in devices]
        if records > MAX_RECORDS:
            raise ValueError("Software collection exceeds aggregate bounds")
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_software(snapshot, links, known)
    return snapshot, _encode(links)
