"""Collect source antivirus health against an explicitly pinned device snapshot."""

from datetime import datetime, timezone
import json

from standalone.evidence_pipeline.parsing.antivirus import (
    RETAINED_FIELDS,
    normalize_antivirus,
)
from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.devices import normalize_devices

from .pipeline import connection_scope, device_binding, selected_device_id
from .source_registry import SOURCE_INPUTS

INPUT_ID = "ms-defender-antivirus-health-v1"
PATH = "/api/deviceavinfo"


def collect_antivirus(
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
    """Return complete source health without treating it as remediation evidence.

    The API returns paginated current snapshots. Full response page chains are checked
    by the transport; only retained fields enter the durable snapshot. History is
    retained through separate collection receipts, not inferred from report dates.
    """
    device_binding(scope, device_snapshot, source="Defender")
    if scope.input_kind != "antivirus" or scope.origin != "lab":
        raise ValueError("Antivirus collection requires its dedicated lab scope")
    if prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud):
        raise ValueError("Antivirus authority does not match connection scope")
    if prepared.endpoint.path_template != PATH:
        raise ValueError("Antivirus collection requires the fixed health endpoint")
    if cancelled():
        raise ValueError("Antivirus collection cancelled")
    devices = normalize_devices(device_snapshot)
    selected_id = selected_device_id(scope)
    if selected_id is not None and (
        len(devices) != 1 or devices[0].native_id != selected_id
    ):
        raise ValueError(
            "Single-device antivirus requires the exact selected device snapshot"
        )
    source = next(item for item in SOURCE_INPUTS if item.input_id == INPUT_ID)
    started = now()
    result = transport.collect(
        prepared=prepared,
        token=token,
        source_input_id=INPUT_ID,
        query={"$filter": f"machineId eq '{selected_id}'", "$top": "10000"}
        if selected_id is not None
        else {},
        allowed_record_fields=RETAINED_FIELDS,
        required_record_fields=frozenset({"id", "machineId"}),
        cancelled=cancelled,
        allow_continuation=selected_id is None,
    )
    if (
        result.input_id != INPUT_ID
        or result.source_contract_id != source.source_contract_id
        or not result.pages
    ):
        raise ValueError("Antivirus response has no matching complete contract")
    if selected_id is not None and len(result.pages[-1].records) >= 10000:
        raise ValueError(
            "Full terminal antivirus page cannot establish snapshot completeness"
        )
    payload = json.dumps(
        [record for page in result.pages for record in page.records],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_antivirus(snapshot, {device.native_id for device in devices})
    return snapshot
