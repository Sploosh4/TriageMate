"""Bounded full/delta Defender exports and replayable collection context."""

from datetime import datetime, timedelta, timezone
from standalone.evidence_pipeline.source_json import encode_source_records

from standalone.evidence_pipeline.contracts import Snapshot, utc, identifier
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
from standalone.evidence_pipeline.parsing.vulnerability_events import (
    RETAINED_FIELDS,
    normalize_assessments,
)

from .pipeline import connection_scope, device_binding, selected_device_allowlist
from .source_registry import SOURCE_INPUTS
from .transport import MicrosoftTransportError, MicrosoftTransportCancelled
from .live_authority import MicrosoftLiveAuthorityError

INPUTS = {
    "vulnerability_baseline": (
        "ms-defender-vulnerability-baseline-v1",
        "/api/machines/SoftwareVulnerabilitiesByMachine",
    ),
    "vulnerability_events": (
        "ms-defender-vulnerability-events-v1",
        "/api/machines/SoftwareVulnerabilityChangesByMachine",
    ),
}


def assessment_context(scope, device_snapshot, since=None):
    if scope.input_kind not in INPUTS or scope.origin != "lab":
        raise ValueError("Assessment requires its dedicated Microsoft scope")
    binding = device_binding(scope, device_snapshot, source="Defender")
    if scope.input_kind == "vulnerability_events":
        if not isinstance(since, datetime):
            raise ValueError("Delta requires an explicit checkpoint time")
        binding["since_time"] = utc(since).isoformat()
    elif since is not None:
        raise ValueError("Full baseline cannot accept a delta checkpoint")
    return binding


def collect_assessments(
    *,
    scope,
    execution_id,
    device_snapshot,
    prepared,
    token,
    transport,
    since=None,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    context = assessment_context(scope, device_snapshot, since)
    allowed_ids = selected_device_allowlist(device_snapshot.scope)
    if allowed_ids is not None and any(
        device.native_id not in allowed_ids
        for device in normalize_devices(device_snapshot)
    ):
        raise ValueError("Device prerequisite exceeds its explicit allowlist")
    input_id, path = INPUTS[scope.input_kind]
    if (
        prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud)
        or prepared.endpoint.path_template != path
    ):
        raise ValueError("Assessment authority or route differs from its scope")
    started = now()
    query = {"pageSize": "1000"}
    if since is not None:
        if not started - timedelta(days=14) <= utc(since) <= started:
            raise ValueError(
                "Delta checkpoint outside provider history; a fresh baseline is required"
            )
        query["sinceTime"] = context["since_time"]
    fields = (
        RETAINED_FIELDS
        if since is not None
        else RETAINED_FIELDS - {"status", "eventTimestamp"}
    )
    source = next(item for item in SOURCE_INPUTS if item.input_id == input_id)
    result = transport.collect(
        prepared=prepared,
        token=token,
        source_input_id=input_id,
        query=query,
        allowed_record_fields=fields,
        required_record_fields=frozenset(
            {"id", "deviceId", "softwareName", "softwareVendor", "softwareVersion"}
            | ({"status", "eventTimestamp"} if since is not None else set())
        ),
        cancelled=cancelled,
    )
    if (
        result.input_id != input_id
        or result.source_contract_id != source.source_contract_id
        or not result.pages
        or not result.pages[-1].terminal
    ):
        raise ValueError("Assessment has no complete matching source response")
    records = [record for page in result.pages for record in page.records]
    if allowed_ids is not None and any(
        record.get("deviceId") not in allowed_ids for record in records
    ):
        raise ValueError("Assessment response exceeds the explicit device allowlist")
    payload = encode_source_records(records)
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_assessments(
        snapshot, {device.native_id for device in normalize_devices(device_snapshot)}
    )
    return snapshot


def prepare_assessments(
    *,
    scope,
    execution_id,
    device_snapshot,
    root,
    fetch,
    since=None,
    predecessor=None,
    now=lambda: datetime.now(timezone.utc),
):
    """Freeze device/checkpoint identity; only replay an existing execution.

    The callback acquires authority only if a new bundle is needed. Database
    persistence and checkpoint advancement must happen after this returns.
    """
    binding = assessment_context(scope, device_snapshot, since)
    if predecessor is not None:
        if since is None:
            raise ValueError("Baseline cannot accept a predecessor")
        binding["predecessor_attempt_id"] = identifier(predecessor)

    def collect():
        started = now()
        try:
            return fetch()
        except MicrosoftTransportCancelled:
            error = "microsoft_collection_cancelled"
        except (MicrosoftTransportError, MicrosoftLiveAuthorityError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_assessment"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        )

    return prepare(scope, execution_id, root, collect=collect, binding=binding)
