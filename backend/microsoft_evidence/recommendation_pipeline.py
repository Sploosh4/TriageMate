"""Collect advice and every explicit device association as one complete input."""

from datetime import datetime, timezone
import json
import re

from standalone.evidence_pipeline.contracts import (
    Snapshot,
    MAX_RECORDS,
)
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.parsing.recommendations import (
    RETAINED_FIELDS,
    normalize_recommendations,
)
from .pipeline import device_binding, connection_scope, selected_device_id
from .source_registry import SOURCE_INPUTS
from standalone.evidence_pipeline.source_json import encode_source_records

INPUT_ID = "ms-defender-recommendation-v1"
DEVICE_INPUT_ID = "ms-defender-recommendation-device-v1"
PATH = "/api/recommendations"
DEVICE_PATH = PATH + "/{id}/machineReferences"


def device_recommendations_path(native_id):
    if not isinstance(native_id, str) or not re.fullmatch(r"[0-9a-f]{40}", native_id):
        raise ValueError("Invalid selected Defender device")
    return "/api/machines/" + native_id + "/recommendations"


def collect_recommendations(
    *,
    scope,
    execution_id,
    device_snapshot,
    prepared,
    token,
    transport,
    association_authority,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    device_binding(scope, device_snapshot, source="Defender")
    if scope.input_kind != "recommendations" or scope.origin != "lab":
        raise ValueError("Recommendation collection requires its own Microsoft scope")
    selected = selected_device_id(scope)
    path = PATH if selected is None else device_recommendations_path(selected)
    if selected is not None and {
        item.native_id for item in normalize_devices(device_snapshot)
    } != {selected}:
        raise ValueError("Recommendation scope requires exactly its selected device")
    if (
        prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud)
        or prepared.endpoint.path_template != path
    ):
        raise ValueError("Recommendation authority differs from input")
    started = now()
    result = transport.collect(
        prepared=prepared,
        token=token,
        source_input_id=INPUT_ID,
        query={},
        allowed_record_fields=RETAINED_FIELDS,
        required_record_fields=frozenset({"id", "recommendationName"}),
        offset_page_size=1000 if selected is None else None,
        allow_continuation=selected is None,
        cancelled=cancelled,
    )
    expected = next(item for item in SOURCE_INPUTS if item.input_id == INPUT_ID)
    if (
        result.input_id != INPUT_ID
        or result.source_contract_id != expected.source_contract_id
        or not result.pages
        or not result.pages[-1].terminal
    ):
        raise ValueError("Incomplete recommendation source contract")
    raw = [item for page in result.pages for item in page.records]
    if selected is not None and len(raw) >= 10000:
        raise ValueError("Saturated scoped recommendation response is incomplete")
    snapshot = Snapshot(
        scope,
        execution_id,
        started,
        now(),
        "success",
        True,
        encode_source_records(raw),
    )
    links = {}
    total = len(raw)
    for item in raw:
        source_id = item.get("id")
        if (
            source_id in (".", "..")
            or not isinstance(source_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_.~-]{1,512}", source_id)
            or source_id in links
        ):
            raise ValueError("Duplicate or unsafe recommendation identity")
        if cancelled():
            raise ValueError("Recommendation collection cancelled")
        if selected is not None:
            # The endpoint itself establishes the device relationship. Preserve
            # publisher counts without treating them as scoped link counts.
            links[source_id] = [selected]
            continue
        authority, lease = association_authority(source_id)
        if (
            authority.scope != prepared.scope
            or authority.endpoint.path_template
            != DEVICE_PATH.replace("{id}", source_id)
        ):
            raise ValueError("Association authority differs from recommendation")
        associated = transport.collect(
            prepared=authority,
            token=lease,
            source_input_id=DEVICE_INPUT_ID,
            query={},
            allowed_record_fields=frozenset({"id"}),
            required_record_fields=frozenset({"id"}),
            cancelled=cancelled,
        )
        expected = next(
            item for item in SOURCE_INPUTS if item.input_id == DEVICE_INPUT_ID
        )
        if (
            associated.input_id != DEVICE_INPUT_ID
            or associated.source_contract_id != expected.source_contract_id
            or not associated.pages
            or not associated.pages[-1].terminal
        ):
            raise ValueError("Incomplete recommendation association contract")
        ids = [row["id"] for page in associated.pages for row in page.records]
        total += len(ids)
        if total > MAX_RECORDS:
            raise ValueError("Recommendation association bounds exceeded")
        links[source_id] = ids
    snapshot = Snapshot(
        scope, execution_id, started, now(), "success", True, snapshot.payload
    )
    normalize_recommendations(
        snapshot, links, {item.native_id for item in normalize_devices(device_snapshot)}
    )
    return snapshot, json.dumps(
        links, separators=(",", ":"), ensure_ascii=False
    ).encode()


def collect_and_ingest_recommendations(
    *,
    scope,
    execution_id,
    root,
    device_snapshot,
    collect,
    now=lambda: datetime.now(timezone.utc),
):
    """Freeze the paired input before import; failures and retries never refetch."""
    from standalone.evidence_pipeline.recommendation_commands import ingest
    from standalone.evidence_pipeline.collection.snapshot_bundle import (
        prepare_recommendations,
    )
    from standalone.evidence_pipeline.parsing.exposure import associations
    from .live_authority import MicrosoftLiveAuthorityError
    from .transport import MicrosoftTransportError

    if scope.input_kind != "recommendations" or scope.origin != "lab":
        raise ValueError("Recommendation collection requires a lab source scope")
    binding = device_binding(scope, device_snapshot, source="Defender")
    known = {device.native_id for device in normalize_devices(device_snapshot)}

    def validated_collection():
        started = now()
        try:
            snapshot, links = collect()
            if snapshot.scope != scope or snapshot.execution_id != execution_id:
                raise ValueError(
                    "Recommendation collector returned a different execution"
                )
            normalize_recommendations(snapshot, associations(links), known)
            return snapshot, links
        except (MicrosoftTransportError, MicrosoftLiveAuthorityError) as exc:
            from .failures import failure_code

            error = failure_code(exc)
        except ValueError:
            error = "invalid_microsoft_collection"
        return Snapshot(
            scope, execution_id, started, now(), "failure", False, b"", error
        ), None

    snapshot, links = prepare_recommendations(
        scope, execution_id, root, collect=validated_collection, binding=binding
    )
    return ingest(snapshot, device_snapshot.execution_id, links)
