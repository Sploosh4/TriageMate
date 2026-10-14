"""Source-reported missing patches and policy status, never remediation inference.

Missing-KB rows must already carry the machine ID from their device-scoped
request. Counts cannot create CVE/device links. Report status never establishes
installation of a named patch or resolution of a vulnerability.
"""

from dataclasses import dataclass

from standalone.evidence_pipeline.parsing.update_report_timestamps import (
    update_report_timestamp,
)
from standalone.evidence_pipeline.contracts import Snapshot, identifier
from standalone.evidence_pipeline.parsing.devices import optional_text
from standalone.evidence_pipeline.parsing.exposure import require_snapshot


def required_text(value, field):
    result = optional_text(value, field)
    if result is None:
        raise ValueError(f"Missing {field}")
    return result


def count(value, field):
    if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
        raise ValueError(f"Invalid {field}")
    return value


@dataclass(frozen=True)
class MissingPatch:
    native_device_id: str
    source_patch_id: str
    title: str | None
    product_labels: tuple[str, ...] | None
    url: str | None
    reported_machine_count: int | None
    reported_cve_count: int | None


def normalize_missing_patches(snapshot: Snapshot, known_device_ids: set[str]):
    """Normalize complete device-bound provider rows; no vulnerability joins."""
    require_snapshot(snapshot, "Defender", "missing_patches")
    known = {required_text(value, "machineId") for value in known_device_ids}
    result, seen = [], set()
    for raw in snapshot.records():
        machine = required_text(raw.get("machineId"), "machineId")
        patch = required_text(raw.get("id"), "id")
        key = (machine, patch)
        if machine not in known or key in seen:
            raise ValueError("Unknown device or duplicate device/patch observation")
        seen.add(key)
        products = raw.get("productsNames")
        if products is not None:
            if not isinstance(products, list):
                raise ValueError("productsNames must be an array")
            products = tuple(
                required_text(value, "productsNames") for value in products
            )
        result.append(
            MissingPatch(
                machine,
                patch,
                optional_text(raw.get("name"), "name"),
                products,
                optional_text(raw.get("url"), "url"),
                count(raw.get("machineMissedOn"), "machineMissedOn"),
                count(raw.get("cveAddressed"), "cveAddressed"),
            )
        )
    return tuple(
        sorted(result, key=lambda row: (row.native_device_id, row.source_patch_id))
    )


UPDATE_TEXT_FIELDS = {
    "device_name": "DeviceName",
    "owner_type": "OwnerType",
    "aggregate_state": "AggregateState",
    "aggregate_state_localized": "AggregateState_loc",
    "current_status": "CurrentDeviceUpdateStatus",
    "current_status_localized": "CurrentDeviceUpdateStatus_loc",
    "current_substatus": "CurrentDeviceUpdateSubstatus",
    "current_substatus_localized": "CurrentDeviceUpdateSubstatus_loc",
    "alert_message": "LatestAlertMessage",
    "alert_message_localized": "LatestAlertMessage_loc",
}


@dataclass(frozen=True)
class UpdatePolicyStatus:
    native_device_id: str
    policy_id: str
    fields: tuple[tuple[str, str | None], ...]

    def observation(self):
        return dict(self.fields)


def normalize_update_status(snapshot: Snapshot, known_device_ids: set[str]):
    require_snapshot(snapshot, "Intune", "update_status")
    known = {identifier(value) for value in known_device_ids}
    result, seen = [], set()
    for raw in snapshot.records():
        device = identifier(raw.get("DeviceId"))
        policy = identifier(raw.get("PolicyId"))
        if device not in known or (device, policy) in seen:
            raise ValueError("Unknown device or duplicate device/policy observation")
        seen.add((device, policy))
        registration = optional_text(raw.get("AADDeviceId"), "AADDeviceId")
        fields = {
            "source_device_id": device,
            "source_registration_id": identifier(registration)
            if registration
            else None,
            "policy_id": policy,
            **{
                column: optional_text(raw.get(source), source)
                for column, source in UPDATE_TEXT_FIELDS.items()
            },
            "event_time": update_report_timestamp(
                raw.get("EventDateTimeUTC"), "EventDateTimeUTC"
            ),
            "last_wu_scan_at": update_report_timestamp(
                raw.get("LastWUScanTimeUTC"), "LastWUScanTimeUTC"
            ),
        }
        result.append(UpdatePolicyStatus(device, policy, tuple(sorted(fields.items()))))
    return tuple(sorted(result, key=lambda row: (row.native_device_id, row.policy_id)))
