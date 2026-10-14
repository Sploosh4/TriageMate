"""Source antivirus observations, not a verdict on overall device security.

Freshness statuses are source text. Only documented True/False values yield
boolean convenience fields; Unknown, empty, absent and unfamiliar labels never
become False. Their source text stays available independently.
"""

from dataclasses import dataclass

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.devices import timestamp
from standalone.evidence_pipeline.parsing.exposure import require_snapshot
from standalone.evidence_pipeline.parsing.update_status import count, required_text


TEXT_FIELDS = {
    "device_name": "computerDnsName",
    "os_kind": "osKind",
    "os_platform": "osPlatform",
    "os_version": "osVersion",
    "mode": "avMode",
    "signature_version": "avSignatureVersion",
    "engine_version": "avEngineVersion",
    "platform_version": "avPlatformVersion",
    "quick_scan_result": "quickScanResult",
    "quick_scan_error": "quickScanError",
    "full_scan_result": "fullScanResult",
    "full_scan_error": "fullScanError",
    "source_rbac_group_name": "rbacGroupName",
}
TIME_FIELDS = {
    "last_seen_at": "lastSeenTime",
    "refreshed_at": "dataRefreshTimestamp",
    "quick_scan_at": "quickScanTime",
    "full_scan_at": "fullScanTime",
    "signature_updated_at": "avSignatureUpdateTime",
    "engine_updated_at": "avEngineUpdateTime",
    "platform_updated_at": "avPlatformUpdateTime",
    "signature_published_at": "avSignaturePublishTime",
}
STATUS_FIELDS = {
    "signature": "avIsSignatureUpToDate",
    "engine": "avIsEngineUpToDate",
    "platform": "avIsPlatformUpToDate",
}
RETAINED_FIELDS = frozenset(
    ("id", "machineId", "rbacGroupId")
    + tuple(TEXT_FIELDS.values())
    + tuple(TIME_FIELDS.values())
    + tuple(STATUS_FIELDS.values())
)


def source_text(value, field):
    """Preserve empty source strings rather than inventing a status or mode."""
    if value is not None and (
        not isinstance(value, str) or len(value) > 8192 or "\x00" in value
    ):
        raise ValueError(f"Invalid antivirus text: {field}")
    return value


@dataclass(frozen=True)
class AntivirusHealth:
    source_record_id: str
    native_device_id: str
    fields: tuple[tuple[str, str | int | bool | None], ...]

    def observation(self):
        return dict(self.fields)


def normalize_antivirus(snapshot: Snapshot, known_device_ids: set[str]):
    """Validate a complete snapshot against its explicitly pinned device set.

    Microsoft describes rows per unique combination of device and health properties;
    distinct source records for a single device must not overwrite one another.
    Transport projects its full response to RETAINED_FIELDS before durable storage.
    """
    require_snapshot(snapshot, "Defender", "antivirus")
    known = {required_text(value, "machineId") for value in known_device_ids}
    result, seen = [], set()
    for raw in snapshot.records():
        if set(raw) - RETAINED_FIELDS:
            raise ValueError("Antivirus snapshot contains unretained fields")
        key = required_text(raw.get("id"), "id")
        machine = required_text(raw.get("machineId"), "machineId")
        if key in seen or machine not in known:
            raise ValueError("Duplicate antivirus record or unknown device")
        seen.add(key)
        fields = {
            "source_record_id": key,
            **{
                column: source_text(raw.get(source), source)
                for column, source in TEXT_FIELDS.items()
            },
            **{
                column: timestamp(raw.get(source), source)
                for column, source in TIME_FIELDS.items()
            },
            "source_rbac_group_id": count(raw.get("rbacGroupId"), "rbacGroupId"),
        }
        for prefix, source in STATUS_FIELDS.items():
            status = source_text(raw.get(source), source)
            fields[prefix + "_status"] = status
            fields[prefix + "_current"] = {"True": True, "False": False}.get(status)
        result.append(AntivirusHealth(key, machine, tuple(sorted(fields.items()))))
    return tuple(sorted(result, key=lambda row: row.source_record_id))
