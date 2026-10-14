"""Microsoft device wire fields mapped to the accepted evidence schema.

Mappings are drawn from the retained source collectors. This adapter has no
agency inference, hostname matching, risk scores or device-changing operations.
"""

from dataclasses import dataclass
import hashlib
import json
from uuid import NAMESPACE_URL, uuid5

from standalone.evidence_pipeline.parsing.source_time import source_datetime

from standalone.evidence_pipeline.contracts import Snapshot, identifier, utc


# target column -> provider field; absent fields remain NULL.
TEXT_FIELDS = {
    "Entra": {
        "display_name": "displayName",
        "operating_system": "operatingSystem",
        "os_version": "operatingSystemVersion",
        "join_type": "trustType",
    },
    "Intune": {
        "display_name": "deviceName",
        "operating_system": "operatingSystem",
        "os_version": "osVersion",
        "management_state": "managementState",
        "compliance_state": "complianceState",
        "owner_type": "managedDeviceOwnerType",
        "manufacturer": "manufacturer",
        "model": "model",
        "serial_number": "serialNumber",
    },
    "Defender": {
        "display_name": "computerDnsName",
        "operating_system": "osPlatform",
        "release_label": "version",
        "onboarding_status": "onboardingStatus",
        "sensor_health": "healthStatus",
    },
}
TIME_FIELDS = {
    "Entra": {
        "registered_at": "registrationDateTime",
        "approximate_last_sign_in": "approximateLastSignInDateTime",
    },
    "Intune": {"enrolled_at": "enrolledDateTime", "last_sync": "lastSyncDateTime"},
    "Defender": {"first_seen": "firstSeen", "last_seen": "lastSeen"},
}
BOOL_FIELDS = {
    "Entra": {
        "account_enabled": "accountEnabled",
        "managed_flag": "isManaged",
        "compliant_flag": "isCompliant",
    },
    "Intune": {},
    "Defender": {},
}
SHARED_FIELD = {
    "Entra": "deviceId",
    "Intune": "azureADDeviceId",
    "Defender": "aadDeviceId",
}


def stable_id(kind: str, *parts: str) -> str:
    """Length-safe namespace encoding; separate source IDs never collide by concatenation."""
    return str(
        uuid5(
            NAMESPACE_URL,
            json.dumps(["triagemate-evidence-v1", kind, *parts], separators=(",", ":")),
        )
    )


def optional_text(value, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 8192 or "\x00" in value:
        raise ValueError(f"Invalid text field: {field}")
    return value if value.strip() else None


def timestamp(value, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"Invalid timestamp field: {field}")
    try:
        return utc(source_datetime(value)).isoformat()
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp field: {field}") from exc


@dataclass(frozen=True)
class Device:
    provider_id: str
    native_id: str
    registration_id: str | None
    identity_issue: str | None
    # A tuple ensures callers cannot mutate validated fields after hashing.
    fields: tuple[tuple[str, str | bool | None], ...]
    content_hash: str

    def observation(self) -> dict:
        return dict(self.fields)


def normalize_devices(snapshot: Snapshot) -> tuple[Device, ...]:
    source = snapshot.scope.source
    if source not in TEXT_FIELDS or snapshot.scope.input_kind != "devices":
        raise ValueError("This adapter accepts only Microsoft device snapshots")
    if not snapshot.complete:
        raise ValueError("Partial or failed attempts must not materialize devices")
    result = []
    seen = set()
    for raw in snapshot.records():
        native = optional_text(raw.get("id"), "id")
        if native is None:
            raise ValueError("A source device ID is required")
        if source in ("Entra", "Intune"):
            native = identifier(native)
        if native in seen:
            raise ValueError("Duplicate device ID within a source snapshot")
        seen.add(native)
        shared = raw.get(SHARED_FIELD[source])
        issue = None
        try:
            registration = identifier(shared)
        except (ValueError, TypeError, AttributeError):
            registration = None
            issue = (
                "missing_registration_id"
                if shared is None or shared == ""
                else "invalid_registration_id"
            )
        fields = {
            target: optional_text(raw.get(field), field)
            for target, field in TEXT_FIELDS[source].items()
        }
        fields.update(
            {
                target: timestamp(raw.get(field), field)
                for target, field in TIME_FIELDS[source].items()
            }
        )
        for target, field in BOOL_FIELDS[source].items():
            value = raw.get(field)
            if value is not None and type(value) is not bool:
                raise ValueError(f"Invalid boolean field: {field}")
            fields[target] = value
        if source == "Defender":
            build = raw.get("osBuild")
            if build is not None and (type(build) is not int or build < 0):
                raise ValueError("Invalid Defender OS build")
            fields["os_build"] = str(build) if build is not None else None
            # Omit absent/unknown extension fields from the normalized hash so
            # historical receipts keep their exact identities after this upgrade.
            for target, field in (
                ("os_architecture", "osArchitecture"),
                ("os_processor", "osProcessor"),
            ):
                value = optional_text(raw.get(field), field)
                if value is not None:
                    fields[target] = value

        # The content hash describes the normalized retained evidence, not the
        # complete wire record. The snapshot separately fingerprints all input.
        retained = [source, native, registration, issue, fields]
        digest = hashlib.sha256(
            json.dumps(
                retained, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest()
        result.append(
            Device(
                stable_id("provider-device", snapshot.scope.connection_id, native),
                native,
                registration,
                issue,
                tuple(sorted(fields.items())),
                digest,
            )
        )
    return tuple(sorted(result, key=lambda item: item.native_id))


def match_device_groups(
    snapshots: list[tuple[Snapshot, tuple[Device, ...]]],
) -> dict[str, tuple[str, str]]:
    """Return provider ID -> (computer ID, basis) for a full current input set.

    A shared GUID matches only across different providers in the same tenant and
    evidence origin. Duplicate GUIDs within one provider remain separate. This
    pure proposal does not relink historical records or settle conflict policy.
    """
    groups = {}
    providers = set()
    for snapshot, devices in snapshots:
        for device in devices:
            if device.provider_id in providers:
                raise ValueError(
                    "Only one current snapshot per provider device is allowed"
                )
            providers.add(device.provider_id)
            key = (
                snapshot.scope.origin,
                snapshot.scope.tenant_id,
                device.registration_id,
            )
            groups.setdefault(key, []).append((snapshot.scope.source, device))
    links = {}
    for (origin, tenant, registration), members in groups.items():
        sources = [source for source, _ in members]
        ambiguous = len(set(sources)) != len(sources)
        for _, device in members:
            if registration and not ambiguous:
                computer = stable_id(
                    "computer-registration", origin, tenant, registration
                )
                basis = "microsoft_registration_id"
            else:
                computer = stable_id("computer-unmatched", device.provider_id)
                basis = (
                    "ambiguous_registration_id"
                    if registration
                    else device.identity_issue
                )
            links[device.provider_id] = (computer, basis)
    return links
