"""Software inventory and source-supported vulnerability relationships.

No CVE joins are treated as patch applicability. Findings and inventory are
separate inputs, so software without vulnerabilities is retained independently.
"""

from dataclasses import dataclass
import re
import json

from standalone.evidence_pipeline.contracts import Snapshot, identifier
from standalone.evidence_pipeline.parsing.devices import optional_text, stable_id


@dataclass(frozen=True)
class Software:
    id: str
    product_name: str
    publisher: str | None
    version: str | None
    platform: str | None


@dataclass(frozen=True)
class SoftwareInventory:
    source_application_id: str
    software: Software
    native_device_ids: tuple[str, ...]
    reported_device_count: int | None


@dataclass(frozen=True)
class Finding:
    source_finding_id: str
    native_device_id: str
    software: Software
    cve_id: str
    source_severity_label: str | None
    fixing_patch_reference: str | None


def software(product, publisher=None, version=None, platform=None):
    name = optional_text(product, "product_name")
    if name is None:
        raise ValueError("Source product name is missing")
    values = (
        name,
        optional_text(publisher, "publisher"),
        optional_text(version, "version"),
        optional_text(platform, "platform"),
    )
    # NULL and literal text "null" must remain different software identities.
    import json

    key = stable_id(
        "software", json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    )
    return Software(key, *values)


def require_snapshot(snapshot, source, kind):
    if (
        snapshot.scope.source != source
        or snapshot.scope.input_kind != kind
        or not snapshot.complete
    ):
        raise ValueError("A complete snapshot of the expected source/input is required")


def selected_software_device_id(scope):
    prefix = "managed-device-apps:"
    if not scope.scope_reference.startswith("managed-device-apps"):
        return None
    native = scope.scope_reference[len(prefix) :]
    if (
        not scope.scope_reference.startswith(prefix)
        or scope.source != "Intune"
        or scope.input_kind != "software"
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", native) is None
    ):
        raise ValueError("Invalid single-device software scope")
    return native


def normalize_software(
    snapshot: Snapshot,
    associations: dict[str, tuple[str, ...]],
    known_device_ids: set[str],
) -> tuple[SoftwareInventory, ...]:
    """Join completed app and app->device API responses, never guess associations.

    Association keys are source app IDs, not assumed UUIDs. Empty association
    lists must be explicit. Known device IDs come from the paired device snapshot.
    The transport must fetch all pages before calling this complete-input adapter.
    """
    require_snapshot(snapshot, "Intune", "software")
    if not isinstance(associations, dict):
        raise ValueError("Explicit app/device associations are required")
    known = {identifier(value) for value in known_device_ids}
    selected = selected_software_device_id(snapshot.scope)
    if selected is not None and known != {selected}:
        raise ValueError("Scoped software requires exactly its selected device")
    result = []
    seen = set()
    for raw in snapshot.records():
        app = optional_text(raw.get("id"), "application_id")
        if app is None or app in seen:
            raise ValueError("Missing or duplicate source application ID")
        seen.add(app)
        if app not in associations or not isinstance(associations[app], (tuple, list)):
            raise ValueError("A completed association result is required for every app")
        ids = tuple(identifier(value) for value in associations[app])
        if len(set(ids)) != len(ids) or not set(ids) <= known:
            raise ValueError("Duplicate or unknown device association")
        count = raw.get("deviceCount")
        if count is not None and (type(count) is not int or count < 0):
            raise ValueError("Invalid reported device count")
        if selected is not None and ids != (selected,):
            raise ValueError(
                "Scoped software requires its explicit device relationship"
            )
        if selected is None and count is not None and count != len(ids):
            raise ValueError(
                "Reported app device count differs from collected associations"
            )
        result.append(
            SoftwareInventory(
                app,
                software(
                    raw.get("displayName"),
                    raw.get("publisher"),
                    raw.get("version"),
                    raw.get("platform"),
                ),
                tuple(sorted(ids)),
                count,
            )
        )
    if set(associations) != seen:
        raise ValueError("Associations refer to an uncollected app")
    return tuple(sorted(result, key=lambda record: record.source_application_id))


def normalize_findings(
    snapshot: Snapshot, known_device_ids: set[str]
) -> tuple[Finding, ...]:
    require_snapshot(snapshot, "Defender", "findings")
    known = {optional_text(value, "machine_id") for value in known_device_ids}
    result = []
    seen = set()
    for raw in snapshot.records():
        key = optional_text(raw.get("id"), "finding_id")
        machine = optional_text(raw.get("machineId"), "machine_id")
        if key is None or key in seen:
            raise ValueError("Missing or duplicate source finding ID")
        seen.add(key)
        if machine is None or machine not in known:
            raise ValueError("Finding refers to an uncollected device")
        cve = raw.get("cveId")
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            raise ValueError("Invalid source CVE identifier")
        result.append(
            Finding(
                key,
                machine,
                software(
                    raw.get("productName"),
                    raw.get("productVendor"),
                    raw.get("productVersion"),
                ),
                cve,
                optional_text(raw.get("severity"), "severity"),
                optional_text(raw.get("fixingKbId"), "fixingKbId"),
            )
        )
    return tuple(sorted(result, key=lambda record: record.source_finding_id))


def associations(raw):
    if not isinstance(raw, bytes):
        raise ValueError("Bounded association bytes are required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate association key")
            result[key] = value
        return result

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid association payload") from exc
    if not isinstance(result, dict):
        raise ValueError("Associations must map app IDs to device ID arrays")
    return result
