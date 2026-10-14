"""Validate inventory without conflating package observations or provider identities.

The inventory is registry uninstall entries and registered Appx packages. It is
not an exhaustive executable scan, an Intune response or an applicability claim.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from standalone.evidence_pipeline.contracts import identifier, utc
from .manifest import validate_manifest
from .bundle_manifest import validate_links, validate_member, validate_summary


CONTRACT = "triagemate-windows-inventory-v1"
APPX_PACKAGE_TYPES = ["Main", "Framework", "Resource", "Bundle", "Xap", "Optional"]
REGISTRY_SUFFIXES = (
    r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)


@dataclass(frozen=True)
class DeviceBinding:
    machine_guid: str
    tenant_id: str
    device_id: str

    def __post_init__(self):
        for name in ("machine_guid", "tenant_id", "device_id"):
            object.__setattr__(self, name, identifier(getattr(self, name)))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Nonfinite inventory value")


def _text(value, *, required=False):
    if value is None and not required:
        return
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or (required and not value.strip())
    ):
        raise ValueError("Invalid inventory text field")


def validate(raw: bytes, expected: DeviceBinding) -> dict:
    """Return exact validated fields; no fuzzy identities or version coercion.

    A source-native ID is unique only within a device and package kind. Registry
    and Appx observations of the same product remain separate source assertions.
    Collection transport owns timeout/cancellation and complete output staging.
    """
    if not isinstance(raw, bytes) or not isinstance(expected, DeviceBinding):
        raise ValueError("Inventory bytes and explicit device binding are required")
    try:
        value = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid inventory JSON") from exc
    return validate_document(value, expected)


def validate_document(
    value: dict, expected: DeviceBinding, *, check_links=True
) -> dict:
    """Validate a materialized envelope (also used for individual streamed rows)."""
    if not isinstance(expected, DeviceBinding):
        raise ValueError("An explicit inventory device binding is required")
    if not isinstance(value, dict) or set(value) != {
        "contract",
        "source",
        "started_at",
        "finished_at",
        "machine_guid",
        "tenant_id",
        "device_id",
        "coverage",
        "records",
        "record_count",
        "complete",
    }:
        raise ValueError("Unexpected inventory envelope")
    if value["contract"] != CONTRACT or value["source"] != "Windows inventory":
        raise ValueError("Unsupported inventory source contract")
    actual = DeviceBinding(
        *(value[key] for key in ("machine_guid", "tenant_id", "device_id"))
    )
    if actual != expected:
        raise ValueError("Inventory target differs from the configured device")
    for key in ("started_at", "finished_at"):
        _text(value[key], required=True)
    started, finished = (
        utc(datetime.fromisoformat(value[key])) for key in ("started_at", "finished_at")
    )
    if finished < started or value["complete"] is not True:
        raise ValueError("Inventory is not a complete timed collection")
    coverage = value["coverage"]
    if (
        not isinstance(coverage, dict)
        or set(coverage)
        != {
            "registry_roots",
            "loaded_user_sids",
            "appx_scope",
            "appx_package_types",
            "unloaded_user_hives",
            "portable_applications",
            "completeness",
        }
        or any(
            coverage[key] != expected_value
            for key, expected_value in {
                "appx_scope": "all-users",
                "appx_package_types": APPX_PACKAGE_TYPES,
                "unloaded_user_hives": "not-read",
                "portable_applications": "not-enumerated",
                "completeness": "within-declared-contract",
            }.items()
        )
    ):
        raise ValueError("Inventory must declare its coverage limitations")
    for key in ("registry_roots", "loaded_user_sids"):
        if not isinstance(coverage[key], list):
            raise ValueError("Inventory coverage requires source arrays")
        for item in coverage[key]:
            _text(item, required=True)
        if len(set(coverage[key])) != len(coverage[key]):
            raise ValueError("Duplicate inventory coverage declaration")
    if any(
        not re.fullmatch(r"S-1-(?:5-21|12-1)-[0-9]+-[0-9]+-[0-9]+-[0-9]+", sid)
        for sid in coverage["loaded_user_sids"]
    ):
        raise ValueError("Invalid loaded-user SID")
    roots = {
        "Registry::" + hive + suffix
        for hive in ["HKEY_LOCAL_MACHINE"]
        + ["HKEY_USERS\\" + sid for sid in coverage["loaded_user_sids"]]
        for suffix in REGISTRY_SUFFIXES
    }
    if set(coverage["registry_roots"]) != roots:
        raise ValueError("Inventory registry coverage differs from its contract")
    records = value["records"]
    if (
        not isinstance(records, list)
        or type(value["record_count"]) is not int
        or value["record_count"] != len(records)
    ):
        raise ValueError("Inventory record count does not match complete output")
    identities = set()
    common = {"kind", "native_id", "name", "version", "publisher"}
    for record in records:
        if not isinstance(record, dict) or record.get("kind") not in (
            "registry",
            "appx",
            "appx_bundle_member",
        ):
            raise ValueError("Unsupported inventory observation")
        if record["kind"] == "appx_bundle_member":
            validate_member(record)
            identity = (record["kind"], record["native_id"])
            if identity in identities:
                raise ValueError("Duplicate inventory native identity")
            identities.add(identity)
            continue
        fields = common | (
            {"install_date", "system_component", "release_type", "parent_key_name"}
            if record["kind"] == "registry"
            else {
                "family_name",
                "architecture",
                "is_framework",
                "is_resource_package",
                "non_removable",
                "status",
                "user_states",
            }
        )
        # Earlier v1 observations omit this additive source fact. Preserve that
        # absence as unknown rather than fabricating a non-bundle assertion.
        if record["kind"] == "appx":
            fields.update(
                {"is_bundle", "manifest", "resource_id", "bundle_manifest"}
                & record.keys()
            )
        if record["kind"] == "registry":
            fields.update({"reported_value_names", "localized_name"} & record.keys())
        if set(record) != fields:
            raise ValueError("Unexpected inventory observation fields")
        boolean_fields = {
            "is_framework",
            "is_resource_package",
            "non_removable",
            "is_bundle",
        }
        for key, item in record.items():
            if key == "bundle_manifest":
                validate_summary(record)
            elif key == "resource_id":
                if not isinstance(item, str) or not (
                    re.fullmatch(r"[A-Za-z0-9.-]{0,30}", item)
                    or (item == "~" and record.get("is_bundle") is True)
                ):
                    raise ValueError("Invalid Appx resource identity")
            elif key == "manifest":
                validate_manifest(record)
            elif key == "reported_value_names":
                if not isinstance(item, list):
                    raise ValueError("Registry value names must be an array")
                for name in item:
                    _text(name)
                    if not isinstance(name, str):
                        raise ValueError("Invalid registry value name")
                if len({name.casefold() for name in item}) != len(item):
                    raise ValueError("Duplicate registry value name")
            elif key == "user_states":
                if not isinstance(item, list):
                    raise ValueError("Appx user states must be an array")
                sids = set()
                for state in item:
                    if not isinstance(state, dict) or set(state) != {
                        "sid",
                        "install_state",
                    }:
                        raise ValueError("Invalid Appx user state")
                    _text(state["sid"], required=True)
                    _text(state["install_state"], required=True)
                    if (
                        not re.fullmatch(r"S-1-\d+(?:-\d+)+", state["sid"])
                        or state["sid"] in sids
                    ):
                        raise ValueError("Invalid or duplicate Appx user SID")
                    sids.add(state["sid"])
            elif key in boolean_fields:
                if type(item) is not bool:
                    raise ValueError("Invalid Appx boolean")
            elif key == "system_component":
                if item is not None and (type(item) is not int or item not in (0, 1)):
                    raise ValueError("Invalid registry system-component flag")
            else:
                _text(item, required=key in ("kind", "native_id"))
        if record["kind"] == "registry" and "reported_value_names" in record:
            names = {name.casefold() for name in record["reported_value_names"]}
            source_fields = {
                "name": "DisplayName",
                "version": "DisplayVersion",
                "publisher": "Publisher",
                "install_date": "InstallDate",
                "system_component": "SystemComponent",
                "release_type": "ReleaseType",
                "parent_key_name": "ParentKeyName",
                "localized_name": "DisplayName_Localized",
            }
            if any(
                record.get(field) is not None and name.casefold() not in names
                for field, name in source_fields.items()
            ):
                raise ValueError(
                    "Registry value presence conflicts with reported facts"
                )
        if record["kind"] == "registry" and not any(
            record["native_id"].startswith(root.removeprefix("Registry::") + "\\")
            and "\\"
            not in record["native_id"][len(root.removeprefix("Registry::")) + 1 :]
            and len(record["native_id"]) > len(root.removeprefix("Registry::")) + 1
            for root in roots
        ):
            raise ValueError("Registry observation is outside declared roots")
        identity = (record["kind"], record["native_id"])
        if identity in identities:
            raise ValueError("Duplicate inventory native identity")
        identities.add(identity)
    if check_links:
        validate_links(records)
    return value


def observation_key(binding: DeviceBinding, record: dict) -> str:
    """Stable local source identity, deliberately distinct from an Intune app ID."""
    return hashlib.sha256(
        json.dumps(
            [
                CONTRACT,
                binding.tenant_id,
                binding.device_id,
                binding.machine_guid,
                record["kind"],
                record["native_id"],
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
